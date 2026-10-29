//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

const (
	siblingStorageBackendsArgName  = "sibling-storage-backends"
	validateStorageBackendsArgName = "validate-storage-backends"
)

type siblingStoragePlan struct {
	Version int                  `json:"version"`
	Disks   []siblingStorageDisk `json:"disks"`
}

type siblingStorageDisk struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	HostPath  string `json:"host_path"`
	Access    string `json:"access"`
	ExportLUN *uint8 `json:"export_lun"`
}

func loadSiblingStoragePlan(c *cli.Context) (*siblingStoragePlan, error) {
	if !c.IsSet(siblingStorageBackendsArgName) {
		if c.Bool(validateStorageBackendsArgName) {
			return nil, fmt.Errorf("--%s requires --%s", validateStorageBackendsArgName, siblingStorageBackendsArgName)
		}
		return nil, nil
	}
	// Optional Unikraft support may be absent from this checkout.
	if c.String("unikraft-diode-package") != "" {
		return nil, fmt.Errorf("--%s requires a Linux diode", siblingStorageBackendsArgName)
	}
	if !c.Bool(validateStorageBackendsArgName) && (!useGCS || !c.Bool(sharedMemoryTwoUVMArgName) ||
		c.GlobalInt(countArgName) != 2 || c.GlobalInt(parallelArgName) != 2 ||
		c.String(siblingBusGuestModuleArgName) == "") {
		return nil, fmt.Errorf("--%s requires a two-Linux-VM sibling pair with GCS and --%s",
			siblingStorageBackendsArgName, siblingBusGuestModuleArgName)
	}
	if c.IsSet(scsiMountsArgName) || c.IsSet(vpmemMountsArgName) ||
		c.Bool(sharedMemoryMappingOnlyArgName) || c.Bool(sharedMemoryGuestInventoryArgName) {
		return nil, fmt.Errorf("--%s is incompatible with ordinary disk mounts and mapping-only/inventory modes",
			siblingStorageBackendsArgName)
	}
	path := c.String(siblingStorageBackendsArgName)
	if path == "" {
		return nil, fmt.Errorf("--%s requires a JSON file", siblingStorageBackendsArgName)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open sibling storage backend plan: %w", err)
	}
	defer file.Close()

	plan, err := decodeSiblingStoragePlan(file)
	if err != nil {
		return nil, fmt.Errorf("load sibling storage backend plan %q: %w", path, err)
	}
	return plan, nil
}

func decodeSiblingStoragePlan(reader io.Reader) (*siblingStoragePlan, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var plan siblingStoragePlan
	if err := decoder.Decode(&plan); err != nil {
		return nil, fmt.Errorf("decode storage plan: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("storage plan contains multiple JSON values")
		}
		return nil, fmt.Errorf("decode storage plan trailing data: %w", err)
	}
	if plan.Version != 1 || len(plan.Disks) == 0 || len(plan.Disks) > 16 {
		return nil, errors.New("storage plan requires version 1 and at least one disk (maximum 16)")
	}
	ids := map[string]bool{}
	luns := map[uint8]bool{}
	var files []os.FileInfo
	var paths []string
	root := false
	for i := range plan.Disks {
		disk := &plan.Disks[i]
		if disk.ID == "" || strings.Trim(disk.ID, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return nil, fmt.Errorf("disk %d: id must contain only lowercase ASCII letters, digits, '-' or '_'", i)
		}
		if ids[disk.ID] {
			return nil, fmt.Errorf("duplicate storage disk id %q", disk.ID)
		}
		ids[disk.ID] = true
		if disk.Role != "root" && disk.Role != "data" {
			return nil, fmt.Errorf("disk %q: role must be root or data", disk.ID)
		}
		if disk.Access != "read-only" && disk.Access != "read-write" {
			return nil, fmt.Errorf("disk %q: access must be read-only or read-write", disk.ID)
		}
		if disk.Role == "root" {
			if root || disk.Access != "read-only" {
				return nil, errors.New("storage plan supports one read-only dm-verity root disk")
			}
			root = true
		}
		if disk.ExportLUN == nil {
			return nil, fmt.Errorf("disk %q: export_lun is required", disk.ID)
		}
		if *disk.ExportLUN == 255 {
			return nil, fmt.Errorf("disk %q: export_lun must be between 0 and 254", disk.ID)
		}
		if luns[*disk.ExportLUN] {
			return nil, fmt.Errorf("duplicate storage export LUN %d", *disk.ExportLUN)
		}
		luns[*disk.ExportLUN] = true
		if !filepath.IsAbs(disk.HostPath) {
			return nil, fmt.Errorf("disk %q: host_path must be absolute", disk.ID)
		}
		disk.HostPath = filepath.Clean(disk.HostPath)
		extension := strings.ToLower(filepath.Ext(disk.HostPath))
		if extension != ".vhd" && extension != ".vhdx" {
			return nil, fmt.Errorf("disk %q: host_path must name a VHD or VHDX", disk.ID)
		}
		info, err := os.Stat(disk.HostPath)
		if err != nil {
			return nil, fmt.Errorf("inspect disk %q: %w", disk.ID, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("disk %q: host_path is not a regular file", disk.ID)
		}
		for j, previous := range files {
			if strings.EqualFold(disk.HostPath, paths[j]) || os.SameFile(info, previous) {
				return nil, fmt.Errorf("disk %q aliases another storage backing file", disk.ID)
			}
		}
		files = append(files, info)
		paths = append(paths, disk.HostPath)
	}
	return &plan, nil
}

type siblingStorageAttachment struct {
	controller uint
	lun        uint
	release    func(context.Context) error
}

type siblingStorageBackendReport struct {
	DiskID       string `json:"disk_id"`
	Role         string `json:"role"`
	HostPath     string `json:"host_path"`
	ReadOnly     bool   `json:"read_only"`
	DiodeVM      string `json:"diode_vm"`
	WorkloadVM   string `json:"workload_vm"`
	ControllerID string `json:"controller_id"`
	Controller   uint   `json:"controller"`
	LUN          uint   `json:"lun"`
	ExportLUN    uint8  `json:"export_lun"`
	State        string `json:"state"`
}

type siblingStorageBackends struct {
	attachments []siblingStorageAttachment
	reports     []siblingStorageBackendReport
}

func prepareSiblingStorageBackends(
	ctx context.Context,
	vmID string,
	plan *siblingStoragePlan,
	attach func(context.Context, siblingStorageDisk) (siblingStorageAttachment, error),
) (_ *siblingStorageBackends, resultErr error) {
	backends := &siblingStorageBackends{}
	if plan == nil {
		return backends, nil
	}
	role, err := sharedMemoryProofRole(vmID)
	if err != nil {
		return nil, err
	}
	if role != "a" {
		return backends, nil
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, backends.close(ctx))
		}
	}()
	slots := map[[2]uint]bool{}
	for _, disk := range plan.Disks {
		attachment, err := attach(ctx, disk)
		if err != nil {
			return nil, fmt.Errorf("attach workload disk %q to diode: %w", disk.ID, err)
		}
		backends.attachments = append(backends.attachments, attachment)
		slot := [2]uint{attachment.controller, attachment.lun}
		if attachment.controller >= uint(len(guestrequest.ScsiControllerGuids)) ||
			slots[slot] || attachment.release == nil {
			return nil, fmt.Errorf("disk %q: invalid or duplicate diode attachment", disk.ID)
		}
		slots[slot] = true
		backends.reports = append(backends.reports, siblingStorageBackendReport{
			DiskID: disk.ID, Role: disk.Role, HostPath: disk.HostPath,
			ReadOnly: disk.Access == "read-only", DiodeVM: vmID, WorkloadVM: "uvmboot-1",
			ControllerID: guestrequest.ScsiControllerGuids[attachment.controller],
			Controller:   attachment.controller, LUN: attachment.lun,
			ExportLUN: *disk.ExportLUN, State: "attached-only",
		})
	}
	return backends, nil
}

func (backends *siblingStorageBackends) close(ctx context.Context) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var resultErr error
	for i := len(backends.attachments) - 1; i >= 0; i-- {
		attachment := backends.attachments[i]
		if attachment.release == nil {
			resultErr = errors.Join(resultErr, errors.New("storage attachment has no release operation"))
			continue
		}
		if err := attachment.release(cleanupCtx); err != nil {
			resultErr = errors.Join(resultErr,
				fmt.Errorf("release diode storage controller %d LUN %d: %w", attachment.controller, attachment.lun, err))
		}
	}
	backends.attachments = nil
	return resultErr
}

func attachSiblingStorageDisk(ctx context.Context, vm *uvm.UtilityVM, disk siblingStorageDisk) (siblingStorageAttachment, error) {
	mount, err := vm.SCSIManager.AddVirtualDisk(ctx, disk.HostPath,
		disk.Access == "read-only", vm.ID(), "", nil)
	if err != nil {
		return siblingStorageAttachment{}, err
	}

	return siblingStorageAttachment{
		controller: mount.Controller(), lun: mount.LUN(), release: mount.Release,
	}, nil
}

func siblingStorageGuestCommand(modulePath, role string, plan *siblingStoragePlan, reports []siblingStorageBackendReport) (string, error) {
	if plan == nil {
		return "", nil
	}
	if role != diodeRole && role != workloadRole {
		return "", fmt.Errorf("invalid storage guest role %q", role)
	}
	command := `mkdir -p /run/diode-storage || exit 1; `
	if role == diodeRole {
		if len(reports) != len(plan.Disks) {
			return "", errors.New("storage export requires every diode attachment mapping")
		}
		command += `storage_backends=; `
		var luns, readOnly []string
		for _, report := range reports {
			// Resolve the RP controller identity, never an assumed sdX name.
			controller := strings.ToLower(strings.Trim(report.ControllerID, "{}"))
			match := fmt.Sprintf(`storage_dev=; storage_count=0; for p in /sys/class/block/*; do `+
				`d=$(readlink -f "$p/device" 2>/dev/null) || continue; `+
				`case "$d" in */%s/host*/target*/*:0:0:%d) `+
				`storage_dev=/dev/${p##*/}; storage_count=$((storage_count+1));; esac; done; `+
				`[ "$storage_count" -eq 1 ] && [ -b "$storage_dev" ]`, controller, report.LUN)
			command += guestWaitFor(match, "diode storage "+report.DiskID)
			command += `storage_backends=${storage_backends:+$storage_backends,}$storage_dev; `
			luns = append(luns, fmt.Sprint(report.ExportLUN))
			readOnly = append(readOnly, fmt.Sprint(report.ReadOnly))
		}
		command += "insmod " + shellSingleQuote(modulePath) +
			` "backends=$storage_backends" ` + shellSingleQuote("luns="+strings.Join(luns, ",")) +
			" " + shellSingleQuote("read_only="+strings.Join(readOnly, ",")) + ` || exit 1; ` +
			`echo 'diode_storage: provider registered'; `
	} else {
		for _, disk := range plan.Disks {
			match := fmt.Sprintf(`storage_dev=; storage_count=0; for p in /sys/class/block/*; do `+
				`d=$(readlink -f "$p/device" 2>/dev/null) || continue; `+
				`case "$d" in */bus"${sb_bus}"-relid*/host*/target*/*:0:0:%d) `+
				`storage_dev=/dev/${p##*/}; storage_count=$((storage_count+1));; esac; done; `+
				`[ "$storage_count" -eq 1 ] && [ -b "$storage_dev" ]`, *disk.ExportLUN)
			command += guestWaitFor(match, "sibling storage "+disk.ID)
			command += `ln -sf "$storage_dev" /run/diode-storage/` + disk.ID + ` || exit 1; ` +
				`echo ` + shellSingleQuote(disk.Access) + ` > /run/diode-storage/` + disk.ID + `.access || exit 1; ` +
				`echo "diode_storage: ready id=` + disk.ID +
				fmt.Sprintf(` lun=%d device=$storage_dev access=%s bus=$sb_bus"; `, *disk.ExportLUN, disk.Access)
		}
		command += `cp /run/diode-storage-test/diode_storage_test /run/dtb-exec/storage-test && ` +
			`chmod 755 /run/dtb-exec/storage-test || { echo 'diode_storage: test staging failed' >&2; exit 1; }; `
	}
	return strings.TrimSuffix(command, "; "), nil
}
