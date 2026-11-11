//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/sibling"
	"github.com/urfave/cli"
)

const unikraftPackageArgName = "unikraft-diode-package"

type unikraftConfig struct {
	*sibling.UnikraftConfig
}

func parseUnikraftManifest(reader io.Reader) (*unikraftConfig, error) {
	config, err := sibling.ParseUnikraftManifest(reader)
	if err != nil {
		return nil, err
	}
	return &unikraftConfig{config}, nil
}

func loadUnikraftConfig(c *cli.Context, plan *siblingStoragePlan) (*unikraftConfig, error) {
	directory := c.String(unikraftPackageArgName)
	if directory == "" {
		return nil, nil
	}
	if c.GlobalUint64(cpusArgName) != 2 {
		return nil, errors.New("unikraft pair requires --cpus=2 for the Linux workload; the Unikraft diode remains one VP")
	}
	if !useGCS || !c.Bool(securityHardwareFlag) || !c.Bool(sharedMemoryTwoUVMArgName) ||
		c.GlobalInt(countArgName) != 2 || c.GlobalInt(parallelArgName) != 2 ||
		c.Uint64(sharedMemorySizeArgName) != 32*1024*1024 || c.String(siblingBusGuestModuleArgName) == "" {
		return nil, errors.New("unikraft diode requires an SNP/GCS two-VM sibling pair, a 32 MiB section and sibling-bus module")
	}
	for _, flag := range []string{sharedMemoryGuestModuleArgName, sharedMemoryMappingOnlyArgName,
		sharedMemoryGuestInventoryArgName, siblingOpenShellBundleArgName, baselineNICArgName, baselinePairArgName,
		scsiMountsArgName, vpmemMountsArgName} {
		if c.IsSet(flag) {
			return nil, fmt.Errorf("unikraft diode does not support --%s", flag)
		}
	}
	if !c.Bool(siblingInteractiveArgName) && !c.IsSet(execCommandLineArgName) && !c.IsSet(execFileArgName) &&
		c.String(networkBenchmarkScriptArgName) == "" && c.String(storageBenchmarkScriptArgName) == "" {
		return nil, errors.New("unikraft pair requires --sibling-interactive or an explicit workload --exec/--exec-file test")
	}
	file, err := os.Open(filepath.Join(directory, "launch-manifest.json"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	cfg, err := parseUnikraftManifest(file)
	if err != nil {
		return nil, err
	}
	if cfg.GCSRelay != c.Bool(siblingGCSRelayArgName) {
		return nil, errors.New("Unikraft firmware gcs_relay selection must match --sibling-gcs-relay; no direct-GCS fallback")
	}
	inputs := []string{filepath.Join(directory, "guest.vmgs"), c.String(siblingBusGuestModuleArgName)}
	if plan != nil {
		inputs = append(inputs, filepath.Join(filepath.Dir(c.String(siblingBusGuestModuleArgName)), "diode_storage_test"))
	}
	for _, path := range inputs {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return nil, fmt.Errorf("missing regular, nonempty input %s", path)
		}
	}
	if c.Bool(siblingDiodeUplinkArgName) != (cfg.Network != nil) {
		return nil, errors.New("--sibling-diode-uplink must match networking in the Unikraft manifest")
	}
	if c.String(networkBenchmarkScriptArgName) != "" && (cfg.Network == nil || !c.Bool(networkBenchmarkSingleVPArgName)) {
		return nil, errors.New("Unikraft network benchmark requires networking and --network-benchmark-single-vp")
	}
	if c.String(networkBenchmarkScriptArgName) != "" && cfg.Idle != c.String(networkBenchmarkIdleArgName) {
		return nil, fmt.Errorf("Unikraft firmware idle=%s does not match benchmark idle=%s", cfg.Idle, c.String(networkBenchmarkIdleArgName))
	}
	if c.String(storageBenchmarkScriptArgName) != "" &&
		(cfg.Network != nil || cfg.Idle != c.String(storageBenchmarkIdleArgName)) {
		return nil, errors.New("Unikraft storage firmware must be network-free and match the requested idle policy")
	}
	if _, _, err := cfg.storageDevices(plan); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *unikraftConfig) storageDevices(plan *siblingStoragePlan) (map[string]hcsschema.Scsi, []siblingStorageBackendReport, error) {
	count := 0
	if plan != nil {
		count = len(plan.Disks)
	}
	if count != len(cfg.LUNs) {
		return nil, nil, errors.New("unikraft manifest LUNs must exactly match the storage backend plan")
	}
	if count == 0 {
		return nil, nil, nil
	}
	attachments := map[string]hcsschema.Attachment{}
	var reports []siblingStorageBackendReport
	for _, disk := range plan.Disks {
		found := false
		for _, lun := range cfg.LUNs {
			if disk.ExportLUN == nil || *disk.ExportLUN != lun.Exported {
				continue
			}
			if lun.ReadOnly != (disk.Access == "read-only") {
				return nil, nil, fmt.Errorf("unikraft access mismatch for %s", disk.ID)
			}
			attachments[strconv.Itoa(int(lun.Root))] = hcsschema.Attachment{
				Type_: "VirtualDisk", Path: disk.HostPath, ReadOnly: lun.ReadOnly,
			}
			controller := uint(0)
			for i, id := range guestrequest.ScsiControllerGuids {
				if strings.EqualFold(id, cfg.Controller) {
					controller = uint(i)
				}
			}
			reports = append(reports, siblingStorageBackendReport{
				DiskID: disk.ID, Role: disk.Role, HostPath: disk.HostPath, ReadOnly: lun.ReadOnly,
				DiodeVM: "uvmboot-0", WorkloadVM: "uvmboot-1", ControllerID: cfg.Controller,
				Controller: controller, LUN: uint(lun.Root), ExportLUN: lun.Exported, State: "configured-at-boot",
			})
			found = true
			break
		}
		if !found {
			return nil, nil, fmt.Errorf("unikraft manifest has no export for %s", disk.ID)
		}
	}
	return map[string]hcsschema.Scsi{cfg.Controller: {Attachments: attachments}}, reports, nil
}
