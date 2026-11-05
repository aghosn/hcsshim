//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Microsoft/go-winio/pkg/guid"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/urfave/cli"
)

const unikraftPackageArgName = "unikraft-diode-package"

type unikraftNetwork struct {
	uplink, gateway, provider, peer netip.Addr
	providerMAC, peerMAC            net.HardwareAddr
}

type unikraftLUN struct {
	root, exported uint8
	readOnly       bool
}

type unikraftConfig struct {
	idle       string
	memoryMB   uint64
	controller string
	luns       []unikraftLUN
	network    *unikraftNetwork
}

// Read the actual IGVM input, not a second set of runtime kernel arguments.
func parseUnikraftManifest(reader io.Reader) (*unikraftConfig, error) {
	var manifest struct {
		Arch   string `json:"guest_arch"`
		Guests []struct {
			Image struct {
				Direct *struct {
					Processors uint64 `json:"processor_count"`
					Pages      uint64 `json:"memory_page_count"`
					Linux      struct {
						CommandLine string `json:"command_line"`
					} `json:"linux"`
				} `json:"snp_linux_direct"`
			} `json:"image"`
		} `json:"guest_configs"`
	}
	limited := &io.LimitedReader{R: reader, N: 65537}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode Unikraft launch manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || limited.N == 0 {
		return nil, errors.New("unikraft manifest must contain one JSON document of at most 64 KiB")
	}
	if manifest.Arch != "x64" || len(manifest.Guests) != 1 || manifest.Guests[0].Image.Direct == nil {
		return nil, errors.New("unikraft requires one x64 snp_linux_direct image")
	}
	image := manifest.Guests[0].Image.Direct
	if image.Processors != 1 || image.Pages < 16384 || image.Pages > 1048576 || image.Pages%256 != 0 {
		return nil, errors.New("unikraft requires one VP and 64..4096 MiB of whole-MiB guest RAM")
	}
	cfg := &unikraftConfig{memoryMB: image.Pages / 256}
	params := map[string]string{}
	application := false
	for _, field := range strings.Fields(image.Linux.CommandLine) {
		if field == "--" {
			application = true
		}
		if !strings.HasPrefix(field, "libukbus_vmbus.") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(field, "libukbus_vmbus."), "=")
		if application || !ok || value == "" || params[key] != "" {
			return nil, fmt.Errorf("invalid, duplicate or post-separator Unikraft parameter %q", field)
		}
		params[key] = value
	}
	take := func(key string) string {
		value := params[key]
		delete(params, key)
		return value
	}
	cfg.idle = take("idle")
	if cfg.idle == "" {
		cfg.idle = "halt"
	}
	if cfg.idle != "halt" && cfg.idle != "poll" {
		return nil, errors.New("unikraft idle policy must be halt or poll")
	}
	controller, luns := take("storage_controller"), take("storage_luns")
	if controller != "" || luns != "" {
		id, err := guid.FromString(controller)
		if err != nil || luns == "" {
			return nil, errors.New("unikraft storage requires a controller GUID and explicit LUN mappings")
		}
		cfg.controller = id.String()
		known := false
		for _, candidate := range guestrequest.ScsiControllerGuids {
			known = known || strings.EqualFold(candidate, cfg.controller)
		}
		if !known {
			return nil, errors.New("unikraft storage controller must use an existing HCS SCSI controller GUID")
		}
		roots, exports := map[uint8]bool{}, map[uint8]bool{}
		for _, mapping := range strings.Split(luns, ",") {
			fields := strings.Split(mapping, ":")
			if len(fields) != 3 {
				return nil, fmt.Errorf("invalid Unikraft LUN mapping %q", mapping)
			}
			root, e1 := strconv.ParseUint(fields[0], 10, 8)
			exported, e2 := strconv.ParseUint(fields[1], 10, 8)
			if e1 != nil || e2 != nil || root >= 64 || exported == 255 ||
				(fields[2] != "ro" && fields[2] != "rw") || roots[uint8(root)] || exports[uint8(exported)] {
				return nil, fmt.Errorf("invalid or duplicate Unikraft LUN mapping %q", mapping)
			}
			roots[uint8(root)], exports[uint8(exported)] = true, true
			cfg.luns = append(cfg.luns, unikraftLUN{uint8(root), uint8(exported), fields[2] == "ro"})
		}
		if len(cfg.luns) > 16 {
			return nil, errors.New("unikraft supports at most 16 exported LUNs")
		}
	}
	keys := []string{"uplink_device", "uplink_address", "uplink_gateway", "provider_address", "peer_address", "provider_mac", "peer_mac"}
	values := make([]string, len(keys))
	network := false
	for i, key := range keys {
		values[i] = take(key)
		network = network || values[i] != ""
	}
	if network {
		if values[0] != "0" {
			return nil, errors.New("unikraft's single pre-boot uplink must be device 0")
		}
		addresses := make([]netip.Addr, 4)
		for i := range addresses {
			address, err := netip.ParseAddr(values[i+1])
			if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
				return nil, fmt.Errorf("invalid Unikraft %s", keys[i+1])
			}
			addresses[i] = address
		}
		subnet := netip.MustParsePrefix(diodeUplinkSubnet)
		last := addresses[0].As4()[3]
		peerSubnet := netip.PrefixFrom(addresses[2], 30).Masked()
		if !subnet.Contains(addresses[0]) || last == 0 || last == 1 || last == 255 ||
			addresses[1].String() != diodeUplinkGateway ||
			!peerSubnet.Contains(addresses[3]) || subnet.Contains(addresses[2]) ||
			addresses[2].As4()[3]%4 != 1 || addresses[3].As4()[3]%4 != 2 {
			return nil, errors.New("unikraft requires an uplink on diode-uplink and provider/peer host addresses 1/2 on a distinct /30")
		}
		macs := make([]net.HardwareAddr, 2)
		for i := range macs {
			mac, err := net.ParseMAC(values[i+5])
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
				return nil, fmt.Errorf("invalid Unikraft %s", keys[i+5])
			}
			macs[i] = mac
		}
		if macs[0].String() == macs[1].String() {
			return nil, errors.New("unikraft provider and peer MACs must differ")
		}
		cfg.network = &unikraftNetwork{addresses[0], addresses[1], addresses[2], addresses[3], macs[0], macs[1]}
	}
	if len(params) != 0 || (cfg.network == nil && len(cfg.luns) == 0) {
		return nil, errors.New("unikraft manifest has unknown parameters or enables no diode services")
	}
	return cfg, nil
}

func loadUnikraftConfig(c *cli.Context, plan *siblingStoragePlan) (*unikraftConfig, error) {
	directory := c.String(unikraftPackageArgName)
	if directory == "" {
		return nil, nil
	}
	if c.GlobalUint64(cpusArgName) != 1 {
		return nil, errors.New("unikraft diode currently requires --cpus=1 for one-to-one workload/diode VP pairing; multicore is not implemented")
	}
	if !useGCS || !c.Bool(securityHardwareFlag) || !c.Bool(sharedMemoryTwoUVMArgName) ||
		c.GlobalInt(countArgName) != 2 || c.GlobalInt(parallelArgName) != 2 ||
		c.Uint64(sharedMemorySizeArgName) != 32*1024*1024 || c.String(siblingBusGuestModuleArgName) == "" {
		return nil, errors.New("unikraft diode requires an SNP/GCS two-VM sibling pair, a 32 MiB section and sibling-bus module")
	}
	for _, flag := range []string{sharedMemoryGuestModuleArgName, sharedMemoryMappingOnlyArgName,
		sharedMemoryGuestInventoryArgName, siblingOpenShellBundleArgName, baselineNICArgName, baselinePairArgName,
		storageBenchmarkScriptArgName, scsiMountsArgName, vpmemMountsArgName} {
		if c.IsSet(flag) {
			return nil, fmt.Errorf("unikraft diode does not support --%s", flag)
		}
	}
	if !c.Bool(siblingInteractiveArgName) && !c.IsSet(execCommandLineArgName) && !c.IsSet(execFileArgName) &&
		c.String(networkBenchmarkScriptArgName) == "" {
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
	if c.Bool(siblingDiodeUplinkArgName) != (cfg.network != nil) {
		return nil, errors.New("--sibling-diode-uplink must match networking in the Unikraft manifest")
	}
	if c.String(networkBenchmarkScriptArgName) != "" && (cfg.network == nil || !c.Bool(networkBenchmarkSingleVPArgName)) {
		return nil, errors.New("Unikraft network benchmark requires networking and --network-benchmark-single-vp")
	}
	if c.String(networkBenchmarkScriptArgName) != "" && cfg.idle != c.String(networkBenchmarkIdleArgName) {
		return nil, fmt.Errorf("Unikraft firmware idle=%s does not match benchmark idle=%s", cfg.idle, c.String(networkBenchmarkIdleArgName))
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
	if count != len(cfg.luns) {
		return nil, nil, errors.New("unikraft manifest LUNs must exactly match the storage backend plan")
	}
	if count == 0 {
		return nil, nil, nil
	}
	attachments := map[string]hcsschema.Attachment{}
	var reports []siblingStorageBackendReport
	for _, disk := range plan.Disks {
		found := false
		for _, lun := range cfg.luns {
			if disk.ExportLUN == nil || *disk.ExportLUN != lun.exported {
				continue
			}
			if lun.readOnly != (disk.Access == "read-only") {
				return nil, nil, fmt.Errorf("unikraft access mismatch for %s", disk.ID)
			}
			attachments[strconv.Itoa(int(lun.root))] = hcsschema.Attachment{
				Type_: "VirtualDisk", Path: disk.HostPath, ReadOnly: lun.readOnly,
			}
			controller := uint(0)
			for i, id := range guestrequest.ScsiControllerGuids {
				if strings.EqualFold(id, cfg.controller) {
					controller = uint(i)
				}
			}
			reports = append(reports, siblingStorageBackendReport{
				DiskID: disk.ID, Role: disk.Role, HostPath: disk.HostPath, ReadOnly: lun.readOnly,
				DiodeVM: "uvmboot-0", WorkloadVM: "uvmboot-1", ControllerID: cfg.controller,
				Controller: controller, LUN: uint(lun.root), ExportLUN: lun.exported, State: "configured-at-boot",
			})
			found = true
			break
		}
		if !found {
			return nil, nil, fmt.Errorf("unikraft manifest has no export for %s", disk.ID)
		}
	}
	return map[string]hcsschema.Scsi{cfg.controller: {Attachments: attachments}}, reports, nil
}
