//go:build windows

package sibling

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/security"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
)

func loadOwnedUnikraft(config *Config) (*UnikraftConfig, error) {
	if config.UnikraftPackage == "" {
		return nil, nil
	}
	file, err := os.Open(filepath.Join(config.UnikraftPackage, "launch-manifest.json"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	cfg, err := ParseUnikraftManifest(file)
	if err != nil {
		return nil, err
	}
	if cfg.MemoryMB != 128 || cfg.Network == nil ||
		!strings.EqualFold(cfg.Controller, guestrequest.ScsiControllerGuids[0]) ||
		len(cfg.LUNs) != 1 || cfg.LUNs[0] != (UnikraftLUN{Root: 0, Exported: 0, ReadOnly: true}) {
		return nil, errors.New("owned Unikraft requires 128 MiB, networking and only a permanent controller-0 read-only root0 export")
	}
	if !cfg.LiveStorage || cfg.GCSRelay != config.MediateGCS {
		return nil, errors.New("owned Unikraft firmware must enable live_storage=1 and match mediate_gcs; no direct-GCS fallback")
	}
	if err := config.validateResources(); err != nil {
		return nil, err
	}
	if config.VMResources != nil {
		if err := config.VMResources[0].ValidateUnikraft(cfg.MemoryMB); err != nil {
			return nil, err
		}
	}
	info, err := os.Stat(filepath.Join(config.UnikraftPackage, "guest.vmgs"))
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, errors.New("owned Unikraft requires a regular nonempty guest.vmgs")
	}
	return cfg, nil
}

func configureOwnedUnikraft(workload, diode *uvm.OptionsLCOW, config *Config, cfg *UnikraftConfig, group string) error {
	if workload.Appliance != nil ||
		(workload.HclEnabled != nil && *workload.HclEnabled) {
		return errors.New("owned Unikraft requires a direct-SNP workload")
	}
	if err := config.validateResources(); err != nil {
		return err
	}
	if config.VMResources != nil {
		if err := config.VMResources[0].ValidateUnikraft(cfg.MemoryMB); err != nil {
			return err
		}
	}
	diode.BootFilesPath, diode.GuestStateFilePath = config.UnikraftPackage, "guest.vmgs"
	diode.UseGuestConnection, diode.ForwardStdout, diode.ForwardStderr = false, false, false
	diode.PreferredRootFSType, diode.DmVerityMode = uvm.PreferredRootFSTypeNA, false
	diode.DmVerityRootFsVhd, diode.KernelBootOptions, diode.ExecCommandLine = "", "", ""
	diode.VPMemDeviceCount, diode.SCSIControllerCount = 0, 1
	diode.MemorySizeInMB, diode.ProcessorCount = cfg.MemoryMB+2, 1
	diode.AllowOvercommit, diode.EnableDeferredCommit = false, false
	hcl := false
	diode.HclEnabled = &hcl
	diode.ConsolePipe = `\\.\pipe\hcsshim-unikraft-` + group
	diode.Appliance = &uvm.LCOWApplianceOptions{
		NativeStorageControl: true,
		SCSI: map[string]hcsschema.Scsi{guestrequest.ScsiControllerGuids[0]: {
			Attachments: map[string]hcsschema.Attachment{
				"0": {Type_: "VirtualDisk",
					Path: filepath.Join(workload.BundleDirectory, vmutils.DefaultDmVerityRootfsVhd), ReadOnly: true},
			},
		}},
	}
	return uvm.VerifyOptions(context.Background(), diode)
}

func (p *Pair) prepareOwnedUnikraft(opts *uvm.OptionsLCOW, cfg *UnikraftConfig, consoleDirectory string) error {
	root := opts.Appliance.SCSI[guestrequest.ScsiControllerGuids[0]].Attachments["0"].Path
	if err := security.GrantVmGroupAccessWithMask(root, security.AccessMaskAll); err != nil {
		return fmt.Errorf("grant access to permanent Unikraft boot root: %w", err)
	}
	endpoint, cleanup, err := PrepareUnikraftUplink(opts.ID, cfg.Network)
	if err != nil {
		return err
	}
	p.uplinkCleanup = cleanup
	opts.Appliance.NetworkAdapters = map[string]hcsschema.NetworkAdapter{
		"00000000-0000-0000-0000-000000000001": {EndpointId: endpoint.Id, MacAddress: endpoint.MacAddress},
	}
	if consoleDirectory == "" {
		consoleDirectory = opts.BundleDirectory
	}
	// Config-file callers retain the console outside the disposable task bundle.
	p.unikraftConsole, err = newOwnedUnikraftConsole(opts.ConsolePipe, consoleDirectory, cfg.Idle)
	return err
}

func (config *Config) moduleInputs() []string {
	if config.UnikraftPackage != "" {
		return []string{"sibling_bus.ko", "demo.sh", "diode-controller"}
	}
	return []string{"sibling_bus.ko", "diode_storvsp.ko", "diode_netvsp.ko", "diode_iptables", "demo.sh", "diode-controller"}
}

func (p *Pair) watchOwnedProvider(control providerState) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-p.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	go func() {
		defer cancel()
		err := waitOwnedProvider(ctx, control, p.unikraftConsole, p.Diode.WaitCtx)
		select {
		case <-p.done:
			return
		default:
		}
		log.G(ctx).WithError(p.close(err)).Error("owned Unikraft provider failed")
	}()
}
