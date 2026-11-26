//go:build windows

package sibling

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/Microsoft/hcsshim/internal/cpugroup"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

func standaloneOptions(base *uvm.OptionsLCOW, config *Config) (*uvm.OptionsLCOW, error) {
	if !config.Standalone {
		return nil, errors.New("standalone requires an explicit standalone config")
	}
	if err := config.validateResources(); err != nil {
		return nil, err
	}
	if base == nil || base.Options == nil || base.ConfidentialLCOWOptions == nil ||
		base.ConfidentialCommonOptions == nil || !base.UseGuestConnection ||
		!base.SecurityPolicyEnabled || !base.DmVerityMode || base.GuestStateFilePath == "" ||
		base.DmVerityRootFsVhd == "" || base.SCSIControllerCount == 0 ||
		!filepath.IsAbs(base.BundleDirectory) || base.ID == "" ||
		base.SiblingRoot || base.Appliance != nil || len(base.SharedMemoryRegions) != 0 ||
		len(base.SiblingCommunicationEndpoints) != 0 || len(base.AssignedDevices) != 0 {
		return nil, errors.New("standalone requires direct GCS, SNP dm-verity boot, a bundle directory and direct SCSI without sibling or appliance devices")
	}
	options := *base
	common := *base.Options
	confidential := *base.ConfidentialLCOWOptions
	security := *base.ConfidentialCommonOptions
	options.Options, options.ConfidentialLCOWOptions = &common, &confidential
	options.ConfidentialCommonOptions = &security
	config.VMResources[0].Apply(options.Options)
	if config.WorkloadGuestStateFile != "" {
		options.GuestStateFilePath = config.WorkloadGuestStateFile
	}
	return &options, nil
}

func startStandalone(ctx context.Context, base *uvm.OptionsLCOW, config *Config) (_ *Pair, resultErr error) {
	options, err := standaloneOptions(base, config)
	if err != nil {
		return nil, err
	}
	pair := &Pair{done: make(chan struct{})}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, pair.Close())
		}
	}()
	pair.cpuGroups, err = prepareResourceCPUGroups(ctx, config, []*uvm.OptionsLCOW{options}, cpugroup.HostOperations)
	if err != nil {
		return nil, err
	}
	// The ordinary LCOW path copies boot templates and attaches root LUN 0
	// directly; no sibling root, provider, shared section or relay is involved.
	pair.Workload, err = uvm.CreateLCOW(ctx, options)
	if pair.Workload != nil {
		pair.workloadCloser = pair.Workload
	}
	if err != nil {
		return nil, fmt.Errorf("create standalone workload: %w", err)
	}
	if err := pair.Workload.Start(ctx); err != nil {
		return nil, fmt.Errorf("start standalone workload: %w", err)
	}
	if config.Interactive {
		pair.interactiveCloser, err = startPairShells(pair)
		if err != nil {
			return nil, fmt.Errorf("start standalone workload shell: %w", err)
		}
	}
	go func() {
		_ = pair.Workload.Wait()
		_ = pair.Close()
	}()
	return pair, nil
}
