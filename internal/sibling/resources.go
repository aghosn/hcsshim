//go:build windows

package sibling

import (
	"context"
	"fmt"
	"math"

	"github.com/Microsoft/hcsshim/internal/cpugroup"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

// MaxMemoryMB keeps MiB-to-byte conversion and HCS 2 MiB alignment in uint64.
const MaxMemoryMB uint64 = math.MaxUint64 >> 20

// VMResources describes one VM, in [diode, workload] or standalone [workload] order.
type VMResources struct {
	ProcessorCount   int32    `json:"processor_count"`
	MemoryMB         uint64   `json:"memory_mb"`
	CPUGroupLPs      []uint32 `json:"cpu_group_lps,omitempty"`
	CPUGroupPriority *uint32  `json:"cpu_group_priority,omitempty"`
}

func (resource VMResources) Apply(options *uvm.Options) {
	options.ProcessorCount = resource.ProcessorCount
	options.MemorySizeInMB = resource.MemoryMB
}

func (resource VMResources) ValidateUnikraft(memoryMB uint64) error {
	if resource.ProcessorCount != 1 || resource.MemoryMB != memoryMB+2 {
		return fmt.Errorf("Unikraft image capability requires provider processor_count=1 and HCS memory_mb=%d (image memory %d MiB plus 2 MiB)", memoryMB+2, memoryMB)
	}
	return nil
}

// ValidateVMResources validates complete HCS allocations before acquiring resources.
func ValidateVMResources(resources []VMResources) error {
	owners := map[uint32]string{}
	prioritized := false
	for _, resource := range resources {
		prioritized = prioritized || resource.CPUGroupPriority != nil
	}
	for i, resource := range resources {
		if resource.ProcessorCount < 1 || resource.ProcessorCount > 256 ||
			resource.MemoryMB == 0 || resource.MemoryMB > MaxMemoryMB {
			return fmt.Errorf("vm_resources[%d] requires processor_count in 1..256 and memory_mb in 1..%d", i, MaxMemoryMB)
		}
		if prioritized && (resource.CPUGroupPriority == nil || resource.CPUGroupLPs == nil ||
			*resource.CPUGroupPriority > cpugroup.MaxSchedulingPriority) {
			return fmt.Errorf("vm_resources[%d] requires CPU affinity and cpu_group_priority in 0..%d for every VM when any priority is specified", i, cpugroup.MaxSchedulingPriority)
		}

		if resource.CPUGroupLPs == nil {
			continue
		}
		lps, key, err := cpugroup.CanonicalLPs(resource.CPUGroupLPs)
		if err != nil {
			return fmt.Errorf("vm_resources[%d]: %w", i, err)
		}
		for _, lp := range lps {
			if owner, ok := owners[lp]; ok && owner != key {
				return fmt.Errorf("vm_resources CPU affinities must be identical or disjoint")
			}
			owners[lp] = key
		}
	}
	return nil
}

func (config *Config) validateResources() error {
	if config.Standalone {
		if len(config.VMResources) != 1 {
			return fmt.Errorf("standalone vm_resources requires exactly one workload entry")
		}
		return ValidateVMResources(config.VMResources)
	}
	if config.VMResources == nil {
		return nil
	}
	if len(config.VMResources) != 2 {
		return fmt.Errorf("vm_resources requires exactly two entries in [diode, workload] order")
	}
	return ValidateVMResources(config.VMResources)
}

func preparePairCPUGroups(ctx context.Context, config *Config, workload, diode *uvm.OptionsLCOW, ops cpugroup.Operations) (*cpugroup.Assignments, error) {
	return prepareResourceCPUGroups(ctx, config, []*uvm.OptionsLCOW{diode, workload}, ops)
}

func prepareResourceCPUGroups(ctx context.Context, config *Config, options []*uvm.OptionsLCOW, ops cpugroup.Operations) (*cpugroup.Assignments, error) {
	if err := config.validateResources(); err != nil {
		return nil, err
	}
	var affinities [][]uint32
	var priorities []uint32
	if config.VMResources != nil {
		if len(config.VMResources) != len(options) {
			return nil, fmt.Errorf("vm_resources count does not match owned VM options")
		}
		for _, resource := range config.VMResources {
			affinities = append(affinities, resource.CPUGroupLPs)
			if resource.CPUGroupPriority != nil {
				priorities = append(priorities, *resource.CPUGroupPriority)
			}
		}
	}
	groups, err := cpugroup.Prepare(ctx, affinities, len(options), ops, priorities...)
	if err != nil {
		return nil, err
	}
	for i, options := range options {
		if len(groups.IDs) != 0 && groups.IDs[i] != "" {
			options.CPUGroupID = groups.IDs[i]
		}
	}
	return groups, nil
}
