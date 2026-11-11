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

// VMResources describes one VM, in [diode, workload] order in Config.
type VMResources struct {
	ProcessorCount int32    `json:"processor_count"`
	MemoryMB       uint64   `json:"memory_mb"`
	CPUGroupLPs    []uint32 `json:"cpu_group_lps,omitempty"`
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
	for i, resource := range resources {
		if resource.ProcessorCount < 1 || resource.ProcessorCount > 256 ||
			resource.MemoryMB == 0 || resource.MemoryMB > MaxMemoryMB {
			return fmt.Errorf("vm_resources[%d] requires processor_count in 1..256 and memory_mb in 1..%d", i, MaxMemoryMB)
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
	if config.VMResources == nil {
		return nil
	}
	if len(config.VMResources) != 2 {
		return fmt.Errorf("vm_resources requires exactly two entries in [diode, workload] order")
	}
	return ValidateVMResources(config.VMResources)
}

func preparePairCPUGroups(ctx context.Context, config *Config, workload, diode *uvm.OptionsLCOW, ops cpugroup.Operations) (*cpugroup.Assignments, error) {
	if err := config.validateResources(); err != nil {
		return nil, err
	}
	var affinities [][]uint32
	if config.VMResources != nil {
		affinities = [][]uint32{config.VMResources[0].CPUGroupLPs, config.VMResources[1].CPUGroupLPs}
	}
	groups, err := cpugroup.Prepare(ctx, affinities, 2, ops)
	if err != nil {
		return nil, err
	}
	for i, options := range []*uvm.OptionsLCOW{diode, workload} {
		if len(groups.IDs) != 0 && groups.IDs[i] != "" {
			options.CPUGroupID = groups.IDs[i]
		}
	}
	return groups, nil
}
