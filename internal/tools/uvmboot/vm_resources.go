//go:build windows

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Microsoft/hcsshim/internal/sibling"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
	"github.com/urfave/cli"
)

const (
	vmCPUsArgName   = "vm-cpus"
	vmMemoryArgName = "vm-memory"
)

func parseVMResourceList(c *cli.Context, name string) ([]uint64, error) {
	if !c.GlobalIsSet(name) {
		return nil, nil
	}
	parts := strings.Split(c.GlobalString(name), ",")
	if len(parts) != c.GlobalInt(countArgName) {
		return nil, fmt.Errorf("--%s requires exactly --count (%d) entries", name, c.GlobalInt(countArgName))
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		value, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("--%s entry %d must be an unsigned integer, got %q", name, i, part)
		}
		values[i] = value
	}
	return values, nil
}

func validateVMResources(c *cli.Context) error {
	_, err := resolvedVMResources(c)
	return err
}

func normalizeVMResources(c *cli.Context) ([]sibling.VMResources, error) {
	cpus, err := parseVMResourceList(c, vmCPUsArgName)
	if err != nil {
		return nil, err
	}
	memory, err := parseVMResourceList(c, vmMemoryArgName)
	if err != nil {
		return nil, err
	}
	count := c.GlobalInt(countArgName)
	if count < 1 {
		return nil, fmt.Errorf("--count must be positive")
	}
	resources := make([]sibling.VMResources, count)
	for i := range resources {
		processors := uint64(vmutils.DefaultProcessorCountForUVM())
		memoryMB := uint64(1024)
		if c.GlobalIsSet(cpusArgName) {
			processors = c.GlobalUint64(cpusArgName)
		}
		if c.GlobalIsSet(memoryArgName) {
			memoryMB = c.GlobalUint64(memoryArgName)
		}
		if cpus != nil {
			processors = cpus[i]
		}
		if memory != nil {
			memoryMB = memory[i]
		}
		if processors > 256 {
			return nil, fmt.Errorf("VM %d processor_count must be in 1..256", i)
		}
		resources[i] = sibling.VMResources{ProcessorCount: int32(processors), MemoryMB: memoryMB}
	}
	if err := sibling.ValidateVMResources(resources); err != nil {
		return nil, err
	}
	return resources, nil
}

func prepareVMResources(c *cli.Context) error {
	if _, ok := c.App.Metadata["vm-resources"].([]sibling.VMResources); ok {
		return nil
	}
	resources, err := normalizeVMResources(c)
	if err != nil {
		return err
	}
	if c.App.Metadata == nil {
		c.App.Metadata = map[string]interface{}{}
	}
	c.App.Metadata["vm-resources"] = resources
	return nil
}

func resolvedVMResources(c *cli.Context) ([]sibling.VMResources, error) {
	if resources, ok := c.App.Metadata["vm-resources"].([]sibling.VMResources); ok {
		return resources, nil
	}
	return normalizeVMResources(c)
}

func vmIndex(id string, count int) (int, error) {
	index, err := strconv.Atoi(strings.TrimPrefix(id, "uvmboot-"))
	if !strings.HasPrefix(id, "uvmboot-") || err != nil || index < 0 || index >= count {
		return 0, fmt.Errorf("no per-VM resources configured for VM %q", id)
	}
	return index, nil
}

func setVMResources(c *cli.Context, options *uvm.Options) error {
	resources, err := resolvedVMResources(c)
	if err != nil {
		return err
	}
	if !c.GlobalIsSet(vmCPUsArgName) && !c.GlobalIsSet(vmMemoryArgName) &&
		!c.GlobalIsSet(cpusArgName) && !c.GlobalIsSet(memoryArgName) {
		return nil
	}
	index, err := vmIndex(options.ID, c.GlobalInt(countArgName))
	if err != nil {
		return err
	}
	resource := resources[index]
	if !c.GlobalIsSet(vmCPUsArgName) && !c.GlobalIsSet(cpusArgName) {
		resource.ProcessorCount = options.ProcessorCount
	}
	if !c.GlobalIsSet(vmMemoryArgName) && !c.GlobalIsSet(memoryArgName) {
		resource.MemoryMB = options.MemorySizeInMB
	}
	resource.Apply(options)
	return nil
}

// Callers validate the complete resource lists before allocating any resources.
func requestedVMProcessors(c *cli.Context, id string) uint64 {
	resources, err := resolvedVMResources(c)
	if err != nil {
		return 0
	}
	index, err := vmIndex(id, len(resources))
	if err != nil {
		return 0
	}
	return uint64(resources[index].ProcessorCount)
}

func validateBenchmarkVMResources(c *cli.Context) error {
	if err := validateVMResources(c); err != nil {
		return err
	}
	for i := 0; i < c.GlobalInt(countArgName); i++ {
		if processors := requestedVMProcessors(c, fmt.Sprintf("uvmboot-%d", i)); processors != 1 && processors != 2 {
			return fmt.Errorf("benchmark VM %d requires one or two requested VPs, got %d", i, processors)
		}
	}
	return nil
}

func validateUnikraftResources(c *cli.Context, memoryMB uint64) error {
	if err := validateVMResources(c); err != nil {
		return err
	}
	resources, err := resolvedVMResources(c)
	if err != nil {
		return err
	}
	resource := sibling.VMResources{ProcessorCount: 1, MemoryMB: memoryMB + 2}
	if c.GlobalIsSet(vmCPUsArgName) {
		resource.ProcessorCount = resources[0].ProcessorCount
	}
	if c.GlobalIsSet(vmMemoryArgName) {
		resource.MemoryMB = resources[0].MemoryMB
	}
	return resource.ValidateUnikraft(memoryMB)
}
