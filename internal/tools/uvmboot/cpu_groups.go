//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/internal/cpugroup"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcs "github.com/Microsoft/hcsshim/internal/hcs/v2"
)

type cpuGroupOperations struct {
	create      func(context.Context, string, []uint32) error
	setPriority func(context.Context, string, uint32) error
	query       func(context.Context, string) (*hcsschema.CpuGroupConfig, error)
	delete      func(context.Context, string) error
}

var hostCPUGroupOperations = cpuGroupOperations{
	create:      cpugroup.Create,
	setPriority: cpugroup.SetSchedulingPriority,
	query:       cpugroup.GetCPUGroupConfig,
	delete:      cpugroup.Delete,
}

type cpuGroupAssignments struct {
	ids     []string
	groups  *cpugroup.Assignments
	reports []cpuGroupReport
}

type cpuGroupReport struct {
	VM                 string   `json:"vm"`
	GroupID            string   `json:"group_id"`
	LogicalProcessors  []uint32 `json:"logical_processors"`
	SchedulingPriority uint32   `json:"scheduling_priority"`
}

const cpuGroupPrioritiesArgName = "cpu-group-priorities"

func parseCPUGroupPriorities(value string) ([]uint32, error) {
	if value == "" {
		return nil, nil
	}
	var priorities []uint32
	for _, part := range strings.Split(value, ",") {
		priority, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
		if err != nil || priority > uint64(cpugroup.MaxSchedulingPriority) {
			return nil, fmt.Errorf("--%s: expected priorities from 0 through %d, got %q",
				cpuGroupPrioritiesArgName, cpugroup.MaxSchedulingPriority, part)
		}
		priorities = append(priorities, uint32(priority))
	}
	return priorities, nil
}

func canonicalLPs(lps []uint32) ([]uint32, string, error) {
	return cpugroup.CanonicalLPs(lps)
}

func prepareCPUGroups(ctx context.Context, groups [][]uint32, vmCount int, ops cpuGroupOperations, priorities ...uint32) (*cpuGroupAssignments, error) {
	owned, err := cpugroup.Prepare(ctx, groups, vmCount, cpugroup.Operations{
		Create: ops.create, SetPriority: ops.setPriority, Query: ops.query, Delete: ops.delete,
	}, priorities...)
	if err != nil {
		return nil, err
	}
	assignments := &cpuGroupAssignments{ids: owned.IDs, groups: owned}
	for i, report := range owned.Reports {
		assignments.reports = append(assignments.reports, cpuGroupReport{
			VM: fmt.Sprintf("uvmboot-%d", i), GroupID: report.GroupID,
			LogicalProcessors: report.LogicalProcessors, SchedulingPriority: report.SchedulingPriority,
		})
	}
	return assignments, nil
}

func (a *cpuGroupAssignments) groupForVM(id string) (string, error) {
	if len(a.ids) == 0 {
		return "", nil
	}
	if !strings.HasPrefix(id, "uvmboot-") {
		return "", fmt.Errorf("cannot assign CPU group to unexpected VM ID %q", id)
	}
	index, err := strconv.Atoi(strings.TrimPrefix(id, "uvmboot-"))
	if err != nil || index < 0 || index >= len(a.ids) {
		return "", fmt.Errorf("no CPU affinity configured for VM %q", id)
	}
	return a.ids[index], nil
}

func (a *cpuGroupAssignments) close(ctx context.Context) error {
	return a.groups.Close(ctx)
}

func hostProcessorTopology(ctx context.Context) (*hcsschema.ProcessorTopology, error) {
	properties, err := hcs.GetServiceProperties(ctx, hcsschema.PropertyQuery{
		PropertyTypes: []hcsschema.PropertyType{hcsschema.PTProcessorTopology},
	})
	if err != nil {
		return nil, fmt.Errorf("query host processor topology: %w", err)
	}
	if len(properties.Properties) != 1 {
		return nil, fmt.Errorf("expected one processor topology, got %d", len(properties.Properties))
	}
	var topology hcsschema.ProcessorTopology
	if err := json.Unmarshal(properties.Properties[0], &topology); err != nil {
		return nil, fmt.Errorf("decode host processor topology: %w", err)
	}
	if topology.LogicalProcessorCount == 0 || int(topology.LogicalProcessorCount) != len(topology.LogicalProcessors) {
		return nil, errors.New("host returned incomplete processor topology")
	}
	return &topology, nil
}

func validateBenchmarkCPUs(topology *hcsschema.ProcessorTopology, groups [][]uint32, noSMT bool, processors uint64) error {
	if topology == nil || len(groups) < 1 || len(groups) > 2 || (processors != 1 && processors != 2) {
		return errors.New("benchmark requires host topology, one or two VM affinities, and one or two VPs per VM")
	}
	byLP := map[uint32]hcsschema.LogicalProcessor{}
	coreLPs := map[string][]uint32{}
	rootPartitionRestricted := false
	for _, lp := range topology.LogicalProcessors {
		if _, exists := byLP[lp.LpIndex]; exists {
			return fmt.Errorf("duplicate LP %d in host topology", lp.LpIndex)
		}
		byLP[lp.LpIndex] = lp
		if lp.RootVpIndex < -1 {
			return fmt.Errorf("invalid root VP index %d for LP %d", lp.RootVpIndex, lp.LpIndex)
		}
		rootPartitionRestricted = rootPartitionRestricted || lp.RootVpIndex == -1
		key := fmt.Sprintf("%d:%d", lp.PackageId, lp.CoreId)
		coreLPs[key] = append(coreLPs[key], lp.LpIndex)
	}
	if noSMT {
		for _, lps := range coreLPs {
			if len(lps) != 1 {
				return errors.New("SMT-off comparison requires host SMT to be disabled")
			}
		}
		if len(groups) == 2 {
			_, firstKey, firstErr := canonicalLPs(groups[0])
			_, secondKey, secondErr := canonicalLPs(groups[1])
			if firstErr != nil || secondErr != nil || firstKey != secondKey {
				return errors.New("SMT-off comparison requires identical two-LP affinities")
			}
		}
	}
	var node uint8
	for i, group := range groups {
		_, key, err := canonicalLPs(group)
		if err != nil || len(group) != 2 {
			return fmt.Errorf("benchmark VM %d requires exactly two distinct logical processors, including complete SMT pairs when SMT is enabled", i)
		}
		first, foundFirst := byLP[group[0]]
		if !foundFirst {
			return fmt.Errorf("benchmark affinity %s includes a nonexistent LP", key)
		}
		second, foundSecond := byLP[group[1]]
		if !foundFirst || !foundSecond {
			return fmt.Errorf("benchmark affinity %s includes a nonexistent LP", key)
		}
		if rootPartitionRestricted && (first.RootVpIndex != -1 || second.RootVpIndex != -1) {
			return fmt.Errorf("MinRoot benchmark affinity %s includes root-partition LPs; select complete root-free cores (RootVpIndex=-1)", key)
		}
		if first.NodeNumber != second.NodeNumber {
			return fmt.Errorf("benchmark affinity %s crosses NUMA nodes", key)
		}
		if !noSMT && (first.PackageId != second.PackageId || first.CoreId != second.CoreId) {
			return fmt.Errorf("benchmark affinity %s is not one physical core's SMT pair", key)
		}
		if !noSMT && len(coreLPs[fmt.Sprintf("%d:%d", first.PackageId, first.CoreId)]) != 2 {
			return fmt.Errorf("benchmark affinity %s does not cover a two-thread SMT core", key)
		}
		if i > 0 && node != first.NodeNumber {
			return errors.New("benchmark physical cores must be in the same NUMA node")
		}
		node = first.NodeNumber
	}
	return nil
}

var cpuTopologyCommand = cli.Command{
	Name:  "cpu-topology",
	Usage: "Print read-only HCS host processor topology as JSON for benchmark affinity selection",
	Action: func(c *cli.Context) error {
		topology, err := hostProcessorTopology(context.Background())
		if err != nil {
			return err
		}
		// HCS structs omit zero-valued package/core/NUMA IDs. Emit them
		// explicitly so consumers can distinguish node zero from missing data.
		type logicalProcessor struct {
			LpIndex     uint32
			NodeNumber  uint8
			PackageId   uint32
			CoreId      uint32
			RootVpIndex int32
		}
		report := struct {
			LogicalProcessorCount uint32
			LogicalProcessors     []logicalProcessor
		}{LogicalProcessorCount: topology.LogicalProcessorCount}
		for _, lp := range topology.LogicalProcessors {
			report.LogicalProcessors = append(report.LogicalProcessors, logicalProcessor{
				lp.LpIndex, lp.NodeNumber, lp.PackageId, lp.CoreId, lp.RootVpIndex,
			})
		}
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	},
}
