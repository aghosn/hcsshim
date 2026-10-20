//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/internal/cpugroup"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcs "github.com/Microsoft/hcsshim/internal/hcs/v2"
)

type cpuGroupOperations struct {
	create func(context.Context, string, []uint32) error
	query  func(context.Context, string) (*hcsschema.CpuGroupConfig, error)
	delete func(context.Context, string) error
}

var hostCPUGroupOperations = cpuGroupOperations{
	create: cpugroup.Create,
	query:  cpugroup.GetCPUGroupConfig,
	delete: cpugroup.Delete,
}

type cpuGroupAssignments struct {
	ids   []string
	owned []string
	ops   cpuGroupOperations
}

func canonicalLPs(lps []uint32) ([]uint32, string, error) {
	if len(lps) == 0 {
		return nil, "", errors.New("CPU affinity cannot be empty")
	}
	ordered := append([]uint32(nil), lps...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	parts := make([]string, len(ordered))
	for i, lp := range ordered {
		if i > 0 && ordered[i-1] == lp {
			return nil, "", fmt.Errorf("duplicate logical processor %d", lp)
		}
		parts[i] = strconv.FormatUint(uint64(lp), 10)
	}
	return ordered, strings.Join(parts, ","), nil
}

func prepareCPUGroups(ctx context.Context, groups [][]uint32, vmCount int, ops cpuGroupOperations) (_ *cpuGroupAssignments, resultErr error) {
	assignments := &cpuGroupAssignments{ops: ops}
	if len(groups) == 0 {
		return assignments, nil
	}
	if len(groups) != vmCount {
		return nil, fmt.Errorf("CPU affinity has %d VM lists, expected %d", len(groups), vmCount)
	}
	ordered := make([][]uint32, len(groups))
	keys := make([]string, len(groups))
	lpOwners := map[uint32]string{}
	for i, group := range groups {
		var err error
		ordered[i], keys[i], err = canonicalLPs(group)
		if err != nil {
			return nil, err
		}
		for _, lp := range ordered[i] {
			if owner, ok := lpOwners[lp]; ok && owner != keys[i] {
				return nil, fmt.Errorf("partially overlapping CPU affinities: %s and %s", owner, keys[i])
			}
			lpOwners[lp] = keys[i]
		}
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, assignments.close(ctx))
		}
	}()
	created := map[string]string{}
	for i, lps := range ordered {
		if id, ok := created[keys[i]]; ok {
			assignments.ids = append(assignments.ids, id)
			continue
		}
		id, err := guid.NewV4()
		if err != nil {
			return nil, fmt.Errorf("allocate CPU group ID: %w", err)
		}
		if err := ops.create(ctx, id.String(), lps); err != nil {
			return nil, fmt.Errorf("create CPU affinity %s: %w", keys[i], err)
		}
		assignments.owned = append(assignments.owned, id.String())
		config, err := ops.query(ctx, id.String())
		if err != nil {
			return nil, fmt.Errorf("verify CPU group %s: %w", id, err)
		}
		if config == nil || config.Affinity == nil {
			return nil, fmt.Errorf("CPU group %s returned no affinity", id)
		}
		actual := make([]uint32, len(config.Affinity.LogicalProcessors))
		for j, lp := range config.Affinity.LogicalProcessors {
			if lp < 0 {
				return nil, fmt.Errorf("CPU group %s returned negative LP %d", id, lp)
			}
			actual[j] = uint32(lp)
		}
		_, actualKey, err := canonicalLPs(actual)
		if err != nil || actualKey != keys[i] || config.Affinity.LogicalProcessorCount != int32(len(lps)) {
			return nil, fmt.Errorf("CPU group %s affinity mismatch: requested %s, got %+v", id, keys[i], config.Affinity)
		}
		created[keys[i]] = id.String()
		assignments.ids = append(assignments.ids, id.String())
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
	var result error
	for i := len(a.owned) - 1; i >= 0; i-- {
		if err := a.ops.delete(ctx, a.owned[i]); err != nil {
			result = errors.Join(result, fmt.Errorf("delete CPU group %s: %w", a.owned[i], err))
		}
	}
	a.owned = nil
	return result
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

func validateBenchmarkCPUs(topology *hcsschema.ProcessorTopology, groups [][]uint32) error {
	if topology == nil || len(groups) < 1 || len(groups) > 2 {
		return errors.New("benchmark requires host topology and one or two CPU affinity pairs")
	}
	byLP := map[uint32]hcsschema.LogicalProcessor{}
	coreLPs := map[string][]uint32{}
	for _, lp := range topology.LogicalProcessors {
		if _, exists := byLP[lp.LpIndex]; exists {
			return fmt.Errorf("duplicate LP %d in host topology", lp.LpIndex)
		}
		byLP[lp.LpIndex] = lp
		key := fmt.Sprintf("%d:%d", lp.PackageId, lp.CoreId)
		coreLPs[key] = append(coreLPs[key], lp.LpIndex)
	}
	var node uint8
	for i, group := range groups {
		_, key, err := canonicalLPs(group)
		if err != nil || len(group) != 2 {
			return fmt.Errorf("benchmark VM %d requires exactly two distinct SMT logical processors", i)
		}
		first, foundFirst := byLP[group[0]]
		second, foundSecond := byLP[group[1]]
		if !foundFirst || !foundSecond {
			return fmt.Errorf("benchmark affinity %s includes a nonexistent LP", key)
		}
		if first.PackageId != second.PackageId || first.CoreId != second.CoreId || first.NodeNumber != second.NodeNumber {
			return fmt.Errorf("benchmark affinity %s is not one physical core's SMT pair", key)
		}
		if len(coreLPs[fmt.Sprintf("%d:%d", first.PackageId, first.CoreId)]) != 2 {
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
