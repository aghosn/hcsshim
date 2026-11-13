//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
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

func checkedCPUGroup(ctx context.Context, id string, lps []uint32, priority uint32, ops cpuGroupOperations) (*cpugroup.Report, error) {
	config, err := ops.query(ctx, id)
	if err != nil {
		return nil, err
	}
	if config == nil || !strings.EqualFold(config.GroupId, id) || config.Affinity == nil {
		return nil, errors.New("CPU group returned missing or mismatched identity/affinity")
	}
	actual := make([]uint32, len(config.Affinity.LogicalProcessors))
	for i, lp := range config.Affinity.LogicalProcessors {
		if lp < 0 {
			return nil, fmt.Errorf("CPU group returned negative LP %d", lp)
		}
		actual[i] = uint32(lp)
	}
	actual, actualKey, err := canonicalLPs(actual)
	_, expectedKey, expectedErr := canonicalLPs(lps)
	if err != nil || expectedErr != nil || actualKey != expectedKey ||
		config.Affinity.LogicalProcessorCount != int32(len(lps)) {
		return nil, errors.New("CPU group affinity mismatch")
	}
	found := false
	for _, property := range config.GroupProperties {
		if property.PropertyCode == hcsschema.CPUSchedulingPriorityProperty {
			if found || property.PropertyValue != priority {
				return nil, errors.New("CPU group scheduling priority mismatch")
			}
			found = true
		}
	}
	if !found {
		return nil, errors.New("CPU group returned no scheduling priority")
	}
	return &cpugroup.Report{GroupID: config.GroupId, LogicalProcessors: actual, SchedulingPriority: priority}, nil
}

func manageCPUGroup(ctx context.Context, action, id string, lps []uint32, priority uint32, ifExists bool, ops cpuGroupOperations) (_ *cpugroup.Report, resultErr error) {
	parsed, err := guid.FromString(id)
	if err != nil || parsed == (guid.GUID{}) {
		return nil, errors.New("CPU group requires a nonzero GUID")
	}
	id = parsed.String()
	lps, _, err = canonicalLPs(lps)
	if err != nil {
		return nil, err
	}
	if priority > cpugroup.MaxSchedulingPriority {
		return nil, errors.New("CPU group scheduling priority must be 0 through 7")
	}
	switch action {
	case "create":
		if err := ops.create(ctx, id, lps); err != nil {
			return nil, err
		}
		defer func() {
			if resultErr != nil {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				defer cancel()
				if err := ops.delete(cleanupCtx, id); err != nil {
					resultErr = errors.Join(resultErr, fmt.Errorf("rollback CPU group %s: %w", id, err))
				}
			}
		}()
		if err := ops.setPriority(ctx, id, priority); err != nil {
			return nil, err
		}
	case "query", "delete":
	default:
		return nil, fmt.Errorf("unknown CPU group action %q", action)
	}
	report, err := checkedCPUGroup(ctx, id, lps, priority, ops)
	if err != nil {
		if action == "delete" && ifExists && errors.Is(err, cpugroup.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if action == "delete" {
		return nil, ops.delete(ctx, id)
	}
	return report, nil
}

func cpuGroupSubcommand(action string) cli.Command {
	flags := []cli.Flag{
		cli.StringFlag{Name: "id", Required: true},
		cli.StringFlag{Name: "lps", Required: true},
		cli.UintFlag{Name: "priority", Required: true},
	}
	if action == "delete" {
		flags = append(flags, cli.BoolFlag{Name: "if-exists", Usage: "Ignore only a successful host query proving the group is absent"})
	}
	return cli.Command{
		Name:  action,
		Flags: flags,
		Action: func(c *cli.Context) error {
			if c.NArg() != 0 {
				return errors.New("unexpected CPU group positional arguments")
			}
			var lps []uint32
			for _, part := range strings.Split(c.String("lps"), ",") {
				lp, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
				if err != nil {
					return fmt.Errorf("invalid logical processor %q: %w", part, err)
				}
				lps = append(lps, uint32(lp))
			}
			if c.Uint("priority") > uint(cpugroup.MaxSchedulingPriority) {
				return errors.New("CPU group scheduling priority must be 0 through 7")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			report, err := manageCPUGroup(ctx, action, c.String("id"), lps, uint32(c.Uint("priority")), c.Bool("if-exists"), hostCPUGroupOperations)
			if err != nil || report == nil {
				return err
			}
			return json.NewEncoder(c.App.Writer).Encode(report)
		},
	}
}

var cpuGroupCommand = cli.Command{
	Name:        "cpu-group",
	Usage:       "Manage an explicitly owned CPU group with identity, affinity and priority readback",
	Subcommands: []cli.Command{cpuGroupSubcommand("create"), cpuGroupSubcommand("query"), cpuGroupSubcommand("delete")},
}

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
