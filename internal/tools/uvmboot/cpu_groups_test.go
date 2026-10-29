//go:build windows

package main

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

func fakeCPUGroupOperations() (cpuGroupOperations, map[string][]uint32, *[]string) {
	groups := map[string][]uint32{}
	priorities := map[string]uint32{}
	deleted := []string{}
	return cpuGroupOperations{
		create: func(_ context.Context, id string, lps []uint32) error {
			groups[id] = append([]uint32(nil), lps...)
			priorities[id] = 1
			return nil
		},
		setPriority: func(_ context.Context, id string, priority uint32) error {
			priorities[id] = priority
			return nil
		},
		query: func(_ context.Context, id string) (*hcsschema.CpuGroupConfig, error) {
			lps := make([]int32, len(groups[id]))
			for i, lp := range groups[id] {
				lps[i] = int32(lp)
			}
			return &hcsschema.CpuGroupConfig{
				GroupId: id,
				GroupProperties: []hcsschema.CpuGroupProperty{{
					PropertyCode:  hcsschema.CPUSchedulingPriorityProperty,
					PropertyValue: priorities[id],
				}},
				Affinity: &hcsschema.CpuGroupAffinity{
					LogicalProcessorCount: int32(len(lps)),
					LogicalProcessors:     lps,
				},
			}, nil
		},
		delete: func(_ context.Context, id string) error {
			deleted = append(deleted, id)
			return nil
		},
	}, groups, &deleted
}

func TestCPUGroupPrioritiesCreateDistinctVerifiedGroups(t *testing.T) {
	for _, priorities := range [][]uint32{{2, 1}, {1, 1}, {0, 7}} {
		ops, groups, deleted := fakeCPUGroupOperations()
		events := []string{}
		create, setPriority, query := ops.create, ops.setPriority, ops.query
		ops.create = func(ctx context.Context, id string, lps []uint32) error {
			events = append(events, "create")
			return create(ctx, id, lps)
		}
		ops.setPriority = func(ctx context.Context, id string, priority uint32) error {
			events = append(events, "priority")
			return setPriority(ctx, id, priority)
		}
		ops.query = func(ctx context.Context, id string) (*hcsschema.CpuGroupConfig, error) {
			events = append(events, "query")
			return query(ctx, id)
		}
		assignments, err := prepareCPUGroups(context.Background(), [][]uint32{{24, 8}, {8, 24}}, 2, ops, priorities...)
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) != 2 || assignments.ids[0] == assignments.ids[1] {
			t.Fatalf("explicit priorities must have distinct groups: %+v", assignments)
		}
		if !reflect.DeepEqual(events, []string{"create", "priority", "query", "create", "priority", "query"}) {
			t.Fatalf("priority must precede verification and VM creation: %v", events)
		}
		for i, report := range assignments.reports {
			if report.VM != "uvmboot-"+strconv.Itoa(i) || report.GroupID != assignments.ids[i] ||
				report.SchedulingPriority != priorities[i] || !reflect.DeepEqual(report.LogicalProcessors, []uint32{8, 24}) {
				t.Fatalf("incorrect readback report: %+v", report)
			}
		}
		if len(assignments.reports) != 2 {
			t.Fatalf("missing group reports: %+v", assignments.reports)
		}
		if err := assignments.close(context.Background()); err != nil ||
			!reflect.DeepEqual(*deleted, []string{assignments.ids[1], assignments.ids[0]}) {
			t.Fatalf("distinct group cleanup: %v, %v", *deleted, err)
		}
	}
}

func TestCPUGroupPriorityFailuresRollBackAllGroups(t *testing.T) {
	for _, failure := range []string{"set", "query", "missing", "mismatch", "duplicate", "id", "delete", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops, _, deleted := fakeCPUGroupOperations()
			setPriority, query, deleteGroup := ops.setPriority, ops.query, ops.delete
			sets, queries := 0, 0
			ops.setPriority = func(ctx context.Context, id string, priority uint32) error {
				sets++
				if sets == 2 && (failure == "set" || failure == "delete" || failure == "cancel") {
					if failure == "cancel" {
						cancel()
					}
					return errors.New("injected priority failure")
				}
				return setPriority(ctx, id, priority)
			}
			ops.query = func(ctx context.Context, id string) (*hcsschema.CpuGroupConfig, error) {
				queries++
				if queries == 2 && failure == "query" {
					return nil, errors.New("injected query failure")
				}
				config, err := query(ctx, id)
				if queries == 2 {
					switch failure {
					case "missing":
						config.GroupProperties = nil
					case "mismatch":
						config.GroupProperties[0].PropertyValue = 7
					case "duplicate":
						config.GroupProperties = append(config.GroupProperties, config.GroupProperties[0])
					case "id":
						config.GroupId = "another-group"
					}
				}
				return config, err
			}
			ops.delete = func(ctx context.Context, id string) error {
				if ctx.Err() != nil {
					t.Fatal("rollback inherited canceled context")
				}
				if err := deleteGroup(ctx, id); err != nil {
					return err
				}
				if failure == "delete" {
					return errors.New("injected delete failure")
				}
				return nil
			}
			assignments, err := prepareCPUGroups(ctx, [][]uint32{{8, 24}, {8, 24}}, 2, ops, 2, 1)
			if err == nil || assignments != nil || len(*deleted) != 2 {
				t.Fatalf("failure must abort and roll back both groups: %v, %v, %v", assignments, err, *deleted)
			}
			if failure == "delete" && !strings.Contains(err.Error(), "injected delete failure") {
				t.Fatalf("cleanup error was hidden: %v", err)
			}
		})
	}
}

func TestCPUGroupRejectsInvalidPrioritiesBeforeCreatingGroups(t *testing.T) {
	for _, test := range []struct {
		groups     [][]uint32
		priorities []uint32
	}{
		{nil, []uint32{2, 1}},
		{[][]uint32{{8, 24}, {8, 24}}, []uint32{2}},
		{[][]uint32{{8, 24}, {8, 24}}, []uint32{2, 1, 1}},
		{[][]uint32{{8, 24}, {8, 24}}, []uint32{8, 1}},
	} {
		ops, created, _ := fakeCPUGroupOperations()
		if _, err := prepareCPUGroups(context.Background(), test.groups, 2, ops, test.priorities...); err == nil || len(created) != 0 {
			t.Fatalf("accepted priorities %v / groups %v: %v", test.priorities, test.groups, err)
		}
	}
}

func TestParseCPUGroupPriorities(t *testing.T) {
	for value, expected := range map[string][]uint32{"": nil, "2,1": {2, 1}, " 0 , 7 ": {0, 7}} {
		actual, err := parseCPUGroupPriorities(value)
		if err != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("parse %q = %v, %v", value, actual, err)
		}
	}
	for _, value := range []string{" ", "8", "-1", "2,", "1.5", "4294967296", "priority"} {
		if _, err := parseCPUGroupPriorities(value); err == nil {
			t.Fatalf("accepted priority %q", value)
		}
	}
}

func TestCPUGroupSharedAffinityHasOneOwner(t *testing.T) {
	ops, groups, deleted := fakeCPUGroupOperations()
	ops.setPriority = func(context.Context, string, uint32) error {
		t.Fatal("default pinning must not change priorities")
		return nil
	}
	assignments, err := prepareCPUGroups(context.Background(), [][]uint32{{8, 24}, {24, 8}}, 2, ops)
	if err != nil {
		t.Fatal(err)
	}
	first, err := assignments.groupForVM("uvmboot-0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := assignments.groupForVM("uvmboot-1")
	if err != nil || first != second || len(groups) != 1 {
		t.Fatalf("VMs must share one CPU group: ids=%v, groups=%v, err=%v", assignments.ids, groups, err)
	}
	if err := assignments.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := assignments.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*deleted) != 1 || (*deleted)[0] != first {
		t.Fatalf("shared CPU group cleanup = %v", *deleted)
	}
}

func TestCPUGroupFailureDoesNotFallBackToUnpinned(t *testing.T) {
	for _, failure := range []string{"create", "query", "mismatch"} {
		t.Run(failure, func(t *testing.T) {
			ops, _, deleted := fakeCPUGroupOperations()
			switch failure {
			case "create":
				ops.create = func(context.Context, string, []uint32) error { return errors.New("injected create failure") }
			case "query":
				ops.query = func(context.Context, string) (*hcsschema.CpuGroupConfig, error) {
					return nil, errors.New("injected query failure")
				}
			case "mismatch":
				ops.query = func(context.Context, string) (*hcsschema.CpuGroupConfig, error) {
					return &hcsschema.CpuGroupConfig{Affinity: &hcsschema.CpuGroupAffinity{
						LogicalProcessorCount: 2, LogicalProcessors: []int32{1, 2},
					}}, nil
				}
			}
			assignments, err := prepareCPUGroups(context.Background(), [][]uint32{{8, 24}}, 1, ops)
			if err == nil || assignments != nil {
				t.Fatalf("failure must abort pinning, got %v, %v", assignments, err)
			}
			if failure != "create" && len(*deleted) != 1 {
				t.Fatalf("created group was not rolled back: %v", *deleted)
			}
		})
	}
}

func TestCPUGroupRejectsInvalidAffinityBeforeCreatingGroups(t *testing.T) {
	for _, groups := range [][][]uint32{
		{{8, 8}}, {{8, 24}, {24, 9}}, {{8, 24}, {}},
	} {
		ops, created, _ := fakeCPUGroupOperations()
		if _, err := prepareCPUGroups(context.Background(), groups, len(groups), ops); err == nil {
			t.Fatalf("accepted invalid affinity %v", groups)
		}
		if len(created) != 0 {
			t.Fatalf("created groups for invalid affinity %v", groups)
		}
	}
	ops, _, _ := fakeCPUGroupOperations()
	if _, err := prepareCPUGroups(context.Background(), [][]uint32{{8, 24}}, 2, ops); err == nil {
		t.Fatal("accepted missing VM affinity")
	}
}

func TestCPUGroupSeparateAffinitiesRemainSeparate(t *testing.T) {
	ops, groups, deleted := fakeCPUGroupOperations()
	assignments, err := prepareCPUGroups(context.Background(), [][]uint32{{8, 24}, {9, 25}}, 2, ops)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || assignments.ids[0] == assignments.ids[1] {
		t.Fatalf("separate core groups collapsed: %+v", assignments)
	}
	if _, err := assignments.groupForVM("uvmboot-2"); err == nil {
		t.Fatal("accepted VM without affinity")
	}
	if err := assignments.close(context.Background()); err != nil || len(*deleted) != 2 {
		t.Fatalf("cleanup = %v, %v", *deleted, err)
	}
}

func TestBenchmarkCPUValidationUsesPhysicalTopologyNotAdjacentLPs(t *testing.T) {
	topology := &hcsschema.ProcessorTopology{LogicalProcessors: []hcsschema.LogicalProcessor{
		{LpIndex: 8, PackageId: 0, CoreId: 4, NodeNumber: 0},
		{LpIndex: 24, PackageId: 0, CoreId: 4, NodeNumber: 0},
		{LpIndex: 9, PackageId: 0, CoreId: 5, NodeNumber: 0},
		{LpIndex: 25, PackageId: 0, CoreId: 5, NodeNumber: 0},
		{LpIndex: 10, PackageId: 1, CoreId: 4, NodeNumber: 1},
		{LpIndex: 26, PackageId: 1, CoreId: 4, NodeNumber: 1},
	}}
	for _, groups := range [][][]uint32{
		{{8, 24}}, {{8, 24}, {9, 25}}, {{8, 24}, {8, 24}},
	} {
		copyBefore := append([]uint32(nil), groups[0]...)
		if err := validateBenchmarkCPUs(topology, groups, false); err != nil {
			t.Fatalf("valid affinity %v rejected: %v", groups, err)
		}
		if !reflect.DeepEqual(copyBefore, groups[0]) {
			t.Fatal("validation changed the affinity input")
		}
	}
	for _, groups := range [][][]uint32{
		{{8}}, {{8, 9}}, {{8, 8}}, {{8, 100}}, {{8, 24}, {10, 26}},
	} {
		if err := validateBenchmarkCPUs(topology, groups, false); err == nil {
			t.Fatalf("accepted invalid physical-core placement %v", groups)
		}

	}
}

func TestBenchmarkMinRootRejectsRootAffinity(t *testing.T) {
	for _, noSMT := range []bool{false, true} {
		t.Run(strconv.FormatBool(noSMT), func(t *testing.T) {
			topology := &hcsschema.ProcessorTopology{LogicalProcessors: []hcsschema.LogicalProcessor{
				{LpIndex: 0, CoreId: 0, RootVpIndex: 0},
				{LpIndex: 16, CoreId: 0, RootVpIndex: 1},
				{LpIndex: 8, CoreId: 4, RootVpIndex: -1},
				{LpIndex: 24, CoreId: 4, RootVpIndex: -1},
				{LpIndex: 9, CoreId: 5, RootVpIndex: -1},
				{LpIndex: 25, CoreId: 5, RootVpIndex: -1},
			}}
			if noSMT {
				for i := range topology.LogicalProcessors {
					topology.LogicalProcessors[i].CoreId = topology.LogicalProcessors[i].LpIndex
				}
			}
			if err := validateBenchmarkCPUs(topology, [][]uint32{{8, 24}, {8, 24}}, noSMT); err != nil {
				t.Fatalf("root-free placement rejected: %v", err)
			}
			if err := validateBenchmarkCPUs(topology, [][]uint32{{0, 16}}, noSMT); err == nil ||
				!strings.Contains(err.Error(), "root-partition LPs") {
				t.Fatalf("root placement not rejected: %v", err)
			}
			topology.LogicalProcessors[3].RootVpIndex = 2
			if err := validateBenchmarkCPUs(topology, [][]uint32{{8, 24}}, noSMT); err == nil ||
				!strings.Contains(err.Error(), "root-partition LPs") {
				t.Fatalf("partially root-owned placement not rejected: %v", err)
			}
			for i := range topology.LogicalProcessors {
				topology.LogicalProcessors[i].RootVpIndex = int32(i)
			}
			if err := validateBenchmarkCPUs(topology, [][]uint32{{8, 24}}, noSMT); err != nil {
				t.Fatalf("unrestricted-root placement rejected: %v", err)
			}
			topology.LogicalProcessors[0].RootVpIndex = -2
			if err := validateBenchmarkCPUs(topology, [][]uint32{{8, 24}}, noSMT); err == nil {
				t.Fatal("invalid root topology accepted")
			}
		})
	}
}

func TestBenchmarkNoSMTRequiresIdenticalTwoCoreAffinities(t *testing.T) {
	topology := &hcsschema.ProcessorTopology{LogicalProcessors: []hcsschema.LogicalProcessor{
		{LpIndex: 0, CoreId: 0}, {LpIndex: 1, CoreId: 1},
		{LpIndex: 2, CoreId: 2}, {LpIndex: 3, CoreId: 3, NodeNumber: 1},
	}}
	groups := [][]uint32{{0, 1}, {1, 0}}
	if err := validateBenchmarkCPUs(topology, groups, true); err != nil {
		t.Fatal(err)
	}
	if err := validateBenchmarkCPUs(topology, groups[:1], true); err != nil {
		t.Fatalf("SMT-off baseline rejected: %v", err)
	}
	if err := validateBenchmarkCPUs(topology, groups, false); err == nil {
		t.Fatal("default SMT validation accepted two physical cores")
	}
	for _, invalid := range [][][]uint32{
		{{0, 1}, {0, 2}}, {{0, 0}, {0, 0}}, {{0, 99}, {0, 99}}, {{0, 3}, {0, 3}},
	} {
		if err := validateBenchmarkCPUs(topology, invalid, true); err == nil {
			t.Fatalf("accepted invalid SMT-off placement %v", invalid)
		}
	}
	topology.LogicalProcessors[1].CoreId = 0
	if err := validateBenchmarkCPUs(topology, groups, true); err == nil {
		t.Fatal("SMT-off mode accepted an enabled SMT pair")
	}
}
