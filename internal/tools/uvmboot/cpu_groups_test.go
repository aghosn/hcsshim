//go:build windows

package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

func fakeCPUGroupOperations() (cpuGroupOperations, map[string][]uint32, *[]string) {
	groups := map[string][]uint32{}
	deleted := []string{}
	return cpuGroupOperations{
		create: func(_ context.Context, id string, lps []uint32) error {
			groups[id] = append([]uint32(nil), lps...)
			return nil
		},
		query: func(_ context.Context, id string) (*hcsschema.CpuGroupConfig, error) {
			lps := make([]int32, len(groups[id]))
			for i, lp := range groups[id] {
				lps[i] = int32(lp)
			}
			return &hcsschema.CpuGroupConfig{
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

func TestCPUGroupSharedAffinityHasOneOwner(t *testing.T) {
	ops, groups, deleted := fakeCPUGroupOperations()
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
		if err := validateBenchmarkCPUs(topology, groups); err != nil {
			t.Fatalf("valid affinity %v rejected: %v", groups, err)
		}
		if !reflect.DeepEqual(copyBefore, groups[0]) {
			t.Fatal("validation changed the affinity input")
		}
	}
	for _, groups := range [][][]uint32{
		{{8}}, {{8, 9}}, {{8, 8}}, {{8, 100}}, {{8, 24}, {10, 26}},
	} {
		if err := validateBenchmarkCPUs(topology, groups); err == nil {
			t.Fatalf("accepted invalid physical-core placement %v", groups)
		}
	}
}
