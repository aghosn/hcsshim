//go:build windows

package sibling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/internal/cpugroup"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

func testResources() []VMResources {
	return []VMResources{{ProcessorCount: 1, MemoryMB: 512}, {ProcessorCount: 8, MemoryMB: 4096}}
}

func TestPairIndependentResourcesKeepBaseAndSecurity(t *testing.T) {
	config := testConfig()
	config.VMResources = testResources()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeConfig(strings.NewReader(string(data)))
	if err != nil || !reflect.DeepEqual(config, decoded) {
		t.Fatalf("resources did not round-trip: %+v %v", decoded, err)
	}
	base := testOptions()
	base.ProcessorCount, base.MemorySizeInMB, base.CPUGroupID = 4, 2048, "inherited"
	workload, diode, err := pairOptions(base, config, "group", &Section{HCSName: "owned", Size: 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for i, options := range []*uvm.OptionsLCOW{diode, workload} {
		resource := config.VMResources[i]
		if options.ProcessorCount != resource.ProcessorCount || options.MemorySizeInMB != resource.MemoryMB ||
			options.SecurityPolicy != base.SecurityPolicy || options.SecurityPolicyEnforcer != base.SecurityPolicyEnforcer ||
			!options.SecurityPolicyEnabled || !options.DmVerityMode || options.CPUGroupID != base.CPUGroupID {
			t.Fatalf("role %d resources/security changed: %+v", i, options)
		}
	}
	workload.ProcessorCount, workload.MemorySizeInMB = 16, 8192
	if base.ProcessorCount != 4 || base.MemorySizeInMB != 2048 ||
		diode.ProcessorCount != 1 || diode.MemorySizeInMB != 512 ||
		config.VMResources[1].ProcessorCount != 8 || config.VMResources[1].MemoryMB != 4096 {
		t.Fatal("resource application mutated caller, sibling or config")
	}
}

func TestPairInvalidResourcesFailBeforeAllocation(t *testing.T) {
	for _, resources := range [][]VMResources{
		{},
		{{ProcessorCount: 1, MemoryMB: 512}},
		{{ProcessorCount: 1, MemoryMB: 512}, {ProcessorCount: 2, MemoryMB: 1024}, {ProcessorCount: 3, MemoryMB: 2048}},
		{{ProcessorCount: 0, MemoryMB: 512}, {ProcessorCount: 2, MemoryMB: 1024}},
		{{ProcessorCount: 1, MemoryMB: 512}, {ProcessorCount: 257, MemoryMB: 1024}},
		{{ProcessorCount: 1, MemoryMB: 0}, {ProcessorCount: 2, MemoryMB: 1024}},
		{{ProcessorCount: 1, MemoryMB: 512}, {ProcessorCount: 2, MemoryMB: MaxMemoryMB + 1}},
		{{ProcessorCount: 1, MemoryMB: 512, CPUGroupLPs: []uint32{}}, {ProcessorCount: 2, MemoryMB: 1024}},
		{{ProcessorCount: 1, MemoryMB: 512, CPUGroupLPs: []uint32{8, 8}}, {ProcessorCount: 2, MemoryMB: 1024}},
		{{ProcessorCount: 1, MemoryMB: 512, CPUGroupLPs: []uint32{8, 24}}, {ProcessorCount: 2, MemoryMB: 1024, CPUGroupLPs: []uint32{24, 9}}},
	} {
		config := testConfig()
		config.VMResources = resources
		if _, err := Start(context.Background(), testOptions(), config); err == nil || !strings.Contains(err.Error(), "vm_resources") {
			t.Fatalf("invalid resources reached input loading/allocation: %+v, %v", resources, err)
		}
		if _, _, err := pairOptions(testOptions(), config, "group", &Section{}); err == nil {
			t.Fatalf("invalid resources reached cloned options: %+v", resources)
		}
	}
	data, _ := json.Marshal(testConfig())
	text := strings.TrimSuffix(string(data), "}") + `,"vm_resources":[]}`
	if _, err := decodeConfig(strings.NewReader(text)); err == nil {
		t.Fatal("explicit empty resource array was accepted as omission")
	}
}

func fakeResourceCPUGroupOperations(events *[]string) (cpugroup.Operations, map[string][]uint32) {
	groups := map[string][]uint32{}
	return cpugroup.Operations{
		Create: func(_ context.Context, id string, lps []uint32) error {
			*events = append(*events, "create:"+id)
			groups[id] = append([]uint32(nil), lps...)
			return nil
		},
		Query: func(_ context.Context, id string) (*hcsschema.CpuGroupConfig, error) {
			lps := make([]int32, len(groups[id]))
			for i, lp := range groups[id] {
				lps[i] = int32(lp)
			}
			return &hcsschema.CpuGroupConfig{GroupId: id, Affinity: &hcsschema.CpuGroupAffinity{
				LogicalProcessorCount: int32(len(lps)), LogicalProcessors: lps,
			}}, nil
		},
		Delete: func(ctx context.Context, id string) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			*events = append(*events, "delete:"+id)
			delete(groups, id)
			return nil
		},
	}, groups
}

func TestPairCPUGroupOwnershipAndInheritedAffinity(t *testing.T) {
	for _, test := range []struct {
		name       string
		affinities [][]uint32
		count      int
	}{
		{"shared", [][]uint32{{8, 24}, {24, 8}}, 1},
		{"separate", [][]uint32{{8, 24}, {9, 25}}, 2},
		{"workload-only", [][]uint32{nil, {8, 24, 9, 25}}, 1},
		{"no-affinity", [][]uint32{nil, nil}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			ops, created := fakeResourceCPUGroupOperations(&events)
			config := testConfig()
			config.VMResources = testResources()
			for i := range config.VMResources {
				config.VMResources[i].CPUGroupLPs = test.affinities[i]
			}
			base := testOptions()
			base.CPUGroupID = "inherited"
			workload, diode, err := pairOptions(base, config, "group", &Section{HCSName: "owned", Size: 16 << 20})
			if err != nil {
				t.Fatal(err)
			}
			groups, err := preparePairCPUGroups(context.Background(), config, workload, diode, ops)
			if err != nil || len(created) != test.count {
				t.Fatalf("prepare groups: created=%v, error=%v", created, err)
			}
			for i, options := range []*uvm.OptionsLCOW{diode, workload} {
				if test.affinities[i] == nil {
					if options.CPUGroupID != "inherited" {
						t.Fatal("unconfigured affinity did not preserve base")
					}
				} else if !reflect.DeepEqual(created[options.CPUGroupID], func() []uint32 {
					lps, _, _ := cpugroup.CanonicalLPs(test.affinities[i])
					return lps
				}()) {
					t.Fatal("VM did not receive its requested CPU group")
				}
			}
			if base.CPUGroupID != "inherited" {
				t.Fatal("affinity assignment mutated base options")
			}
			events = nil
			pair := &Pair{
				cpuGroups:      groups,
				workloadCloser: closeFunc(func() error { events = append(events, "workload"); return nil }),
				diodeCloser:    closeFunc(func() error { events = append(events, "diode"); return nil }),
			}
			for range 2 {
				if err := pair.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if len(created) != 0 || len(events) != 2+test.count ||
				events[0] != "workload" || events[1] != "diode" {
				t.Fatalf("group ownership/close order changed: %v", events)
			}
		})
	}
}

func TestPairCPUGroupFailureRollsBackWithoutChangingOptions(t *testing.T) {
	config := testConfig()
	config.VMResources = testResources()
	config.VMResources[0].CPUGroupLPs = []uint32{8, 24}
	config.VMResources[1].CPUGroupLPs = []uint32{9, 25}
	var events []string
	ops, created := fakeResourceCPUGroupOperations(&events)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	query := ops.Query
	queries := 0
	failure := errors.New("injected group verification failure")
	ops.Query = func(ctx context.Context, id string) (*hcsschema.CpuGroupConfig, error) {
		queries++
		if queries == 2 {
			cancel()
			return nil, failure
		}

		return query(ctx, id)
	}
	workload, diode := testOptions(), testOptions()
	workload.CPUGroupID, diode.CPUGroupID = "workload-base", "diode-base"
	if groups, err := preparePairCPUGroups(ctx, config, workload, diode, ops); groups != nil || !errors.Is(err, failure) {
		t.Fatalf("verification failure hidden: %+v %v", groups, err)
	}
	if len(created) != 0 || len(events) != 4 ||
		events[2] != strings.Replace(events[1], "create:", "delete:", 1) ||
		events[3] != strings.Replace(events[0], "create:", "delete:", 1) ||
		workload.CPUGroupID != "workload-base" || diode.CPUGroupID != "diode-base" {
		t.Fatalf("partial groups or options escaped failed allocation: %v", events)
	}
}

func TestResourceCPUGroupPriorities(t *testing.T) {
	for _, standalone := range []bool{false, true} {
		t.Run(fmt.Sprint(standalone), func(t *testing.T) {
			config := testConfig()
			config.VMResources = testResources()
			if standalone {
				config = testStandaloneConfig()
			}
			var events []string
			ops, created := fakeResourceCPUGroupOperations(&events)
			priorities := map[string]uint32{}
			ops.SetPriority = func(_ context.Context, id string, priority uint32) error {
				priorities[id] = priority
				return nil
			}
			query := ops.Query
			ops.Query = func(ctx context.Context, id string) (*hcsschema.CpuGroupConfig, error) {
				result, err := query(ctx, id)
				result.GroupProperties = []hcsschema.CpuGroupProperty{{
					PropertyCode: hcsschema.CPUSchedulingPriorityProperty, PropertyValue: priorities[id],
				}}
				return result, err
			}
			var options []*uvm.OptionsLCOW
			for i := range config.VMResources {
				priority := uint32(0)
				config.VMResources[i].CPUGroupLPs = []uint32{8, 24, 9, 25, 10, 26}
				config.VMResources[i].CPUGroupPriority = &priority
				options = append(options, testOptions())
			}
			groups, err := prepareResourceCPUGroups(context.Background(), config, options, ops)
			if err != nil {
				t.Fatal(err)
			}
			defer groups.Close(context.Background())
			if len(created) != len(options) || len(groups.Reports) != len(options) ||
				len(priorities) != len(options) {
				t.Fatalf("explicit equal priorities did not create and verify independent groups: %+v", groups)
			}
			for i, option := range options {
				if option.CPUGroupID != groups.IDs[i] || groups.Reports[i].SchedulingPriority != 0 {
					t.Fatal("priority/group assignment mismatch")
				}
			}
			if len(options) == 2 && options[0].CPUGroupID == options[1].CPUGroupID {
				t.Fatal("explicit shared-pool priorities reused a single group")
			}
		})
	}
}

func TestResourceCPUGroupPriorityValidation(t *testing.T) {
	zero, max, invalid := uint32(0), cpugroup.MaxSchedulingPriority, cpugroup.MaxSchedulingPriority+1
	for _, resources := range [][]VMResources{
		{{ProcessorCount: 8, MemoryMB: 65536, CPUGroupPriority: &zero}},
		{{ProcessorCount: 8, MemoryMB: 65536, CPUGroupLPs: []uint32{8, 24}, CPUGroupPriority: &invalid}},
		{{ProcessorCount: 8, MemoryMB: 65536, CPUGroupLPs: []uint32{}, CPUGroupPriority: &zero}},
		{{ProcessorCount: 8, MemoryMB: 65536, CPUGroupLPs: []uint32{8, 8}, CPUGroupPriority: &zero}},
		{{ProcessorCount: 1, MemoryMB: 2048, CPUGroupLPs: []uint32{8, 24}, CPUGroupPriority: &max},
			{ProcessorCount: 16, MemoryMB: 131072, CPUGroupLPs: []uint32{8, 24}}},
	} {
		if err := ValidateVMResources(resources); err == nil {
			t.Fatalf("invalid priority configuration accepted: %+v", resources)
		}
	}
}

func TestPairOverlappingPrioritizedAffinities(t *testing.T) {
	pool := []uint32{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25}
	for _, test := range []struct {
		name       string
		affinities [][]uint32
	}{
		{"diode-subset", [][]uint32{{10, 11}, pool}},
		{"workload-subset", [][]uint32{pool, {10, 11}}},
		{"partial-overlap", [][]uint32{{10, 11}, {11, 12}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			priority := uint32(1)
			config := testConfig()
			config.VMResources = []VMResources{
				{ProcessorCount: 2, MemoryMB: 2048, CPUGroupLPs: test.affinities[0], CPUGroupPriority: &priority},
				{ProcessorCount: 16, MemoryMB: 131072, CPUGroupLPs: test.affinities[1], CPUGroupPriority: &priority},
			}
			workload, diode, err := pairOptions(testOptions(), config, "group", &Section{HCSName: "owned", Size: 16 << 20})
			if err != nil {
				t.Fatal(err)
			}
			var events []string
			ops, created := fakeResourceCPUGroupOperations(&events)
			priorities := map[string]uint32{}
			ops.SetPriority = func(_ context.Context, id string, value uint32) error {
				priorities[id] = value
				return nil
			}
			query := ops.Query
			ops.Query = func(ctx context.Context, id string) (*hcsschema.CpuGroupConfig, error) {
				result, err := query(ctx, id)
				result.GroupProperties = []hcsschema.CpuGroupProperty{{
					PropertyCode: hcsschema.CPUSchedulingPriorityProperty, PropertyValue: priorities[id],
				}}
				return result, err
			}
			groups, err := preparePairCPUGroups(context.Background(), config, workload, diode, ops)
			if err != nil {
				t.Fatal(err)
			}
			defer groups.Close(context.Background())
			if len(created) != 2 || len(groups.Reports) != 2 || diode.CPUGroupID == workload.CPUGroupID {
				t.Fatalf("overlapping affinities did not create independent groups: %+v", groups)
			}
			for i, options := range []*uvm.OptionsLCOW{diode, workload} {
				expected, _, _ := cpugroup.CanonicalLPs(test.affinities[i])
				resource := config.VMResources[i]
				if options.CPUGroupID != groups.IDs[i] ||
					!reflect.DeepEqual(created[options.CPUGroupID], expected) ||
					!reflect.DeepEqual(groups.Reports[i].LogicalProcessors, expected) ||
					groups.Reports[i].SchedulingPriority != priority ||
					options.ProcessorCount != resource.ProcessorCount || options.MemorySizeInMB != resource.MemoryMB {
					t.Fatalf("role %d affinity, priority or allocation changed: %+v", i, options)
				}
			}
		})
	}
}

func TestResourceCPUGroupPriorityFailureRollsBack(t *testing.T) {
	config := testStandaloneConfig()
	priority := uint32(0)
	config.VMResources[0].CPUGroupPriority = &priority
	config.VMResources[0].CPUGroupLPs = []uint32{8, 24}
	var events []string
	ops, created := fakeResourceCPUGroupOperations(&events)
	failure := errors.New("injected priority failure")
	ops.SetPriority = func(context.Context, string, uint32) error { return failure }
	options := testOptions()
	options.CPUGroupID = "inherited"
	groups, err := prepareResourceCPUGroups(context.Background(), config, []*uvm.OptionsLCOW{options}, ops)
	if !errors.Is(err, failure) || groups != nil || len(created) != 0 ||
		options.CPUGroupID != "inherited" || len(events) != 2 {
		t.Fatalf("priority failure did not roll back: %+v %v %v", groups, err, events)
	}
}
