//go:build windows

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/internal/sibling"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/urfave/cli"
)

func resourceTestContext(t *testing.T, values map[string]string) *cli.Context {
	t.Helper()
	c := benchmarkTestContext(t)
	for name, value := range values {
		if err := c.GlobalSet(name, value); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestVMResourceListsOverrideScalarDefaultsForLCOWAndWCOW(t *testing.T) {
	c := resourceTestContext(t, map[string]string{
		countArgName: "2", cpusArgName: "4", memoryArgName: "2048",
		vmCPUsArgName: " 1,8 ", vmMemoryArgName: "130,4096",
	})
	if err := prepareVMResources(c); err != nil {
		t.Fatal(err)
	}
	for i, expected := range []sibling.VMResources{
		{ProcessorCount: 1, MemoryMB: 130}, {ProcessorCount: 8, MemoryMB: 4096},
	} {
		id := fmt.Sprintf("uvmboot-%d", i)
		for _, options := range []*uvm.Options{
			uvm.NewDefaultOptionsLCOW(id, "").Options,
			uvm.NewDefaultOptionsWCOW(id, "").Options,
		} {
			if err := setGlobalOptions(c, options); err != nil {
				t.Fatal(err)
			}
			if options.ProcessorCount != expected.ProcessorCount || options.MemorySizeInMB != expected.MemoryMB {
				t.Fatalf("%s resources = %d/%d, expected %+v", id, options.ProcessorCount, options.MemorySizeInMB, expected)
			}
		}
		if got := requestedVMProcessors(c, id); got != uint64(expected.ProcessorCount) {
			t.Fatalf("%s requested processors = %d", id, got)
		}
	}
}

func TestVMResourceListsPreserveUnspecifiedAndScalarDefaults(t *testing.T) {
	for _, test := range []struct {
		values map[string]string
		cpus   int32
		memory uint64
	}{
		{map[string]string{}, 2, 2048},
		{map[string]string{cpusArgName: "4", memoryArgName: "3072"}, 4, 3072},
		{map[string]string{vmCPUsArgName: "1"}, 1, 2048},
		{map[string]string{vmMemoryArgName: "8192"}, 2, 8192},
		{map[string]string{vmCPUsArgName: "1", memoryArgName: "3072"}, 1, 3072},
		{map[string]string{vmMemoryArgName: "8192", cpusArgName: "4"}, 4, 8192},
	} {
		c := resourceTestContext(t, test.values)
		options := &uvm.Options{ID: "uvmboot-0", ProcessorCount: 2, MemorySizeInMB: 2048}
		if err := setGlobalOptions(c, options); err != nil {
			t.Fatal(err)
		}
		if options.ProcessorCount != test.cpus || options.MemorySizeInMB != test.memory {
			t.Fatalf("flags %v: got %d/%d, want %d/%d", test.values,
				options.ProcessorCount, options.MemorySizeInMB, test.cpus, test.memory)
		}
	}
}

func TestVMResourceListsRejectInvalidValuesBeforeApplication(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		{vmCPUsArgName, ""}, {vmCPUsArgName, "1"}, {vmCPUsArgName, "1,2,3"},
		{vmCPUsArgName, "1,"}, {vmCPUsArgName, "1,0"}, {vmCPUsArgName, "-1,2"},
		{vmCPUsArgName, "1,257"}, {vmCPUsArgName, "1,4294967297"},
		{vmCPUsArgName, "1,two"}, {vmCPUsArgName, "1,18446744073709551616"},
		{vmMemoryArgName, ""}, {vmMemoryArgName, "512"},
		{vmMemoryArgName, "512,0"}, {vmMemoryArgName, "512,-1"},
		{vmMemoryArgName, fmt.Sprintf("512,%d", sibling.MaxMemoryMB+1)},
		{vmMemoryArgName, "512,18446744073709551616"},
	} {
		t.Run(test.name+"="+test.value, func(t *testing.T) {
			c := resourceTestContext(t, map[string]string{countArgName: "2", test.name: test.value})
			if err := prepareVMResources(c); err == nil {
				t.Fatal("invalid resource list was accepted")
			}
			options := &uvm.Options{ID: "uvmboot-0", ProcessorCount: 2, MemorySizeInMB: 2048}
			if err := setGlobalOptions(c, options); err == nil {
				t.Fatal("invalid resource list reached option application")
			}
			if options.ProcessorCount != 2 || options.MemorySizeInMB != 2048 {
				t.Fatal("invalid list partially mutated VM options")
			}
		})
	}
	c := resourceTestContext(t, map[string]string{vmCPUsArgName: "256", vmMemoryArgName: fmt.Sprint(sibling.MaxMemoryMB)})
	if err := validateVMResources(c); err != nil {
		t.Fatalf("valid integer boundaries rejected: %v", err)
	}
	options := &uvm.Options{ID: "uvmboot-1"}
	if err := setGlobalOptions(c, options); err == nil {
		t.Fatal("missing VM resource entry silently fell back")
	}
}

func TestUnikraftExplicitResourcesMatchImageWithoutConstrainingWorkload(t *testing.T) {
	for _, test := range []struct {
		values map[string]string
		want   string
	}{
		{map[string]string{cpusArgName: "8", memoryArgName: "4096"}, ""},
		{map[string]string{vmCPUsArgName: "1,8", vmMemoryArgName: "130,4096"}, ""},
		{map[string]string{vmCPUsArgName: "1,1", vmMemoryArgName: "130,8192"}, ""},
		{map[string]string{vmCPUsArgName: "1,4"}, ""},
		{map[string]string{cpusArgName: "8", vmMemoryArgName: "130,4096"}, ""},
		{map[string]string{vmCPUsArgName: "2,8"}, "image capability"},
		{map[string]string{vmMemoryArgName: "128,4096"}, "image capability"},
		{map[string]string{vmMemoryArgName: "132,4096"}, "image capability"},
		{map[string]string{vmCPUsArgName: "1,0"}, "processor_count"},
	} {
		values := map[string]string{countArgName: "2"}
		for name, value := range test.values {
			values[name] = value
		}
		c := resourceTestContext(t, values)
		err := validateUnikraftResources(c, 128)
		if (err != nil) != (test.want != "") || (err != nil && !strings.Contains(err.Error(), test.want)) {
			t.Fatalf("flags %v: error %v, want %q", test.values, err, test.want)
		}
	}
}

func TestBenchmarkResourcesValidateEachRequestedCount(t *testing.T) {
	for _, test := range []struct {
		cpus string
		want bool
	}{
		{"1,1", true}, {"1,2", true}, {"2,1", true}, {"2,2", true},
		{"3,1", false}, {"1,3", false}, {"0,2", false},
	} {
		c := resourceTestContext(t, map[string]string{countArgName: "2", vmCPUsArgName: test.cpus})
		if err := validateBenchmarkVMResources(c); (err == nil) != test.want {
			t.Fatalf("CPUs %s: %v", test.cpus, err)
		}
	}
}
