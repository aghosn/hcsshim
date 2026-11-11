//go:build windows

package sibling

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/internal/uvm"
)

func testStandaloneConfig() *Config {
	return &Config{Version: 1, Standalone: true, VMResources: []VMResources{
		{ProcessorCount: 8, MemoryMB: 65536},
	}}
}

func TestStandaloneConfigAndDirectBootOptions(t *testing.T) {
	for _, vmgs := range []string{"", "direct-root.vmgs"} {
		config := testStandaloneConfig()
		config.WorkloadGuestStateFile = vmgs
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeConfig(strings.NewReader(string(data)))
		if err != nil || !reflect.DeepEqual(decoded, config) {
			t.Fatalf("standalone config rejected: %+v %v", decoded, err)
		}
		base := testOptions()
		base.CPUGroupID = "inherited"
		options, err := standaloneOptions(base, decoded)
		if err != nil {
			t.Fatal(err)
		}
		expected := *base
		common := *base.Options
		common.ProcessorCount, common.MemorySizeInMB = 8, 65536
		expected.Options = &common
		confidential := *base.ConfidentialLCOWOptions
		security := *base.ConfidentialCommonOptions
		expected.ConfidentialLCOWOptions = &confidential
		expected.ConfidentialCommonOptions = &security
		if vmgs != "" {
			expected.GuestStateFilePath = vmgs
		}
		actual := *options
		actual.OutputHandlerCreator, expected.OutputHandlerCreator = nil, nil
		if !reflect.DeepEqual(&actual, &expected) {
			t.Fatalf("standalone altered direct boot, devices or security: %+v", options)
		}
		if options.SiblingRoot || len(options.SharedMemoryRegions) != 0 ||
			len(options.SiblingCommunicationEndpoints) != 0 || options.Appliance != nil {
			t.Fatal("standalone inherited sibling/provider setup")
		}
		options.ProcessorCount = 16
		options.SecurityPolicy = "changed"
		if base.ProcessorCount == 16 || base.SecurityPolicy != "existing-policy" {
			t.Fatal("standalone aliased base option structures")
		}
		if _, _, err := pairOptions(base, config, "group", &Section{}); err == nil {
			t.Fatal("standalone accepted pair option creation")
		}
	}
}

func TestStandaloneRejectsPairConfigurationBeforeAllocation(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.VMResources = nil },
		func(c *Config) { c.VMResources = []VMResources{} },
		func(c *Config) { c.VMResources = testResources() },
		func(c *Config) { c.VMResources[0].ProcessorCount = 0 },
		func(c *Config) { c.ModuleDirectory = `C:\modules` },
		func(c *Config) { c.SharedMemoryBytes = 32 << 20 },
		func(c *Config) { c.MediateGCS = true },
		func(c *Config) { c.UnikraftPackage = `C:\unikraft` },
		func(c *Config) { c.WorkloadGuestStateFile = `..\kernel.vmgs` },
	} {
		config := testStandaloneConfig()
		change(config)
		if _, err := Start(context.Background(), testOptions(), config); err == nil {
			t.Fatalf("invalid standalone config reached allocation: %+v", config)
		}
	}
}

func TestStandaloneRejectsNonDirectBootOptions(t *testing.T) {
	for _, change := range []func(*uvm.OptionsLCOW){
		func(o *uvm.OptionsLCOW) { o.UseGuestConnection = false },
		func(o *uvm.OptionsLCOW) { o.SecurityPolicyEnabled = false },
		func(o *uvm.OptionsLCOW) { o.DmVerityMode = false },
		func(o *uvm.OptionsLCOW) { o.GuestStateFilePath = "" },
		func(o *uvm.OptionsLCOW) { o.DmVerityRootFsVhd = "" },
		func(o *uvm.OptionsLCOW) { o.SCSIControllerCount = 0 },
		func(o *uvm.OptionsLCOW) { o.SiblingRoot = true },
		func(o *uvm.OptionsLCOW) { o.Appliance = &uvm.LCOWApplianceOptions{} },
		func(o *uvm.OptionsLCOW) { o.BundleDirectory = "relative" },
		func(o *uvm.OptionsLCOW) {
			o.SharedMemoryRegions = []uvm.LCOWSharedMemoryRegion{{SectionName: "another-owner"}}
		},
	} {
		base := testOptions()
		change(base)
		if _, err := standaloneOptions(base, testStandaloneConfig()); err == nil {
			t.Fatalf("non-direct boot accepted: %+v", base)
		}
	}
}

func TestStandaloneResourcesAndCleanup(t *testing.T) {
	var events []string
	ops, created := fakeResourceCPUGroupOperations(&events)
	config := testStandaloneConfig()
	config.VMResources[0].CPUGroupLPs = []uint32{24, 8, 25, 9, 26, 10}
	options, err := standaloneOptions(testOptions(), config)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := prepareResourceCPUGroups(context.Background(), config, []*uvm.OptionsLCOW{options}, ops)
	if err != nil || len(created) != 1 || options.CPUGroupID != groups.IDs[0] {
		t.Fatalf("standalone arbitrary LP pool assignment failed: %+v %v", groups, err)
	}
	pair := &Pair{
		Workload: new(uvm.UtilityVM), cpuGroups: groups,
		done:           make(chan struct{}),
		workloadCloser: closeFunc(func() error { events = append(events, "workload"); return nil }),
	}
	guests := pairShellGuests(pair)
	if len(guests) != 1 || guests[0].name != "workload" || guests[0].vm != pair.Workload ||
		pair.Diode != nil || pair.section != nil {
		t.Fatal("standalone exposes or owns a diode")
	}
	events = nil
	for range 2 {
		if err := pair.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if len(created) != 0 || len(events) != 2 || events[0] != "workload" || !strings.HasPrefix(events[1], "delete:") {
		t.Fatalf("standalone cleanup was not consumer-before-group and idempotent: %v", events)
	}
	select {
	case <-pair.done:
	default:
		t.Fatal("standalone lifetime notification remained open")
	}
}
