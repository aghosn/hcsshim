//go:build windows

package uvm

import (
	"encoding/json"
	"syscall"
	"testing"

	"github.com/Microsoft/hcsshim/internal/computecore"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcsv2 "github.com/Microsoft/hcsshim/internal/hcs/v2"
)

// protectedSharedOptionsFixture supplies one Bootstrap or Import option shape.
// The handle and lease are model values only: these tests never dispatch them
// and cannot establish native capability authority or backing initialization.
func protectedSharedOptionsFixture(t *testing.T, siblingRoot bool, mode hcsschema.ProtectedSharedBackingMode) *OptionsLCOW {
	t.Helper()
	opts := NewDefaultOptionsLCOW(t.Name(), "")
	opts.SiblingRoot = siblingRoot
	opts.SharedMemoryRegions = []LCOWSharedMemoryRegion{{
		SectionName: "protected-shape", Length: 32 << 20, AllowGuestWrite: true,
		ProtectedShared: true, ProtectedSharedControllerUri: "controller-shape",
		ProtectedSharedBackingMode: mode,
	}}
	if mode == hcsschema.ProtectedSharedBackingImport {
		opts.SharedMemoryRegions[0].ProtectedSharedLeaseId = 7
	}
	opts.ProtectedSharedResources = []hcsv2.OperationResource{{
		Type: computecore.HcsResourceTypeFile, URI: "controller-shape", Handle: syscall.Handle(1),
	}}
	return opts
}

// TestProtectedSharedSiblingRootOptions admits only the single Import workload
// shape while keeping Bootstrap direct-root and ordinary sibling roots valid.
// It protects routing without claiming that model handles authorize native work.
func TestProtectedSharedSiblingRootOptions(t *testing.T) {
	for _, mode := range []hcsschema.ProtectedSharedBackingMode{hcsschema.ProtectedSharedBackingBootstrap, hcsschema.ProtectedSharedBackingImport} {
		for _, siblingRoot := range []bool{false, true} {
			opts := protectedSharedOptionsFixture(t, siblingRoot, mode)
			err := validateProtectedSharedOptions(opts)
			wantError := siblingRoot && mode == hcsschema.ProtectedSharedBackingBootstrap
			if (err != nil) != wantError {
				t.Fatalf("mode=%s sibling-root=%t: %v, want failure=%t", mode, siblingRoot, err, wantError)
			}
		}
	}
	ordinary := NewDefaultOptionsLCOW(t.Name(), "")
	ordinary.SiblingRoot = true
	ordinary.SharedMemoryRegions = []LCOWSharedMemoryRegion{{SectionName: "ordinary", Length: 4096}}
	if err := validateProtectedSharedOptions(ordinary); err != nil {
		t.Fatalf("ordinary sibling root changed: %v", err)
	}
}

// TestProtectedSharedSiblingRootRejectsMalformedOptions checks capability,
// lease, role and region-shape failures on Import. The narrow root extension
// must not admit mixed backing, hidden regions, appliances or private fields.
func TestProtectedSharedSiblingRootRejectsMalformedOptions(t *testing.T) {
	for _, name := range []string{
		"missing-resource", "wrong-uri", "wrong-type", "zero-handle", "invalid-handle",
		"duplicate-resource", "extra-resource", "missing-lease", "bootstrap-lease",
		"missing-mode", "hidden", "appliance", "ordinary-mix", "protected-mix",
		"startup-action", "lifetime", "page-index", "page-count", "ordinary-private",
	} {
		opts := protectedSharedOptionsFixture(t, true, hcsschema.ProtectedSharedBackingImport)
		region := &opts.SharedMemoryRegions[0]
		switch name {
		case "missing-resource":
			opts.ProtectedSharedResources = nil
		case "wrong-uri":
			opts.ProtectedSharedResources[0].URI = "other-controller"
		case "wrong-type":
			opts.ProtectedSharedResources[0].Type = computecore.HcsResourceTypeJob
		case "zero-handle":
			opts.ProtectedSharedResources[0].Handle = 0
		case "invalid-handle":
			opts.ProtectedSharedResources[0].Handle = syscall.InvalidHandle
		case "duplicate-resource":
			opts.ProtectedSharedResources = append(opts.ProtectedSharedResources, opts.ProtectedSharedResources[0])
		case "extra-resource":
			extra := opts.ProtectedSharedResources[0]
			extra.URI = "unselected-controller"
			opts.ProtectedSharedResources = append(opts.ProtectedSharedResources, extra)
		case "missing-lease":
			region.ProtectedSharedLeaseId = 0
		case "bootstrap-lease":
			opts.SiblingRoot = false
			region.ProtectedSharedBackingMode = hcsschema.ProtectedSharedBackingBootstrap
		case "missing-mode":
			region.ProtectedSharedBackingMode = ""
		case "hidden":
			region.HiddenFromGuest = true
		case "appliance":
			opts.Appliance = &LCOWApplianceOptions{}
		case "ordinary-mix":
			opts.SharedMemoryRegions = append(opts.SharedMemoryRegions, LCOWSharedMemoryRegion{SectionName: "ordinary", Length: 4096})
		case "protected-mix":
			extra := *region
			extra.SectionName = "second-protected"
			opts.SharedMemoryRegions = append(opts.SharedMemoryRegions, extra)
		case "startup-action":
			region.ProtectedSharedOperation = hcsschema.ProtectedSharedSeal
		case "lifetime":
			region.ProtectedSharedLifetimeId = 1
		case "page-index":
			region.ProtectedSharedPageIndex = 1
		case "page-count":
			region.ProtectedSharedPageCount = 1
		case "ordinary-private":
			region.ProtectedShared = false
			opts.ProtectedSharedResources = nil
		}
		if err := validateProtectedSharedOptions(opts); err == nil {
			t.Fatalf("accepted malformed Import options: %s", name)
		}
	}
}

func TestParseSharedMemoryRegionResponse(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{
			name: "array",
			response: `[{"SectionName":"section",` +
				`"GuestPhysicalAddress":131072}]`,
		},
		{
			name: "shared memory region info wrapper",
			response: `{"SharedMemoryRegionInfo":[` +
				`{"SectionName":"section",` +
				`"GuestPhysicalAddress":131072}]}`,
		},
		{
			name: "regions wrapper",
			response: `{"Regions":[{"SectionName":"section",` +
				`"GuestPhysicalAddress":131072}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regions, err := parseSharedMemoryRegionResponse(
				json.RawMessage(tt.response),
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(regions) != 1 {
				t.Fatalf("got %d regions, want 1", len(regions))
			}
			if regions[0].SectionName != "section" ||
				regions[0].GuestPhysicalAddress != 131072 {
				t.Fatalf("unexpected region: %+v", regions[0])
			}
		})
	}
}

func TestParseSharedMemoryRegionResponseEmpty(t *testing.T) {
	if _, err := parseSharedMemoryRegionResponse(
		json.RawMessage(`{"Regions":[]}`),
	); err == nil {
		t.Fatal("expected empty response error")
	}
}

func TestApplyLCOWSharedMemory(t *testing.T) {
	doc := &hcsschema.ComputeSystem{
		VirtualMachine: &hcsschema.VirtualMachine{},
	}
	regions := []hcsschema.SharedMemoryRegion{
		{
			SectionName:     `\Sessions\3\BaseNamedObjects\hcsshim-test`,
			Length:          4096,
			AllowGuestWrite: true,
		},
	}

	applyLCOWSharedMemory(doc, regions)

	if doc.VirtualMachine.Devices == nil {
		t.Fatal("expected devices configuration")
	}
	if doc.VirtualMachine.Devices.SharedMemory == nil {
		t.Fatal("expected shared-memory configuration")
	}
	got := doc.VirtualMachine.Devices.SharedMemory.Regions
	if len(got) != 1 {
		t.Fatalf("got %d shared-memory regions, want 1", len(got))
	}
	if got[0] != regions[0] {
		t.Fatalf("got shared-memory region %+v, want %+v", got[0], regions[0])
	}

	regions[0].SectionName = `\Sessions\3\BaseNamedObjects\changed`
	if got[0].SectionName == regions[0].SectionName {
		t.Fatal("shared-memory regions were not copied")
	}
}

func TestApplyLCOWSharedMemoryEmpty(t *testing.T) {
	doc := &hcsschema.ComputeSystem{
		VirtualMachine: &hcsschema.VirtualMachine{
			Devices: &hcsschema.Devices{},
		},
	}

	applyLCOWSharedMemory(doc, nil)

	if doc.VirtualMachine.Devices.SharedMemory != nil {
		t.Fatal("unexpected shared-memory configuration")
	}
}
