//go:build windows

package uvm

import (
	"encoding/json"
	"testing"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

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
