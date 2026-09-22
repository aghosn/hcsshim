//go:build windows

package uvm

import (
	"testing"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

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
