//go:build windows

package uvm

import (
	"context"
	"strings"
	"testing"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
)

func TestVMGSSiblingRootOmitsOnlyWorkloadRPAttachment(t *testing.T) {
	for _, siblingRoot := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "sibling"}[siblingRoot], func(t *testing.T) {
			opts := NewDefaultOptionsLCOW(t.Name(), "")
			opts.PreferredRootFSType, opts.DmVerityMode = PreferredRootFSTypeNA, true
			opts.SiblingRoot = siblingRoot
			vm := &UtilityVM{id: t.Name(), scsiControllerCount: 1}
			doc := &hcsschema.ComputeSystem{VirtualMachine: &hcsschema.VirtualMachine{
				Devices: &hcsschema.Devices{},
			}}
			applyLCOWVMGSStorage(doc, opts, vm, `C:\fixture\rootfs.vhd`)
			controller := doc.VirtualMachine.Devices.Scsi[guestrequest.ScsiControllerGuids[0]]
			attachment, attached := controller.Attachments["0"]
			if attached == siblingRoot || (attached && !attachment.ReadOnly) {
				t.Fatalf("RP root attachment=%v, read-only=%v, sibling=%v", attached, attachment.ReadOnly, siblingRoot)
			}
			if siblingRoot && (len(controller.Attachments) != 0 || len(vm.reservedSCSISlots) != 0) {
				t.Fatal("sibling root retained direct RP storage or a reserved root slot")
			}
			if attached && attachment.Path != `C:\fixture\rootfs.vhd` {
				t.Fatal("changed the ordinary root image")
			}
		})
	}
}

// Unit tests for negative testing of input to uvm.Create()

func TestCreateBadBootFilesPath(t *testing.T) {
	ctx := context.Background()
	opts := NewDefaultOptionsLCOW(t.Name(), "")
	opts.UpdateBootFilesPath(ctx, `c:\does\not\exist\I\hope`)

	_, err := CreateLCOW(ctx, opts)
	if err == nil || err.Error() != `kernel: 'c:\does\not\exist\I\hope\kernel' not found` {
		t.Fatal(err)
	}
}

func TestConfidentialVMGSFileName(t *testing.T) {
	for _, tc := range []struct {
		isolationType string
		want          string
	}{
		{"SecureNestedPaging", "cwcow.snp.vmgs"},
		{"VirtualizationBasedSecurity", "cwcow.vbs.vmgs"},
		{"GuestStateOnly", "cwcow.gso.vmgs"},
		{"", "cwcow.snp.vmgs"},              // unknown defaults to SNP
		{"SomethingElse", "cwcow.snp.vmgs"}, // unknown defaults to SNP
	} {
		if got := ConfidentialVMGSFileName(tc.isolationType); got != tc.want {
			t.Errorf("ConfidentialVMGSFileName(%q) = %q, want %q", tc.isolationType, got, tc.want)
		}
	}
}

func TestVerifyLCOWSharedMemoryRegions(t *testing.T) {
	tests := []struct {
		name   string
		region LCOWSharedMemoryRegion
		want   string
	}{
		{
			name:   "empty section name",
			region: LCOWSharedMemoryRegion{Length: 4096},
			want:   "empty section name",
		},
		{
			name: "negative offset",
			region: LCOWSharedMemoryRegion{
				SectionName: `\Sessions\3\BaseNamedObjects\test`,
				StartOffset: -4096,
				Length:      4096,
			},
			want: "negative start offset",
		},
		{
			name: "zero length",
			region: LCOWSharedMemoryRegion{
				SectionName: `\Sessions\3\BaseNamedObjects\test`,
			},
			want: "length must be greater than zero",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := NewDefaultOptionsLCOW(t.Name(), "")
			opts.SharedMemoryRegions = []LCOWSharedMemoryRegion{tc.region}

			err := VerifyOptions(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyOptions() error = %v, want error containing %q", err, tc.want)
			}
		})
	}
}
