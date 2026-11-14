//go:build windows

package uvm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/internal/diodecontrol"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
)

func TestVMGSApplianceBootDocument(t *testing.T) {
	opts := NewDefaultOptionsLCOW("appliance-test", "")
	opts.BootFilesPath, opts.BundleDirectory = t.TempDir(), t.TempDir()
	opts.GuestStateFilePath = "guest.vmgs"
	opts.PreferredRootFSType, opts.DmVerityMode = PreferredRootFSTypeNA, false
	opts.UseGuestConnection, opts.ForwardStdout, opts.ForwardStderr = false, false, false
	opts.AllowOvercommit, opts.EnableDeferredCommit = false, false
	opts.SecurityPolicyEnabled = true
	hcl := false
	opts.HclEnabled = &hcl
	opts.ConsolePipe = `\\.\pipe\appliance-test`
	opts.ProcessorCount, opts.MemorySizeInMB = 1, 130
	opts.Appliance = &LCOWApplianceOptions{
		SCSI: map[string]hcsschema.Scsi{guestrequest.ScsiControllerGuids[0]: {
			Attachments: map[string]hcsschema.Attachment{"3": {Type_: "VirtualDisk", Path: `C:\fixture\data.vhdx`, ReadOnly: true}},
		}},
		NetworkAdapters: map[string]hcsschema.NetworkAdapter{"nic": {EndpointId: "endpoint"}},
	}
	if err := VerifyOptions(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(opts.BootFilesPath, opts.GuestStateFilePath), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	vm := &UtilityVM{id: opts.ID, scsiControllerCount: 1}
	doc, err := makeLCOWVMGSBootDoc(context.Background(), opts, vm, &hcsschema.VirtualMachineProcessor{Count: 1})
	if err != nil {
		t.Fatal(err)
	}
	devices := doc.VirtualMachine.Devices
	if devices.HvSocket != nil || devices.Plan9 != nil ||
		devices.ComPorts["0"].NamedPipe != opts.ConsolePipe ||
		devices.NetworkAdapters["nic"].EndpointId != "endpoint" ||
		!devices.Scsi[guestrequest.ScsiControllerGuids[0]].Attachments["3"].ReadOnly {
		t.Fatalf("wrong standalone SNP boot document: %+v", doc)
	}
	files, err := os.ReadDir(opts.BundleDirectory)
	if err != nil || len(files) != 1 || files[0].Name() != "guest.vmgs" {
		t.Fatalf("appliance staged Linux rootfs files: %v %v", files, err)
	}
	opts.Appliance.NativeStorageControl, opts.SCSIControllerCount = true, 1
	opts.Appliance.SCSI[guestrequest.ScsiControllerGuids[0]].Attachments["0"] =
		hcsschema.Attachment{Type_: "VirtualDisk", Path: `C:\fixture\root.vhd`, ReadOnly: true}
	if err := VerifyOptions(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	nativeDoc, err := makeLCOWVMGSBootDoc(context.Background(), opts, vm,
		&hcsschema.VirtualMachineProcessor{Count: 1})
	if err != nil {
		t.Fatal(err)
	}
	sockets := nativeDoc.VirtualMachine.Devices.HvSocket.HvSocketConfig.ServiceTable
	if _, ok := sockets[winio.VsockServiceID(diodecontrol.Port).String()]; !ok || len(sockets) != 1 {
		t.Fatalf("appliance enabled unrelated Linux/GCS services: %v", sockets)
	}
	slots, err := applianceStorageSlots(opts.Appliance)
	if err != nil || len(slots) != 2 || slots[0].LUN != 0 || slots[1].LUN != 3 {
		t.Fatalf("boot attachment reservations: %v, %v", slots, err)
	}
	if err := verifyApplianceExports(opts.Appliance,
		[]diodecontrol.Export{{LUN: 0, RootLUN: 0, Flags: diodecontrol.Boot | diodecontrol.ReadOnly}}); err != nil {
		t.Fatal(err)
	}
	if err := verifyApplianceExports(opts.Appliance,
		[]diodecontrol.Export{{LUN: 0, RootLUN: 3, Flags: diodecontrol.Boot | diodecontrol.ReadOnly}}); err == nil {
		t.Fatal("accepted a root export using a different boot backing")
	}
	opts.UseGuestConnection = true
	if err := VerifyOptions(context.Background(), opts); err == nil {
		t.Fatal("accepted GCS in appliance mode")
	}
	opts.UseGuestConnection, opts.KernelBootOptions = false, "ignored arguments"
	if err := VerifyOptions(context.Background(), opts); err == nil {
		t.Fatal("accepted ignored runtime VMGS command line")
	}
}

func TestApplianceStorageRejectsAmbiguousBootSlots(t *testing.T) {
	for _, invalid := range []string{"00", "64", "255", "not-a-lun"} {
		t.Run(invalid, func(t *testing.T) {
			opts := &LCOWApplianceOptions{SCSI: map[string]hcsschema.Scsi{
				guestrequest.ScsiControllerGuids[0]: {Attachments: map[string]hcsschema.Attachment{
					"0":     {Type_: "VirtualDisk", Path: "root.vhd", ReadOnly: true},
					invalid: {Type_: "VirtualDisk", Path: "extra.vhd", ReadOnly: true},
				}},
			}}
			if _, err := applianceStorageSlots(opts); err == nil {
				t.Fatal("accepted an ambiguous/out-of-range boot slot")
			}
		})
	}
}

// TestVMGSSiblingRootOmitsOnlyWorkloadRPAttachment keeps diode Bootstrap roots
// direct/read-only and sibling roots mediated. Only the protected workload omits
// RP controllers; its logical capacity remains available for sibling storage.
// Document fixtures dispatch no model capability and allocate no VM.
func TestVMGSSiblingRootOmitsOnlyWorkloadRPAttachment(t *testing.T) {
	for _, test := range []struct {
		name        string
		siblingRoot bool
		protected   bool
	}{
		{"ordinary", false, false}, {"sibling", true, false},
		{"protected-diode", false, true}, {"protected-workload", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Compare only document routing after validating the role's option
			// shape; no native receipt or capability is fabricated by dispatch.
			siblingRoot := test.siblingRoot
			opts := NewDefaultOptionsLCOW(t.Name(), "")
			if test.protected {
				mode := hcsschema.ProtectedSharedBackingBootstrap
				if siblingRoot {
					mode = hcsschema.ProtectedSharedBackingImport
				}
				opts = protectedSharedOptionsFixture(t, siblingRoot, mode)
			}
			opts.PreferredRootFSType, opts.DmVerityMode = PreferredRootFSTypeNA, true
			opts.SiblingRoot = siblingRoot
			if err := VerifyOptions(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			vm := &UtilityVM{id: t.Name(), scsiControllerCount: 1}
			doc := &hcsschema.ComputeSystem{VirtualMachine: &hcsschema.VirtualMachine{
				Devices: &hcsschema.Devices{},
			}}
			applyLCOWVMGSStorage(doc, opts, vm, `C:\fixture\rootfs.vhd`)
			applyLCOWSharedMemory(doc, opts.SharedMemoryRegions)
			if test.protected && (doc.VirtualMachine.Devices.SharedMemory == nil ||
				doc.VirtualMachine.Devices.SharedMemory.Regions[0] != opts.SharedMemoryRegions[0]) {
				t.Fatal("document lost the protected startup region")
			}
			wantControllers := 1
			if test.protected && siblingRoot {
				wantControllers = 0
			}
			if len(doc.VirtualMachine.Devices.Scsi) != wantControllers || vm.scsiControllerCount != 1 {
				t.Fatalf("RP controllers=%d, want %d; logical capacity=%d, want 1",
					len(doc.VirtualMachine.Devices.Scsi), wantControllers, vm.scsiControllerCount)
			}
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
