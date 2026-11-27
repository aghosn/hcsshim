//go:build windows

package uvm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/computecore"
	"github.com/Microsoft/hcsshim/internal/diodecontrol"
	"github.com/Microsoft/hcsshim/internal/gcs/prot"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
)

// workloadVmbusNoRpOptionsFixture models the final Import workload after pair
// acquisition. Its borrowed handle is shape-only: no capability is dispatched
// and it proves neither authorization nor the measured VMGS contents.
func workloadVmbusNoRpOptionsFixture(t *testing.T) *OptionsLCOW {
	t.Helper()
	opts := protectedSharedOptionsFixture(t, true, hcsschema.ProtectedSharedBackingImport)
	opts.WorkloadVmbusNoRp = true
	opts.SecurityPolicyEnabled, opts.DmVerityMode = true, true
	opts.PreferredRootFSType, opts.VPMemDeviceCount = PreferredRootFSTypeNA, 0
	opts.AllowOvercommit, opts.EnableDeferredCommit = false, false
	hcl := false
	opts.HclEnabled = &hcl
	relay, err := guid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	opts.TimesyncRelayID = &relay
	opts.GuestStateFilePath, opts.DmVerityRootFsVhd = "fixture.vmgs", "fixture.vhd"
	opts.BootFilesPath, opts.BundleDirectory = t.TempDir(), t.TempDir()
	opts.SiblingCommunicationEndpoints = []hcsschema.SiblingCommunicationEndpoint{{
		GroupID: "fixture-group", Role: hcsschema.SiblingCommunicationEndpointRoleWorkload,
		SharedMemorySectionName: opts.SharedMemoryRegions[0].SectionName,
	}}
	return opts
}

// TestWorkloadVmbusNoRpDocument serializes the production VMGS document to prove
// exact schema-2.5 selection/omission, preserving sockets, relay and protected
// sibling configuration. Temporary boot bytes are not real executable images.
func TestWorkloadVmbusNoRpDocument(t *testing.T) {
	for _, mode := range []string{"selected", "rollback", "diode", "ordinary"} {
		t.Run(mode, func(t *testing.T) {
			opts := workloadVmbusNoRpOptionsFixture(t)
			opts.WorkloadVmbusNoRp = mode == "selected"
			switch mode {
			case "diode":
				opts.SiblingRoot, opts.TimesyncRelayID = false, nil
				opts.SiblingCommunicationEndpoints[0].Role = hcsschema.SiblingCommunicationEndpointRoleBackend
				opts.SharedMemoryRegions[0].ProtectedSharedBackingMode = hcsschema.ProtectedSharedBackingBootstrap
				opts.SharedMemoryRegions[0].ProtectedSharedLeaseId = 0
			case "ordinary":
				opts.SiblingRoot, opts.TimesyncRelayID = false, nil
				opts.SharedMemoryRegions, opts.ProtectedSharedResources, opts.SiblingCommunicationEndpoints = nil, nil, nil
			}
			for _, name := range []string{opts.GuestStateFilePath, opts.DmVerityRootFsVhd} {
				if err := os.WriteFile(filepath.Join(opts.BootFilesPath, name), []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			vm := &UtilityVM{id: opts.ID, scsiControllerCount: 1}
			doc, err := makeLCOWVMGSBootDoc(context.Background(), opts, vm, &hcsschema.VirtualMachineProcessor{Count: 1})
			if err != nil {
				t.Fatal(err)
			}
			applyLCOWSharedMemory(doc, opts.SharedMemoryRegions)
			applyLCOWSiblingCommunication(doc, opts.SiblingCommunicationEndpoints)
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				SchemaVersion  struct{ Major, Minor int }
				VirtualMachine struct{ Devices map[string]json.RawMessage }
			}
			if err := json.Unmarshal(data, &wire); err != nil {
				t.Fatal(err)
			}
			bit, present := wire.VirtualMachine.Devices["WorkloadVmbusNoRp"]
			wantCount := 0
			if opts.WorkloadVmbusNoRp {
				wantCount = 1
			}
			if present != opts.WorkloadVmbusNoRp || (present && string(bit) != "true") ||
				strings.Count(string(data), `"WorkloadVmbusNoRp"`) != wantCount ||
				wire.SchemaVersion.Major != 2 || wire.SchemaVersion.Minor != 5 {
				t.Fatalf("wrong native bit or schema: %s", data)
			}
			if _, present := wire.VirtualMachine.Devices["VMBus"]; present {
				t.Fatal("introduced public schema-2.7 VMBus object")
			}
			devices := doc.VirtualMachine.Devices
			for _, port := range []uint32{vmutils.LinuxEntropyVsockPort, vmutils.LinuxLogVsockPort, prot.LinuxGcsVsockPort, prot.LinuxGcsVsockPort + 1} {
				if _, ok := devices.HvSocket.HvSocketConfig.ServiceTable[winio.VsockServiceID(port).String()]; !ok {
					t.Fatalf("lost existing socket %d", port)
				}
			}
			if devices.Plan9 == nil || !reflect.DeepEqual(devices.SiblingCommunicationEndpoints, opts.SiblingCommunicationEndpoints) {
				t.Fatal("changed existing Plan9/sibling configuration")
			}
			if len(opts.SharedMemoryRegions) != 0 && !reflect.DeepEqual(devices.SharedMemory.Regions, opts.SharedMemoryRegions) {
				t.Fatal("changed protected region configuration")
			}
			if opts.TimesyncRelayID != nil &&
				doc.VirtualMachine.Services.Timesync.RelayId != strings.ToLower(opts.TimesyncRelayID.String()) {
				t.Fatal("changed timesync relay selection")
			}
		})
	}
}

// TestWorkloadVmbusNoRpRejectsMalformed checks final selected shape/association
// before any native creation or boot-file copy, including direct boot-doc calls.
// Generic VerifyOptions must not become a post-acquisition-only entrypoint.
func TestWorkloadVmbusNoRpRejectsMalformed(t *testing.T) {
	for name, change := range map[string]func(*OptionsLCOW){
		"no-common":       func(o *OptionsLCOW) { o.Options = nil },
		"no-confidential": func(o *OptionsLCOW) { o.ConfidentialLCOWOptions = nil },
		"no-security":     func(o *OptionsLCOW) { o.ConfidentialCommonOptions = nil },
		"ordinary":        func(o *OptionsLCOW) { o.GuestStateFilePath = "" },
		"not-snp":         func(o *OptionsLCOW) { o.SecurityPolicyEnabled = false },
		"not-verity":      func(o *OptionsLCOW) { o.DmVerityMode = false },
		"direct-root":     func(o *OptionsLCOW) { o.SiblingRoot = false },
		"no-gcs":          func(o *OptionsLCOW) { o.UseGuestConnection = false },
		"appliance":       func(o *OptionsLCOW) { o.Appliance = &LCOWApplianceOptions{} },
		"hcl-default":     func(o *OptionsLCOW) { o.HclEnabled = nil },
		"hcl-enabled":     func(o *OptionsLCOW) { *o.HclEnabled = true },
		"no-relay":        func(o *OptionsLCOW) { o.TimesyncRelayID = nil },
		"zero-relay":      func(o *OptionsLCOW) { *o.TimesyncRelayID = guid.GUID{} },
		"time-disabled":   func(o *OptionsLCOW) { o.DisableTimeSyncService = true },
		"overcommit":      func(o *OptionsLCOW) { o.AllowOvercommit = true },
		"deferred":        func(o *OptionsLCOW) { o.EnableDeferredCommit = true },
		"root-type":       func(o *OptionsLCOW) { o.PreferredRootFSType = PreferredRootFSTypeVHD },
		"no-scsi":         func(o *OptionsLCOW) { o.SCSIControllerCount = 0 },
		"assigned":        func(o *OptionsLCOW) { o.AssignedDevices = []VPCIDeviceID{{}} },
		"no-endpoint":     func(o *OptionsLCOW) { o.SiblingCommunicationEndpoints = nil },
		"extra-endpoint": func(o *OptionsLCOW) {
			o.SiblingCommunicationEndpoints = append(o.SiblingCommunicationEndpoints, o.SiblingCommunicationEndpoints[0])
		},
		"backend": func(o *OptionsLCOW) {
			o.SiblingCommunicationEndpoints[0].Role = hcsschema.SiblingCommunicationEndpointRoleBackend
		},
		"empty-group":      func(o *OptionsLCOW) { o.SiblingCommunicationEndpoints[0].GroupID = "" },
		"section-mismatch": func(o *OptionsLCOW) { o.SiblingCommunicationEndpoints[0].SharedMemorySectionName = "other" },
		"empty-section":    func(o *OptionsLCOW) { o.SiblingCommunicationEndpoints[0].SharedMemorySectionName = "" },
		"no-region":        func(o *OptionsLCOW) { o.SharedMemoryRegions = nil },
		"extra-region":     func(o *OptionsLCOW) { o.SharedMemoryRegions = append(o.SharedMemoryRegions, o.SharedMemoryRegions[0]) },
		"ordinary-region":  func(o *OptionsLCOW) { o.SharedMemoryRegions[0].ProtectedShared = false },
		"hidden":           func(o *OptionsLCOW) { o.SharedMemoryRegions[0].HiddenFromGuest = true },
		"bootstrap": func(o *OptionsLCOW) {
			o.SharedMemoryRegions[0].ProtectedSharedBackingMode = hcsschema.ProtectedSharedBackingBootstrap
		},
		"no-lease":       func(o *OptionsLCOW) { o.SharedMemoryRegions[0].ProtectedSharedLeaseId = 0 },
		"unaligned":      func(o *OptionsLCOW) { o.SharedMemoryRegions[0].StartOffset = 1 },
		"no-resource":    func(o *OptionsLCOW) { o.ProtectedSharedResources = nil },
		"wrong-uri":      func(o *OptionsLCOW) { o.ProtectedSharedResources[0].URI = "other" },
		"wrong-type":     func(o *OptionsLCOW) { o.ProtectedSharedResources[0].Type = computecore.HcsResourceTypeJob },
		"zero-handle":    func(o *OptionsLCOW) { o.ProtectedSharedResources[0].Handle = 0 },
		"invalid-handle": func(o *OptionsLCOW) { o.ProtectedSharedResources[0].Handle = syscall.InvalidHandle },
		"extra-resource": func(o *OptionsLCOW) {
			o.ProtectedSharedResources = append(o.ProtectedSharedResources, o.ProtectedSharedResources[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			opts := workloadVmbusNoRpOptionsFixture(t)
			bundle := opts.BundleDirectory
			change(opts)
			if _, err := CreateLCOW(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "WorkloadVmbusNoRp") {
				t.Fatalf("CreateLCOW did not reject selected shape: %v", err)
			}
			if _, err := makeLCOWVMGSBootDoc(context.Background(), opts, nil, nil); err == nil || !strings.Contains(err.Error(), "WorkloadVmbusNoRp") {
				t.Fatalf("boot doc did not reject before file copies: %v", err)
			}
			files, err := os.ReadDir(bundle)
			if err != nil || len(files) != 0 {
				t.Fatalf("invalid request wrote boot files: %v %v", files, err)
			}
		})
	}
	opts := workloadVmbusNoRpOptionsFixture(t)
	if _, err := MakeLCOWDoc(context.Background(), opts, nil); err == nil || !strings.Contains(err.Error(), "WorkloadVmbusNoRp") {
		t.Fatalf("ordinary document accepted native selection: %v", err)
	}
}

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
