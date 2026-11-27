//go:build windows

package uvm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/internal/computecore"
	"github.com/Microsoft/hcsshim/internal/diodecontrol"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcsv2 "github.com/Microsoft/hcsshim/internal/hcs/v2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
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

// protectedSharedApplianceFixture models the appliance options, not an actual
// borrowed handle, HCS create or bootable image.
func protectedSharedApplianceFixture(t *testing.T) *OptionsLCOW {
	t.Helper()
	opts := protectedSharedOptionsFixture(t, false, hcsschema.ProtectedSharedBackingBootstrap)
	hcl := false
	opts.HclEnabled = &hcl
	opts.SecurityPolicyEnabled = true
	opts.UseGuestConnection, opts.ForwardStdout, opts.ForwardStderr = false, false, false
	opts.AllowOvercommit, opts.EnableDeferredCommit = false, false
	opts.PreferredRootFSType, opts.VPMemDeviceCount, opts.SCSIControllerCount = PreferredRootFSTypeNA, 0, 1
	opts.ProcessorCount, opts.MemorySizeInMB = 1, 130
	opts.GuestStateFilePath, opts.ConsolePipe = "guest.vmgs", `\\.\pipe\protected-appliance`
	opts.Appliance = &LCOWApplianceOptions{
		NativeStorageControl: true,
		SCSI: map[string]hcsschema.Scsi{guestrequest.ScsiControllerGuids[0]: {
			Attachments: map[string]hcsschema.Attachment{
				"0": {Type_: "VirtualDisk", Path: `C:\fixture\root.vhd`, ReadOnly: true},
			},
		}},
		NetworkAdapters: map[string]hcsschema.NetworkAdapter{
			"00000000-0000-0000-0000-000000000001": {
				EndpointId: "ca3eebdf-3a4b-41fd-bdec-1a40270f58be", MacAddress: "00-15-5D-02-03-04",
			},
		},
	}
	opts.SiblingCommunicationEndpoints = []hcsschema.SiblingCommunicationEndpoint{{
		GroupID: "f7514ab9-9413-460e-9383-4bed4bcea3c4", Role: hcsschema.SiblingCommunicationEndpointRoleBackend,
		SharedMemorySectionName: opts.SharedMemoryRegions[0].SectionName,
		TargetSINT:              3,
	}}
	return opts
}

// TestProtectedSharedApplianceDocument checks that admissible Bootstrap keeps
// the appliance storage/control/network/console devices and protected settings
// together, without introducing direct guest services or serialized handles.
func TestProtectedSharedApplianceDocument(t *testing.T) {
	ctx := context.Background()
	opts := protectedSharedApplianceFixture(t)
	opts.BootFilesPath, opts.BundleDirectory = t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(opts.BootFilesPath, opts.GuestStateFilePath), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOptions(ctx, opts); err != nil {
		t.Fatal(err)
	}
	vm := &UtilityVM{id: opts.ID, scsiControllerCount: 1}
	doc, err := makeLCOWVMGSBootDoc(ctx, opts, vm, &hcsschema.VirtualMachineProcessor{Count: 1})
	if err != nil {
		t.Fatal(err)
	}
	d := doc.VirtualMachine.Devices
	if d.Plan9 != nil || d.WorkloadVmbusNoRp || d.ComPorts["0"].NamedPipe != opts.ConsolePipe ||
		!reflect.DeepEqual(d.Scsi, opts.Appliance.SCSI) || !reflect.DeepEqual(d.NetworkAdapters, opts.Appliance.NetworkAdapters) ||
		d.SharedMemory == nil || !reflect.DeepEqual(d.SharedMemory.Regions, opts.SharedMemoryRegions) ||
		!reflect.DeepEqual(d.SiblingCommunicationEndpoints, opts.SiblingCommunicationEndpoints) {
		t.Fatalf("unexpected protected VMGS appliance devices: %+v", d)
	}
	sockets := d.HvSocket.HvSocketConfig.ServiceTable
	if _, ok := sockets[winio.VsockServiceID(diodecontrol.Port).String()]; !ok || len(sockets) != 1 {
		t.Fatalf("storage handshake socket missing or unrelated sockets enabled: %v", sockets)
	}
}

// TestProtectedSharedApplianceRejectsMalformedOptions checks that the appliance
// exception grants neither Import nor generic protected mapping or storage.
// The ordinary native appliance must still work without protected settings.
func TestProtectedSharedApplianceRejectsMalformedOptions(t *testing.T) {
	for name, change := range map[string]func(*OptionsLCOW){
		"not-native":       func(o *OptionsLCOW) { o.Appliance.NativeStorageControl = false },
		"not-direct-snp":   func(o *OptionsLCOW) { o.HclEnabled = nil },
		"guest-connection": func(o *OptionsLCOW) { o.UseGuestConnection = true },
		"root-consumer":    func(o *OptionsLCOW) { o.SiblingRoot = true },
		"workload-no-rp":   func(o *OptionsLCOW) { o.WorkloadVmbusNoRp = true },
		"no-root":          func(o *OptionsLCOW) { o.Appliance.SCSI = nil },
		"wrong-vp-count":   func(o *OptionsLCOW) { o.ProcessorCount = 2 },
		"wrong-memory":     func(o *OptionsLCOW) { o.MemorySizeInMB = 128 },
		"missing-uplink":   func(o *OptionsLCOW) { o.Appliance.NetworkAdapters = nil },
		"extra-uplink": func(o *OptionsLCOW) {
			o.Appliance.NetworkAdapters["00000000-0000-0000-0000-000000000002"] =
				o.Appliance.NetworkAdapters["00000000-0000-0000-0000-000000000001"]
		},
		"invalid-uplink-endpoint": func(o *OptionsLCOW) {
			id := "00000000-0000-0000-0000-000000000001"
			adapter := o.Appliance.NetworkAdapters[id]
			adapter.EndpointId = ""
			o.Appliance.NetworkAdapters[id] = adapter
		},
		"invalid-uplink-mac": func(o *OptionsLCOW) {
			id := "00000000-0000-0000-0000-000000000001"
			adapter := o.Appliance.NetworkAdapters[id]
			adapter.MacAddress = "FF-FF-FF-FF-FF-FF"
			o.Appliance.NetworkAdapters[id] = adapter
		},
		"writable-root": func(o *OptionsLCOW) {
			o.Appliance.SCSI[guestrequest.ScsiControllerGuids[0]].Attachments["0"] =
				hcsschema.Attachment{Type_: "VirtualDisk", Path: `C:\fixture\root.vhd`}
		},
		"extra-disk": func(o *OptionsLCOW) {
			r := o.Appliance.SCSI[guestrequest.ScsiControllerGuids[0]].Attachments
			r["1"] = r["0"]
		},
		"import": func(o *OptionsLCOW) {
			o.SharedMemoryRegions[0].ProtectedSharedBackingMode = hcsschema.ProtectedSharedBackingImport
			o.SharedMemoryRegions[0].ProtectedSharedLeaseId = 1
		},
		"wrong-size":         func(o *OptionsLCOW) { o.SharedMemoryRegions[0].Length = 16 << 20 },
		"offset":             func(o *OptionsLCOW) { o.SharedMemoryRegions[0].StartOffset = 4096 },
		"hidden":             func(o *OptionsLCOW) { o.SharedMemoryRegions[0].HiddenFromGuest = true },
		"borrowed-lease":     func(o *OptionsLCOW) { o.SharedMemoryRegions[0].ProtectedSharedLeaseId = 1 },
		"missing-controller": func(o *OptionsLCOW) { o.ProtectedSharedResources = nil },
		"wrong-uri":          func(o *OptionsLCOW) { o.ProtectedSharedResources[0].URI = "unowned" },
		"wrong-type":         func(o *OptionsLCOW) { o.ProtectedSharedResources[0].Type = computecore.HcsResourceTypeJob },
		"invalid-handle":     func(o *OptionsLCOW) { o.ProtectedSharedResources[0].Handle = syscall.InvalidHandle },
		"duplicate-controller": func(o *OptionsLCOW) {
			o.ProtectedSharedResources = append(o.ProtectedSharedResources, o.ProtectedSharedResources[0])
		},
		"no-endpoint":   func(o *OptionsLCOW) { o.SiblingCommunicationEndpoints = nil },
		"bad-group":     func(o *OptionsLCOW) { o.SiblingCommunicationEndpoints[0].GroupID = "group" },
		"wrong-section": func(o *OptionsLCOW) { o.SiblingCommunicationEndpoints[0].SharedMemorySectionName = "unmatched" },
		"workload-role": func(o *OptionsLCOW) {
			o.SiblingCommunicationEndpoints[0].Role = hcsschema.SiblingCommunicationEndpointRoleWorkload
		},
		"mixed-regions": func(o *OptionsLCOW) {
			o.SharedMemoryRegions = append(o.SharedMemoryRegions, LCOWSharedMemoryRegion{SectionName: "ordinary", Length: 4096})
		},
	} {
		opts := protectedSharedApplianceFixture(t)
		change(opts)
		if err := VerifyOptions(context.Background(), opts); err == nil {
			t.Errorf("accepted malformed appliance Bootstrap: %s", name)
		}
	}
	ordinary := protectedSharedApplianceFixture(t)
	ordinary.SharedMemoryRegions, ordinary.ProtectedSharedResources, ordinary.SiblingCommunicationEndpoints = nil, nil, nil
	ordinary.ProcessorCount, ordinary.MemorySizeInMB, ordinary.Appliance.NetworkAdapters = 2, 128, nil
	if err := VerifyOptions(context.Background(), ordinary); err != nil {
		t.Fatalf("ordinary native appliance rejected: %v", err)
	}
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
