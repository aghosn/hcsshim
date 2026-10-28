//go:build windows

package uvm

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
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

// protectedSharedPartitionFixture returns independent synthetic owned-region
// configuration and successful v1/v2 property receipts. No VM/resources are
// acquired; callers may mutate their copies to test fail-closed validation.
func protectedSharedPartitionFixture() (hcsschema.SharedMemoryRegion, hcsschema.SharedMemoryRegionInfo) {
	region := hcsschema.SharedMemoryRegion{
		SectionName: "partition-section", Length: 4096, HiddenFromGuest: false,
		AllowGuestWrite: true, ProtectedShared: true, ProtectedSharedControllerUri: "controller",
		ProtectedSharedLeaseId: 7, ProtectedSharedOperation: hcsschema.ProtectedSharedSealPartition,
	}
	info := hcsschema.SharedMemoryRegionInfo{
		SectionName: region.SectionName, GuestPhysicalAddress: 131072,
		ProtectedShared: &hcsschema.ProtectedSharedRegionInfo{
			Version: 2, Prepared: true, Installed: true, LeaseId: 7, PageCount: 1,
			InitializedPages: 1,
		},
		ProtectedSharedPartition: &hcsschema.ProtectedSharedPartitionInfo{
			Version: 1, Operation: hcsschema.ProtectedSharedSealPartition,
			HypervisorPartitionId: 42, PartitionIdValid: true, SealCompleted: true,
		},
	}
	return region, info
}

// protectedSharedPartitionJSON wraps a caller-supplied receipt JSON using each
// existing array/legacy response shape. It leaves ordinary unknown fields intact
// to protect backward compatibility; it performs no decoding or native work.
func protectedSharedPartitionJSON(receipt, shape string) string {
	field := ""
	if receipt != "" {
		field = `,"ProtectedSharedPartition":` + receipt
	}
	array := `[{"SectionName":"partition-section","GuestPhysicalAddress":131072,"OrdinaryFutureField":true` + field + `}]`
	if shape == "array" {
		return array
	}
	return `{"` + shape + `":` + array + `}`
}

// TestProtectedSharedPartitionDecodeCompatibility exercises valid and absent
// optional siblings through all array/wrapper shapes. Ordinary fields and absent
// partition receipts must retain legacy behavior rather than require opt-in.
func TestProtectedSharedPartitionDecodeCompatibility(t *testing.T) {
	_, info := protectedSharedPartitionFixture()
	encoded, err := json.Marshal(info.ProtectedSharedPartition)
	if err != nil {
		t.Fatal(err)
	}
	for _, shape := range []string{"array", "SharedMemoryRegionInfo", "Regions"} {
		for _, receipt := range []string{"", string(encoded)} {
			regions, err := parseSharedMemoryRegionResponse(json.RawMessage(protectedSharedPartitionJSON(receipt, shape)))
			if err != nil || len(regions) != 1 {
				t.Fatalf("%s: valid/absent sibling rejected: %v", shape, err)
			}
			if regions[0].SectionName != info.SectionName || regions[0].GuestPhysicalAddress != info.GuestPhysicalAddress ||
				(regions[0].ProtectedSharedPartition == nil) != (receipt == "") {
				t.Fatalf("%s: ordinary fields or optional sibling changed", shape)
			}
		}
	}
}

// TestProtectedSharedPartitionDecodeStrict requires each exact nonnull field,
// rejects malformed/unknown/overflow/version frames in every legacy shape, and
// checks atomic receiver preservation. Invalid JSON must never publish a partial
// identity or completion acknowledgment; existing v2 strictness is unchanged.
func TestProtectedSharedPartitionDecodeStrict(t *testing.T) {
	_, info := protectedSharedPartitionFixture()
	valid, err := json.Marshal(info.ProtectedSharedPartition)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(valid, &fields); err != nil {
		t.Fatal(err)
	}
	bad := []string{
		`{`, `[]`, `"receipt"`,
		strings.Replace(string(valid), `"Version":1`, `"Version":2`, 1),
		strings.Replace(string(valid), `"Version":1`, `"version":1`, 1),
		strings.Replace(string(valid), `"HypervisorPartitionId":42`, `"HypervisorPartitionId":18446744073709551616`, 1),
		strings.Replace(string(valid), `"OperationHresult":0`, `"OperationHresult":4294967296`, 1),
		strings.Replace(string(valid), `"OperationHresult":0`, `"OperationHresult":-1`, 1),
		strings.Replace(string(valid), `"PartitionIdValid":true`, `"PartitionIdValid":1`, 1),
		strings.TrimSuffix(string(valid), "}") + `,"Unknown":0}`,
		strings.TrimSuffix(string(valid), "}") + `,"Version":1}`,
	}
	for name := range fields {
		for _, null := range []bool{false, true} {
			var next map[string]json.RawMessage
			if err := json.Unmarshal(valid, &next); err != nil {
				t.Fatal(err)
			}
			if null {
				next[name] = json.RawMessage("null")
			} else {
				delete(next, name)
			}
			encoded, err := json.Marshal(next)
			if err != nil {
				t.Fatal(err)
			}
			bad = append(bad, string(encoded))
		}
	}
	for i, receipt := range bad {
		before := *info.ProtectedSharedPartition
		receiver := before
		if err := json.Unmarshal([]byte(receipt), &receiver); err == nil || receiver != before {
			t.Errorf("case %d: invalid frame accepted or receiver changed", i)
		}
		for _, shape := range []string{"array", "SharedMemoryRegionInfo", "Regions"} {
			regions, err := parseSharedMemoryRegionResponse(json.RawMessage(protectedSharedPartitionJSON(receipt, shape)))
			if err == nil || regions != nil {
				t.Errorf("case %d %s: malformed sibling published partial regions", i, shape)
			}
		}
	}
	// A new optional sibling must not weaken the existing compact v2 decoder.
	if _, err := parseSharedMemoryRegionResponse(json.RawMessage(`[{"ProtectedShared":{"Version":2}}]`)); err == nil {
		t.Fatal("incomplete existing v2 receipt accepted")
	}
}

// TestProtectedSharedPartitionOwnedReceipt checks exact named-region/lease/
// owner/action/target selection. Duplicates, missing owners and stale actions
// must fail, while unrelated regions and an old page-action failure cannot
// override the independent successful partition receipt.
func TestProtectedSharedPartitionOwnedReceipt(t *testing.T) {
	request, _ := protectedSharedPartitionFixture()
	for _, scenario := range []string{
		"valid", "other region", "page action failed", "missing", "duplicate", "lease",
		"owner absent", "owner removed", "owner unprepared", "GPA", "sibling absent",
		"version", "stale action", "invalid ID", "zero ID", "self ID", "wrong target",
	} {
		_, info := protectedSharedPartitionFixture()
		regions := []hcsschema.SharedMemoryRegionInfo{info}
		switch scenario {
		case "other region":
			regions = append(regions, hcsschema.SharedMemoryRegionInfo{SectionName: "unrelated"})
		case "page action failed":
			info.ProtectedShared.OperationHresult = 0x80004005
		case "missing":
			regions = nil
		case "duplicate":
			regions = append(regions, info)
		case "lease":
			info.ProtectedShared.LeaseId++
		case "owner absent":
			regions[0].ProtectedShared = nil
		case "owner removed":
			info.ProtectedShared.Removed = true
		case "owner unprepared":
			info.ProtectedShared.Prepared = false
		case "GPA":
			regions[0].GuestPhysicalAddress = -1
		case "sibling absent":
			regions[0].ProtectedSharedPartition = nil
		case "version":
			info.ProtectedSharedPartition.Version++
		case "stale action":
			info.ProtectedSharedPartition.Operation = hcsschema.ProtectedSharedPartitionIdentity
		case "invalid ID":
			info.ProtectedSharedPartition.PartitionIdValid = false
		case "zero ID":
			info.ProtectedSharedPartition.HypervisorPartitionId = 0
		case "self ID":
			info.ProtectedSharedPartition.HypervisorPartitionId = math.MaxUint64
		case "wrong target":
			info.ProtectedSharedPartition.HypervisorPartitionId++
		}
		_, err := protectedSharedPartitionReceipt(regions, request, 42)
		wantSuccess := scenario == "valid" || scenario == "other region" || scenario == "page action failed"
		if (err == nil) != wantSuccess {
			t.Errorf("%s: unexpected validation error %v", scenario, err)
		}
	}
}

// TestProtectedSharedPartitionOutcome requires both actual action success and
// matching completed receipt, including repeat seal and identity discovery.
// Action/transport/decode failures must stay independently visible and never be
// laundered into success by an old successful receipt or nonzero success HRESULT.
func TestProtectedSharedPartitionOutcome(t *testing.T) {
	actionErr := errors.New("action transport failed")
	queryErr := errors.New("property transport/decode failed")
	for _, scenario := range []string{
		"seal", "repeat seal", "identity", "action failed", "query failed", "both failed",
		"not dispatched", "missing receipt", "false completion", "identity completion",
		"failed HRESULT", "S_FALSE", "wrong action", "wrong target", "unbound seal",
	} {
		_, info := protectedSharedPartitionFixture()
		outcome := ProtectedSharedPartitionOutcome{
			Dispatched: true, Region: &info, Receipt: info.ProtectedSharedPartition,
		}
		action, target := hcsschema.ProtectedSharedSealPartition, uint64(42)
		switch scenario {
		case "identity", "identity completion":
			action, target = hcsschema.ProtectedSharedPartitionIdentity, 0
			outcome.Receipt.Operation = action
			outcome.Receipt.SealCompleted = scenario == "identity completion"
		case "action failed":
			outcome.ActionError = actionErr
		case "query failed":
			outcome.ReceiptError = queryErr
		case "both failed":
			outcome.ActionError, outcome.ReceiptError = actionErr, queryErr
		case "not dispatched":
			outcome.Dispatched = false
		case "missing receipt":
			outcome.Receipt = nil
		case "false completion":
			outcome.Receipt.SealCompleted = false
		case "failed HRESULT":
			outcome.Receipt.OperationHresult = 0x80004005
		case "S_FALSE":
			outcome.Receipt.OperationHresult = 1
		case "wrong action":
			outcome.Receipt.Operation = hcsschema.ProtectedSharedSeal
		case "wrong target":
			outcome.Receipt.HypervisorPartitionId++
		case "unbound seal":
			target = 0
		}
		err := ValidateProtectedSharedPartitionOutcome(outcome, action, target)
		wantSuccess := scenario == "seal" || scenario == "repeat seal" || scenario == "identity"
		if (err == nil) != wantSuccess {
			t.Errorf("%s: unexpected outcome error %v", scenario, err)
		}
		if outcome.ActionError != nil && !errors.Is(err, actionErr) {
			t.Errorf("%s: actual action failure lost", scenario)
		}
		if outcome.ReceiptError != nil && !errors.Is(err, queryErr) {
			t.Errorf("%s: independent query failure lost", scenario)
		}
	}
}

// TestProtectedSharedPartitionRequest rejects lifecycle ranges and unowned
// targets before HCS dispatch, preventing accidental page-action routing.
// A VM without a compute system must fail without querying or consuming owners.
func TestProtectedSharedPartitionRequest(t *testing.T) {
	for _, scenario := range []string{"valid", "lease", "lifetime", "index", "count", "page action", "target", "self target"} {
		request, _ := protectedSharedPartitionFixture()
		target := uint64(42)
		switch scenario {
		case "lease":
			request.ProtectedSharedLeaseId = 0
		case "lifetime":
			request.ProtectedSharedLifetimeId = 1
		case "index":
			request.ProtectedSharedPageIndex = 1
		case "count":
			request.ProtectedSharedPageCount = 1
		case "page action":
			request.ProtectedSharedOperation = hcsschema.ProtectedSharedSeal
		case "target":
			target = 0
		case "self target":
			target = math.MaxUint64
		}
		if err := validateProtectedSharedPartitionRequest(request, target); (err == nil) != (scenario == "valid") {
			t.Errorf("%s: unexpected preflight error %v", scenario, err)
		}
		outcome := (&UtilityVM{}).ModifyProtectedSharedPartitionWithOutcome(context.Background(), request, target)
		if outcome.Dispatched || outcome.ActionError == nil || outcome.ReceiptError != nil || outcome.Receipt != nil {
			t.Errorf("%s: invalid/missing-system request dispatched or queried", scenario)
		}
	}
}
