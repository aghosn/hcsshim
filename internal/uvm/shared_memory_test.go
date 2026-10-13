//go:build windows

package uvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Microsoft/hcsshim/internal/computecore"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcsv2 "github.com/Microsoft/hcsshim/internal/hcs/v2"
)

// protectedRawJSON serializes owned test data without converting private wire
// primitives into schema structs. Failures abort the test, never become fixtures
// with success-shaped zero values.
func protectedRawJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// protectedRawInfoFixture returns independent raw fields shaped like the OS
// private response, including every zero/default value and an actual empty
// array for preparation. The optional snapshot has one installed binding with
// explicit zero VTL/removal reason. These are JSON fixtures, not MM evidence.
func protectedRawInfoFixture(t *testing.T, snapshot bool) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	err := json.Unmarshal([]byte(`{
		"Version":1,"Prepared":true,"Installed":false,"Removed":false,
		"LeaseId":10,"PageCount":1,"InitializedPages":0,"PreparedParticipants":1,
		"OperationHresult":0,"OperationStatus":0,"OperationResultValid":true,"PagesProcessed":0,
		"MapSequence":0,"LastMapPagesProcessed":0,"LastMapStatus":0,
		"PageIndex":0,"NextPageIndex":0,"RegionComplete":false,
		"QueryHresult":0,"QueryStatus":0,"QueryResultValid":true,"SnapshotValid":false,"Complete":false,
		"SpaPage":0,"LifetimeId":0,"MutationSequence":0,"ShareCount":0,
		"State":0,"Initialization":0,"RootProtection":0,"Reclaim":0,"PageType":0,"PageOwnership":0,
		"Registrations":[]
	}`), &fields)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot {
		for name, raw := range map[string]string{
			"Installed":             "true",
			"InitializedPages":      "1",
			"MapSequence":           "1",
			"LastMapPagesProcessed": "1",
			"NextPageIndex":         "1",
			"RegionComplete":        "true",
			"SnapshotValid":         "true",
			"Complete":              "true",
			"SpaPage":               "20",
			"LifetimeId":            "30",
			"MutationSequence":      "4",
			"ShareCount":            "1",
			"State":                 "1",
			"Initialization":        "2",
			"RootProtection":        "1",
			"PageType":              "1",
			"Registrations":         `[{"RegistrationId":40,"PartitionId":50,"GpaPage":131072,
				"SharePermission":3,"Vtl":0,"State":1,"RemovalReason":0}]`,
		} {
			fields[name] = json.RawMessage(raw)
		}
	}
	return fields
}

// decodeProtectedRawRoute exercises the same Properties unmarshaler used by
// HCS V2 and V3, followed by the actual named-response parser where applicable.
// A nil frame omits the optional legacy field; literal null retains that legacy
// representation. Any error returns no regions, as the production consumers do.
// It invokes no HCS operation and supplies no fake resource/protection behavior.
func decodeProtectedRawRoute(route string, frame json.RawMessage) ([]hcsschema.SharedMemoryRegionInfo, error) {
	region := `{"SectionName":"section","GuestPhysicalAddress":131072`
	if frame != nil {
		region += `,"ProtectedShared":` + string(frame)
	}
	array := `[` + region + `}]`
	var document string
	switch route {
	case "direct":
		document = `{"SharedMemoryRegionInfo":` + array + `}`
	case "named-array":
		document = `{"PropertyResponses":{"SharedMemoryRegion":{"Response":` + array + `}}}`
	case "named-info":
		document = `{"PropertyResponses":{"SharedMemoryRegion":{"Response":{"SharedMemoryRegionInfo":` + array + `}}}}`
	case "named-regions":
		document = `{"PropertyResponses":{"SharedMemoryRegion":{"Response":{"Regions":` + array + `}}}}`
	default:
		return nil, errors.New("unknown raw-response test route")
	}
	var props hcsschema.Properties
	if err := json.Unmarshal([]byte(document), &props); err != nil {
		return nil, err
	}
	if route == "direct" {
		return props.SharedMemoryRegionInfo, nil
	}
	return parseSharedMemoryRegionResponse(props.PropertyResponses[sharedMemoryRegionProperty].Response)
}

// assertProtectedRawRejected requires each real decode route to reject malformed
// private JSON and retain its raw metadata in the error. Direct unmarshaling into
// an existing valid receiver must also leave every field and binding unchanged;
// a late scalar/nested failure must not publish an earlier decoded prefix.
func assertProtectedRawRejected(t *testing.T, label string, raw json.RawMessage) {
	t.Helper()
	for _, route := range []string{"direct", "named-array", "named-info", "named-regions"} {
		regions, err := decodeProtectedRawRoute(route, raw)
		if err == nil || len(regions) != 0 {
			t.Fatalf("%s/%s published malformed private data: %+v, %v", label, route, regions, err)
		}
		if !strings.Contains(err.Error(), string(raw)) {
			t.Fatalf("%s/%s lost original private metadata: %v", label, route, err)
		}
	}
	var receiver hcsschema.ProtectedSharedRegionInfo
	if err := json.Unmarshal(protectedRawJSON(t, protectedRawInfoFixture(t, true)), &receiver); err != nil {
		t.Fatal(err)
	}
	before := protectedRawJSON(t, receiver)
	if err := json.Unmarshal(raw, &receiver); err == nil {
		t.Fatalf("%s accepted malformed private object", label)
	}
	if !bytes.Equal(before, protectedRawJSON(t, receiver)) {
		t.Fatalf("%s partially changed receiver on failed decode", label)
	}
}

// TestProtectedRawResponseRoutes protects upstream provenance in both HCS
// property routes. Prepared and installed producer-shaped records must decode;
// every required field must reject missing/null/wrong primitives before scalar
// zeroing. The sole null exception is an empty, zero-share registration slice.
func TestProtectedRawResponseRoutes(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		fields := protectedRawInfoFixture(t, snapshot)
		for _, route := range []string{"direct", "named-array", "named-info", "named-regions"} {
			regions, err := decodeProtectedRawRoute(route, protectedRawJSON(t, fields))
			if err != nil || len(regions) != 1 {
				t.Fatalf("%s snapshot=%t rejected valid raw response: %v", route, snapshot, err)
			}
			lifetime := uint64(0)
			if snapshot {
				lifetime = 30
			}
			if err := ValidateProtectedSharedInfo(regions[0].ProtectedShared, 10, 1, 0, lifetime, snapshot); err != nil {
				t.Fatal(err)
			}
		}
		// Mutations remain raw JSON, including the reported QueryStatus:null
		// and omitted QueryStatus on an otherwise valid prepared-only frame.
		names := make([]string, 0, len(fields))
		for name := range fields {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			original := fields[name]
			for _, replacement := range []json.RawMessage{nil, json.RawMessage("null"), json.RawMessage(`"0"`)} {
				if name == "Registrations" && !snapshot && string(replacement) == "null" {
					continue
				}
				if replacement == nil {
					delete(fields, name)
				} else {
					fields[name] = replacement
				}
				assertProtectedRawRejected(t, name+"/"+string(replacement), protectedRawJSON(t, fields))
				fields[name] = original
			}
		}
	}

	// Ordinary optional JSON must remain ordinary on every route, not acquire
	// private opt-in or a default protected-success object.
	for _, route := range []string{"direct", "named-array", "named-info", "named-regions"} {
		for _, frame := range []json.RawMessage{nil, json.RawMessage("null")} {
			regions, err := decodeProtectedRawRoute(route, frame)
			if err != nil || len(regions) != 1 || regions[0].ProtectedShared != nil {
				t.Fatalf("%s changed legacy optional response: %+v, %v", route, regions, err)
			}
			if bytes.Contains(protectedRawJSON(t, regions[0]), []byte("ProtectedShared")) {
				t.Fatal("legacy response serialized private metadata")
			}
		}
		fields := protectedRawInfoFixture(t, false)
		fields["Registrations"] = json.RawMessage("null")
		if _, err := decodeProtectedRawRoute(route, protectedRawJSON(t, fields)); err != nil {
			t.Fatalf("%s rejected valid Go nil/zero-share inventory: %v", route, err)
		}
	}
}

// TestProtectedRawRegistrationAndTypes requires all nested registration
// primitives and rejects null records, case-folded aliases and typed overflow.
// It also verifies atomicity when an error occurs inside an installed inventory.
func TestProtectedRawRegistrationAndTypes(t *testing.T) {
	fields := protectedRawInfoFixture(t, true)
	var registrations []map[string]json.RawMessage
	if err := json.Unmarshal(fields["Registrations"], &registrations); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(registrations[0]))
	for name := range registrations[0] {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		original := registrations[0][name]
		for _, replacement := range []json.RawMessage{nil, json.RawMessage("null"), json.RawMessage(`"0"`)} {
			if replacement == nil {
				delete(registrations[0], name)
			} else {
				registrations[0][name] = replacement
			}
			fields["Registrations"] = protectedRawJSON(t, registrations)
			assertProtectedRawRejected(t, "registration/"+name+"/"+string(replacement), protectedRawJSON(t, fields))

			// Standalone registration decoding must be atomic too, not just
			// protected by the enclosing region's unpublished local copy.
			previous := hcsschema.ProtectedSharedRegistrationInfo{
				RegistrationId:  99,
				PartitionId:     100,
				GpaPage:         101,
				SharePermission: 3,
				State:           1,
			}
			receiver := previous
			if err := json.Unmarshal(protectedRawJSON(t, registrations[0]), &receiver); err == nil || receiver != previous {
				t.Fatalf("registration/%s changed or accepted an invalid standalone record: %+v, %v", name, receiver, err)
			}
			registrations[0][name] = original
		}
	}
	for _, test := range []struct {
		name string
		raw  string
	}{
		{"QueryStatus", "true"},
		{"QueryHresult", "4294967296"},
		{"OperationStatus", "-1"},
		{"OperationHresult", "1.0"},
		{"LeaseId", "18446744073709551616"},
		{"Prepared", "0"},
		{"Registrations", "[null]"},
		{"Registrations", "[{}]"},
		{"Registrations", "[true]"},
		{"Registrations", "{}"},
		{"querystatus", "null"},
	} {
		fields = protectedRawInfoFixture(t, true)
		fields[test.name] = json.RawMessage(test.raw)
		assertProtectedRawRejected(t, test.name+"/"+test.raw, protectedRawJSON(t, fields))
	}
}

// TestProtectedRawIndependentErrors preserves explicit unsigned failure bits
// and valid action progress through both raw routes. Failed actions must not
// invalidate independent snapshots, and nested query errors must remain visible
// for semantic rejection rather than being normalized into success by decoding.
func TestProtectedRawIndependentErrors(t *testing.T) {
	for _, route := range []string{"direct", "named-array", "named-info", "named-regions"} {
		fields := protectedRawInfoFixture(t, true)
		fields["OperationHresult"] = json.RawMessage("2147942405")
		fields["OperationStatus"] = json.RawMessage("3224698888")
		fields["PagesProcessed"] = json.RawMessage("1")
		fields["MapSequence"] = json.RawMessage("18446744073709551615")
		regions, err := decodeProtectedRawRoute(route, protectedRawJSON(t, fields))
		if err != nil || len(regions) != 1 {
			t.Fatalf("%s lost framed operation failure: %v", route, err)
		}
		p := regions[0].ProtectedShared
		if p.OperationHresult != 0x80070005 || p.OperationStatus != 0xc0350008 ||
			!p.OperationResultValid || p.PagesProcessed != 1 || p.MapSequence != math.MaxUint64 {
			t.Fatalf("%s lost explicit failure bits/progress: %+v", route, p)
		}
		if err := ValidateProtectedSharedInfo(p, 10, 1, 0, 30, true); err != nil {
			t.Fatalf("%s rejected independent snapshot: %v", route, err)
		}
		fields = protectedRawInfoFixture(t, false)
		fields["QueryHresult"] = json.RawMessage("2147942405")
		fields["QueryStatus"] = json.RawMessage("3221225506")
		regions, err = decodeProtectedRawRoute(route, protectedRawJSON(t, fields))
		if err != nil || len(regions) != 1 {
			t.Fatalf("%s discarded explicit query failure: %v", route, err)
		}
		p = regions[0].ProtectedShared
		if p.QueryHresult != 0x80070005 || p.QueryStatus != 0xc0000022 ||
			ValidateProtectedSharedInfo(p, 10, 1, 0, 0, false) == nil {
			t.Fatalf("%s accepted nested query failure: %+v", route, p)
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

// TestProtectedUnits checks signed and overflowing inputs before page arithmetic,
// while retaining the historical page-index contract and valid GPA zero.
func TestProtectedUnits(t *testing.T) {
	for _, test := range []struct {
		page, length int64
		want         uint64
		valid        bool
	}{
		{0x20000, 4096, 0x20000000, true},
		{0, 4096, 0, true},
		{-1, 4096, 0, false},
		{1, -1, 0, false},
		{1, 4097, 0, false},
		{math.MaxInt64, 4096, 0, false},
		{int64(math.MaxUint64 >> 12), 4096, 0, false},
	} {
		got, err := SharedMemoryByteGPA(test.page, test.length)
		if (err == nil) != test.valid || (err == nil && got != test.want) {
			t.Fatalf("page=%d length=%d: got %#x, %v", test.page, test.length, got, err)
		}
	}
}

// protectedInfoFixture returns an owned v1 frame with distinct live registrations.
// It is parser input, not evidence of real HV enforcement.
func protectedInfoFixture() *hcsschema.ProtectedSharedRegionInfo {
	return &hcsschema.ProtectedSharedRegionInfo{
		Version: 1, LeaseId: 10, PageCount: 1, PageIndex: 0, NextPageIndex: 1,
		Prepared: true, Installed: true, InitializedPages: 1, PreparedParticipants: 2,
		OperationResultValid: true, QueryResultValid: true, SnapshotValid: true,
		Complete: true, RegionComplete: true, SpaPage: 20, LifetimeId: 30,
		MutationSequence: 4, ShareCount: 2, State: 2, Initialization: 2,
		RootProtection: 1, PageType: 1,
		Registrations: []hcsschema.ProtectedSharedRegistrationInfo{
			{RegistrationId: 40, PartitionId: 50, GpaPage: 0, SharePermission: 3, State: 1},
			{RegistrationId: 41, PartitionId: 51, GpaPage: 0x20000, SharePermission: 7, State: 1},
		},
	}
}

// TestProtectedJSONAndDiagnostics rejects malformed, stale and incomplete
// diagnostics and preserves unsigned failures. No legacy mapped response may
// replace a private frame; historical endpoints are not identity duplicates.
func TestProtectedJSONAndDiagnostics(t *testing.T) {
	b, err := json.Marshal(hcsschema.SharedMemoryRegionInfo{
		SectionName: "section", GuestPhysicalAddress: 0x20000, ProtectedShared: protectedInfoFixture(),
	})
	if err != nil {
		t.Fatal(err)
	}
	regions, err := parseSharedMemoryRegionResponse(append(append([]byte{'['}, b...), ']'))
	if err != nil || len(regions) != 1 {
		t.Fatalf("valid private JSON: %v", err)
	}
	if err := ValidateProtectedSharedInfo(regions[0].ProtectedShared, 10, 1, 0, 30, true); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`[`, `[{"GuestPhysicalAddress":-2147483649}]`, `[{"ProtectedShared":{"LeaseId":-1}}]`} {
		if _, err := parseSharedMemoryRegionResponse(json.RawMessage(bad)); err == nil {
			t.Fatalf("malformed JSON accepted: %s", bad)
		}
	}
	for _, mutate := range []func(*hcsschema.ProtectedSharedRegionInfo){
		// Stale immutable lease.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.LeaseId++ },
		// Stale lifetime at the same page cursor.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.LifetimeId++ },
		// Incomplete snapshot.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.Complete = false },
		// Missing query frame.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.QueryResultValid = false },
		// Prepared-only response cannot satisfy snapshot acceptance.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.SnapshotValid = false },
		// Cursor skipped a page.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.NextPageIndex++ },
		// Prefix exceeds the control bound.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.PagesProcessed = 5 },
		// Registration identity reused.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.Registrations[1].RegistrationId = 40 },
		// Unknown permission bit.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.Registrations[0].SharePermission = 8 },
		// Unsupported VTL.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.Registrations[0].Vtl = 1 },
		// Live registration with a removal reason.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.Registrations[0].RemovalReason = 1 },
		// Invalid partition incarnation.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.Registrations[0].PartitionId = 0 },
		// GPA outside the SNP architecture ceiling.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.Registrations[0].GpaPage = 1 << 40 },
		// Unknown lifecycle.
		func(p *hcsschema.ProtectedSharedRegionInfo) { p.State = 4 },
	} {
		p := protectedInfoFixture()
		mutate(p)
		if err := ValidateProtectedSharedInfo(p, 10, 1, 0, 30, true); err == nil {
			t.Fatalf("malformed frame accepted: %+v", p)
		}
	}
	if err := ValidateProtectedSharedInfo(nil, 10, 1, 0, 30, true); err == nil {
		t.Fatal("ordinary mapped response accepted as protected evidence")
	}
	p := protectedInfoFixture()
	p.OperationHresult, p.OperationStatus = 0x80070005, 0xc0350008
	if err := ValidateProtectedSharedInfo(p, 10, 1, 0, 30, true); err != nil {
		t.Fatal("failed operation lost valid independent snapshot:", err)
	}
	p.Registrations[1] = p.Registrations[0]
	p.Registrations[1].RegistrationId++
	p.Registrations[1].State, p.Registrations[1].RemovalReason = 3, 3
	p.Registrations[0].SharePermission = 0
	p.Registrations[1].SharePermission = 4
	if err := ValidateProtectedSharedInfo(p, 10, 1, 0, 30, true); err != nil {
		t.Fatal(err)
	}
}

// TestProtectedOptInAndPreparation keeps ordinary JSON unchanged and requires
// an actual matching operation-resource descriptor for hidden preparation.
func TestProtectedOptInAndPreparation(t *testing.T) {
	ordinary := hcsschema.SharedMemoryRegion{SectionName: "section", Length: 4096, AllowGuestWrite: true}
	b, err := json.Marshal(ordinary)
	if err != nil || string(b) != `{"SectionName":"section","Length":4096,"AllowGuestWrite":true}` {
		t.Fatalf("legacy JSON changed: %s, %v", b, err)
	}
	private := ordinary
	private.HiddenFromGuest, private.ProtectedShared = true, true
	private.ProtectedSharedControllerUri = "hcs:/test"
	opts := &OptionsLCOW{SharedMemoryRegions: []hcsschema.SharedMemoryRegion{private}}
	if err := validateProtectedSharedOptions(opts); err == nil {
		t.Fatal("schema opt-in without capability accepted")
	}
	opts.ProtectedSharedResources = []hcsv2.OperationResource{{
		Type: computecore.HcsResourceTypeFile, URI: "hcs:/test", Handle: syscall.Handle(123),
	}}
	if err := validateProtectedSharedOptions(opts); err != nil {
		t.Fatal(err)
	}
	b, err = json.Marshal(private)
	if err != nil || !strings.Contains(string(b), `"ProtectedShared":true`) ||
		!strings.Contains(string(b), `"HiddenFromGuest":true`) ||
		strings.Contains(string(b), "ProtectedSharedOperation") {
		t.Fatalf("incorrect preparation JSON: %s, %v", b, err)
	}
	opts.SharedMemoryRegions[0].HiddenFromGuest = false
	if err := validateProtectedSharedOptions(opts); err == nil {
		t.Fatal("visible protected creation accepted")
	}
	private.StartOffset = -4096
	if err := ValidateProtectedSharedRegion(private); err == nil {
		t.Fatal("negative byte offset accepted")
	}
}

// TestProtectedSnapshotFreeQuery checks the legitimate pre-initialization query,
// rejects nested failures despite outer/action success, and classifies reclaimed
// or stale STATUS_NOT_FOUND without discarding the independent action prefix.
func TestProtectedSnapshotFreeQuery(t *testing.T) {
	for _, test := range []struct {
		name        string
		valid       bool
		hresult     uint32
		status      uint32
		initialized uint64
		wantError   bool
		unavailable bool
	}{
		{"prepared", true, 0, 0, 0, false, false},
		{"unframed", false, 0, 0, 0, true, false},
		{"failed-hresult", true, 0x80070005, 0, 0, true, false},
		{"failed-status", true, 0, 0xc0000022, 0, true, false},
		{"initialized-without-snapshot", true, 0, 0, 1, true, false},
		{"reclaimed-or-stale", true, 0x80070490, 0xc0000225, 1, true, true},
	} {
		processed := uint32(test.initialized)
		p := &hcsschema.ProtectedSharedRegionInfo{
			Version: 1, LeaseId: 10, PageCount: 1, Prepared: true,
			QueryResultValid: test.valid, QueryHresult: test.hresult, QueryStatus: test.status,
			InitializedPages: test.initialized, OperationResultValid: true, PagesProcessed: processed,
		}
		err := ValidateProtectedSharedInfo(p, 10, 1, 0, 0, false)
		if (err != nil) != test.wantError || errors.Is(err, ErrProtectedSharedPageUnavailable) != test.unavailable {
			t.Fatalf("%s: unexpected query classification: %v", test.name, err)
		}
		if !p.OperationResultValid || p.PagesProcessed != processed || p.QueryStatus != test.status {
			t.Fatalf("%s: independent raw progress was discarded", test.name)
		}
	}
}

// TestProtectedCollectionBounds rejects missing deadlines, malformed ranges,
// identity-count mismatches and cancellation before reaching HCS. It protects
// bounded collection semantics without a worker mock or a native call.
func TestProtectedCollectionBounds(t *testing.T) {
	var vm UtilityVM
	region := hcsschema.SharedMemoryRegion{
		SectionName: "section", Length: 4096, ProtectedShared: true,
		ProtectedSharedControllerUri: "hcs:/test", ProtectedSharedLeaseId: 1,
	}
	resource := hcsv2.OperationResource{Type: computecore.HcsResourceTypeFile, URI: "hcs:/test", Handle: syscall.Handle(123)}
	if _, err := vm.CollectProtectedShared(context.Background(), region, resource, []uint64{1}); err == nil {
		t.Fatal("unbounded collection accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := vm.CollectProtectedShared(ctx, region, resource, nil); err == nil {
		t.Fatal("missing page identities accepted")
	}
	bad := region
	bad.Length = -4096
	if _, err := vm.CollectProtectedShared(ctx, bad, resource, []uint64{1}); err == nil {
		t.Fatal("negative collection length accepted")
	}
	cancel()
	prefix, err := vm.CollectProtectedShared(ctx, region, resource, []uint64{1})
	if !errors.Is(err, context.Canceled) || len(prefix) != 0 {
		t.Fatalf("cancelled collection returned an invalid prefix/error: %v, %v", prefix, err)
	}
}
