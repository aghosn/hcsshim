//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"golang.org/x/sys/windows"
)

// protectedSharedHvGolden decodes test-only literal wire bytes. Invalid fixture
// text fails the calling test, never a transport or native operation.
func protectedSharedHvGolden(t *testing.T, text string) []byte {
	t.Helper()
	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestProtectedSharedHvProbeGolden protects the unchanged native AMD64 ABI:
// tfkcontrol.h's align(16) header, tfcomponent.h component 101, hvtestcasedefs.h
// cases 35/36, winhvkt.h native sizes/padding, HvAmApi.h cache WB=6 and
// hvgdk_mini.w HV_INPUT_VTL UseTargetVtl=bit4/VTL0. Literal bytes below are
// independent of encoder offsets; a four-byte-header or packed-C client fails.
func TestProtectedSharedHvProbeGolden(t *testing.T) {
	target := protectedSharedHvTarget{
		partitionID: 0x0102030405060708, partitionIDValid: true, pageGPA: 0x1020304050607000,
	}
	for _, write := range []bool{false, true} {
		header := "23006500" // little-endian (101<<16)|35
		if write {
			header = "24006500" // little-endian (101<<16)|36
		}
		golden := header + "000000000000000000000000" + // 12-byte header padding
			"0807060504030201" + // input offset 0: actual partition ID
			"0000000000000000" + // offset 8: VP0 plus four-byte native gap
			"0071605040302010" + // offset 16: page GPA + 256
			"0800000000000000" + // offset 24: byte count 8 plus native gap
			"0610000000000000" // offset 32: WB=6, explicit VTL0=0x10
		if write {
			golden += "484f53544b4545500000000000000000" // DataBuffer[16], 8 used
		}
		frame, err := encodeProtectedSharedHvRequest(target, 256, write, [8]byte{'H', 'O', 'S', 'T', 'K', 'E', 'E', 'P'})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(frame, protectedSharedHvGolden(t, golden)) {
			// Do not format wire buffers: the runtime version can carry data.
			t.Errorf("write=%t: native input layout differs from golden", write)
		}
	}
	if protectedSharedHvIOCTLCode != 9 || protectedSharedHvPolicyDenied != 0xc0350006 {
		t.Fatal("IOCTL or verified native policy-denial constant changed")
	}
}

// TestProtectedSharedHvProbeBounds rejects invalid/alias IDs, invalid validity,
// misaligned/overflowing GPAs and cross-page accesses before any IOCTL. The last
// valid eight-byte offset remains allowed; bounds cannot manufacture a denial.
func TestProtectedSharedHvProbeBounds(t *testing.T) {
	for _, scenario := range []string{"valid", "last eight", "invalid validity", "zero ID", "self ID", "unaligned", "overflow", "cross page", "huge offset"} {
		target := protectedSharedHvTarget{partitionID: 42, partitionIDValid: true, pageGPA: 0x1000}
		offset := uint32(256)
		switch scenario {
		case "last eight":
			offset = 4088
		case "invalid validity":
			target.partitionIDValid = false
		case "zero ID":
			target.partitionID = 0
		case "self ID":
			target.partitionID = math.MaxUint64
		case "unaligned":
			target.pageGPA++
		case "overflow":
			target.pageGPA = math.MaxUint64 - 7
		case "cross page":
			offset = 4089
		case "huge offset":
			offset = math.MaxUint32
		}
		frame, err := encodeProtectedSharedHvRequest(target, offset, false, [8]byte{})
		wantSuccess := scenario == "valid" || scenario == "last eight"
		if (err == nil) != wantSuccess || (!wantSuccess && frame != nil) {
			t.Errorf("%s: invalid bounds acceptance", scenario)
		}
	}
}

// TestProtectedSharedHvProbeNativeResults uses literal native outputs matching
// winhvkt.h Status@0/pad@4/AccessResult@8/DataBuffer@16 (32 read, 16 write).
// WinHv am.c publishes nested fields only on NT_SUCCESS; hypercall.c/winhvp.h
// and ntstatus.mc map HV_STATUS_ACCESS_DENIED=6 to c0350006, NOT c0000022
// or c0350008. Garbage nested bytes on native failure must stay invalid.
// Inline success with BytesProcessed zero must pass, intercepts must not.
func TestProtectedSharedHvProbeNativeResults(t *testing.T) {
	for _, write := range []bool{false, true} {
		for _, scenario := range []struct {
			name     string
			wire     string
			positive bool
			denial   bool
			access   bool
		}{
			{"inline zero processed", "00000000000000000000000000000000", true, false, true},
			{"processed eight", "00000000000000000000000008000000", true, false, true},
			{"unmapped", "00000000000000000100000000000000", false, false, true},
			{"read intercept", "00000000000000000200000000000000", false, false, true},
			{"write intercept", "00000000000000000300000000000000", false, false, true},
			{"native policy", "060035c000000000ffffffffffffffff", false, true, false},
			{"generic access denied", "220000c0000000000000000000000000", false, false, false},
			{"install operation denied", "080035c0000000000000000000000000", false, false, false},
			{"HRESULT access denied", "06003580000000000000000000000000", false, false, false},
			{"HRESULT install denied", "08003580000000000000000000000000", false, false, false},
			{"invalid partition", "0d0035c0000000000000000000000000", false, false, false},
			{"invalid VP", "0e0035c0000000000000000000000000", false, false, false},
			{"informational status", "01000000000000000000000000000000", false, false, true},
		} {
			wire := scenario.wire
			if !write {
				wire += "484f53544b4545500000000000000000"
			}
			output := protectedSharedHvGolden(t, wire)
			r := decodeProtectedSharedHvResult(output, uint32(len(output)), write, nil)
			if !r.nativeStatusValid || r.accessResultValid != scenario.access ||
				(r.requirePositive() == nil) != scenario.positive ||
				(r.requirePolicyDenial() == nil) != scenario.denial {
				t.Errorf("%s write=%t: incorrect native/access classification", scenario.name, write)
			}
			if !scenario.access && (r.resultCode != 0 || r.bytesProcessed != 0 || r.dataValid || r.data != [8]byte{}) {
				t.Errorf("%s: native failure interpreted unset nested output", scenario.name)
			}
			if r.dataValid != (!write && scenario.positive) {
				t.Errorf("%s: wrong data validity", scenario.name)
			}
			if r.dataValid && r.data != [8]byte{'H', 'O', 'S', 'T', 'K', 'E', 'E', 'P'} {
				t.Error("valid read did not preserve synthetic sentinel")
			}
		}
	}
}

// TestProtectedSharedHvProbeTransport uses only a narrow synchronous IOCTL fake.
// The fake asserts handle/code/sizes/alignment then returns synthetic status,
// without a driver or VM. Short/oversized frames, ACL errors and generic IOCTL
// failure cannot become a native protection pass, even with denial-looking data.
func TestProtectedSharedHvProbeTransport(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("wire transport client is explicitly Windows AMD64 only")
	}
	transportErr := errors.New("IOCTL failed")
	for _, write := range []bool{false, true} {
		for _, scenario := range []string{"exact", "positive", "short", "oversized", "ACL", "IOCTL"} {
			calls := 0
			// The synchronous fake borrows aligned storage, fills only native
			// output, and never retains pointers or grants real HV authority.
			ioctl := func(handle windows.Handle, code uint32, input, output []byte) (uint32, error) {
				calls++
				inputSize, outputSize, id := 56, 32, uint32(0x00650023)
				if write {
					inputSize, outputSize, id = 72, 16, 0x00650024
				}
				if handle != 123 || code != 9 || len(input) != inputSize || len(output) != outputSize ||
					uintptr(unsafe.Pointer(&input[0]))%16 != 0 || uintptr(unsafe.Pointer(&output[0]))%16 != 0 ||
					binary.LittleEndian.Uint32(input[0:4]) != id {
					t.Fatal("fake received wrong handle/IOCTL/layout/alignment")
				}
				binary.LittleEndian.PutUint32(output[0:4], 0xc0350006)
				returned := uint32(outputSize)
				switch scenario {
				case "positive":
					binary.LittleEndian.PutUint32(output[0:4], 0)
					if !write {
						copy(output[16:24], []byte("HOSTKEEP"))
					}
				case "short":
					returned--
				case "oversized":
					returned++
				case "ACL":
					return returned, windows.ERROR_ACCESS_DENIED
				case "IOCTL":
					return returned, transportErr
				}
				return returned, nil
			}
			probe := &protectedSharedHvProbe{handle: 123, ioctl: ioctl}
			target := protectedSharedHvTarget{partitionID: 42, partitionIDValid: true, pageGPA: 0x1000}
			var r protectedSharedHvProbeResult
			if write {
				r = probe.write(target, 256, [8]byte{'B', 'A', 'D', 'W', 'R', 'I', 'T', 'E'})
			} else {
				r = probe.read(target, 256)
			}
			if calls != 1 || (r.requirePolicyDenial() == nil) != (scenario == "exact") ||
				(r.requirePositive() == nil) != (scenario == "positive") {
				t.Errorf("%s write=%t: transport failure misclassified", scenario, write)
			}
			if scenario != "exact" && scenario != "positive" &&
				(r.transportError == nil || r.nativeStatusValid || r.accessResultValid || r.dataValid) {
				t.Errorf("%s: failed transport published nested native fields", scenario)
			}
			if scenario == "positive" && (r.bytesProcessed != 0 || (!write &&
				(!r.dataValid || r.data != [8]byte{'H', 'O', 'S', 'T', 'K', 'E', 'E', 'P'}))) {
				t.Error("inline positive control lost zero processed or synthetic read data")
			}
			if scenario == "ACL" && !errors.Is(r.transportError, windows.ERROR_ACCESS_DENIED) {
				t.Error("transport ACL diagnostic lost")
			}
			if scenario == "IOCTL" && !errors.Is(r.transportError, transportErr) {
				t.Error("transport diagnostic lost")
			}
		}
	}
	// Buffer length as well as reported byte count is part of exact framing.
	for _, length := range []int{0, 31, 33} {
		r := decodeProtectedSharedHvResult(make([]byte, length), 32, false, nil)
		if r.transportError == nil || r.nativeStatusValid || r.requirePolicyDenial() == nil {
			t.Errorf("buffer length %d accepted as native evidence", length)
		}
	}
}

// TestProtectedSharedHvProbePrerequisites ensures unavailable clients and
// invalid targets fail before invoking the seam. Missing/closed/unsupported
// driver prerequisites must never satisfy the negative protection classifier.
func TestProtectedSharedHvProbePrerequisites(t *testing.T) {
	calls := 0
	// This fake must never run: preflight must reject each supplied client.
	ioctl := func(windows.Handle, uint32, []byte, []byte) (uint32, error) {
		calls++
		return 0, nil
	}
	for _, probe := range []*protectedSharedHvProbe{
		nil, {}, {handle: windows.InvalidHandle, ioctl: ioctl}, {handle: 123},
		{handle: 123, ioctl: ioctl},
	} {
		r := probe.read(protectedSharedHvTarget{}, 256)
		if r.transportError == nil || r.nativeStatusValid || r.requirePositive() == nil || r.requirePolicyDenial() == nil {
			t.Error("unavailable driver/target was accepted")
		}
	}
	if calls != 0 {
		t.Fatal("prerequisite failure reached IOCTL")
	}
}

// partitionSealFake records only runner steps, acquired owners and supplied
// lifecycle prefixes. It is not a VM, HCS, driver or HV-policy simulation.
// The single chosen failing step may still return valid ownership/progress;
// this protects the coordinator's consume-before-error cleanup contract.
type partitionSealFake struct {
	steps                             []partitionSealStep
	events                            []string
	initialized                       map[string]uint64
	leases                            map[string]uint64
	vmOwned                           map[string]bool
	backing                           map[string]bool
	failKind, failLifetime, failVM     string
	failErr, evidenceErr               error
	cancel                            context.CancelFunc
	partial                           uint32
	unframed, uncertain, omitVM        bool
	cleanupContextInvalid, doubleClose bool
}

// newPartitionSealFake returns an empty receipt recorder with no real resource
// acquisition. Its maps track two independent synthetic lease identities only.
func newPartitionSealFake() *partitionSealFake {
	return &partitionSealFake{initialized: map[string]uint64{}, leases: map[string]uint64{},
		vmOwned: map[string]bool{}, backing: map[string]bool{}}
}

// EvidenceError supplies the fake's sticky evidence error without changing its
// recorded ownership. Cleanup must still proceed when diagnostics have failed.
func (f *partitionSealFake) EvidenceError() error { return f.evidenceErr }

// Run records a synchronous step and returns synthetic acquisition/progress
// facts before its configured error/cancellation. Cleanup calls are required
// to have a fresh live deadline; releases/VM closes are recorded separately so
// tests can detect forgotten partial owners, duplicate closes and unsafe frees.
func (f *partitionSealFake) Run(ctx context.Context, s partitionSealStep) (partitionSealResult, error) {
	f.steps = append(f.steps, s)
	cleanup := s.Kind == "teardown" || s.Kind == "remove" || s.Kind == "terminate" ||
		s.Kind == "reclaim" || s.Kind == "zero" || s.Kind == "release" || s.Kind == "close-driver"
	if cleanup {
		_, bounded := ctx.Deadline()
		f.cleanupContextInvalid = f.cleanupContextInvalid || ctx.Err() != nil || !bounded
	}
	fail := s.Kind == f.failKind && (f.failLifetime == "" || s.Lifetime == f.failLifetime) &&
		(f.failVM == "" || s.Participant == f.failVM)
	r := partitionSealResult{}
	switch s.Kind {
	case "driver":
		r.DriverOwned = true
		f.events = append(f.events, "acquire-driver")
	case "open":
		f.backing[s.Lifetime] = true
		f.events = append(f.events, "acquire-"+s.Lifetime)
	case "prepare":
		if !fail || !f.omitVM {
			r.VMOwned = true
			f.vmOwned[s.Participant] = true
			f.events = append(f.events, "acquire-vm-"+s.Participant)
		}
		f.leases["primary"] = 11
	case "late-prepare":
		f.leases["late"] = 22
		f.events = append(f.events, "borrow-a")
	case "initialize", "seal", "teardown", "reclaim":
		processed := s.Count
		if fail && f.partial < processed {
			processed = f.partial
		}
		if s.Kind == "initialize" {
			f.initialized[s.Lifetime] += uint64(processed)
			f.events = append(f.events, "progress-"+s.Lifetime)
		}
		r.ControlAttempted = true
		r.proofResult = proofResult{Framed: !(fail && f.unframed), Initialized: f.initialized[s.Lifetime],
			Processed: processed, LeaseId: f.leases[s.Lifetime]}
	case "zero":
		r.ZeroVerifiedBytes = f.initialized[s.Lifetime] * 4096
	case "release":
		f.events = append(f.events, "release-"+s.Lifetime)
	case "terminate":
		if !f.vmOwned[s.Participant] {
			f.doubleClose = true
		}
		f.vmOwned[s.Participant] = false
		f.events = append(f.events, "close-vm-"+s.Participant)
	case "close-driver":
		f.events = append(f.events, "close-driver")
	}
	r.BackingOwned = f.backing[s.Lifetime]
	if r.LeaseId == 0 {
		r.LeaseId = f.leases[s.Lifetime]
	}
	if fail {
		r.Uncertain = f.uncertain
		if f.cancel != nil {
			f.cancel()
		}
		return r, f.failErr
	}
	return r, nil
}

// partitionStepPosition locates a recorded operation, optionally narrowed to a
// lease/VM, returning -1 if absent. It reads only fake diagnostics, no HV state.
func partitionStepPosition(steps []partitionSealStep, kind, lifetime, participant string) int {
	for i, s := range steps {
		if s.Kind == kind && (lifetime == "" || s.Lifetime == lifetime) &&
			(participant == "" || s.Participant == participant) {
			return i
		}
	}
	return -1
}

// TestProtectedSharedPartitionOrder records a five-page 4+1 run. Both installed
// VM page-lock barriers must precede controls and seals, both completed seals
// and repeats precede negatives/late acquisition, and late remains unsealed
// and alive through fresh primary exchange. Separate cleanup must zero-check
// both leases before release and close exactly the two independently owned VMs.
// This protects orchestration only; synthetic steps do not prove HV behavior.
func TestProtectedSharedPartitionOrder(t *testing.T) {
	f := newPartitionSealFake()
	if err := executePartitionSealProof(context.Background(), f, 5, time.Minute); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"driver//", "open/primary/", "seed/primary/", "prepare/primary/a", "prepare/primary/b",
		"initialize/primary/", "initialize/primary/", "install/primary/a", "install/primary/b",
		"seal/primary/", "seal/primary/", "identity/primary/a", "identity/primary/b",
		"hv-positive/primary/a", "hv-positive/primary/b",
		"partition-seal/primary/a", "partition-seal/primary/b",
		"partition-seal-repeat/primary/a", "partition-seal-repeat/primary/b",
		"hv-negative/primary/a", "hv-negative/primary/b",
		"open/late/", "seed/late/", "late-prepare/late/a", "initialize/late/",
		"late-install-denial/late/a", "exchange/primary/",
		"teardown/primary/", "teardown/primary/", "remove/primary/a", "remove/primary/b",
		"teardown/late/", "remove/late/a", "terminate//a", "terminate//b",
		"reclaim/late/", "zero/late/", "release/late/",
		"reclaim/primary/", "reclaim/primary/", "zero/primary/", "release/primary/", "close-driver//",
	}
	if len(f.steps) != len(expected) {
		t.Fatalf("got %d steps, expected %d", len(f.steps), len(expected))
	}
	for i, s := range f.steps {
		if got := s.Kind + "/" + s.Lifetime + "/" + s.Participant; got != expected[i] {
			t.Errorf("step %d: %s, expected %s", i, got, expected[i])
		}
		if s.Kind == "initialize" || s.Kind == "seal" || s.Kind == "teardown" || s.Kind == "reclaim" {
			wantCount := uint32(1)
			if s.Lifetime == "primary" && s.Index == 0 {
				wantCount = 4
			}
			if s.Count != wantCount || (s.Index != 0 && s.Index != 4) {
				t.Errorf("step %d: incorrect 4+1 lifecycle range", i)
			}
		}
	}
	if strings.Count(strings.Join(f.events, ","), "acquire-vm-") != 2 ||
		strings.Count(strings.Join(f.events, ","), "close-vm-") != 2 ||
		f.cleanupContextInvalid || f.doubleClose {
		t.Fatal("VM ownership or independent cleanup contract violated")
	}
}

// TestProtectedSharedPartitionPartialAcquisition cancels/errors at acquired VM,
// partial primary initialization, and late acquisition/preparation/initialization.
// Returned owners and valid prefixes must enter cleanup before forward work
// stops. Fresh cleanup must still remove late's borrowed owner, close A only
// once, and use each lease's actual prefix (including zero/no-init cases).
func TestProtectedSharedPartitionPartialAcquisition(t *testing.T) {
	for _, scenario := range []struct {
		name, kind, lifetime, vm string
		cancel                  bool
		partial                 uint32
		wantPrimary, wantLate    uint64
	}{
		{"acquired A then cancel", "prepare", "primary", "a", true, 0, 0, 0},
		{"acquired B then error", "prepare", "primary", "b", false, 0, 0, 0},
		{"partial init then cancel", "initialize", "primary", "", true, 2, 2, 0},
		{"partial init then error", "initialize", "primary", "", false, 2, 2, 0},
		{"late open then cancel", "open", "late", "", true, 0, 5, 0},
		{"late owner then error", "late-prepare", "late", "a", false, 0, 5, 0},
		{"late initialized then cancel", "initialize", "late", "", true, 1, 5, 1},
		{"late install unexpected result", "late-install-denial", "late", "a", false, 0, 5, 1},
	} {
		// Each subtest owns a fresh recorder/context. No native resource or
		// protection result is fabricated; only step receipts are supplied.
		t.Run(scenario.name, func(t *testing.T) {
			f := newPartitionSealFake()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.failKind, f.failLifetime, f.failVM = scenario.kind, scenario.lifetime, scenario.vm
			f.partial = scenario.partial
			f.failErr = errors.New("operation failed after acquisition/progress")
			if scenario.cancel {
				f.cancel, f.failErr = cancel, nil
			}
			if err := executePartitionSealProof(ctx, f, 5, time.Minute); err == nil {
				t.Fatal("failed/cancelled forward operation passed")
			}
			failed := partitionStepPosition(f.steps, scenario.kind, scenario.lifetime, scenario.vm)
			for _, s := range f.steps[failed+1:] {
				switch s.Kind {
				case "teardown", "remove", "terminate", "reclaim", "zero", "release", "close-driver":
				default:
					t.Errorf("forward work continued after failure: %s", s.Kind)
				}
			}
			for name, initialized := range map[string]uint64{"primary": scenario.wantPrimary, "late": scenario.wantLate} {
				var teardown, reclaim uint64
				for _, s := range f.steps {
					if s.Lifetime == name && s.Kind == "teardown" {
						teardown += uint64(s.Count)
					}
					if s.Lifetime == name && s.Kind == "reclaim" {
						reclaim += uint64(s.Count)
					}
				}
				if teardown != initialized || reclaim != initialized {
					t.Errorf("%s: cleanup discarded returned progress: teardown=%d reclaim=%d expected=%d",
						name, teardown, reclaim, initialized)
				}
			}
			if partitionStepPosition(f.steps, "terminate", "", "a") < 0 ||
				partitionStepPosition(f.steps, "release", "primary", "") < 0 {
				t.Error("acquired A/primary was lost on error/cancellation")
			}
			if scenario.lifetime == "late" && partitionStepPosition(f.steps, "release", "late", "") < 0 {
				t.Error("known late acquisition was not cleaned")
			}
			if scenario.kind == "late-prepare" || scenario.wantLate != 0 {
				if partitionStepPosition(f.steps, "remove", "late", "a") < 0 {
					t.Error("prepared unmapped late owner was not explicitly removed")
				}
			}
			if f.cleanupContextInvalid || f.doubleClose {
				t.Error("cleanup inherited cancellation or duplicated VM ownership")
			}
		})
	}
}

// TestProtectedSharedPartitionRetainsUncertain supplies unknown initialization/
// preparation or failed detach, VM termination and partial reclaim receipts.
// The affected lifetime must never be released, while independent safe owners
// still get cleanup. In particular late uncertainty cannot be mistaken for
// zero native initialization work or independent ownership of VM A.
func TestProtectedSharedPartitionRetainsUncertain(t *testing.T) {
	for _, scenario := range []struct {
		name, kind, lifetime, vm  string
		unframed, uncertain      bool
		retainPrimary, retainLate bool
	}{
		{"unknown primary init", "initialize", "primary", "", true, false, true, false},
		{"unknown primary page lock", "seal", "primary", "", true, false, true, false},
		{"unknown late owner", "late-prepare", "late", "a", false, true, false, true},
		{"unknown late init", "initialize", "late", "", true, false, false, true},
		{"primary detach failure", "remove", "primary", "a", false, false, true, false},
		{"late detach failure", "remove", "late", "a", false, false, false, true},
		{"A termination failure", "terminate", "", "a", false, false, true, true},
		{"B termination failure", "terminate", "", "b", false, false, true, false},
		{"primary partial reclaim", "reclaim", "primary", "", false, false, true, false},
		{"late partial reclaim", "reclaim", "late", "", false, false, false, true},
		{"late zero failure", "zero", "late", "", false, false, false, true},
	} {
		// Failure is injected only into this unit recorder, not the lab
		// coordinator/native implementation or partition sealing primitive.
		t.Run(scenario.name, func(t *testing.T) {
			f := newPartitionSealFake()
			f.failKind, f.failLifetime, f.failVM = scenario.kind, scenario.lifetime, scenario.vm
			f.unframed, f.uncertain = scenario.unframed, scenario.uncertain
			f.failErr = errors.New("uncertain or failed cleanup operation")
			if err := executePartitionSealProof(context.Background(), f, 5, time.Minute); err == nil {
				t.Fatal("uncertain/failed operation passed")
			}
			for name, retain := range map[string]bool{"primary": scenario.retainPrimary, "late": scenario.retainLate} {
				released := partitionStepPosition(f.steps, "release", name, "") >= 0
				acquired := partitionStepPosition(f.steps, "open", name, "") >= 0
				if retain && released {
					t.Errorf("%s backing released after uncertain/failed progress", name)
				}
				if acquired && !retain && !released {
					t.Errorf("independent safe %s lifetime was not cleaned", name)
				}
			}
			if f.cleanupContextInvalid || f.doubleClose {
				t.Error("unsafe VM or cleanup-context ownership")
			}
		})
	}
}

// TestProtectedSharedPartitionPartialSealing fails B's seal after A succeeded.
// Forward work must stop without negative probes or late creation, while normal
// two-VM teardown/reclaim/release remains required. No seal reopening operation
// exists in the recorder or coordinator; partial sealing is not special cleanup.
func TestProtectedSharedPartitionPartialSealing(t *testing.T) {
	f := newPartitionSealFake()
	f.failKind, f.failVM, f.failErr = "partition-seal", "b", errors.New("B seal failed")
	if err := executePartitionSealProof(context.Background(), f, 5, time.Minute); err == nil {
		t.Fatal("B seal failure passed")
	}
	if partitionStepPosition(f.steps, "partition-seal", "", "a") < 0 ||
		partitionStepPosition(f.steps, "hv-negative", "", "") >= 0 ||
		partitionStepPosition(f.steps, "open", "late", "") >= 0 ||
		partitionStepPosition(f.steps, "release", "primary", "") < 0 ||
		partitionStepPosition(f.steps, "terminate", "", "a") < 0 ||
		partitionStepPosition(f.steps, "terminate", "", "b") < 0 {
		t.Fatal("partial seal violated stop-forward or ordinary safe cleanup")
	}
}

// TestProtectedSharedPartitionNoPhantomOwner rejects invalid bounds without
// dispatch and exercises failed acquisition with no VM returned. Only actually
// returned VM ownership permits termination; sticky evidence still closes an
// acquired driver even though no backing or further forward work is allowed.
func TestProtectedSharedPartitionNoPhantomOwner(t *testing.T) {
	for _, pages := range []uint64{0, 4097} {
		f := newPartitionSealFake()
		if err := executePartitionSealProof(context.Background(), f, pages, time.Minute); err == nil || len(f.steps) != 0 {
			t.Error("invalid page bound acquired resources")
		}
	}
	f := newPartitionSealFake()
	f.failKind, f.failVM, f.omitVM, f.failErr = "prepare", "a", true, errors.New("no returned VM")
	if err := executePartitionSealProof(context.Background(), f, 1, time.Minute); err == nil ||
		partitionStepPosition(f.steps, "terminate", "", "") >= 0 || f.doubleClose {
		t.Error("failed acquisition invented a VM owner")
	}
	f = newPartitionSealFake()
	f.evidenceErr = errors.New("evidence write failed")
	if err := executePartitionSealProof(context.Background(), f, 1, time.Minute); err == nil ||
		partitionStepPosition(f.steps, "open", "", "") >= 0 ||
		partitionStepPosition(f.steps, "close-driver", "", "") < 0 {
		t.Error("sticky evidence failure hid acquisition or allowed forward progress")
	}
}

// TestProtectedSharedPartitionNamedPreparation keeps M1's single exact primary
// response requirement and permits only A's named metadata-only extra slot.
// Native ordinary-hidden slots may be omitted; an exposed/reversed property
// must not select late as primary. Duplicate/missing primary, unexpected or
// already-protected slots must fail without claiming ownership.
func TestProtectedSharedPartitionNamedPreparation(t *testing.T) {
	primary := hcsschema.SharedMemoryRegionInfo{SectionName: "primary", GuestPhysicalAddress: 10}
	late := hcsschema.SharedMemoryRegionInfo{SectionName: "late", GuestPhysicalAddress: 20}
	for _, scenario := range []struct {
		name, slot, id string
		regions        []hcsschema.SharedMemoryRegionInfo
		success        bool
	}{
		{"M1 one", "", "a", []hcsschema.SharedMemoryRegionInfo{primary}, true},
		{"M1 rejects extra", "", "a", []hcsschema.SharedMemoryRegionInfo{primary, late}, false},
		{"A reverse order", "late", "a", []hcsschema.SharedMemoryRegionInfo{late, primary}, true},
		{"B stays single", "late", "b", []hcsschema.SharedMemoryRegionInfo{primary}, true},
		{"B rejects extra", "late", "b", []hcsschema.SharedMemoryRegionInfo{primary, late}, false},
		{"duplicate primary", "late", "a", []hcsschema.SharedMemoryRegionInfo{primary, primary}, false},
		{"missing primary", "late", "a", []hcsschema.SharedMemoryRegionInfo{late, late}, false},
		{"native hidden omitted", "late", "a", []hcsschema.SharedMemoryRegionInfo{primary}, true},
		{"protected late", "late", "a", []hcsschema.SharedMemoryRegionInfo{primary,
			{SectionName: "late", ProtectedShared: &hcsschema.ProtectedSharedRegionInfo{}}}, false},
	} {
		found, err := selectProtectedProofRegion(scenario.regions, "primary", scenario.slot, scenario.id)
		if (err == nil) != scenario.success || (err == nil && (found == nil || found.GuestPhysicalAddress != 10)) {
			t.Errorf("%s: incorrect named region selection", scenario.name)
		}
	}
}
