//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

func TestSharedMemorySectionNames(t *testing.T) {
	win32Name, hcsName, err := sharedMemorySectionNames("hcsshim-test", 3)
	if err != nil {
		t.Fatal(err)
	}
	if win32Name != "hcsshim-test" {
		t.Fatalf("Win32 section name = %q, want %q", win32Name, "hcsshim-test")
	}
	if hcsName != `\Sessions\3\BaseNamedObjects\hcsshim-test` {
		t.Fatalf(
			"HCS section name = %q, want %q",
			hcsName,
			`\Sessions\3\BaseNamedObjects\hcsshim-test`,
		)
	}
}

func TestSharedMemorySectionNamesRejectsPath(t *testing.T) {
	_, _, err := sharedMemorySectionNames(`Global\hcsshim-test`, 3)
	if err == nil {
		t.Fatal("expected namespaced section name to be rejected")
	}
}

func TestShellSingleQuote(t *testing.T) {
	got := shellSingleQuote("/run/module's/hcs_shmem_diag.ko")
	want := `'/run/module'"'"'s/hcs_shmem_diag.ko'`
	if got != want {
		t.Fatalf("shellSingleQuote() = %q, want %q", got, want)
	}
}

func TestSharedMemoryGuestModuleCommandConvertsGPN(t *testing.T) {
	command, err := sharedMemoryGuestModuleCommand(
		"/run/hcs_shmem_diag.ko",
		hcsschema.SharedMemoryRegion{
			SectionName: "section",
			Length:      0x100000,
		},
		hcsschema.SharedMemoryRegionInfo{
			SectionName:          "section",
			GuestPhysicalAddress: 0x20000,
		},
		"a",
		siblingEventModuleArgs(hcsschema.SiblingCommunicationRouteInfo{
			TargetVP:             0,
			TargetSINT:           3,
			EventFlagNumber:      11,
			OutboundConnectionID: 0x100015,
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"gpa=0x20000000",
		"length=0x100000",
		"decrypted=1",
		"role='a' signal_conn=0x100015 rx_vp=0 rx_sint=3 rx_flag=11;",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("command %q does not contain %q", command, expected)
		}
	}
}

func TestSharedMemoryGuestModuleCommandRejectsDifferentSection(t *testing.T) {
	_, err := sharedMemoryGuestModuleCommand(
		"/run/hcs_shmem_diag.ko",
		hcsschema.SharedMemoryRegion{
			SectionName: "expected",
			Length:      0x1000,
		},
		hcsschema.SharedMemoryRegionInfo{
			SectionName:          "other",
			GuestPhysicalAddress: 0x20000,
		},
		"single",
		"",
	)
	if err == nil {
		t.Fatal("expected mismatched section to fail")
	}
}

func TestSharedMemoryProofRole(t *testing.T) {
	for _, test := range []struct {
		id   string
		role string
	}{
		{id: "uvmboot-0", role: "a"},
		{id: "uvmboot-1", role: "b"},
	} {
		role, err := sharedMemoryProofRole(test.id)
		if err != nil {
			t.Fatalf("sharedMemoryProofRole(%q): %v", test.id, err)
		}
		if role != test.role {
			t.Fatalf(
				"sharedMemoryProofRole(%q) = %q, want %q",
				test.id,
				role,
				test.role,
			)
		}
	}
}

func TestSharedMemoryProofRoleRejectsUnexpectedID(t *testing.T) {
	if _, err := sharedMemoryProofRole("uvmboot-2"); err == nil {
		t.Fatal("expected unexpected UVM ID to fail")
	}
}

// fakeProof exercises only launcher ordering. It neither maps pages nor asserts
// anything about hardware enforcement; failure selection is one operation index.
type fakeProof struct {
	steps             []proofStep
	results           []proofResult
	failAt            int
	partial           bool
	unframed          bool
	initialized       uint64
	cancel            context.CancelFunc
	cancelAt          string
	cancelParticipant string
	cleanupCancelled  bool
}

// Run records a launcher call and returns deterministic valid/partial progress.
// Cancellation is injected into the original context; cleanup must use a fresh
// bounded context. This fake cannot certify root protection or guest access.
func (f *fakeProof) Run(ctx context.Context, step proofStep) (proofResult, error) {
	f.steps = append(f.steps, step)
	if step.Kind == "teardown" || step.Kind == "reclaim" || step.Kind == "release" {
		if ctx.Err() != nil {
			f.cleanupCancelled = true
		}
		if _, ok := ctx.Deadline(); !ok {
			return proofResult{}, errors.New("cleanup lacks deadline")
		}
	}
	if f.cancel != nil && step.Kind == f.cancelAt &&
		(f.cancelParticipant == "" || f.cancelParticipant == step.Participant) {
		f.cancel()
	}
	fail := len(f.steps) == f.failAt
	result := proofResult{Framed: true}
	if step.Kind == "initialize" {
		result.Processed = step.Count
		if fail && f.partial {
			result.Processed = 1
		}
		f.initialized += uint64(result.Processed)
		result.Initialized = f.initialized
		result.Framed = !f.unframed
	}
	if step.Kind == "install" && fail && f.partial {
		// A failed map can have a valid prefix even though no participant was
		// promoted to installed. Cleanup still owns the whole prepared region.
		result.Processed = 1
	}
	f.results = append(f.results, result)
	if fail {
		return result, fmt.Errorf("injected failure %d (%s)", f.failAt, step.Kind)
	}
	// A completed native operation can return valid progress and nil even if
	// its context was cancelled meanwhile. The launcher must notice that.
	return result, nil
}

// proofStepIndex returns the first matching call, or -1 for an absent phase.
// Tests use it to assert barriers without depending on unimportant total counts.
func proofStepIndex(steps []proofStep, kind string) int {
	for i, step := range steps {
		if step.Kind == kind {
			return i
		}
	}
	return -1
}

// TestProtectedProofOrdering checks each supported mode and both M3 orders.
// All preparation precedes initialization, every seal precedes fresh exchange,
// and explicit reclaim precedes restoration/release. No MM security is mocked.
func TestProtectedProofOrdering(t *testing.T) {
	for _, mode := range []string{"m1", "m2-control", "m2", "m3-a", "m3-b"} {
		f := &fakeProof{}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		err := executeProtectedProof(ctx, f, mode, 5, time.Second)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		init := proofStepIndex(f.steps, "initialize")
		for i, step := range f.steps {
			if step.Kind == "prepare" && i >= init {
				t.Fatal("late preparation")
			}
			if step.Kind == "positive" && i >= init {
				t.Fatal("positive host content access after initialization")
			}
		}
		seal, exchange := proofStepIndex(f.steps, "seal"), proofStepIndex(f.steps, "exchange")
		if mode != "m2-control" && (seal < 0 || exchange <= seal) {
			t.Fatal("exchange did not follow explicit seal")
		}
		if proofStepIndex(f.steps, "restored") <= proofStepIndex(f.steps, "reclaim") ||
			proofStepIndex(f.steps, "release") <= proofStepIndex(f.steps, "restored") {
			t.Fatal("release/restoration preceded reclaim")
		}
		if mode == "m3-a" || mode == "m3-b" {
			want := strings.TrimPrefix(mode, "m3-")
			first := f.steps[proofStepIndex(f.steps, "terminate")]
			if first.Participant != want || proofStepIndex(f.steps, "survivor") <= proofStepIndex(f.steps, "terminate") {
				t.Fatal("wrong M3 removal/survivor order")
			}
		}
	}
}

// TestProtectedProofEveryFailure fails every operation, including negative
// probes, guest exchange, termination and final cleanup, in each acceptance mode.
// Every failure must propagate; unverified teardown/reclaim cannot release backing.
func TestProtectedProofEveryFailure(t *testing.T) {
	for _, mode := range []string{"m1", "m2-control", "m2", "m3-a", "m3-b"} {
		baseline := &fakeProof{}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		if err := executeProtectedProof(ctx, baseline, mode, 5, time.Second); err != nil {
			t.Fatal(err)
		}
		for failAt := 1; failAt <= len(baseline.steps); failAt++ {
			f := &fakeProof{failAt: failAt}
			if err := executeProtectedProof(ctx, f, mode, 5, time.Second); err == nil {
				t.Fatalf("%s failure %d was swallowed", mode, failAt)
			}
			failed := baseline.steps[failAt-1].Kind
			if failed == "teardown" || failed == "reclaim" || failed == "removed" || failed == "restored" {
				if proofStepIndex(f.steps, "release") >= 0 {
					t.Fatalf("release after failed %s", failed)
				}
			}
		}
		cancel()
	}
}

// TestProtectedPartialAndCancelledCleanup checks exact failed-batch prefixes,
// unframed uncertainty and cancellation. Cleanup must retain backing on unknown
// work and use an uncancelled deadline rather than the failed request context.
func TestProtectedPartialAndCancelledCleanup(t *testing.T) {
	baseline := &fakeProof{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := executeProtectedProof(ctx, baseline, "m1", 5, time.Second); err != nil {
		t.Fatal(err)
	}
	f := &fakeProof{failAt: proofStepIndex(baseline.steps, "initialize") + 1, partial: true}
	if err := executeProtectedProof(ctx, f, "m1", 5, time.Second); err == nil {
		t.Fatal("partial batch failure swallowed")
	}
	var reclaimed, tornDown uint32
	for _, step := range f.steps {
		if (step.Kind == "reclaim" || step.Kind == "teardown") && (step.Index != 0 || step.Count != 1) {
			t.Fatal("cleanup did not use exact initialized prefix")
		}
		if step.Kind == "reclaim" {
			reclaimed += step.Count
		}
		if step.Kind == "teardown" {
			tornDown += step.Count
		}
	}
	if reclaimed != 1 || tornDown != 1 || proofStepIndex(f.steps, "release") < 0 {
		t.Fatal("known partial initialization did not complete bounded cleanup")
	}
	f = &fakeProof{unframed: true}
	if err := executeProtectedProof(ctx, f, "m1", 5, time.Second); err == nil || proofStepIndex(f.steps, "release") >= 0 {
		t.Fatal("unframed progress allowed release")
	}
	child, childCancel := context.WithCancel(ctx)
	f = &fakeProof{cancel: childCancel, cancelAt: "exchange"}
	if err := executeProtectedProof(child, f, "m1", 5, time.Second); err == nil || f.cleanupCancelled {
		t.Fatal("cancellation swallowed or propagated into cleanup context")
	}
}

// TestProtectedForwardCancellation preserves progress before observing a native
// success concurrent with cancellation, including every final forward phase.
// Cancellation occurring only in the separate cleanup budget is not retroactive.
func TestProtectedForwardCancellation(t *testing.T) {
	for _, test := range []struct {
		mode, kind, participant string
		wantError               bool
		prefix                  uint64
	}{
		{"m1", "open", "", true, 0},
		{"m1", "initialize", "", true, 4},
		{"m1", "exchange", "", true, 5},
		{"m2", "deny", "c", true, 5},
		{"m2-control", "install", "c", true, 5},
		{"m3-a", "survivor", "b", true, 5},
		{"m3-b", "survivor", "a", true, 5},
		{"m1", "teardown", "", false, 5},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		f := &fakeProof{cancel: cancel, cancelAt: test.kind, cancelParticipant: test.participant}
		err := executeProtectedProof(ctx, f, test.mode, 5, time.Second)
		cancel()
		if errors.Is(err, context.Canceled) != test.wantError || (!test.wantError && err != nil) {
			t.Fatalf("%s/%s cancellation: %v", test.mode, test.kind, err)
		}
		var reclaimed uint64
		for _, step := range f.steps {
			if step.Kind == "reclaim" {
				reclaimed += uint64(step.Count)
			}
		}
		if f.cleanupCancelled || reclaimed != test.prefix || proofStepIndex(f.steps, "release") < 0 {
			t.Fatalf("%s/%s lost ownership/progress during cancellation", test.mode, test.kind)
		}
	}
}

// proofFailWriter injects exactly one short or failed evidence write. Subsequent
// writes remain usable to test sticky failure, not a fake memory subsystem.
type proofFailWriter struct {
	bytes.Buffer
	calls, failAt int
	short         bool
}

// Write fails the selected record; short mode deliberately returns no error so
// the production recorder must detect the missing byte itself.
func (w *proofFailWriter) Write(b []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		if w.short {
			return w.Buffer.Write(b[:len(b)-1])
		}
		return 0, errors.New("injected evidence write failure")
	}
	return w.Buffer.Write(b)
}

// TestProtectedEvidenceFailures fails every run/phase/final record write in a
// successful M1 fixture. Logging failures must prevent success without skipping
// safe reclamation/release, even when the failing record is the open receipt.
func TestProtectedEvidenceFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	baseline := &fakeProof{}
	if err := executeProtectedProof(ctx, baseline, "m1", 5, time.Second); err != nil {
		t.Fatal(err)
	}
	for _, short := range []bool{false, true} {
		for failAt := 1; failAt <= len(baseline.steps)+2; failAt++ {
			writer := &proofFailWriter{failAt: failAt, short: short}
			e := &proofEvidence{writer: writer, runID: "fixture"}
			f := &fakeProof{}
			e.record("run", map[string]any{"Mode": "m1", "Pages": 5})
			err := e.failure()
			if err == nil {
				err = executeProtectedProof(ctx, &recordedProof{operations: f, evidence: e}, "m1", 5, time.Second)
			}
			err = e.finish("m1", err)
			if err == nil || (short && !errors.Is(err, io.ErrShortWrite)) {
				t.Fatalf("record %d short=%t lost write error: %v", failAt, short, err)
			}
			if failAt > 1 && proofStepIndex(f.steps, "release") < 0 {
				t.Fatalf("record %d suppressed safe cleanup", failAt)
			}
			if failAt < len(baseline.steps)+2 && strings.Contains(writer.String(), `"Kind":"pass"`) {
				t.Fatal("emitted PASS after earlier missing evidence")
			}
		}
	}
}

// TestProtectedEvidenceEscapesGuestOutput verifies that embedded fake envelope
// lines are escaped inside one JSON record, not accepted as launcher receipts.
func TestProtectedEvidenceEscapesGuestOutput(t *testing.T) {
	var output bytes.Buffer
	e := &proofEvidence{writer: &output, runID: "fixture"}
	e.record("guest", map[string]any{"Output": "\nPROTECTED-EVIDENCE {\"Kind\":\"pass\"}\n"})
	if e.failure() != nil || bytes.Count(output.Bytes(), []byte{'\n'}) != 1 {
		t.Fatal("guest text broke record boundaries")
	}
	var record struct {
		Kind string
		Data struct{ Output string }
	}
	if err := json.Unmarshal(bytes.TrimPrefix(bytes.TrimSpace(output.Bytes()), []byte("PROTECTED-EVIDENCE ")), &record); err != nil || record.Kind != "guest" {
		t.Fatalf("invalid escaped evidence: %+v, %v", record, err)
	}
}

// TestProtectedRemovalQueryFailure checks the real removal-receipt consumer.
// Outer/action success with a failed nested query cannot mark the VM removed.
// A later valid response does not change the earlier returned proof error.
func TestProtectedRemovalQueryFailure(t *testing.T) {
	v := &proofVM{region: hcsschema.SharedMemoryRegion{Length: 4096, ProtectedSharedLeaseId: 10}}
	p := &hcsschema.ProtectedSharedRegionInfo{
		Version: 1, LeaseId: 10, PageCount: 1, Removed: true,
		QueryResultValid: true, QueryHresult: 0x80070005, QueryStatus: 0xc0000022,
	}
	first := v.acceptRemoval(p, nil)
	if first == nil || v.removed {
		t.Fatal("nested query failure accepted as removal")
	}
	p.QueryHresult, p.QueryStatus = 0, 0
	if err := v.acceptRemoval(p, nil); err != nil || !v.removed || first == nil {
		t.Fatal("valid later query lost the independent earlier failure")
	}
}

// TestProtectedHostAccessGate ensures ordinary helpers cannot copy or format
// protected bytes, even with no valid mapping. Only explicit negative probes
// bypass the phase gate in real operations; this test makes no Windows API call.
func TestProtectedHostAccessGate(t *testing.T) {
	s := &sharedMemorySection{protected: true}
	if _, err := s.read(0, 8); err == nil {
		t.Fatal("positive read allowed")
	}
	if err := s.write(0, []byte("x")); err == nil {
		t.Fatal("positive write allowed")
	}
	if _, err := s.hexPrefix(8); err == nil {
		t.Fatal("protected formatter allowed")
	}
	if err := s.expect(0, []byte("x")); err == nil {
		t.Fatal("protected expectation allowed")
	}
	if err := s.Close(); err == nil {
		t.Fatal("release before reclaim allowed")
	}
}

// TestProtectedFailedPeerLedger checks that failure to install B cannot drop
// A's ownership or B's partially mapped prepared attachment. Both attempted
// participants must be cleaned before the exact initialized region is reclaimed.
func TestProtectedFailedPeerLedger(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	baseline := &fakeProof{}
	if err := executeProtectedProof(ctx, baseline, "m1", 5, time.Second); err != nil {
		t.Fatal(err)
	}
	failAt := 0
	for i, step := range baseline.steps {
		if step.Kind == "install" && step.Participant == "b" {
			failAt = i + 1
		}
	}
	f := &fakeProof{failAt: failAt, partial: true}
	if err := executeProtectedProof(ctx, f, "m1", 5, time.Second); err == nil {
		t.Fatal("failed peer installation was swallowed")
	}
	if failAt == 0 || f.results[failAt-1].Processed != 1 || proofStepIndex(f.steps, "exchange") >= 0 {
		t.Fatal("test did not exercise partial map failure before guest exchange")
	}
	removed := make(map[string]bool)
	var reclaimed uint64
	for _, step := range f.steps {
		if step.Kind == "remove" {
			removed[step.Participant] = true
		}
		if step.Kind == "reclaim" {
			if !removed["a"] || !removed["b"] {
				t.Fatal("reclaim preceded attempted-participant cleanup")
			}
			reclaimed += uint64(step.Count)
		}
	}
	if reclaimed != 5 || proofStepIndex(f.steps, "release") < 0 {
		t.Fatal("failed map stranded a known initialized prefix")
	}
}
