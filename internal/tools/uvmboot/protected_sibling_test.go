//go:build windows

package main

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
)

// protectedDependencyBarrier permits deterministic callback overlap without
// sleeps; releasing it more than once is safe, including during test cleanup.
type protectedDependencyBarrier struct {
	ch   chan struct{}
	once sync.Once
}

// newProtectedDependencyBarrier creates an initially blocked callback gate.
func newProtectedDependencyBarrier() *protectedDependencyBarrier {
	return &protectedDependencyBarrier{ch: make(chan struct{})}
}

// release unblocks the callback and any later observation of this barrier.
func (b *protectedDependencyBarrier) release() {
	// The once callback permits both the scenario and cleanup to release.
	b.once.Do(func() { close(b.ch) })
}

// protectedDependencyFixture records only dependency operations, not native
// startup/receipts. Its barriers exercise the production owner's real ordering.
type protectedDependencyFixture struct {
	pair         *protectedSiblingPair
	owner        *protectedSiblingDependencies
	creation     *protectedDependencyBarrier
	ready        *protectedDependencyBarrier
	exit         *protectedDependencyBarrier
	waitReturn   *protectedDependencyBarrier
	startEntered chan struct{}
	waitEntered  chan struct{}
	readyEntered chan struct{}
	depCtx       context.Context
	startErr     error
	exited       bool
	exitErr      error
	quiesceErr   error
	releaseErr   error
	mu           sync.Mutex
	calls        []string
}

// record serializes callback evidence so tests can inspect overlap safely.
func (f *protectedDependencyFixture) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

// recorded returns an independent snapshot of the observed callback order.
func (f *protectedDependencyFixture) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// newProtectedDependencyFixture supplies explicit per-instance callbacks and a
// retained bundle/mount record; it fabricates no native backing authority.
func newProtectedDependencyFixture(t *testing.T) *protectedDependencyFixture {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	f := &protectedDependencyFixture{
		pair:     &protectedSiblingPair{ctx: ctx, cancel: cancel},
		creation: newProtectedDependencyBarrier(), ready: newProtectedDependencyBarrier(),
		exit: newProtectedDependencyBarrier(), waitReturn: newProtectedDependencyBarrier(),
		startEntered: make(chan struct{}), waitEntered: make(chan struct{}), readyEntered: make(chan struct{}),
		exited: true,
	}
	f.creation.release()
	f.waitReturn.release()
	root := &siblingStorageAttachment{
		// release models only the Mount.Release outcome and records its order.
		release: func(context.Context) error {
			f.record("release")
			return f.releaseErr
		},
	}
	ops := protectedSiblingDependencyOps{
		// start may remain synchronous past cancellation, like GCS creation.
		start: func(ctx context.Context) error {
			f.depCtx = ctx
			f.record("start")
			close(f.startEntered)
			<-f.creation.ch
			return f.startErr
		},
		// stop requests exit without cancelling dependency borrowers.
		stop: func(context.Context) error {
			f.record("stop")
			f.exit.release()
			return nil
		},
		// wait retains the borrower until both exit and explicit join gates.
		wait: func() (bool, error) {
			f.record("wait")
			close(f.waitEntered)
			select {
			case <-f.exit.ch:
			case <-f.depCtx.Done():
			}
			<-f.waitReturn.ch
			f.record("joined")
			return f.exited, f.exitErr
		},
		// ready is independent of creation and can be interrupted by exit.
		ready: func(ctx context.Context) error {
			f.record("ready")
			close(f.readyEntered)
			select {
			case <-f.ready.ch:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		// quiesce records confirmed provider drain or an explicit failure.
		quiesce: func(context.Context) error {
			f.record("quiesce")
			return f.quiesceErr
		},
	}
	f.owner = newProtectedSiblingDependencies(f.pair.stop, ops, &protectedSiblingVM{bundleOwned: true}, root)
	f.pair.mediated = f.owner
	// Cleanup releases test barriers before joining, even after a failed
	// assertion; it never leaves a fixture-owned borrower running.
	t.Cleanup(func() {
		f.creation.release()
		f.ready.release()
		f.waitReturn.release()
		f.exit.release()
		cancel(nil)
		_ = f.pair.joinServices(context.Background())
		_ = f.owner.drain(context.Background(), true)
	})
	return f
}

// protectedDependencyAwait bounds a barrier observation, failing rather than
// hanging the suite if an owner transition no longer reaches its callback.
func protectedDependencyAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("dependency callback did not reach barrier")
	}
}

// protectedDependencyResult bounds observation of a helper's returned error.
func protectedDependencyResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("dependency helper did not return")
		return nil
	}
}

// TestProtectedRelayReadinessSeparateFromCreation checks T3's early-process
// overlap: creation alone cannot satisfy even relay readiness, and readiness
// does not end the service. Workload Start/receipt gating is separate.
func TestProtectedRelayReadinessSeparateFromCreation(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.owner.start(ctx); err != nil {
		t.Fatal(err)
	}
	protectedDependencyAwait(t, f.waitEntered)
	result := make(chan error, 1)
	// Exercise the real readiness helper while the service is still running.
	go func() { result <- f.owner.waitReady(ctx) }()
	protectedDependencyAwait(t, f.readyEntered)
	select {
	case err := <-result:
		t.Fatalf("process creation was mistaken for readiness: %v", err)
	default:
	}
	f.ready.release()
	if err := protectedDependencyResult(t, result); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.owner.done:
		t.Fatal("relay readiness ended the dependency lifetime")
	default:
	}
	if f.pair.ctx.Err() != nil {
		t.Fatal("relay readiness cancelled forward work")
	}
}

// TestProtectedRelayForwardStopPreservesDependencies checks T4: stop and an
// unconfirmed workload drain must not kill the relay or release its root.
func TestProtectedRelayForwardStopPreservesDependencies(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	if err := f.owner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	protectedDependencyAwait(t, f.waitEntered)
	f.pair.stop(context.Canceled)
	if f.depCtx.Err() != nil {
		t.Fatal("forward cancellation destroyed dependency context")
	}
	if err := f.owner.drain(context.Background(), false); err == nil {
		t.Fatal("unconfirmed workload drainage allowed cleanup")
	}
	if f.depCtx.Err() != nil || f.owner.root == nil || f.owner.providerDrained {
		t.Fatal("dependencies released before workload drainage")
	}
	if err := f.owner.drain(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.recorded(), []string{"start", "wait", "stop", "joined", "quiesce", "release"}) {
		t.Fatalf("invalid consumer/provider order: %v", f.recorded())
	}
}

// TestProtectedRelayExpectedClosingDoesNotCrash checks T4's expected-exit
// distinction: an owned nonzero process exit during drain is not a pair crash.
func TestProtectedRelayExpectedClosingDoesNotCrash(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	// This is an error-type fixture only; f.exited separately supplies the
	// observed-exit decision and no real command or native startup is faked.
	f.exitErr = &cmd.ExitError{ExitState: &cmd.ExitState{}}
	if err := f.owner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.drain(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if f.pair.ctx.Err() != nil {
		t.Fatalf("expected closing reported a crash: %v", context.Cause(f.pair.ctx))
	}
}

// TestProtectedRelayExpectedExitBeforeDrain checks S2-R1's workload-first stop
// interval: relay completion after beginClosing but before dependency drainage
// must not report a crash or release dependencies. Stream/Close errors and
// unconfirmed process exit must remain observable during the later drain.
func TestProtectedRelayExpectedExitBeforeDrain(t *testing.T) {
	streamFailure := errors.New("stream/Close join failed")
	waitFailure := errors.New("process exit unconfirmed")
	tests := []struct {
		name    string
		exited  bool
		exitErr error
		wantErr error
	}{
		{name: "clean-exit", exited: true},
		{name: "workload-eof", exited: true, exitErr: &cmd.ExitError{ExitState: &cmd.ExitState{}}},
		{
			name: "joined-error", exited: true,
			exitErr: errors.Join(&cmd.ExitError{ExitState: &cmd.ExitState{}}, streamFailure),
			wantErr: streamFailure,
		},
		{name: "unconfirmed-exit", exitErr: waitFailure, wantErr: waitFailure},
	}
	for _, tt := range tests {
		// Each case completes the relay behind a barrier before drain, so
		// dependency cancellation cannot accidentally make the exit expected.
		t.Run(tt.name, func(t *testing.T) {
			f := newProtectedDependencyFixture(t)
			f.exited, f.exitErr = tt.exited, tt.exitErr
			if err := f.owner.start(context.Background()); err != nil {
				t.Fatal(err)
			}
			protectedDependencyAwait(t, f.waitEntered)
			f.owner.beginClosing()
			if f.depCtx.Err() != nil || f.pair.ctx.Err() != nil ||
				!reflect.DeepEqual(f.recorded(), []string{"start", "wait"}) {
				t.Fatal("expected-closing transition stopped or cancelled dependencies")
			}
			// Model relay EOF caused by workload termination, with provider/
			// attachment drainage deliberately not entered yet.
			f.exit.release()
			protectedDependencyAwait(t, f.owner.done)
			if f.pair.ctx.Err() != nil || f.owner.failure != nil {
				t.Fatalf("expected pre-drain exit reported a crash: %v", context.Cause(f.pair.ctx))
			}
			if f.depCtx.Err() != nil || f.owner.root == nil ||
				f.owner.providerDrained || f.owner.rootReleased ||
				!reflect.DeepEqual(f.recorded(), []string{"start", "wait", "joined"}) {
				t.Fatal("expected relay completion destroyed still-owned dependencies")
			}
			err := f.owner.drain(context.Background(), true)
			if (tt.wantErr == nil && err != nil) || (tt.wantErr != nil && !errors.Is(err, tt.wantErr)) {
				t.Fatalf("drain error = %v, want %v", err, tt.wantErr)
			}
			if f.pair.ctx.Err() != nil {
				t.Fatal("drain converted expected completion into a crash")
			}
			if tt.exited {
				if !f.owner.providerDrained || !f.owner.rootReleased {
					t.Fatal("confirmed exit did not permit ordered dependency drainage")
				}
			} else if f.owner.root == nil || f.owner.providerDrained || f.owner.rootReleased {
				t.Fatal("unconfirmed exit allowed dependency release")
			}
		})
	}
}

// TestProtectedRelayExpectedExitPreservesDrainErrors checks T4: normalizing an
// expected termination must not swallow a joined stream/Close failure or erase
// confirmed release progress. Closing still must not create a new pair crash.
func TestProtectedRelayExpectedExitPreservesDrainErrors(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	failure := errors.New("final stream drain failed")
	f.exitErr = errors.Join(&cmd.ExitError{ExitState: &cmd.ExitState{}}, failure)
	if err := f.owner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.drain(context.Background(), true); !errors.Is(err, failure) {
		t.Fatalf("expected exit hid a separate drainage error: %v", err)
	}
	if !f.owner.providerDrained || !f.owner.rootReleased || f.pair.ctx.Err() != nil {
		t.Fatal("drain error erased exact progress or created a closing crash")
	}
}

// TestProtectedRelayUnexpectedExitCancelsReadiness checks T3/T4: an exit after
// creation cancels pending readiness, preserves its cause and never releases
// root dependencies merely because the foreground service died. A later
// expected-closing transition must not erase the already observed failure.
func TestProtectedRelayUnexpectedExitCancelsReadiness(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	failure := errors.New("relay transport failed")
	f.exitErr = failure
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.owner.start(ctx); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	// Readiness deliberately remains pending until unexpected process exit.
	go func() { result <- f.owner.waitReady(ctx) }()
	protectedDependencyAwait(t, f.readyEntered)
	f.exit.release()
	if err := protectedDependencyResult(t, result); !errors.Is(err, failure) {
		t.Fatalf("lost relay failure: %v", err)
	}
	if !errors.Is(context.Cause(f.pair.ctx), failure) || f.depCtx.Err() != nil || f.owner.root == nil {
		t.Fatal("exit lost its cause or destroyed still-needed dependencies")
	}
	f.owner.beginClosing()
	if err := f.owner.drain(ctx, true); !errors.Is(err, failure) {
		t.Fatalf("cleanup hid the original service failure: %v", err)
	}
}

// TestProtectedRelayMarkerCannotOverrideExit checks T3's stale-success race:
// even a successful ready-file callback cannot revive an exited relay or permit
// a later ready/seal phase. The bootstrap helper separately gates the handshake.
func TestProtectedRelayMarkerCannotOverrideExit(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	failure := errors.New("relay exited after writing ready file")
	f.exitErr = failure
	if err := f.owner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.ready.release()
	f.exit.release()
	protectedDependencyAwait(t, f.owner.done)
	if err := f.owner.waitReady(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("ready marker overrode process exit: %v", err)
	}
	if f.owner.root == nil {
		t.Fatal("marker/exit observation released live workload dependencies")
	}
}

// TestProtectedRelayCancelledReadinessJoinsBorrower checks T3/T4: cancellation
// fails readiness but cannot return while a synchronous GCS borrower still
// runs, nor kill dependencies that workload shutdown may still require.
func TestProtectedRelayCancelledReadinessJoinsBorrower(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	join := newProtectedDependencyBarrier()
	t.Cleanup(join.release)
	cancelObserved := make(chan struct{})
	// Model a synchronous ready check that notices cancellation but cannot
	// return until its native/GCS call releases the borrowed VM.
	f.owner.ops.ready = func(ctx context.Context) error {
		close(f.readyEntered)
		<-ctx.Done()
		close(cancelObserved)
		<-join.ch
		return ctx.Err()
	}
	if err := f.owner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	// Observe the production helper's join rather than a test-only flow.
	go func() { result <- f.owner.waitReady(ctx) }()
	protectedDependencyAwait(t, f.readyEntered)
	cancel()
	protectedDependencyAwait(t, cancelObserved)
	select {
	case err := <-result:
		t.Fatalf("readiness abandoned a synchronous borrower: %v", err)
	default:
	}
	join.release()
	if err := protectedDependencyResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("readiness lost cancellation: %v", err)
	}
	if f.depCtx.Err() != nil || f.owner.root == nil || f.pair.ctx.Err() == nil {
		t.Fatal("failed readiness did not stop forward work independently")
	}
}

// TestProtectedRelayCreationFailureRetainsOwners checks T3/T4: failure during
// Start is not proof of zero native progress, so Wait is not called and root/
// bundle ownership survives even after the creation call has been joined.
func TestProtectedRelayCreationFailureRetainsOwners(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	failure := errors.New("GCS creation outcome unavailable")
	f.startErr = failure
	if err := f.owner.start(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("lost creation failure: %v", err)
	}
	if err := f.owner.drain(context.Background(), true); !errors.Is(err, failure) {
		t.Fatalf("uncertain creation was treated as drained: %v", err)
	}
	if !reflect.DeepEqual(f.recorded(), []string{"start"}) ||
		f.owner.root == nil || f.owner.rootOwner == nil || f.owner.providerDrained {
		t.Fatalf("uncertain creation released ownership: %v", f.recorded())
	}
}

// TestProtectedRelayCancelledBeforeCreation checks T3: a pre-cancelled forward
// budget must not dispatch new dependency work or manufacture creation progress.
func TestProtectedRelayCancelledBeforeCreation(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.owner.start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled creation lost its cause: %v", err)
	}
	if f.owner.attempted || len(f.recorded()) != 0 || f.owner.root == nil {
		t.Fatal("pre-cancelled startup dispatched work or discarded ownership")
	}
}

// TestProtectedRelayCancelledCreationIsJoined checks T3/T4: forward cancellation
// can return while synchronous creation is blocked, but cleanup must retain the
// borrower and cannot quiesce/release until creation and Wait actually finish.
func TestProtectedRelayCancelledCreationIsJoined(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	f.creation = newProtectedDependencyBarrier()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	// Block real owner creation, rather than a separate simulated startup flow.
	go func() { result <- f.owner.start(ctx) }()
	protectedDependencyAwait(t, f.startEntered)
	cancel()
	if err := protectedDependencyResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost forward cancellation: %v", err)
	}
	if f.depCtx.Err() != nil {
		t.Fatal("creation cancellation killed dependency lifetime")
	}
	if err := f.owner.drain(ctx, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup abandoned blocked creation: %v", err)
	}
	if f.owner.root == nil || f.owner.providerDrained {
		t.Fatal("root released before creation outcome was joined")
	}
	f.creation.release()
	if err := f.owner.drain(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	calls := f.recorded()
	if len(calls) != 6 || calls[0] != "start" || calls[3] != "joined" ||
		calls[4] != "quiesce" || calls[5] != "release" {
		t.Fatalf("creation borrower was not joined first: %v", calls)
	}
}

// TestProtectedRelayCleanupTimeoutRetainsBorrower checks T4: a cancelled cleanup
// budget is not proof of Wait completion and must retain root/bundle records.
func TestProtectedRelayCleanupTimeoutRetainsBorrower(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	f.waitReturn = newProtectedDependencyBarrier()
	if err := f.owner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	protectedDependencyAwait(t, f.waitEntered)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.owner.drain(ctx, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("missing incomplete join error: %v", err)
	}
	if f.owner.root == nil || f.owner.rootOwner == nil || f.owner.providerDrained {
		t.Fatal("unjoined Wait allowed root release")
	}
	f.waitReturn.release()
	if err := f.owner.drain(context.Background(), true); err != nil {
		t.Fatal(err)
	}
}

// TestProtectedRelayJoinedWaitIsNotExitProof checks T4: a failed process wait
// can finish every host borrower without observing guest exit. A late provider
// starter could still run, so neither quiescence nor disk release may follow.
func TestProtectedRelayJoinedWaitIsNotExitProof(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	failure := errors.New("process wait transport lost")
	f.exited, f.exitErr = false, failure
	if err := f.owner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	protectedDependencyAwait(t, f.waitEntered)
	if err := f.owner.drain(context.Background(), true); !errors.Is(err, failure) {
		t.Fatalf("unobserved exit lost the wait error: %v", err)
	}
	if f.owner.root == nil || f.owner.rootOwner == nil || f.owner.providerDrained {
		t.Fatal("joined but unobserved process exit released dependencies")
	}
	calls := f.recorded()
	if len(calls) != 4 || calls[0] != "start" || calls[3] != "joined" {
		t.Fatalf("provider cleanup raced an unconfirmed starter exit: %v", calls)
	}
	if f.pair.ctx.Err() != nil {
		t.Fatal("expected closing was reported as a new crash")
	}
}

// TestProtectedRelayDrainAndReleaseFailuresRetainRoot checks T4: neither a failed
// provider check nor failed guest unplug/host detach can erase the mount record;
// a later confirmed release may advance without repeating successful drainage.
func TestProtectedRelayDrainAndReleaseFailuresRetainRoot(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	drainFailure, releaseFailure := errors.New("provider busy"), errors.New("guest unplug failed")
	f.quiesceErr = drainFailure
	if err := f.owner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	protectedDependencyAwait(t, f.waitEntered)
	if err := f.owner.drain(context.Background(), true); !errors.Is(err, drainFailure) {
		t.Fatalf("lost provider failure: %v", err)
	}
	if f.owner.root == nil || f.owner.providerDrained {
		t.Fatal("failed provider check allowed root release")
	}
	f.quiesceErr, f.releaseErr = nil, releaseFailure
	if err := f.owner.drain(context.Background(), true); !errors.Is(err, releaseFailure) {
		t.Fatalf("lost release failure: %v", err)
	}
	if f.owner.root == nil || f.owner.rootOwner == nil || !f.owner.providerDrained {
		t.Fatal("failed release discarded mount/bundle or confirmed drain evidence")
	}
	f.releaseErr = nil
	if err := f.owner.drain(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if f.owner.root != nil || !f.owner.rootReleased {
		t.Fatal("successful release did not advance ownership")
	}
	want := []string{"start", "wait", "stop", "joined", "quiesce", "quiesce", "release", "release"}
	if !reflect.DeepEqual(f.recorded(), want) {
		t.Fatalf("unexpected drain/release transitions: %v", f.recorded())
	}
}

// TestProtectedRelayForegroundCommand checks relevant T6 contracts without guest
// execution: fresh exclusive paths, guarded peer discovery, actual RP identity,
// read-only provider before foreground relay, and no workload-IP/GCS dependency.
func TestProtectedRelayForegroundCommand(t *testing.T) {
	plan := storageTestPlan(t)
	plan.Disks = plan.Disks[:1]
	reports := []siblingStorageBackendReport{{
		DiskID: "workload-root", Role: "root", ReadOnly: true, ExportLUN: 0,
		ControllerID: guestrequest.ScsiControllerGuids[0], LUN: 7,
	}}
	bus, storage := "/run/staged bus/sibling_bus.ko", "/run/storage/diode_storvsp.ko"
	command, ready, err := protectedSiblingRelayCommands("pair fixture", bus, storage, plan, reports)
	if err != nil {
		t.Fatal(err)
	}

	other, otherReady, err := protectedSiblingRelayCommands("pair fixture", bus, storage, plan, reports)
	if err != nil {
		t.Fatal(err)
	}
	if command == other || ready == otherReady {
		t.Fatal("relay reused another run's ready/log paths")
	}
	for _, fragment := range []string{
		"umask 077; mkdir '/run/protected-sibling-",
		"trap 'exit 1' TERM INT;",
		"protected diode bootstrap/relay run=pair fixture",
		siblingBusLoadCommand(bus), siblingInstanceDiscoveryCommand(), siblingVsockReadyCommand(diodeRole),
		`[ "$sb_peer" = 3 ]`, storageRPDeviceCommand(reports[0].ControllerID, 7),
		"insmod '" + storage + "'", "'luns=0'", "'read_only=true'",
		"exec /bin/gcs -sibling-relay -relay-ready '/run/protected-sibling-",
	} {
		if !strings.Contains(command, fragment) {
			t.Fatalf("missing protected bootstrap contract %q", fragment)
		}
	}
	if strings.Index(command, "insmod '"+storage+"'") > strings.Index(command, "exec /bin/gcs") {
		t.Fatal("relay starts before root provider registration")
	}
	for _, forbidden := range []string{" & ", "rm -f", "ip addr", "ip route", "ahv-guest-ctl", "/dev/sda", "GCS_RELAY_READY"} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("early bootstrap introduced forbidden dependency/behavior %q", forbidden)
		}
	}
	if !strings.Contains(ready, "relay.ready") || !strings.Contains(ready, "relay.log") ||
		!strings.Contains(ready, "readiness timed out") || strings.Contains(ready, "GCS_RELAY_READY") {
		t.Fatal("relay readiness lacks explicit fresh-path observation/failure")
	}
	reports[0].ReadOnly = false
	if _, _, err := protectedSiblingRelayCommands("pair fixture", bus, storage, plan, reports); err == nil {
		t.Fatal("accepted writable root provider")
	}
}

// protectedBootstrapTestOps labels the production helper's callback boundaries.
// It supplies orchestration observations only, never VM/controller receipts.
func protectedBootstrapTestOps(call func(context.Context, string) error) protectedSiblingBootstrapOps {
	// step binds one boundary while keeping all effects instance-local.
	step := func(name string) func(context.Context) error {
		// Record/perform only the selected scenario's orchestration callback.
		return func(ctx context.Context) error { return call(ctx, name) }
	}
	return protectedSiblingBootstrapOps{
		bootstrap: step("bootstrap"), create: step("create"), configure: step("configure"),
		attach: step("attach"), stageDiode: step("stage-diode"),
		startServer:       step("start-server"),
		startDependencies: step("start-dependencies"), startWorkload: step("start-workload"),
		ready: step("relay-ready"), stageWorkload: step("stage-workload"),
	}
}

// TestProtectedCombinedBootstrapOverlap checks T3/T6 through the production
// orchestrator: configure and diode staging precede Start, early dependencies
// survive a pending workload handshake, and a ready marker cannot skip it.
func TestProtectedCombinedBootstrapOverlap(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	workload := newProtectedDependencyBarrier()
	t.Cleanup(workload.release)
	entered := make(chan struct{})
	// Model only workload GCS blocking; native receipt validation remains
	// concrete in the production startWorkload callback, outside this seam.
	ops := protectedBootstrapTestOps(func(ctx context.Context, name string) error {
		f.record(name)
		switch name {
		case "start-dependencies":
			if err := f.owner.start(ctx); err != nil {
				return err
			}
			<-f.waitEntered
		case "start-workload":
			close(entered)
			select {
			case <-workload.ch:
			case <-ctx.Done():
				return ctx.Err()
			}
		case "relay-ready":
			return f.owner.waitReady(ctx)
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	// Run the same ordered bootstrap helper that the real pair uses.
	go func() { result <- protectedSiblingBootstrap(ctx, ops) }()
	protectedDependencyAwait(t, entered)
	f.ready.release()
	want := []string{"bootstrap", "create", "configure", "attach", "stage-diode", "start-server",
		"start-dependencies", "start", "wait", "start-workload"}
	if !reflect.DeepEqual(f.recorded(), want) {
		t.Fatalf("incorrect native/configure/dependency order: %v", f.recorded())
	}
	select {
	case err := <-result:
		t.Fatalf("relay marker bypassed workload handshake: %v", err)
	default:
	}
	workload.release()
	if err := protectedDependencyResult(t, result); err != nil {
		t.Fatal(err)
	}
	want = append(want, "relay-ready", "ready", "stage-workload")
	if !reflect.DeepEqual(f.recorded(), want) || f.depCtx.Err() != nil {
		t.Fatalf("readiness/tool staging order or dependency lifetime changed: %v", f.recorded())
	}
}

// TestProtectedCombinedBootstrapFailures checks T3's before/after-create and
// readiness failures at every production callback boundary. No later tool/
// readiness step may run after an error, including a failed workload Start.
func TestProtectedCombinedBootstrapFailures(t *testing.T) {
	steps := []string{"bootstrap", "create", "configure", "attach", "stage-diode", "start-server",
		"start-dependencies", "start-workload", "relay-ready", "stage-workload"}
	for i, failed := range steps {
		// Each independent failure must leave exactly its attempted prefix.
		t.Run(failed, func(t *testing.T) {
			failure := errors.New("failed " + failed)
			var calls []string
			// Return an error at one orchestration boundary, without native fakes.
			ops := protectedBootstrapTestOps(func(_ context.Context, name string) error {
				calls = append(calls, name)
				if name == failed {
					return failure
				}
				return nil
			})
			if err := protectedSiblingBootstrap(context.Background(), ops); !errors.Is(err, failure) {
				t.Fatalf("lost bootstrap failure: %v", err)
			}
			if !reflect.DeepEqual(calls, steps[:i+1]) {
				t.Fatalf("work continued after failure: %v", calls)
			}
		})
	}
}

// TestProtectedCombinedBootstrapCancellation checks T3: cancellation returned
// by an otherwise successful callback prevents every later boundary, including
// tool/readiness steps, and final callback cancellation cannot report success.
func TestProtectedCombinedBootstrapCancellation(t *testing.T) {
	steps := []string{"bootstrap", "create", "configure", "attach", "stage-diode", "start-server",
		"start-dependencies", "start-workload", "relay-ready", "stage-workload"}
	for i := -1; i < len(steps); i++ {
		ctx, cancel := context.WithCancel(context.Background())
		var calls []string
		if i == -1 {
			cancel()
		}
		// Cancel after a selected synchronous borrower has returned its work.
		ops := protectedBootstrapTestOps(func(_ context.Context, name string) error {
			calls = append(calls, name)
			if i >= 0 && name == steps[i] {
				cancel()
			}
			return nil
		})
		err := protectedSiblingBootstrap(ctx, ops)
		cancel()
		if !errors.Is(err, context.Canceled) || len(calls) != i+1 {
			t.Fatalf("cancel boundary=%d: calls=%v err=%v", i, calls, err)
		}
	}
}

// protectedDrainTestOps binds shutdown ordering to the real dependency owner.
// Native termination is represented only by a confirmed-drain decision, not a
// fake VM or protected backing receipt.
func protectedDrainTestOps(f *protectedDependencyFixture, forwardErr error,
	workloadDrained, diodeDrained bool) protectedSiblingDrainOps {
	return protectedSiblingDrainOps{
		// joinForward must finish while both dependency paths are still live.
		joinForward: func(context.Context) error {
			f.record("join-forward")
			return forwardErr
		},
		// Mark expected EOF without cancelling dependencies or erasing failure.
		beginClosing: func() {
			f.record("begin-closing")
			f.owner.beginClosing()
		},
		// Termination may cause relay EOF before the later drain call.
		terminateWorkload: func(context.Context) (bool, error) {
			f.record("terminate-workload")
			if workloadDrained {
				f.exit.release()
				<-f.owner.done
				return true, nil
			}
			return false, errors.New("workload wait unconfirmed")
		},
		// Use the production lifetime/retention decisions, not a fake drain.
		drainDependencies: func(ctx context.Context, drained bool) error {
			f.record("drain-dependencies")
			return f.owner.drain(ctx, drained)
		},
		// A diode stop is still attempted after earlier unconfirmed drainage.
		terminateDiode: func(context.Context) (bool, error) {
			f.record("terminate-diode")
			if !diodeDrained {
				return false, errors.New("diode wait unconfirmed")
			}
			return true, nil
		},
	}
}

// TestProtectedCombinedDrainOrdering checks T4/S2-R1 at the production cleanup
// seam. Forward borrowers join before expected EOF/native workload termination;
// provider/root release precede diode termination and backing-release authority.
func TestProtectedCombinedDrainOrdering(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	if err := f.owner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	protectedDependencyAwait(t, f.waitEntered)
	safe, err := protectedSiblingDrain(context.Background(), protectedDrainTestOps(f, nil, true, true))
	if err != nil || !safe {
		t.Fatalf("confirmed ordered cleanup did not authorize later backing cleanup: %v", err)
	}
	want := []string{"start", "wait", "join-forward", "begin-closing", "terminate-workload",
		"joined", "drain-dependencies", "quiesce", "release", "terminate-diode"}
	if !reflect.DeepEqual(f.recorded(), want) || f.pair.ctx.Err() != nil ||
		!f.owner.rootReleased || !f.owner.providerDrained {
		t.Fatalf("unsafe cleanup/expected EOF handling: %v cause=%v", f.recorded(), context.Cause(f.pair.ctx))
	}
}

// TestProtectedCombinedDrainFailures checks T4: failed borrower/native drainage,
// quiescence, root unplug or cleanup budget cannot authorize backing release.
// Native diode termination remains best-effort even when root ownership stays.
func TestProtectedCombinedDrainFailures(t *testing.T) {
	for _, scenario := range []string{"forward-join", "workload-wait", "provider", "root-release", "diode-wait", "timeout"} {
		// Each case drives the actual dependency retention helper.
		t.Run(scenario, func(t *testing.T) {
			f := newProtectedDependencyFixture(t)
			failure := errors.New(scenario)
			var forwardErr error
			workloadDrained, diodeDrained := true, true
			switch scenario {
			case "forward-join":
				forwardErr = failure
			case "workload-wait":
				workloadDrained = false
			case "provider":
				f.quiesceErr = failure
			case "root-release":
				f.releaseErr = failure
			case "diode-wait":
				diodeDrained = false
			}
			if err := f.owner.start(context.Background()); err != nil {
				t.Fatal(err)
			}
			protectedDependencyAwait(t, f.waitEntered)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "timeout" {
				cancel()
				f.quiesceErr = context.Canceled
			}
			safe, err := protectedSiblingDrain(ctx, protectedDrainTestOps(f, forwardErr, workloadDrained, diodeDrained))
			if safe || err == nil {
				t.Fatal("incomplete cleanup authorized backing release")
			}
			calls := f.recorded()
			if calls[len(calls)-1] != "terminate-diode" {
				t.Fatalf("early failure skipped native diode termination: %v", calls)
			}
			if scenario != "diode-wait" && (f.owner.root == nil || f.owner.rootOwner == nil || f.owner.rootReleased) {
				t.Fatal("unresolved usage/release discarded workload root ownership")
			}
		})
	}
}

// TestProtectedCombinedFailedWorkloadKeepsDependencies checks T3/T4 after real
// helper-owned process creation: a workload Start failure skips all later
// readiness/staging, but forward stop cannot kill the dependency lifetime.
func TestProtectedCombinedFailedWorkloadKeepsDependencies(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	failure := errors.New("workload Start failed")
	// Reuse the production bootstrap owner and its independent dependency ctx.
	ops := protectedBootstrapTestOps(func(ctx context.Context, name string) error {
		f.record(name)
		switch name {
		case "start-dependencies":
			return f.owner.start(ctx)
		case "start-workload":
			return failure
		case "relay-ready", "stage-workload":
			t.Error("unsafe readiness after failed workload Start")
		}
		return nil
	})
	if err := protectedSiblingBootstrap(context.Background(), ops); !errors.Is(err, failure) {
		t.Fatalf("lost workload failure: %v", err)
	}
	protectedDependencyAwait(t, f.waitEntered)
	f.pair.stop(failure)
	if f.depCtx.Err() != nil || f.owner.root == nil || f.owner.rootOwner == nil {
		t.Fatal("failed workload startup destroyed required dependencies")
	}
}

// TestProtectedCombinedOwnedRoot checks T1/T6's source-lifetime contract: the
// attached disk is the workload bundle copy, not the outer caller's template,
// and selecting it does not mutate the preflight plan.
func TestProtectedCombinedOwnedRoot(t *testing.T) {
	plan := storageTestPlan(t)
	plan.Disks = plan.Disks[:1]
	template := plan.Disks[0].HostPath
	options := uvm.NewDefaultOptionsLCOW("uvmboot-1", "fixture")
	options.BundleDirectory = t.TempDir()
	workload := &protectedSiblingVM{options: options, bundleOwned: true}
	owned, err := protectedSiblingOwnedRoot(workload, plan)
	if err != nil {
		t.Fatal(err)
	}
	if owned.Disks[0].HostPath != filepath.Join(options.BundleDirectory, vmutils.DefaultDmVerityRootfsVhd) ||
		owned.Disks[0].HostPath == template || plan.Disks[0].HostPath != template ||
		owned.Disks[0].Access != "read-only" || *owned.Disks[0].ExportLUN != 0 {
		t.Fatal("owned root selection changed the read-only route or borrowed a template")
	}
	workload.bundleOwned = false
	if _, err := protectedSiblingOwnedRoot(workload, plan); err == nil {
		t.Fatal("unowned root bundle accepted")
	}
}

// TestProtectedToolStagingIsolation checks H-side T6: both roles receive checked
// copies on one tmpfs, but only the diode receives AHV tooling, and staging has
// no implicit prepare/report operation.
func TestProtectedToolStagingIsolation(t *testing.T) {
	for _, role := range []string{diodeRole, workloadRole} {
		artifacts := protectedSiblingToolArtifacts(role)
		command := protectedSiblingToolCommand(artifacts, "metadata-stage; ")
		ahv := false
		for _, artifact := range artifacts {
			if artifact.host == "ahv-guest-ctl" {
				ahv = true
			}
			if !strings.Contains(command, "cp "+shellSingleQuote(artifact.root+"/"+artifact.host)) ||
				!strings.Contains(command, "chmod 755 /run/dtb-exec/"+artifact.destination) {
				t.Fatalf("%s tool %s not checked/staged", role, artifact.host)
			}
		}
		if ahv != (role == diodeRole) ||
			strings.Contains(command, "ahv-guest-ctl") != (role == diodeRole) ||
			strings.Count(command, "mount -t tmpfs") != 1 ||
			!strings.Contains(command, "metadata-stage; ") {
			t.Fatalf("%s lost role isolation/single tmpfs staging", role)
		}
		for _, forbidden := range []string{"ahv-guest-ctl prepare", "ahv-guest-ctl report", "exec /run/dtb-exec/ahv-guest-ctl"} {
			if strings.Contains(command, forbidden) {
				t.Fatalf("implicit AHV operation in %s staging: %s", role, forbidden)
			}
		}
	}
}

// TestProtectedCombinedRelayLossDuringStart checks T3/T4: relay failure cancels
// a pending workload handshake, suppresses later readiness/tool steps and keeps
// dependencies/root ownership available for native workload shutdown.
func TestProtectedCombinedRelayLossDuringStart(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	failure := errors.New("relay lost during workload handshake")
	f.exitErr = failure
	entered := make(chan struct{})
	// Drive the production bootstrap with the real dependency cancellation
	// owner; only the blocking workload operation is an orchestration callback.
	ops := protectedBootstrapTestOps(func(ctx context.Context, name string) error {
		f.record(name)
		switch name {
		case "start-dependencies":
			return f.owner.start(ctx)
		case "start-workload":
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		case "relay-ready", "stage-workload":
			t.Error("relay loss permitted later readiness/staging")
		}
		return nil
	})
	result := make(chan error, 1)
	// Relay loss must interrupt the actual production ordering helper.
	go func() { result <- protectedSiblingBootstrap(f.pair.ctx, ops) }()
	protectedDependencyAwait(t, entered)
	f.exit.release()
	if err := protectedDependencyResult(t, result); err == nil ||
		!errors.Is(context.Cause(f.pair.ctx), failure) {
		t.Fatalf("pending Start lost dependency failure: %v cause=%v", err, context.Cause(f.pair.ctx))
	}
	if f.depCtx.Err() != nil || f.owner.root == nil || f.owner.rootOwner == nil {
		t.Fatal("relay loss destroyed owners before workload native drainage")
	}
}

// TestProtectedRootAttachFailureRetention checks T4's actual attachment seam:
// an uncertain attach without a release callback retains a sentinel and bundle;
// a returned partial mount stays owned and is released only after quiescence.
func TestProtectedRootAttachFailureRetention(t *testing.T) {
	for _, partial := range []bool{false, true} {
		f := newProtectedDependencyFixture(t)
		failure := errors.New("attach failed after possible native progress")
		attachment := *f.owner.root
		// Supply only an attachment result/error, matching the existing small
		// storage-test seam rather than introducing a fake SCSI manager.
		err := f.owner.attachRoot(context.Background(), siblingStorageDisk{},
			func(context.Context, siblingStorageDisk) (siblingStorageAttachment, error) {
				if partial {
					return attachment, failure
				}
				return siblingStorageAttachment{}, failure
			})
		if !errors.Is(err, failure) || f.owner.root == nil || f.owner.rootOwner == nil {
			t.Fatal("failed attach discarded its root attempt or bundle owner")
		}
		err = f.owner.drain(context.Background(), false)
		if err == nil || f.owner.root == nil || f.owner.providerDrained {
			t.Fatal("attach failure bypassed workload drain prerequisite")
		}
		err = f.owner.drain(context.Background(), true)
		if partial {
			if err != nil || f.owner.root != nil || !f.owner.rootReleased ||
				!reflect.DeepEqual(f.recorded(), []string{"quiesce", "release"}) {
				t.Fatalf("partial mount was not released after quiescence: %v calls=%v", err, f.recorded())
			}
		} else if err == nil || f.owner.root == nil || f.owner.rootReleased {
			t.Fatal("unobservable attachment outcome allowed ownership release")
		}
	}
}

// startServer reuses this fixture's per-instance process callbacks at the real
// pair service boundary. It models no VM/native receipt or socket readiness.
func (f *protectedDependencyFixture) startServer() error {
	return f.pair.startOwnedService(&protectedSiblingService{done: make(chan struct{})},
		"diode fixture", "ahv-guest-ctl boot-server", f.owner.ops)
}

// TestProtectedBootServerOrdering checks T4's early boot barrier: a persistent
// foreground server is owned before workload Start and remains live while GCS
// is blocked. No socket/peer readiness is needed to permit native workload boot.
func TestProtectedBootServerOrdering(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	workload := newProtectedDependencyBarrier()
	t.Cleanup(workload.release)
	entered := make(chan struct{})
	// Observe the production ordering callbacks with the real service owner.
	ops := protectedBootstrapTestOps(func(ctx context.Context, name string) error {
		f.record(name)
		switch name {
		case "start-server":
			if err := f.startServer(); err != nil {
				return err
			}
			<-f.waitEntered
		case "start-workload":
			close(entered)
			select {
			case <-workload.ch:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	result := make(chan error, 1)
	// The production helper must progress despite the server's pending Wait.
	go func() { result <- protectedSiblingBootstrap(f.pair.ctx, ops) }()
	protectedDependencyAwait(t, entered)
	want := []string{"bootstrap", "create", "configure", "attach", "stage-diode",
		"start-server", "start", "wait", "start-dependencies", "start-workload"}
	if !reflect.DeepEqual(f.recorded(), want) || len(f.pair.services) != 1 {
		t.Fatalf("server not owned before workload boot: %v", f.recorded())
	}
	select {
	case <-f.pair.services[0].done:
		t.Fatal("server ended before the workload handshake")
	default:
	}
	workload.release()
	if err := protectedDependencyResult(t, result); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.pair.services[0].done:
		t.Fatal("successful boot ended persistent server")
	default:
	}
}

// TestProtectedBootServerCreationFailure checks T4's pre-Start failure path.
// Even partial process creation stays registered, prevents workload Start and
// forbids root/backing release rather than mistaking a returned error for exit.
func TestProtectedBootServerCreationFailure(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	failure := errors.New("partial server creation")
	f.startErr = failure
	// Drive the actual ordered server boundary, not a second bootstrap flow.
	ops := protectedBootstrapTestOps(func(_ context.Context, name string) error {
		if name == "start-server" {
			return f.startServer()
		}
		if name == "start-workload" {
			t.Error("workload started after server creation failure")
		}
		return nil
	})
	if err := protectedSiblingBootstrap(f.pair.ctx, ops); !errors.Is(err, failure) {
		t.Fatalf("lost server creation failure: %v", err)
	}
	if len(f.pair.services) != 1 || !errors.Is(f.pair.joinServices(context.Background()), failure) {
		t.Fatal("failed creation lost its registered owner or uncertainty")
	}
	safe, err := protectedSiblingDrain(context.Background(),
		protectedDrainTestOps(f, f.pair.joinServices(context.Background()), false, true))
	if safe || err == nil || f.owner.root == nil || f.owner.rootReleased {
		t.Fatal("partial server creation authorized dependency/backing release")
	}
}

// TestProtectedBootServerPrematureExit checks T4's pre-workload exit race:
// even a clean server exit is a startup failure, not a readiness signal that
// permits workload native boot or later staging.
func TestProtectedBootServerPrematureExit(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	// Complete the real service watcher before the next ordering boundary.
	ops := protectedBootstrapTestOps(func(_ context.Context, name string) error {
		if name == "start-server" {
			if err := f.startServer(); err != nil {
				return err
			}
			f.exit.release()
			<-f.pair.services[0].done
		}
		if name == "start-workload" || name == "start-dependencies" {
			t.Error("startup continued after server exit")
		}
		return nil
	})
	if err := protectedSiblingBootstrap(f.pair.ctx, ops); err == nil ||
		context.Cause(f.pair.ctx) == nil {
		t.Fatal("premature server exit was mistaken for successful readiness")
	}
}

// TestProtectedBootServerLossDuringGCS checks T4's pending-handshake paths:
// premature exit and parent cancellation stop forward boot, skip later staging,
// and leave root dependencies owned until workload drainage is confirmed.
func TestProtectedBootServerLossDuringGCS(t *testing.T) {
	for _, scenario := range []string{"exit", "cancel"} {
		// Each case blocks only the workload GCS callback, not native authority.
		t.Run(scenario, func(t *testing.T) {
			f := newProtectedDependencyFixture(t)
			failure := errors.New("server failed during collection")
			f.exitErr = failure
			entered := make(chan struct{})
			// Bind real service ownership into the production bootstrap order.
			ops := protectedBootstrapTestOps(func(ctx context.Context, name string) error {
				switch name {
				case "start-server":
					return f.startServer()
				case "start-workload":
					close(entered)
					<-ctx.Done()
					return ctx.Err()
				case "relay-ready", "stage-workload":
					t.Error("server failure/cancellation permitted later startup")
				}
				return nil
			})
			result := make(chan error, 1)
			// Keep the helper and all service callbacks joined by this fixture.
			go func() { result <- protectedSiblingBootstrap(f.pair.ctx, ops) }()
			protectedDependencyAwait(t, entered)
			if scenario == "exit" {
				f.exit.release()
			} else {
				f.pair.stop(context.Canceled)
			}
			if err := protectedDependencyResult(t, result); err == nil {
				t.Fatal("pending GCS wait survived service loss/cancellation")
			}
			protectedDependencyAwait(t, f.pair.services[0].done)
			if scenario == "exit" && !errors.Is(context.Cause(f.pair.ctx), failure) {
				t.Fatal("premature server exit lost its failure cause")
			}
			if err := f.owner.drain(context.Background(), false); err == nil ||
				f.owner.root == nil || f.owner.providerDrained {
				t.Fatal("server loss released still-needed root dependencies")
			}
		})
	}
}

// TestProtectedBootServerPartialCreationCancellation checks T4's registration
// race: cancellation cannot forget a synchronous creation borrower, even before
// its outcome is known. A cleanup join timeout must retain root/backing owners.
func TestProtectedBootServerPartialCreationCancellation(t *testing.T) {
	f := newProtectedDependencyFixture(t)
	f.creation = newProtectedDependencyBarrier()
	result := make(chan error, 1)
	// The production service registers itself before entering this barrier.
	go func() { result <- f.startServer() }()
	protectedDependencyAwait(t, f.startEntered)
	if len(f.pair.services) != 1 {
		t.Fatal("creation began without a registered owner")
	}
	f.pair.stop(context.Canceled)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	joinErr := f.pair.joinServices(ctx)
	if !errors.Is(joinErr, context.Canceled) {
		t.Fatalf("blocked creation was not retained: %v", joinErr)
	}
	safe, err := protectedSiblingDrain(ctx, protectedDrainTestOps(f, joinErr, false, true))
	if safe || err == nil || f.owner.root == nil || f.owner.providerDrained {
		t.Fatal("unjoined creation authorized root/backing release")
	}
	f.creation.release()
	if err := protectedDependencyResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("creation returned success after cancellation: %v", err)
	}
	if err := f.pair.joinServices(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestProtectedBootServerJoinRetention checks T4's Wait/exit distinction:
// a blocked join, unobserved exit or stream failure prevents safe dependency/
// backing release. Expected cancellation alone is not evidence of drainage.
func TestProtectedBootServerJoinRetention(t *testing.T) {
	for _, scenario := range []string{"blocked-wait", "unknown-exit", "stream-failure"} {
		// All cases use the service owner and existing barrier process fixture.
		t.Run(scenario, func(t *testing.T) {
			f := newProtectedDependencyFixture(t)
			failure := errors.New("joined stream/exit failure")
			switch scenario {
			case "blocked-wait":
				f.waitReturn = newProtectedDependencyBarrier()
			case "unknown-exit":
				f.exited = false
			case "stream-failure":
				f.exitErr = failure
			}
			if err := f.startServer(); err != nil {
				t.Fatal(err)
			}
			protectedDependencyAwait(t, f.waitEntered)
			f.pair.stop(context.Canceled)
			ctx := context.Background()
			if scenario == "blocked-wait" {
				bounded, cancel := context.WithCancel(ctx)
				cancel()
				ctx = bounded
			} else {
				protectedDependencyAwait(t, f.pair.services[0].done)
			}
			joinErr := f.pair.joinServices(ctx)
			if joinErr == nil {
				t.Fatal("incomplete service drainage reported success")
			}
			drainOps := protectedDrainTestOps(f, joinErr, false, true)
			// Even confirmed native workload drainage cannot supersede a
			// service borrower. No relay was started in this service fixture.
			drainOps.terminateWorkload = func(context.Context) (bool, error) {
				f.record("terminate-workload")
				return true, nil
			}
			safe, err := protectedSiblingDrain(ctx, drainOps)
			if safe || err == nil || f.owner.root == nil || f.owner.providerDrained {
				t.Fatal("incomplete service join authorized root/backing release")
			}
			f.waitReturn.release()
			protectedDependencyAwait(t, f.pair.services[0].done)
		})
	}
}

// TestProtectedBootstrapBudgets checks T4's profile selection without waiting:
// only the combined setup gets ten minutes and only its workload gets seven;
// legacy and diode starts continue through the public default Start path.
func TestProtectedBootstrapBudgets(t *testing.T) {
	for _, profile := range []protectedSiblingProfile{protectedSiblingDirectRoot, protectedSiblingMediatedRoot} {
		p := &protectedSiblingPair{profile: profile}
		wantSetup := 5 * time.Minute
		wantWorkload := time.Duration(0)
		if profile == protectedSiblingMediatedRoot {
			wantSetup, wantWorkload = 10*time.Minute, 7*time.Minute
		}
		before := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), p.setupBudget())
		after := time.Now()
		deadline, ok := ctx.Deadline()
		cancel()
		if !ok || deadline.Before(before.Add(wantSetup)) || deadline.After(after.Add(wantSetup)) ||
			p.gcsTimeout(workloadRole) != wantWorkload || p.gcsTimeout(diodeRole) != 0 {
			t.Fatalf("wrong profile startup budgets: profile=%d setup=%s workload=%s diode=%s",
				profile, p.setupBudget(), p.gcsTimeout(workloadRole), p.gcsTimeout(diodeRole))
		}
	}
}
