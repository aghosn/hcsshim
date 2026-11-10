//go:build windows

package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
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
		_ = f.owner.drain(context.Background(), true)
		cancel(nil)
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
// does not end the service. Workload Start/receipt gating belongs to S3.
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
// a later ready/seal phase. Workload handshake gating remains an S3 obligation.
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
