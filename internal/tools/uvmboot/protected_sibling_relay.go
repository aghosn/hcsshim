//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/sibling"
	"github.com/Microsoft/hcsshim/internal/signals"
)

// protectedSiblingDependencyOps is the per-instance orchestration seam for
// runProtectedSibling. Successful start transfers exactly one Wait obligation;
// failed start promises only that the synchronous call has returned, not exit.
// wait reports observed exit separately from joined callbacks/stream errors.
// stop must let foreground bootstrap children finish before observed exit and
// must not abandon its own synchronous signal borrower on context expiration.
// ready establishes relay/root connectivity, never a workload GCS handshake.
type protectedSiblingDependencyOps struct {
	start   func(context.Context) error
	stop    func(context.Context) error
	wait    func() (bool, error)
	ready   func(context.Context) error
	quiesce func(context.Context) error
}

// protectedSiblingDependencies retains the early diode process and workload
// root mount for runProtectedSibling. Its context deliberately does not inherit
// forward cancellation: workload shutdown still needs relay/storage services.
// The pair coordinator serializes start, waitReady and drain; only completion
// and closing observation use mu. A bounded join failure retains this owner,
// including any in-flight native/GCS borrower and the workload's bundle owner.
type protectedSiblingDependencies struct {
	ctx    context.Context
	cancel context.CancelFunc
	ops    protectedSiblingDependencyOps
	stop   func(error)

	rootOwner *protectedSiblingVM
	root      *siblingStorageAttachment

	attempted       bool
	created         chan struct{}
	done            chan struct{}
	mu              sync.Mutex
	closing         bool
	startErr        error
	exited          bool
	exitErr         error
	failure         error
	providerDrained bool
	rootReleased    bool
}

// newProtectedSiblingDependencies prepares an independent dependency lifetime.
// Callers retain the returned owner before start and retain rootOwner until
// drain confirms release. It does not acquire a VM, mount or native receipt.
func newProtectedSiblingDependencies(stop func(error), ops protectedSiblingDependencyOps,
	rootOwner *protectedSiblingVM, root *siblingStorageAttachment) *protectedSiblingDependencies {
	ctx, cancel := context.WithCancel(context.Background())
	return &protectedSiblingDependencies{
		ctx: ctx, cancel: cancel, ops: ops, stop: stop,
		rootOwner: rootOwner, root: root,
		created: make(chan struct{}), done: make(chan struct{}),
	}
}

// protectedSiblingRelayCommands builds the early diode service used by
// runProtectedSibling, using actual RP reports rather than guessed disk names.
// The fresh directory is claimed exclusively in the guest; collisions fail
// without deleting unknown ready/log state. Discovery may await peer native
// startup after GCS process creation; no workload GCS or IP setup is involved.
func protectedSiblingRelayCommands(run, busModule, storageModule string,
	plan *siblingStoragePlan, reports []siblingStorageBackendReport) (command, ready string, err error) {
	if plan == nil || len(plan.Disks) != 1 || len(reports) != 1 {
		return "", "", errors.New("protected relay requires one attached workload root")
	}
	disk, report := plan.Disks[0], reports[0]
	if disk.ID != "workload-root" || disk.Role != "root" || disk.Access != "read-only" ||
		disk.Removable || disk.ExportLUN == nil || *disk.ExportLUN != 0 ||
		report.DiskID != disk.ID || report.Role != disk.Role || !report.ReadOnly || report.ExportLUN != 0 ||
		run == "" || busModule == "" || storageModule == "" {
		return "", "", errors.New("protected relay requires a fixed read-only root at LUN 0 and staged modules")
	}
	if _, err := sibling.RPDeviceIdentityMatch(report.ControllerID, report.LUN); err != nil {
		return "", "", err
	}
	storage, err := siblingStorageGuestCommand(storageModule, diodeRole, plan, reports, false)
	if err != nil {
		return "", "", err
	}
	id, err := guid.NewV4()
	if err != nil {
		return "", "", fmt.Errorf("protected relay run identity: %w", err)
	}
	dir := "/run/protected-sibling-" + id.String()
	marker, log := shellSingleQuote(dir+"/relay.ready"), shellSingleQuote(dir+"/relay.log")
	identity := shellSingleQuote("protected diode bootstrap/relay run=" + run + " " + dir)
	// A trapped TERM waits for the current foreground child before exiting.
	// SIGKILL of the shell could orphan a late insmod; drain must instead
	// signal TERM and observe exit before checking/removing the provider.
	command = `trap 'exit 1' TERM INT; set -eu; umask 077; mkdir ` + shellSingleQuote(dir) +
		` || { echo 'protected relay run directory already exists or cannot be created' >&2; exit 1; }; ` +
		`echo ` + identity + `; exec >` + log + ` 2>&1; echo ` + identity + `; ` +
		siblingBusLoadCommand(busModule) +
		siblingInstanceDiscoveryCommand() + siblingVsockReadyCommand(diodeRole) +
		`[ "$sb_peer" = 3 ] || { echo 'protected relay peer CID mismatch' >&2; exit 1; }; ` +
		storage + `; exec /bin/gcs -sibling-relay -relay-ready ` + marker
	// This is an independently checked guest command, not stdout-marker
	// parsing. Its success still says nothing about workload Start completion.
	ready = `set -eu; n=0; until [ -f ` + marker + ` ]; do n=$((n+1)); ` +
		`if [ "$n" -ge 100 ]; then echo ` + identity + ` >&2; ` +
		`if [ -f ` + log + ` ]; then cat ` + log + ` >&2; fi; ` +
		`echo 'protected relay readiness timed out' >&2; exit 1; fi; sleep 0.1; done`
	return command, ready, nil
}

// newProtectedSiblingRelay binds the real cmd/GCS operations to the same owner
// exercised by helper tests. runProtectedSibling must retain it on the pair
// before start, after attaching the workload bundle's root copy to the diode.
func newProtectedSiblingRelay(p *protectedSiblingPair, diode, workload *protectedSiblingVM,
	root *siblingStorageAttachment, command, ready string) *protectedSiblingDependencies {
	// Configure before Start; cmd owns cancellation, streams and Process.Close
	// through Wait, including synchronous calls that outlive a cleanup budget.
	process := cmd.CommandContext(context.Background(), diode.vm, "sh", "-c", command)
	process.JoinBackgroundOperations = true
	process.CopyAfterExitTimeout = 5 * time.Second
	process.Stdout, process.Stderr = os.Stdout, os.Stderr
	process.Log = process.Log.WithField("protected_run", p.run).WithField("role", diode.role).WithField("vm", diode.options.ID)
	var processMu sync.Mutex
	retired := false
	ops := protectedSiblingDependencyOps{
		// start installs the dependency context, never the forward context.
		start: func(ctx context.Context) error {
			process.Context = ctx
			return process.Start()
		},
		// stop joins its own signal borrower before Wait can close Process.
		// TERM lets the shell finish/reap a foreground provider loader.
		stop: func(ctx context.Context) error {
			processMu.Lock()
			defer processMu.Unlock()
			if retired {
				return nil
			}
			options, err := signals.ValidateSigstrLCOW("TERM", true)
			if err != nil {
				return err
			}
			_, err = process.Process.Signal(ctx, options)
			return err
		},
		// wait first observes the direct-GCS process's cached wait, allowing
		// Signal concurrently. The final cmd wait joins streams/callbacks
		// and Close under the same gate as Signal, so no borrowed process
		// can be closed while that synchronous call is still executing.
		wait: func() (bool, error) {
			_ = process.Process.Wait()
			processMu.Lock()
			defer processMu.Unlock()
			err := process.Wait()
			retired = true
			return process.ExitState.ExitCode() != -1, err
		},
		// ready borrows only the diode's direct GCS, not workload management.
		ready: func(ctx context.Context) error {
			return protectedSiblingGuest(ctx, diode, ready)
		},
		// quiesce is valid only after the potential provider starter is joined.
		// rmmod drains provider work; failure/failed observation forbids release.
		quiesce: func(ctx context.Context) error {
			return protectedSiblingGuest(ctx, diode,
				`set -eu; if [ -d /sys/module/diode_storvsp ]; then rmmod diode_storvsp; fi; `+
					`[ ! -d /sys/module/diode_storvsp ]`)
		},
	}
	// Attribute asynchronous failure to this pair and its diode, not a
	// standalone background command whose ownership cannot be reconstructed.
	stop := func(err error) {
		p.stop(fmt.Errorf("protected dependency run=%s vm=%s: %w", p.run, diode.options.ID, err))
	}
	return newProtectedSiblingDependencies(stop, ops, workload, root)
}

// start initiates and retains process creation before waiting under the forward
// budget. Timeout cancels forward work but cannot abandon an executing Start or
// kill dependencies still needed by workload shutdown. done is closed only
// after Start and, on success, its single joined Wait have returned.
func (d *protectedSiblingDependencies) start(ctx context.Context) error {
	if d.attempted {
		return errors.New("protected dependency start already attempted")
	}
	if ctx.Err() != nil {
		d.stop(context.Cause(ctx))
		return context.Cause(ctx)
	}
	if d.ctx.Err() != nil {
		return errors.New("protected dependencies already closing")
	}
	d.attempted = true
	// The borrower is retained before launch, even if creation blocks in GCS.
	go func() {
		err := d.ops.start(d.ctx)
		d.startErr = err
		close(d.created)
		if err == nil {
			d.exited, err = d.ops.wait()
		}
		d.mu.Lock()
		d.exitErr = err
		if !d.closing {
			d.failure = errors.Join(errors.New("protected diode bootstrap/relay exited"), err)
			d.stop(d.failure)
		}
		close(d.done)
		d.mu.Unlock()
	}()
	select {
	case <-d.created:
		if d.startErr != nil {
			d.stop(d.startErr)
			return d.startErr
		}
		if ctx.Err() != nil {
			d.stop(context.Cause(ctx))
			return context.Cause(ctx)
		}
		return nil
	case <-ctx.Done():
		d.stop(context.Cause(ctx))
		return context.Cause(ctx)
	}
}

// waitReady checks dependency readiness separately from creation and completion.
// runProtectedSibling must additionally require workload Start and its concrete
// Import receipt before any ready/seal transition. Even on cancellation the
// synchronous ready callback is joined before this method returns.
func (d *protectedSiblingDependencies) waitReady(ctx context.Context) error {
	if ctx.Err() != nil {
		d.stop(context.Cause(ctx))
		return context.Cause(ctx)
	}
	if !d.attempted {
		return errors.New("protected dependency start not attempted")
	}
	select {
	case <-d.created:
		if d.startErr != nil {
			return d.startErr
		}
	default:
		return errors.New("protected dependency creation not observed")
	}
	checkCtx, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	// Interrupt readiness on service exit, but retain the GCS borrower until
	// the callback returns; cancellation itself is not drainage evidence.
	go func() {
		defer close(joined)
		select {
		case <-d.done:
			cancel()
		case <-checkCtx.Done():
		}
	}()
	err := d.ops.ready(checkCtx)
	cancel()
	<-joined
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing {
		err = errors.Join(err, errors.New("protected dependencies closing"))
	}
	select {
	case <-d.done:
		err = errors.Join(err, errors.New("protected relay exited before readiness"), d.exitErr)
	default:
	}
	err = errors.Join(err, ctx.Err())
	if err != nil {
		d.stop(err)
	}
	return err
}

// protectedSiblingStopError removes only cmd's expected nonzero-exit leaf after
// an owned stop. Joined transport, stream and Close errors remain observable;
// an exit error must not hide an unrelated failure during runProtectedSibling.
func protectedSiblingStopError(err error) error {
	if _, ok := err.(*cmd.ExitError); ok {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var result error
		for _, child := range joined.Unwrap() {
			result = errors.Join(result, protectedSiblingStopError(child))
		}
		return result
	}
	return err
}

// drain stops/joins the starter, quiesces storage via diode GCS and releases the
// root while guest unplug is still possible. The caller must first join setup/
// shell borrowers and observe workload native drainage. A failed join, uncertain
// creation, provider drain or Mount.Release retains the attachment and bundle
// owner; no result authorizes native backing reclaim. S3 owns best-effort native
// termination and sticky pair uncertainty after any incomplete cleanup.
func (d *protectedSiblingDependencies) drain(ctx context.Context, workloadDrained bool) error {
	if !workloadDrained {
		return errors.New("protected workload drainage unconfirmed; dependencies retained")
	}
	d.mu.Lock()
	d.closing = true
	d.mu.Unlock()
	var result error
	if d.attempted {
		// Do not cancel cmd's context here: its SIGKILL could orphan a shell
		// child still loading the provider. First join creation, then request
		// a trapped graceful stop and retain everything until observed exit.
		select {
		case <-d.created:
		case <-ctx.Done():
			return fmt.Errorf("protected bootstrap creation join unobserved; retain owners: %w", ctx.Err())
		}
		if d.startErr == nil {
			select {
			case <-d.done:
				// A completed foreground service has no process left to signal.
			default:
				result = d.ops.stop(ctx)
			}
		}
		select {
		case <-d.done:
		case <-ctx.Done():
			return errors.Join(result, fmt.Errorf("protected bootstrap/relay join unobserved; retain owners: %w", ctx.Err()))
		}
		if d.startErr != nil {
			return fmt.Errorf("protected process creation outcome uncertain; retain owners: %w", d.startErr)
		}
		result = errors.Join(result, d.failure)
		if !d.exited {
			return errors.Join(result, d.exitErr,
				errors.New("protected bootstrap/relay exit unconfirmed; retain owners"))
		}
		if d.failure == nil {
			result = errors.Join(result, protectedSiblingStopError(d.exitErr))
		}
	}
	// No command-owned cancellation callback can now borrow the process.
	d.cancel()
	if !d.providerDrained {
		if err := d.ops.quiesce(ctx); err != nil {
			return errors.Join(result, fmt.Errorf("protected provider drain unconfirmed: %w", err))
		}
		d.providerDrained = true
	}
	if d.root != nil {
		if d.root.release == nil {
			return errors.Join(result, errors.New("protected root release unavailable; retain attachment"))
		}
		if err := d.root.release(ctx); err != nil {
			return errors.Join(result, fmt.Errorf("protected root release incomplete: %w", err))
		}
		// Mount.Release retains partial progress on error. Forget the record
		// only on confirmed release, never by unconditional list clearing.
		d.root = nil
		d.rootReleased = true
	}
	return result
}
