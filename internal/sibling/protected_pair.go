//go:build windows

package sibling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/cpugroup"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcsv2 "github.com/Microsoft/hcsshim/internal/hcs/v2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/internal/timeout"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/uvm/scsi"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/windows"
)

const (
	protectedPairSetupBudget     = 10 * time.Minute
	protectedPairGCSBudget       = 7 * time.Minute
	protectedPartitionBudget     = 5 * time.Minute
	protectedPairLogName         = "protected-pair.log"
	protectedCleanupBudget       = 2 * time.Minute
	protectedUnikraftReadyBudget = 3 * time.Minute
	protectedUnikraftRootName    = "unikraft-root.vhd"
)

// protectedVMAttempt is retained before CreateLCOW, even when it returns no VM.
// Such a failure is unknown native ownership, not evidence of zero work.
type protectedVMAttempt struct {
	options       *uvm.OptionsLCOW
	region        hcsschema.SharedMemoryRegion
	vm            *uvm.UtilityVM
	createAttempt bool
	bundleOwned   bool
}

// protectedService tracks startup liveness, not backing ownership.
type protectedService struct {
	done chan struct{}
	err  error
}

// protectedPair owns the native capability and participant operations. Guest
// commands and child containers do not hold this boundary or authorize release.
type protectedPair struct {
	pair               *Pair
	config             *Config
	backing            *ProtectedBacking
	unikraft           *UnikraftConfig
	applianceRootOwned bool
	diode              protectedVMAttempt
	workload           protectedVMAttempt
	uplinkAttempt      bool
	services           []*protectedService
	timesync           *pairTimesync
	log                *os.File
	startupDone        chan struct{}
	startupParent      context.Context // Checked at seal commitment, never used as a service lifetime.
	ctx                context.Context
	cancel             context.CancelCauseFunc
	watchCtx           context.Context
	stopWatch          context.CancelFunc
	forwardMu          sync.Mutex
	closing            bool
	nativeMu           sync.Mutex // Acquisition, Create/Start, seals and final controls only.
	// Attempts are retained evidence, not permission to replay controls.
	admissionAttempt bool
	sealAttempt      [2]bool

	// Startup owns this pending close until startupDone. Housekeeping can retry
	// a failed close after native release, before joining other borrowers.
	probeEntropyClose func(context.Context) error
}

// startProtectedPair implements the owned Bootstrap-before-Import sequence.
// It preflights without backing, validates diode native startup before workload
// creation, creates independent foreground AHV, root/GCS and timesync services
// before workload Start, then checks mediation and seals before sandbox creation.
// Only the cloned workload receives a fresh pair-owned native timesync route;
// pipe/device acquisition overlaps boot, with no sample/convergence handoff gate.
// The explicitly selected Unikraft backend instead prepares its permanent
// root, then gates a bounded workload Start on console readiness after Create.
// That probe always returns an error and never reaches readiness or seals.
//
// After owner allocation,
// even an error returns the Pair: the caller must retain it, never ordinary-close
// its VMs or delete its prepared bundle. Native calls are synchronous and joined;
// deadlines cannot abandon executing calls, buffers or controller capabilities.
func startProtectedPair(parent context.Context, base *uvm.OptionsLCOW, config *Config) (*Pair, error) {
	if config == nil {
		return nil, errors.New("protected pair config is nil")
	}
	config, err := config.validatedCopy()
	if err != nil {
		return nil, err
	}
	if !config.ProtectedShared {
		return nil, errors.New("protected pair requires protected_shared")
	}
	group, err := guid.NewV4()
	if err != nil {
		return nil, err
	}
	workload, diode, err := commonPairOptions(base, config, group.String())
	if err != nil {
		return nil, err
	}
	if config.PageMetadataOutputPath != "" {
		// The explicit export opts only the cloned diode into writable shares.
		// Preserve the caller's and workload's inherited restrictions.
		diode.NoWritableFileShares = false
	}
	native, err := loadOwnedUnikraft(config)
	if err != nil {
		return nil, err
	}
	if native != nil {
		root := filepath.Join(diode.BundleDirectory, protectedUnikraftRootName)
		if err := configureOwnedUnikraft(workload, diode, config, native, group.String(), root); err != nil {
			return nil, err
		}
	} else {
		// Only the protected Linux provider owns the root-facing log service.
		// commonPairOptions may retain inherited slice storage; do not mutate it.
		diode.ExtraVSockPorts = append(append([]uint32(nil), diode.ExtraVSockPorts...), guestresource.GCSRelayLogPort)
	}
	if err := preflightProtectedPair(parent, config, workload, diode); err != nil {
		return nil, err
	}
	workload.TimesyncRelayID = &group

	ctx, cancel := context.WithCancelCause(context.Background())
	watch, stopWatch := context.WithCancel(context.Background())
	pair := &Pair{done: make(chan struct{}), unikraft: native != nil}
	p := &protectedPair{
		pair: pair, config: config, unikraft: native, ctx: ctx, cancel: cancel,
		watchCtx: watch, stopWatch: stopWatch, startupDone: make(chan struct{}), startupParent: parent,
		diode: protectedVMAttempt{options: diode}, workload: protectedVMAttempt{options: workload},
	}
	pair.protected = p
	if err := registerProtectedPair(p); err != nil {
		cancel(err)
		stopWatch()
		return nil, err
	}
	// Native shutdown must not depend on guest process or output completion,
	// including service/participant loss while bootstrap is still in a guest RPC.
	go func() {
		<-pair.done
		if err := pair.Close(); err != nil {
			log.G(context.Background()).WithError(err).Error("protected pair shutdown")
		}
	}()
	// The create RPC owns cancellation only until this bridge is detached and
	// joined. Owner/service contexts do not inherit its eventual completion.
	detach, bridged := make(chan struct{}), make(chan struct{})
	// Bridge startup cancellation without making it the dependency lifetime.
	go func() {
		defer close(bridged)
		select {
		case <-parent.Done():
			p.stop(context.Cause(parent))
		case <-detach:
		}
	}()
	defer close(p.startupDone)
	err = p.bootstrap(group.String())
	// Detach/join before the final liveness check. Cancellation observed by
	// the bridge cannot arrive after a successful check and silently undo it.
	close(detach)
	<-bridged
	p.forwardMu.Lock()
	if parent.Err() != nil {
		p.cancel(context.Cause(parent))
	}
	err = errors.Join(err, context.Cause(p.ctx))
	p.forwardMu.Unlock()
	if err != nil {
		p.stop(err)
		if p.log != nil {
			_, logErr := fmt.Fprintf(p.log, "startup failed run=%s diode=%s workload=%s error=%v\n",
				p.config.RunID, diode.ID, workload.ID, err)
			err = errors.Join(err, logErr)
		}
	}
	return pair, err
}

// preflightProtectedPair rejects excluded profiles and missing inputs before
// startProtectedPair acquires its log, bundle, backing or native controller.
func preflightProtectedPair(ctx context.Context, config *Config, workload, diode *uvm.OptionsLCOW) error {
	if config.PageMetadataOutputPath != "" {
		// Inspect every component without accepting any reparse-point redirection.
		for path := filepath.Clean(config.PageMetadataOutputPath); ; path = filepath.Dir(path) {
			info, err := os.Lstat(path)
			if err != nil {
				return fmt.Errorf("page metadata output directory %q: %w", path, err)
			}
			name, err := windows.UTF16PtrFromString(path)
			if err != nil {
				return err
			}
			attributes, err := windows.GetFileAttributes(name)
			if err != nil {
				return fmt.Errorf("page metadata output directory attributes %q: %w", path, err)
			}
			if !info.IsDir() || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				return fmt.Errorf("page metadata output %q must be a directory without links or reparse points", path)
			}
			if filepath.Dir(path) == path {
				break
			}
		}
	}
	if err := ValidateProtectedControllerABI(); err != nil {
		return err
	}
	if err := ValidateProtectedBackingSize(config.SharedMemoryBytes); err != nil {
		return err
	}
	appliance := config.UnikraftPackage != ""
	if appliance != (diode.Appliance != nil) || appliance && !diode.Appliance.NativeStorageControl {
		return errors.New("protected provider options do not match the selected bootstrap")
	}
	for _, options := range []*uvm.OptionsLCOW{diode, workload} {
		if (options == workload && options.Appliance != nil) || options.HclEnabled == nil || *options.HclEnabled ||
			options.AllowOvercommit || options.EnableDeferredCommit ||
			options.PreferredRootFSType != uvm.PreferredRootFSTypeNA ||
			options.CPUGroupID != "" || options.ResourcePartitionID != nil ||
			options.ProcessorLimit != 0 || options.ProcessorWeight != 0 ||
			len(options.ProtectedSharedResources) != 0 || options.NetworkConfigProxy != "" ||
			options.DisableTimeSyncService {
			return errors.New("protected owned pair requires direct SNP with timesync enabled, a Linux workload and no CPU-group or processor tuning")
		}
		if err := uvm.VerifyOptions(ctx, options); err != nil {
			return err
		}
	}
	paths := []string{
		filepath.Join(diode.BootFilesPath, diode.GuestStateFilePath),
		filepath.Join(workload.BootFilesPath, workload.GuestStateFilePath),
		filepath.Join(workload.BootFilesPath, workload.DmVerityRootFsVhd),
	}
	if !appliance {
		for _, name := range protectedPairInputs() {
			paths = append(paths, filepath.Join(config.ModuleDirectory, name))
		}
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("protected input %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("protected input %q is not a regular file", path)
		}
		if appliance && info.Size() == 0 {
			return fmt.Errorf("protected appliance input %q is empty", path)
		}
	}
	logPath := filepath.Join(filepath.Dir(config.CleanupReceiptPath), protectedPairLogName)
	if filepath.Base(config.CleanupReceiptPath) != "protected-cleanup-result.json" {
		return errors.New("protected receipt must be named protected-cleanup-result.json in the fresh session")
	}
	if strings.EqualFold(filepath.Clean(config.CleanupReceiptPath), logPath) {
		return errors.New("protected cleanup receipt must be separate from the run log")
	}
	parent, err := os.Stat(filepath.Dir(config.CleanupReceiptPath))
	if err != nil {
		return err
	}
	if !parent.IsDir() {
		return errors.New("protected cleanup receipt parent is not a directory")
	}
	outputs := []string{config.CleanupReceiptPath, logPath, diode.BundleDirectory}
	if appliance {
		outputs = append(outputs, filepath.Join(filepath.Dir(logPath), "unikraft-console.log"))
	}
	for _, path := range outputs {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(err, fmt.Errorf("protected output must be fresh: %s", path))
		}
	}
	return ctx.Err()
}

// protectedPairInputs is the minimal owned profile, excluding benchmark/demo
// services. The optional diode output directory is not a staged tool input.
// The workload client stays in its root.
func protectedPairInputs() []string {
	return []string{"sibling_bus.ko", "diode_timesyncvsp.ko", "diode_storvsp.ko", "diode_netvsp.ko", "diode_iptables", "ahv-guest-ctl"}
}

// stop cancels forward work without waiting for guest cooperation. Native
// dispatch checks cancellation under nativeMu before acquiring any capability.
func (p *protectedPair) stop(cause error) {
	p.forwardMu.Lock()
	if !p.closing {
		p.closing = true
		close(p.pair.done)
	}
	p.cancel(cause)
	p.forwardMu.Unlock()
}

// bootstrap owns all effects for startProtectedPair. Attempts and partial results
// stay attached to p on failure; close alone decides drainage and reclaim.
func (p *protectedPair) bootstrap(group string) error {
	setup, stopSetup := context.WithTimeout(p.ctx, protectedPairSetupBudget)
	defer stopSetup()
	if err := setup.Err(); err != nil {
		return context.Cause(setup)
	}
	var err error
	p.log, err = os.OpenFile(filepath.Join(filepath.Dir(p.config.CleanupReceiptPath), protectedPairLogName),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(p.log, "protected owned pair run=%s diode=%s workload=%s\n",
		p.config.RunID, p.diode.options.ID, p.workload.options.ID); err != nil {
		return err
	}
	if p.config.PageMetadataOutputPath != "" {
		if _, err := fmt.Fprintf(p.log, "page metadata output run=%s vm=%s host=%q guest=/run/page-metadata-results writable=true\n",
			p.config.RunID, p.diode.options.ID, p.config.PageMetadataOutputPath); err != nil {
			return err
		}
	}
	if err := os.Mkdir(p.diode.options.BundleDirectory, 0700); err != nil {
		return fmt.Errorf("create owned diode bundle: %w", err)
	}
	p.diode.bundleOwned = true
	p.nativeMu.Lock()
	if err = p.ctx.Err(); err == nil {
		p.backing, err = NewProtectedBacking("hcsshim-protected-"+group, p.config.SharedMemoryBytes)
	}
	p.nativeMu.Unlock()
	if err != nil {
		return err
	}
	for _, v := range []*protectedVMAttempt{&p.diode, &p.workload} {
		v.options.SiblingCommunicationEndpoints[0].SharedMemorySectionName = p.backing.SectionName()
	}
	p.pair.cpuGroups, err = preparePairCPUGroups(setup, p.config, p.workload.options, p.diode.options, cpugroup.HostOperations)
	if err != nil {
		return err
	}
	if p.unikraft != nil {
		return p.bootstrapUnikraft(setup)
	}

	// Import is impossible until the diode's actual complete Install receipt
	// supplies the lease. Neither Create success nor GCS presence substitutes.
	if err := p.create(setup, &p.diode, hcsschema.ProtectedSharedBackingBootstrap); err != nil {
		return err
	}
	if err := p.start(setup, &p.diode); err != nil {
		return err
	}
	if err := p.create(setup, &p.workload, hcsschema.ProtectedSharedBackingImport); err != nil {
		return err
	}
	if err := p.configureGCSRelay(setup); err != nil {
		return err
	}
	root, err := p.diode.vm.SCSIManager.AddVirtualDisk(setup,
		filepath.Join(p.workload.options.BundleDirectory, vmutils.DefaultDmVerityRootfsVhd),
		true, p.diode.options.ID, "", nil)
	if err != nil {
		return fmt.Errorf("attach protected workload root: %w", err)
	}
	if root == nil {
		return errors.New("protected root attachment returned no mount")
	}
	if err := p.stageDiode(setup); err != nil {
		return err
	}
	resolve, err := RPDeviceCommand(root.Controller(), root.LUN())
	if err != nil {
		return err
	}
	// These are separate foreground owners. Creation does not wait for peer
	// offers; their guest waits overlap workload native Start and GCS bootstrap.
	if err := p.startService(setup, &p.diode, "exec /run/sibling-exec/ahv-guest-ctl boot-server"); err != nil {
		return err
	}
	provider := `trap 'exit 1' TERM INT; ` +
		BusLoadCommand("/run/sibling/sibling_bus.ko/sibling_bus.ko") +
		protectedDiodeLinkCommand() +
		`insmod /run/sibling/diode_timesyncvsp.ko/diode_timesyncvsp.ko; ` + resolve +
		storageProviderCommand(p.config.StorageDirectIO) + `; ` +
		`exec /bin/gcs -sibling-relay -sibling-log-relay -relay-ready /run/sibling-exec/gcs-relay.ready`
	if err := p.startService(setup, &p.diode, provider); err != nil {
		return err
	}
	// The time process never loads the bus itself. Its device wait and the
	// asynchronous native bridge must exist before workload Start dispatch.
	if err := p.startTimesync(setup); err != nil {
		return err
	}
	if err := p.start(setup, &p.workload); err != nil {
		return err
	}
	if err := p.timesync.waitReady(setup); err != nil {
		return err
	}
	if _, err := p.guest(setup, &p.diode,
		`until [ -f /run/sibling-exec/gcs-relay.ready ]; do sleep 0.1; done`); err != nil {
		return err
	}
	if err := p.configure(setup); err != nil {
		return err
	}
	shells, err := startPairShells(p.pair)
	if err != nil {
		return err
	}
	p.forwardMu.Lock()
	if p.closing {
		p.forwardMu.Unlock()
		_ = shells.Close()
		return context.Cause(p.ctx)
	}
	p.pair.interactiveCloser = shells
	p.forwardMu.Unlock()
	if err := p.checkServices(); err != nil {
		return err
	}
	if err := p.seal(setup, -1, 0); err != nil {
		return err
	}
	// Each selected partition gets its own fresh allowance, not the remaining
	// setup budget. No fallback, changed mask, retry or detached native syscall.
	stopSetup()
	for i, mask := range []*uint64{p.config.DiodePartitionSealMask, p.config.WorkloadPartitionSealMask} {
		if mask == nil {
			continue
		}
		v := &p.diode
		if i == 1 {
			v = &p.workload
		}
		ctx, cancel := context.WithTimeout(p.ctx, protectedPartitionBudget)
		err := p.seal(ctx, i, *mask)
		cancel()
		_, logErr := fmt.Fprintf(p.log, "partition seal run=%s vm=%s mask=%d error=%v\n",
			p.config.RunID, v.options.ID, *mask, err)
		if err != nil || logErr != nil {
			return errors.Join(err, logErr)
		}
	}
	return p.checkServices()
}

// protectedUnikraftSteps are the forward milestones only. The protected pair
// owns partial acquisitions and all cleanup, regardless of which step fails.
type protectedUnikraftSteps struct {
	prepare, createDiode, startDiode, createWorkload, configureRelay, waitReady func(context.Context) error
	startWorkload                                                               func(context.Context) protectedStartOutcome
}

var errProtectedUnikraftBringUpOnly = errors.New("protected Unikraft bring-up only: workload Start returned successfully; no sandbox published")

// run executes the probe's receipt-before-Import and readiness-before-Start
// gates. A successful Start is still a terminal probe result, not a handoff.
func (s protectedUnikraftSteps) run(ctx context.Context, record func(string, error) error) error {
	var diagnostics error
	for _, step := range []struct {
		phase string
		run   func(context.Context) error
	}{
		{"diode_prepare", s.prepare},
		{"diode_create", s.createDiode},
		{"diode_start_and_storage_handshake", s.startDiode},
		{"workload_create", s.createWorkload},
		{"workload_gcs_relay", s.configureRelay},
		{"provider_readiness", s.waitReady},
	} {
		if err := context.Cause(ctx); err != nil {
			return errors.Join(fmt.Errorf("protected Unikraft before %s: %w", step.phase, err), diagnostics)
		}
		err := step.run(ctx)
		diagnostics = errors.Join(diagnostics, record(step.phase, err))
		if err != nil {
			return errors.Join(fmt.Errorf("protected Unikraft %s: %w", step.phase, err), diagnostics)
		}
	}
	outcome := protectedStartOutcome{err: context.Cause(ctx)}
	if outcome.err == nil {
		outcome = s.startWorkload(ctx)
	}
	phase := "workload_start_not_dispatched"
	if outcome.called {
		phase = "workload_start_result"
	}
	diagnostics = errors.Join(diagnostics, outcome.diagnosticErr, record(phase, outcome.err))
	if outcome.err != nil {
		return errors.Join(fmt.Errorf("protected Unikraft %s: %w", phase, outcome.err), diagnostics)
	}
	return errors.Join(errProtectedUnikraftBringUpOnly, diagnostics)
}

// bootstrapUnikraft runs the appliance probe for bootstrap. Storage management
// still uses the native export check in Start. Neither console nor control work
// sits on the native receipt or termination boundary.
func (p *protectedPair) bootstrapUnikraft(ctx context.Context) error {
	diodeID, workloadID := p.diode.options.ID, p.workload.options.ID
	// The setup deadline can request native shutdown even if the storage/GCS
	// call has not returned. A voluntary end of startup is not a timeout.
	stopTimeout := context.AfterFunc(ctx, func() {
		if ctx.Err() == context.DeadlineExceeded {
			p.stop(fmt.Errorf("protected Unikraft setup: %w", context.Cause(ctx)))
		}
	})
	defer stopTimeout()
	defer p.recordUnikraftBoot()
	var storageControl providerState
	steps := protectedUnikraftSteps{
		// Prepare the root before arming the console or creating the diode;
		// workload Create owns a different copy and cannot replace this disk.
		prepare: func(ctx context.Context) error {
			if err := stageProtectedUnikraftRoot(ctx, p.workload.options, p.diode.options); err != nil {
				return err
			}
			p.applianceRootOwned = true
			if err := p.pair.prepareOwnedUnikraft(p.diode.options, p.unikraft, filepath.Dir(p.config.CleanupReceiptPath)); err != nil {
				return err
			}
			p.watchUnikraftService(p.pair.unikraftConsole, "console")
			return nil
		},
		// Only the protected owner can dispatch Bootstrap with its controller.
		createDiode: func(ctx context.Context) error {
			return p.create(ctx, &p.diode, hcsschema.ProtectedSharedBackingBootstrap)
		},
		// Wait for the storage handshake after the native receipt has been
		// observed; neither handshake success nor console output grants Import.
		startDiode: func(ctx context.Context) error {
			if err := p.start(ctx, &p.diode); err != nil {
				return err
			}
			p.recordUnikraftBoot()
			control, err := p.diode.vm.NativeStorageControl()
			if err != nil {
				return err
			}
			storageControl = control
			p.watchUnikraftService(control, "storage control")
			return nil
		},
		// Region(Import) consumes the lease already validated by diode Start.
		createWorkload: func(ctx context.Context) error {
			// Import borrows the controller only for the existing native path.
			create := func(ctx context.Context) error {
				return p.create(ctx, &p.workload, hcsschema.ProtectedSharedBackingImport)
			}
			// The workload VM is published only on successful Create.
			disable := func(ctx context.Context) error { return p.workload.vm.DisableBootEntropy(ctx) }
			return p.createUnikraftWorkload(ctx, create, disable)
		},
		configureRelay: p.configureGCSRelay,
		// This is an ordering probe: readiness before Start is not established.
		waitReady: func(ctx context.Context) error {
			ready, cancel := context.WithTimeout(ctx, protectedUnikraftReadyBudget)
			defer cancel()
			return p.pair.unikraftConsole.waitReady(ready)
		},
		// Attempt real protected Start, without Linux diode scripts, dummy
		// services, application publication or any kind of seal.
		startWorkload: func(ctx context.Context) protectedStartOutcome {
			select {
			case <-storageControl.Done():
				return protectedStartOutcome{err: fmt.Errorf("protected Unikraft storage control ended: %w", storageControl.Err())}
			case <-p.pair.unikraftConsole.Done():
				return protectedStartOutcome{err: fmt.Errorf("protected Unikraft console ended: %w", p.pair.unikraftConsole.Err())}
			default:
				return p.startWithNativeCompletion(ctx, &p.workload, p.log, p.workload.vm.StartWithNativeStartCompletion)
			}
		},
	}
	// Report each gate result with the same run and participant identities.
	return steps.run(ctx, func(phase string, err error) error {
		if _, logErr := fmt.Fprintf(p.log, "unikraft phase=%s run=%s diode=%s workload=%s error=%v\n",
			phase, p.config.RunID, diodeID, workloadID, err); logErr != nil {
			return fmt.Errorf("log protected Unikraft %s: %w", phase, logErr)
		}
		return nil
	})
}

// recordUnikraftBoot records an already captured guest marker without waiting
// for console output. The console retains the raw text even on handshake failure.
func (p *protectedPair) recordUnikraftBoot() {
	if p.pair.unikraftConsole == nil {
		return
	}
	select {
	case observed := <-p.pair.unikraftConsole.boot:
		if _, err := fmt.Fprintf(p.log, "unikraft phase=guest_boot run=%s vm=%s marker=direct-SNP observed=%s\n",
			p.config.RunID, p.diode.options.ID, observed.Format(time.RFC3339Nano)); err != nil {
			log.G(p.ctx).WithError(err).Warn("protected Unikraft boot marker could not be logged")
		}
	default:
	}
}

// watchUnikraftService turns console/control loss into a protected stop without
// joining guest I/O. Native exit is monitored independently by watch.
func (p *protectedPair) watchUnikraftService(state providerState, name string) {
	// Observe service loss independently of the startup goroutine's current wait.
	go func() {
		select {
		case <-p.watchCtx.Done():
		case <-state.Done():
			p.stop(fmt.Errorf("protected Unikraft %s ended: %w", name, state.Err()))
		}
	}()
}

// create records the attempt and real capability before synchronous CreateLCOW.
// Existing CreateLCOW error cleanup is unchanged; unobservable work stays unknown.
func (p *protectedPair) create(ctx context.Context, v *protectedVMAttempt, mode hcsschema.ProtectedSharedBackingMode) error {
	p.nativeMu.Lock()
	defer p.nativeMu.Unlock()
	if err := p.ctx.Err(); err != nil {
		return context.Cause(p.ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	region, err := p.backing.Region(mode)
	if err != nil {
		return err
	}
	v.region = region
	v.options.SharedMemoryRegions = []uvm.LCOWSharedMemoryRegion{region}
	v.options.ProtectedSharedResources = []hcsv2.OperationResource{p.backing.Resource()}
	v.createAttempt = true
	p.backing.MarkCreateAttempt()
	v.vm, err = uvm.CreateLCOW(ctx, v.options)
	if v == &p.diode {
		p.pair.Diode = v.vm
	} else {
		p.pair.Workload = v.vm
	}
	if err != nil {
		p.backing.MarkUnknown()
		return fmt.Errorf("protected create %s (ownership unobservable): %w", v.options.ID, err)
	}
	return nil
}

// createUnikraftWorkload disables entropy as part of successful Create even
// if cancellation has ended forward work. This runs outside nativeMu, before
// relay binding or Start. Housekeeping can retry if the first close failed.
func (p *protectedPair) createUnikraftWorkload(ctx context.Context, create, disable func(context.Context) error) error {
	if err := create(ctx); err != nil {
		return err
	}
	p.probeEntropyClose = disable
	return p.disableUnikraftEntropy(context.WithoutCancel(ctx))
}

// disableUnikraftEntropy closes a published pre-Start listener if still owned.
// Only startup, or housekeeping after startupDone, may call it.
func (p *protectedPair) disableUnikraftEntropy(ctx context.Context) error {
	if p.probeEntropyClose == nil {
		return nil
	}
	if err := p.probeEntropyClose(ctx); err != nil {
		return fmt.Errorf("disable protected Unikraft workload boot entropy: %w", err)
	}
	p.probeEntropyClose = nil
	return nil
}

// configureGCSRelay publishes the listener before native Start. For the probe
// relay setup is startup-owned and cannot delay native cleanup. Housekeeping
// waits for startupDone before touching its listeners.
func (p *protectedPair) configureGCSRelay(ctx context.Context) error {
	if p.unikraft == nil {
		p.nativeMu.Lock()
		defer p.nativeMu.Unlock()
	}
	if err := p.ctx.Err(); err != nil {
		return context.Cause(p.ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.workload.vm.ConfigureGCSRelay(p.diode.vm); err != nil {
		return err
	}
	// If the probe inherits a workload output listener, retarget it too; never
	// fall back to direct host output or invent an appliance log service.
	if p.unikraft == nil || p.workload.options.ForwardStdout || p.workload.options.ForwardStderr {
		if err := p.workload.vm.ConfigureGCSLogRelay(p.diode.vm); err != nil {
			return err
		}
	}
	if p.unikraft == nil {
		return p.workload.vm.DisableBootEntropy(ctx)
	}
	return nil
}

// start retains native dispatch through its actual return and receipt observation,
// then releases nativeMu before ordinary GCS bootstrap. Guest bootstrap failure
// cannot invalidate an already observed native result or delay native shutdown.
func (p *protectedPair) start(ctx context.Context, v *protectedVMAttempt) error {
	outcome := p.startWithNativeCompletion(ctx, v, p.log, v.vm.StartWithNativeStartCompletion)
	if outcome.diagnosticErr != nil {
		return errors.Join(outcome.err, outcome.diagnosticErr)
	}
	return outcome.err
}

// protectedStartOutcome keeps the owner-side call boundary and operational
// result independent of diagnostic I/O. Called does not prove native dispatch.
type protectedStartOutcome struct {
	called        bool
	err           error
	diagnosticErr error
}

// startWithNativeCompletion records an admitted owner attempt before entering
// Start, without holding nativeMu across the diagnostic write. Admission is
// checked again under nativeMu; install evidence still requires the callback.
func (p *protectedPair) startWithNativeCompletion(ctx context.Context, v *protectedVMAttempt, attemptLog io.Writer,
	start func(context.Context, time.Duration, func(context.Context, error) error) error,
) protectedStartOutcome {
	var logErr error
	if p.unikraft != nil && v == &p.workload {
		if err := p.startCancellation(ctx); err != nil {
			return protectedStartOutcome{err: err}
		}
		_, logErr = fmt.Fprintf(attemptLog, "unikraft phase=workload_start_attempt run=%s vm=%s attempted=%s\n",
			p.config.RunID, v.options.ID, time.Now().Format(time.RFC3339Nano))
	}

	p.nativeMu.Lock()
	locked := true
	// A receipt callback releases native authority before guest bootstrap.
	unlock := func() {
		if locked {
			locked = false
			p.nativeMu.Unlock()
		}
	}
	defer unlock()
	if err := p.startCancellation(ctx); err != nil {
		return protectedStartOutcome{err: err, diagnosticErr: logErr}
	}
	connectionTimeout := timeout.GCSConnectionTimeout
	if v == &p.workload {
		connectionTimeout = protectedPairGCSBudget
	}
	var gpa uint64
	observed := false
	// The callback captures the native outcome even if guest startup cannot finish.
	err := start(ctx, connectionTimeout, func(ctx context.Context, nativeErr error) (result error) {
		// Publish probe evidence after unlocking, but before the later storage
		// handshake or GCS bootstrap can wait or fail.
		if p.unikraft != nil {
			defer func() {
				if observed {
					_, receiptLogErr := fmt.Fprintf(p.log, "startup run=%s vm=%s mode=%s lease=%d byte_gpa=%#x installed=true\n",
						p.config.RunID, v.options.ID, v.region.ProtectedSharedBackingMode, v.region.ProtectedSharedLeaseId, gpa)
					logErr = errors.Join(logErr, receiptLogErr)
				}
			}()
		}
		defer func() {
			if result != nil {
				p.stop(result)
			}
			unlock()
		}()
		if nativeErr != nil {
			p.backing.MarkUnknown()
			p.observeFailedStartup(v)
			return fmt.Errorf("protected native start %s (progress uncertain): %w", v.options.ID, nativeErr)
		}
		if p.unikraft != nil {
			// Cancellation and console loss are not native receipt evidence.
			// Observe completed Start with an independent, bounded native query.
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
		}
		regions, err := v.vm.SharedMemoryRegions(ctx)
		if err != nil || len(regions) != 1 || regions[0].SectionName != v.region.SectionName {
			p.backing.MarkUnknown()
			return errors.Join(err, fmt.Errorf("protected %s missing exact startup region", v.options.ID))
		}
		if err := p.backing.ObserveStartup(regions[0].ProtectedShared); err != nil {
			return err
		}
		v.region.ProtectedSharedLeaseId = regions[0].ProtectedShared.LeaseId
		gpa, err = uvm.SharedMemoryByteGPA(regions[0].GuestPhysicalAddress, int64(v.region.Length))
		if err != nil {
			p.backing.MarkUnknown()
			return err
		}
		observed = true
		p.watch(v)
		return nil
	})
	if p.unikraft != nil {
		if observed && v == &p.diode && err != nil {
			err = fmt.Errorf("Unikraft native storage handshake: %w", err)
		}
		return protectedStartOutcome{called: true, err: err, diagnosticErr: logErr}
	}
	if observed {
		_, logErr := fmt.Fprintf(p.log, "startup run=%s vm=%s mode=%s lease=%d byte_gpa=%#x installed=true\n",
			p.config.RunID, v.options.ID, v.region.ProtectedSharedBackingMode, v.region.ProtectedSharedLeaseId, gpa)
		err = errors.Join(err, logErr)
	}
	return protectedStartOutcome{called: true, err: err}
}

// startCancellation preserves the owner's stop cause ahead of startup
// cancellation. Both are checked again at the native dispatch boundary.
func (p *protectedPair) startCancellation(ctx context.Context) error {
	if err := context.Cause(p.ctx); err != nil {
		return err
	}
	return ctx.Err()
}

// observeFailedStartup retains only validated cached initialization history,
// with an independent observation budget. It never authorizes release.
func (p *protectedPair) observeFailedStartup(v *protectedVMAttempt) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	regions, err := v.vm.SharedMemoryRegions(ctx)
	if err == nil && len(regions) == 1 && regions[0].SectionName == v.region.SectionName {
		if p.backing.ObserveFailedStartup(regions[0].ProtectedShared) == nil {
			v.region.ProtectedSharedLeaseId = regions[0].ProtectedShared.LeaseId
		}
	}
}

// watch reaches native shutdown on participant loss, independently of logs.
func (p *protectedPair) watch(v *protectedVMAttempt) {
	// Native exit, not log delivery, triggers loss notification.
	go func() {
		err := v.vm.WaitNativeExit(p.watchCtx)
		if p.watchCtx.Err() == nil {
			cause := errors.Join(fmt.Errorf("protected VM %s exited", v.options.ID), err, v.vm.ExitError())
			p.stop(cause)
			log.G(context.Background()).WithField("vm", v.options.ID).WithError(cause).Warn("protected VM ended")
		}
	}()
}

// guest uses the joined command path and correlates setup/export diagnostics.
func (p *protectedPair) guest(ctx context.Context, v *protectedVMAttempt, script string) (string, error) {
	if _, err := fmt.Fprintf(p.log, "guest run=%s vm=%s\n", p.config.RunID, v.options.ID); err != nil {
		log.G(ctx).WithError(err).Warn("protected guest command could not be logged")
	}
	output, err := runGuestJoined(ctx, v.vm, script, p.log)
	if err != nil {
		_, _ = fmt.Fprintf(p.log, "guest run=%s vm=%s error=%v\n", p.config.RunID, v.options.ID, err)
	}
	return output, err
}

// stageDiode provisions modules and tools only on the diode before its services
// start. The workload uses its built-in adapter and verified-root tools.
// The optional writable output share precedes services and sealing; the VM owns
// cleanup and existing host captures are left untouched.
func (p *protectedPair) stageDiode(ctx context.Context) error {
	if p.config.PageMetadataOutputPath != "" {
		if err := p.diode.vm.Share(ctx, p.config.PageMetadataOutputPath, "/run/page-metadata-results", false); err != nil {
			return fmt.Errorf("share diode page metadata output: %w", err)
		}
	}
	for _, name := range protectedPairInputs() {
		if err := p.diode.vm.Share(ctx, filepath.Join(p.config.ModuleDirectory, name), "/run/sibling/"+name, true); err != nil {
			return err
		}
	}
	_, err := p.guest(ctx, &p.diode,
		`mkdir /run/sibling-exec; mount -t tmpfs -o exec,size=16m tmpfs /run/sibling-exec; `+
			`for tool in diode_iptables ahv-guest-ctl; do `+
			`cp /run/sibling/$tool/$tool /run/sibling-exec/$tool; chmod 755 /run/sibling-exec/$tool; done`)
	return err
}

// startService observes process loss before output drainage. The VM owns the
// service lifetime; stopping it requires neither successful signaling nor Wait.
func (p *protectedPair) startService(ctx context.Context, v *protectedVMAttempt, script string) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if err := p.ctx.Err(); err != nil {
		return context.Cause(p.ctx)
	}
	command := joinedGuestCommand(ctx, v.vm, script, p.log)
	command.Context = nil
	command.Host = contextHost{v.vm, ctx}
	command.Log = command.Log.WithField("protected_run", p.config.RunID).WithField("vm", v.options.ID)
	service := &protectedService{done: make(chan struct{})}
	p.services = append(p.services, service)
	if _, err := fmt.Fprintf(p.log, "service run=%s vm=%s command=%s\n",
		p.config.RunID, v.options.ID, script); err != nil {
		command.Log.WithError(err).Warn("protected service command could not be logged")
	}
	if err := command.Start(); err != nil {
		service.err = err
		close(service.done)
		return fmt.Errorf("protected service create %s uncertain: %w", v.options.ID, err)
	}
	go func() {
		waitErr := command.Process.Wait()
		if p.ctx.Err() == nil {
			p.stop(errors.Join(fmt.Errorf("protected service on %s exited unexpectedly", v.options.ID), waitErr))
		}
		service.err = waitErr
		close(service.done)
		if err := command.Wait(); err != nil {
			command.Log.WithError(err).Debug("protected service command output completed")
		}
	}()
	return nil
}

// checkServices requires live foreground owners in addition to guest readiness.
// It cannot prove a socket is ready or turn creation into an exit observation.
func (p *protectedPair) checkServices() error {
	if err := p.ctx.Err(); err != nil {
		return context.Cause(p.ctx)
	}
	for _, service := range p.services {
		select {
		case <-service.done:
			return errors.Join(errors.New("protected foreground service ended before handoff"), service.err)
		default:
		}
	}
	if p.timesync == nil {
		return errors.New("protected timesync service is missing")
	}
	return p.timesync.check()
}

// seal retains the native operation through return and excludes final reclaim.
// Negative index denotes backing admission, not a partition mask.
func (p *protectedPair) seal(ctx context.Context, index int, mask uint64) error {
	p.nativeMu.Lock()
	defer p.nativeMu.Unlock()
	if p.startupParent.Err() != nil {
		p.cancel(context.Cause(p.startupParent))
	}
	if err := p.ctx.Err(); err != nil {
		return context.Cause(p.ctx)
	}
	if index < 0 {
		if p.admissionAttempt {
			return errors.New("protected admission seal already attempted")
		}
		p.admissionAttempt = true
		return p.backing.SealAdmission(ctx)
	} else {
		if p.sealAttempt[index] {
			return errors.New("protected partition seal already attempted")
		}
		p.sealAttempt[index] = true
	}
	v := &p.diode
	if index == 1 {
		v = &p.workload
	}
	return v.vm.SealPartition(ctx, mask)
}

// sealPartition checks live owner cancellation before commitment under forwardMu,
// not the detached startup caller or one-attempt guards. Probe owners never
// admit seals. Startup completion is observed
// nonblockingly so a request cannot hold the lock needed to finish startup.
// Committed execution has no cancellation or deadline: nativeMu retains the
// VM/backing until the HCS wait observes actual completion, even on disconnect.
func (p *protectedPair) sealPartition(role string, mask uint64) (string, error) {
	v := &p.workload
	if role == "diode" {
		v = &p.diode
	}
	id := v.options.ID
	if p.unikraft != nil {
		return id, &uvm.PartitionSealError{Err: errors.New("protected Unikraft bring-up does not admit partition seals")}
	}
	select {
	case <-p.startupDone:
	default:
		return id, &uvm.PartitionSealError{Err: errors.New("protected owner startup is not complete")}
	}
	p.nativeMu.Lock()
	defer p.nativeMu.Unlock()
	p.forwardMu.Lock()
	ready := !p.closing && p.ctx.Err() == nil
	ctx := context.WithoutCancel(p.ctx)
	p.forwardMu.Unlock()
	if !ready || v.vm == nil {
		return id, &uvm.PartitionSealError{Err: errors.New("protected owner is shutting down or has no live VM")}
	}
	return v.vm.ID(), v.vm.SealPartition(ctx, mask)
}

// protectedDiodeLinkCommand waits inside the foreground dependency process.
// Re-expansion permits workload offers after process creation; exact transport
// version and diode/workload CIDs are checked before provider/relay startup.
func protectedDiodeLinkCommand() string {
	return `until set -- /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance; ` +
		`[ "$#" -eq 1 ] && [ -r "$1" ] && grep -q 'ready=1' "$1"; do sleep 0.1; done; ` +
		`set -- $(cat "$1"); [ "$#" -eq 5 ]; [ "${2#*=}" = 4 ]; [ "${3#*=}" = 3 ]; ` +
		fmt.Sprintf(`[ "${4#*=}" = %d ]; [ "${5#*=}" = 1 ]; `, TransportVersion) +
		`until [ -d /sys/bus/vmbus/drivers/hv_sock ]; do sleep 0.1; done; `
}

// configure checks native routes, guest networking/DNS and the real root
// provider, then installs the existing dynamic storage backend before any task.
func (p *protectedPair) configure(ctx context.Context) error {
	for _, v := range []*protectedVMAttempt{&p.diode, &p.workload} {
		if _, err := WaitForRoute(ctx, v.vm, v.options.SiblingCommunicationEndpoints[0]); err != nil {
			return err
		}
	}
	dns, err := HostDNSServers()
	if err != nil || len(dns) == 0 {
		return errors.Join(err, errors.New("protected workload requires host DNS resolvers"))
	}
	p.uplinkAttempt = true
	uplink, cleanup, err := AttachUplink(ctx, p.diode.vm)
	p.pair.uplinkCleanup = cleanup
	if err != nil {
		return err
	}
	device, err := p.configureNetwork(ctx, uplink, dns)
	if err != nil {
		return err
	}
	if _, err := p.guest(ctx, &p.workload, `ping -c 2 -W 2 10.200.0.1`); err != nil {
		return err
	}
	if err := p.workload.vm.ConfigureSiblingNetworking(guestresource.LCOWNetworkAdapter{
		ID: device, DNSServerList: strings.Join(dns, ","),
		IPConfigs: []guestresource.LCOWIPConfig{{IPAddress: "10.200.0.2", PrefixLength: 30}},
		Routes:    []guestresource.LCOWRoute{{DestinationPrefix: "0.0.0.0/0", NextHop: "10.200.0.1"}},
	}); err != nil {
		return err
	}
	// Export operations use the existing protocol with joined command drainage.
	control := newExportControl(
		// Export commands own ordinary guest/process references, not backing capabilities.
		func(ctx context.Context, script string) (string, error) { return p.guest(ctx, &p.diode, script) })
	if err := control.checkProvider(ctx); err != nil {
		return err
	}
	backend, err := scsi.NewSiblingHostBackend(p.diode.vm.SCSIManager, p.diode.options.ID, control)
	if err != nil {
		return err
	}
	if err := p.workload.vm.ConfigureSiblingStorage(backend); err != nil {
		return err
	}
	if p.config.directory != "" {
		metadata, err := newBenchmarkNetwork("10.200.0.2", uplink.Address, "linux", p.workload.vm.ID(), p.diode.vm.ID())
		if err != nil {
			return err
		}
		metadata.PublishedTCPPorts = append([]uint16(nil), p.config.PublishedTCPPorts...)
		if err := writeBenchmarkNetwork(p.config.directory, metadata); err != nil {
			return err
		}
	}
	return nil
}

// IsProtected identifies the native protected-backing owner.
func (p *Pair) IsProtected() bool { return p != nil && p.protected != nil }

// Done notifies the pod that protected dispatch has stopped.
func (p *Pair) Done() <-chan struct{} { return p.done }

// Stop requests native shutdown without waiting for ordinary guest cleanup.
func (p *Pair) Stop() {
	if p.IsProtected() {
		p.protected.stop(nil)
	}
}

var protectedOwners = struct {
	sync.Mutex
	shutdown          bool
	pairs             map[*protectedPair]struct{}
	probeHousekeeping map[*protectedPair]struct{}
}{
	pairs:             make(map[*protectedPair]struct{}),
	probeHousekeeping: make(map[*protectedPair]struct{}),
}

// registerProtectedPair races atomically with shim shutdown, before effects.
func registerProtectedPair(p *protectedPair) error {
	protectedOwners.Lock()
	defer protectedOwners.Unlock()
	if protectedOwners.shutdown {
		return errors.New("shim shutdown has closed protected owner admission")
	}
	protectedOwners.pairs[p] = struct{}{}
	return nil
}

// PrepareProtectedShutdown refuses shim exit while native ownership remains
// unresolved or a released probe still owes receipt publication or cleanup.
func PrepareProtectedShutdown() error {
	protectedOwners.Lock()
	defer protectedOwners.Unlock()
	if err := protectedShutdownBlocker(); err != nil {
		return err
	}
	protectedOwners.shutdown = true
	return nil
}

// protectedShutdownBlocker checks orderly exit eligibility with the registry
// locked, without committing to shutdown.
func protectedShutdownBlocker() error {
	if len(protectedOwners.pairs) != 0 {
		return fmt.Errorf("%d protected pair owners remain live or incomplete; retain shim and prepared inputs", len(protectedOwners.pairs))
	}
	if len(protectedOwners.probeHousekeeping) != 0 {
		return fmt.Errorf("%d protected Unikraft probes still publishing receipts or cleaning up; retain shim", len(protectedOwners.probeHousekeeping))
	}
	return nil
}

// close makes one native decision, excluding new acquisition and joining actual
// native dispatch. Ordinary processes, disks and output cannot veto its attempt.
func (p *protectedPair) close() error {
	p.nativeMu.Lock()
	nativeLocked := true
	defer func() {
		if nativeLocked {
			p.nativeMu.Unlock()
		}
	}()
	p.stopWatch()
	// Each participant gets an independent allowance. A failed workload stop
	// must not prevent a diode termination attempt.
	var nativeErr error
	for _, v := range []*protectedVMAttempt{&p.workload, &p.diode} {
		ctx, cancel := context.WithTimeout(context.Background(), protectedCleanupBudget)
		nativeErr = errors.Join(nativeErr, terminateProtectedVM(ctx, v))
		cancel()
	}
	// Actual exits permit the attempt; native participant/progress checks still
	// authorize reclaim. Ordinary guest/disk/log results are not inputs here.
	if nativeErr == nil && p.backing != nil {
		ctx, cancel := context.WithTimeout(context.Background(), protectedCleanupBudget)
		defer cancel()
		err := p.backing.BeginTeardown(ctx)
		if err == nil {
			err = p.backing.Reclaim(ctx)
		}
		nativeErr = errors.Join(nativeErr, err)
		if nativeErr == nil {
			nativeErr = p.backing.Release(ctx)
		}
	}
	if nativeErr != nil {
		return fmt.Errorf("protected native cleanup incomplete; retain backing owner and prepared inputs: %w", nativeErr)
	}
	// Native ownership ends here. Atomically replace probe ownership with an
	// orderly shutdown hold; it grants no authority over the released backing.
	protectedOwners.Lock()
	delete(protectedOwners.pairs, p)
	if p.unikraft != nil {
		protectedOwners.probeHousekeeping[p] = struct{}{}
	}
	protectedOwners.Unlock()
	// Native authority is finished. Release its lock before publication or any
	// ordinary cleanup can start waiting for guest/process/output borrowers.
	p.nativeMu.Unlock()
	nativeLocked = false
	receiptErr := p.publishReceipt()
	// Startup may still publish GCS/listener/output state or await a guest RPC.
	// Defer ordinary closure until those publishers return, without delaying
	// native reclaim or the receipt. No new native acquisition can be dispatched.
	go func() {
		<-p.startupDone
		p.cleanup()
		if p.unikraft != nil {
			protectedOwners.Lock()
			delete(protectedOwners.probeHousekeeping, p)
			protectedOwners.Unlock()
		}
	}()
	if receiptErr != nil {
		return fmt.Errorf("protected backing released, but cleanup receipt publication failed: %w", receiptErr)
	}
	return nil
}

// cleanup retires ordinary handles and prepared files after native release and
// startup return. Its diagnostics cannot suppress a truthful released receipt.
func (p *protectedPair) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), protectedCleanupBudget)
	defer cancel()
	result := p.disableUnikraftEntropy(ctx)
	// Ordinary attach and time I/O can wait for drainage only after both native
	// participants and backing are decided, with nativeMu no longer held.
	if p.pair.interactiveCloser != nil {
		result = errors.Join(result, p.pair.interactiveCloser.Close())
	}
	if p.timesync != nil {
		result = errors.Join(result, p.timesync.join())
	}
	if p.pair.unikraftConsole != nil {
		result = errors.Join(result, p.pair.unikraftConsole.Close())
	}
	for _, v := range []*protectedVMAttempt{&p.workload, &p.diode} {
		if v.vm != nil {
			result = errors.Join(result, v.vm.CloseAfterNativeExit(ctx))
		}
	}
	if p.pair.cpuGroups != nil {
		result = errors.Join(result, p.pair.cpuGroups.Close(ctx))
	}
	if p.workload.vm != nil {
		if err := os.Remove(filepath.Join(p.workload.options.BundleDirectory, p.workload.options.GuestStateFilePath)); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove owned workload VMGS copy: %w", err))
		}
	}
	if p.pair.uplinkCleanup != nil {
		result = errors.Join(result, p.pair.uplinkCleanup())
	} else if p.uplinkAttempt {
		result = errors.Join(result, errors.New("protected uplink ownership is unknown"))
	}
	if p.diode.bundleOwned {
		if p.applianceRootOwned {
			if err := os.Remove(filepath.Join(p.diode.options.BundleDirectory, protectedUnikraftRootName)); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, err)
			}
		}
		// Appliance Create copies only the VMGS; Linux Create also copies
		// rootfs.vhd. Other files are retained, never recursively deleted.
		if p.diode.createAttempt {
			bootCopies := []string{p.diode.options.GuestStateFilePath}
			if p.diode.options.Appliance == nil {
				bootCopies = append(bootCopies, vmutils.DefaultDmVerityRootfsVhd)
			}
			for _, name := range bootCopies {
				if err := os.Remove(filepath.Join(p.diode.options.BundleDirectory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
					result = errors.Join(result, err)
				}
			}
		}
		result = errors.Join(result, os.Remove(p.diode.options.BundleDirectory))
	}
	if result != nil {
		log.G(ctx).WithError(result).Warn("protected backing released with housekeeping warnings")
	}
	if p.log != nil {
		_, err := fmt.Fprintf(p.log, "cleanup run=%s workload=%s diode=%s error=%v\n",
			p.config.RunID, p.workload.options.ID, p.diode.options.ID, result)
		if logErr := errors.Join(err, p.log.Close()); logErr != nil {
			log.G(ctx).WithError(logErr).Warn("protected cleanup log could not be completed")
		}
	}
}

// terminateProtectedVM observes only native exit. GCS/listener/resource closure
// waits for ordinary startup publication in cleanup; it is not native authority.
// Terminate errors are diagnostic after confirmed exit. Unobservable creation
// or failed exit observation still denies release.
func terminateProtectedVM(ctx context.Context, v *protectedVMAttempt) error {
	if v.vm == nil {
		if v.createAttempt {
			return fmt.Errorf("protected VM %s creation is unobservable", v.options.ID)
		}
		return nil
	}
	err := v.vm.Terminate(ctx)
	if hcsv2.IsAlreadyStopped(err) {
		err = nil
	}
	if waitErr := v.vm.WaitNativeExit(ctx); waitErr != nil {
		return errors.Join(err, fmt.Errorf("protected VM %s native exit unobserved: %w", v.options.ID, waitErr))
	}
	if err != nil {
		log.G(ctx).WithField("vm", v.options.ID).WithError(err).Warn("protected VM exited after terminate error")
	}
	return nil
}

// publishReceipt atomically links a complete, flushed file to a fresh final
// name without replacement. Publication failure never replays native cleanup.
func (p *protectedPair) publishReceipt() error {
	receipt := struct {
		Version    int    `json:"version"`
		RunID      string `json:"run_id"`
		WorkloadID string `json:"workload_vm_id"`
		DiodeID    string `json:"diode_vm_id"`
		Result     string `json:"result"`
	}{1, p.config.RunID, p.workload.options.ID, p.diode.options.ID, "released"}
	file, err := os.CreateTemp(filepath.Dir(p.config.CleanupReceiptPath), ".protected-cleanup-*")
	if err != nil {
		return err
	}
	// The temporary name is ours even if final publication fails.
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(receipt)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	return os.Link(file.Name(), p.config.CleanupReceiptPath)
}

// configureNetwork overlaps carrier waits on both guests, then joins both
// commands before returning the actual workload peer identity.
func (p *protectedPair) configureNetwork(ctx context.Context, uplink *Uplink, dns []string) (string, error) {
	group, ctx := errgroup.WithContext(ctx)
	var device string
	// Provider creation and carrier checks may await workload NIC configuration.
	group.Go(func() error {
		_, err := p.guest(ctx, &p.diode, protectedDiodeNetworkCommand(uplink, p.config.PublishedTCPPorts...))
		return err
	})
	// The workload can discover its NIC only after the provider starts.
	group.Go(func() error {
		command := workloadNICDiscoveryCommand("", true)
		output, err := p.guest(ctx, &p.workload, command)
		if err != nil {
			return err
		}
		device = strings.TrimSpace(output)
		if !guestresource.IsSiblingVMBusDeviceID(device) {
			return fmt.Errorf("protected workload has invalid peer NIC %q", device)
		}
		_, err = p.guest(ctx, &p.workload, protectedWorkloadNetworkCommand(device, dns))
		return err
	})
	err := group.Wait()
	return device, err
}

// protectedDiodeNetworkCommand configures only the stock provider, NAT, and
// optional published TCP port DNAT rules. It uses staged iptables, never
// demo/benchmark services or a second tmpfs mount.
func protectedDiodeNetworkCommand(uplink *Uplink, ports ...uint16) string {
	command := `insmod /run/sibling/diode_netvsp.ko/diode_netvsp.ko; ` +
		`until [ -e /sys/class/net/dvsp0 ]; do sleep 0.1; done; ` +
		`ip addr add 10.200.0.1/30 dev dvsp0; ip link set dvsp0 up; ` +
		`until up=; count=0; for p in /sys/class/net/*; do [ -e "$p/device" ] || continue; ` +
		`d=$(readlink -f "$p/device"); case ${d##*/} in bus*-relid*) continue;; esac; ` +
		`up=${p##*/}; count=$((count+1)); done; [ "$count" -le 1 ] || exit 1; [ "$count" -eq 1 ]; do sleep 0.1; done; ` +
		`ip addr add ` + Quote(uplink.Address) + ` dev "$up"; ip link set "$up" up; ` +
		`ip route replace default via ` + Quote(uplink.Gateway) + ` dev "$up"; ` +
		`until [ "$(cat /sys/class/net/$up/carrier)" = 1 ] && [ "$(cat /sys/class/net/dvsp0/carrier)" = 1 ]; do sleep 0.1; done; ` +
		`echo 1 >/proc/sys/net/ipv4/ip_forward; ` +
		`/run/sibling-exec/diode_iptables iptables -w -P FORWARD ACCEPT; ` +
		`/run/sibling-exec/diode_iptables iptables -w -t nat -A POSTROUTING -s 10.200.0.0/30 -o "$up" -j MASQUERADE; ` +
		`/run/sibling-exec/diode_iptables iptables -w -t nat -C POSTROUTING -s 10.200.0.0/30 -o "$up" -j MASQUERADE; ` +
		`[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]; ` +
		`ip route show default | grep -q "via ` + uplink.Gateway + ` dev $up"; ` +
		`ip -4 addr show dev "$up" | grep -qF ` + Quote(uplink.Address)
	address := strings.SplitN(uplink.Address, "/", 2)[0]
	for _, port := range ports {
		command += fmt.Sprintf(`; /run/sibling-exec/diode_iptables iptables -w -t nat -A PREROUTING -i "$up" -d %s -p tcp --dport %d -j DNAT --to-destination 10.200.0.2:%d`,
			Quote(address), port, port)
	}
	return command
}

// protectedWorkloadNetworkCommand applies the discovered stock peer NIC only.
// It checks the resulting route, read-only root and DNS file, including the
// existing bind/overlay strategy when /etc is immutable.
func protectedWorkloadNetworkCommand(device string, dns []string) string {
	command := `nic=; for p in /sys/class/net/*; do d=$(readlink -f "$p/device" 2>/dev/null || true); ` +
		`[ "${d##*/}" != ` + Quote(device) + ` ] || nic=${p##*/}; done; [ -n "$nic" ]; ` +
		`if [ "$nic" != dvsc0 ]; then ip link set "$nic" name dvsc0; fi; ` +
		`ip addr add 10.200.0.2/30 dev dvsc0; ip link set dvsc0 up; ` +
		`ip route replace default via 10.200.0.1 dev dvsc0; ` +
		`printf 'nameserver %s\n' ` + strings.Join(dns, " ") + ` >/run/resolv.conf; ` +
		`if cp /run/resolv.conf /etc/resolv.conf 2>/dev/null; then :; ` +
		`elif [ -e /etc/resolv.conf ]; then mount --bind /run/resolv.conf /etc/resolv.conf; ` +
		`else o=/run/etc-overlay; mkdir -p $o; mount -t tmpfs tmpfs $o; mkdir $o/up $o/work; ` +
		`mount -t overlay overlay -o lowerdir=/etc,upperdir=$o/up,workdir=$o/work /etc; cp /run/resolv.conf /etc/resolv.conf; fi; `
	for _, server := range dns {
		command += `grep -qFx ` + Quote("nameserver "+server) + ` /etc/resolv.conf; `
	}
	return command +
		`until [ "$(cat /sys/class/net/dvsc0/carrier)" = 1 ]; do sleep 0.1; done; ` +
		`ip route show default | grep -q 'via 10.200.0.1 dev dvsc0'; ` +
		`ip -4 addr show dev dvsc0 | grep -qF '10.200.0.2/30'; ` +
		`awk '$2=="/" {found=1; if ($4 !~ /(^|,)ro(,|$)/) exit 1} END {if (!found) exit 1}' /proc/mounts; ` +
		`test -x /usr/bin/ahv-guest-ctl`
}
