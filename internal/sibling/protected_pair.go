//go:build windows

package sibling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/cmd"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcsv2 "github.com/Microsoft/hcsshim/internal/hcs/v2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/internal/signals"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/uvm/scsi"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
	"golang.org/x/sync/errgroup"
)

const (
	protectedPairSetupBudget = 10 * time.Minute
	protectedPairGCSBudget   = 7 * time.Minute
	protectedPartitionBudget = 5 * time.Minute
	protectedPairLogName     = "protected-pair.log"
	protectedCleanupBudget   = 2 * time.Minute
)

// protectedVMAttempt is retained before CreateLCOW, even when it returns no VM.
// Such a failure is unknown native ownership, not evidence of zero work.
type protectedVMAttempt struct {
	options       *uvm.OptionsLCOW
	region        hcsschema.SharedMemoryRegion
	vm            *uvm.UtilityVM
	createAttempt bool
	startAttempt  bool
	started       bool
	bundleAttempt bool
	bundleOwned   bool
}

// protectedService retains creation and the sole joined Wait obligation.
// done publishes err/exited; a failed Start never proves that no guest ran.
type protectedService struct {
	command    *cmd.Cmd
	done       chan struct{}
	startErr   error
	err        error
	exited     bool
	dependency bool
	attempted  bool
	unexpected error
	mu         sync.Mutex
	retiring   bool
	signals    sync.WaitGroup
	signalErr  error
}

// protectedPair is a serial lifecycle owner, not a second VM/task implementation.
// Close joins startup, tasks, watchers and services before retiring
// their owners. Dependencies intentionally survive stop: workload shutdown
// still needs the diode's root/provider/relay. No implicit backing Close exists.
type protectedPair struct {
	pair                *Pair
	config              *Config
	backing             *ProtectedBacking
	diode               protectedVMAttempt
	workload            protectedVMAttempt
	rootAttempt         bool
	root                *scsi.Mount
	providerStarted     bool // Latched readiness proves insmod returned, not current liveness.
	uplinkAttempt       bool
	services            []*protectedService
	control             *ExportControl
	backend             scsi.HostBackend
	log                 *os.File
	startupDone         chan struct{}
	startupErr          error
	startupParent       context.Context // Checked at seal commitment, never used as a service lifetime.
	ctx                 context.Context
	cancel              context.CancelCauseFunc
	dependencyCtx       context.Context
	stopDependencies    context.CancelFunc
	watchCtx            context.Context
	stopWatch           context.CancelFunc
	watchers            sync.WaitGroup
	forwardMu           sync.Mutex
	closing             bool
	tasks               int
	tasksDone           chan struct{}
	taskErr             error
	dependenciesClosing bool // Guarded by forwardMu; expected relay EOF, not cancellation.
	// Attempts are retained evidence, not permission to replay controls.
	admissionAttempt bool
	sealAttempt      [2]bool
}

// startProtectedPair implements the owned Bootstrap-before-Import sequence.
// It preflights without backing, validates diode native startup before workload
// creation, creates independent foreground AHV and root/GCS services before
// workload Start, then checks mediation and seals before sandbox creation.
//
// After owner allocation,
// even an error returns the Pair: the caller must retain it, never ordinary-close
// its VMs or delete its prepared bundle. Native calls are synchronous and joined;
// deadlines cannot abandon executing calls, buffers or controller capabilities.
func startProtectedPair(parent context.Context, base *uvm.OptionsLCOW, config *Config) (*Pair, error) {
	if config == nil {
		return nil, errors.New("protected pair config is nil")
	}
	// Reuse strict validation for future programmatic dispatch, not just files.
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	config, err = decodeConfig(strings.NewReader(string(encoded)))
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
	if err := preflightProtectedPair(parent, config, workload, diode); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	dependencies, stopDependencies := context.WithCancel(context.Background())
	watch, stopWatch := context.WithCancel(context.Background())
	pair := &Pair{done: make(chan struct{})}
	p := &protectedPair{
		pair: pair, config: config, ctx: ctx, cancel: cancel,
		dependencyCtx: dependencies, stopDependencies: stopDependencies,
		watchCtx: watch, stopWatch: stopWatch, startupDone: make(chan struct{}), startupParent: parent,
		tasksDone: make(chan struct{}),
		diode:     protectedVMAttempt{options: diode}, workload: protectedVMAttempt{options: workload},
	}
	pair.protected = p
	if err := registerProtectedPair(p); err != nil {
		cancel(err)
		stopDependencies()
		stopWatch()
		return nil, err
	}
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
	p.startupErr = err
	if err != nil {
		p.stop(err)
		if p.log != nil {
			_, logErr := fmt.Fprintf(p.log, "startup failed run=%s diode=%s workload=%s error=%v\n",
				p.config.RunID, diode.ID, workload.ID, err)
			err = errors.Join(err, logErr)
			p.startupErr = err
		}
	}
	return pair, err
}

// preflightProtectedPair rejects excluded profiles and missing inputs before
// startProtectedPair acquires its log, bundle, backing or native controller.
func preflightProtectedPair(ctx context.Context, config *Config, workload, diode *uvm.OptionsLCOW) error {
	if err := ValidateProtectedControllerABI(); err != nil {
		return err
	}
	if err := ValidateProtectedBackingSize(config.SharedMemoryBytes); err != nil {
		return err
	}
	for _, options := range []*uvm.OptionsLCOW{diode, workload} {
		if options.Appliance != nil || options.HclEnabled == nil || *options.HclEnabled ||
			options.AllowOvercommit || options.EnableDeferredCommit ||
			options.PreferredRootFSType != uvm.PreferredRootFSTypeNA ||
			options.CPUGroupID != "" || options.ResourcePartitionID != nil ||
			options.ProcessorLimit != 0 || options.ProcessorWeight != 0 ||
			len(options.ProtectedSharedResources) != 0 || options.NetworkConfigProxy != "" {
			return errors.New("protected owned pair requires unchanged direct SNP Linux dm-verity boot without CPU-group/tuning or appliance options")
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
	for _, name := range protectedPairInputs() {
		paths = append(paths, filepath.Join(config.ModuleDirectory, name))
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("protected input %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("protected input %q is not a regular file", path)
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
	for _, path := range []string{config.CleanupReceiptPath, logPath, diode.BundleDirectory} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(err, fmt.Errorf("protected output must be fresh: %s", path))
		}
	}
	return ctx.Err()
}

// protectedPairInputs is the minimal owned profile, excluding benchmark/demo
// services and host page-metadata exports. The workload client stays in its root.
func protectedPairInputs() []string {
	return []string{"sibling_bus.ko", "diode_storvsp.ko", "diode_netvsp.ko", "diode_iptables", "ahv-guest-ctl"}
}

// stop closes forward work only, serialized with irreversible seal commitment.
// It never cancels dependencies needed by workload drainage.
func (p *protectedPair) stop(cause error) {
	p.forwardMu.Lock()
	if !p.closing {
		p.closing = true
		close(p.pair.done)
		if p.tasks == 0 {
			close(p.tasksDone)
		}
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
	p.diode.bundleAttempt = true
	if err := os.Mkdir(p.diode.options.BundleDirectory, 0700); err != nil {
		return fmt.Errorf("create owned diode bundle: %w", err)
	}
	p.diode.bundleOwned = true
	p.backing, err = NewProtectedBacking("hcsshim-protected-"+group, p.config.SharedMemoryBytes)
	if err != nil {
		return err
	}
	for _, v := range []*protectedVMAttempt{&p.diode, &p.workload} {
		v.options.SiblingCommunicationEndpoints[0].SharedMemorySectionName = p.backing.SectionName()
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
	if err := p.workload.vm.ConfigureGCSRelay(p.diode.vm); err != nil {
		return err
	}
	p.rootAttempt = true
	p.root, err = p.diode.vm.SCSIManager.AddVirtualDisk(setup,
		filepath.Join(p.workload.options.BundleDirectory, vmutils.DefaultDmVerityRootfsVhd),
		true, p.diode.options.ID, "", nil)
	if err != nil {
		return fmt.Errorf("protected root attachment uncertain; retain both bundles: %w", err)
	}
	if p.root == nil {
		return errors.New("protected root attachment has no release owner")
	}
	if err := p.stage(setup, &p.diode); err != nil {
		return err
	}
	resolve, err := RPDeviceCommand(p.root.Controller(), p.root.LUN())
	if err != nil {
		return err
	}
	// These are separate foreground owners. Creation does not wait for peer
	// offers; their guest waits overlap workload native Start and GCS bootstrap.
	if err := p.startService(setup, &p.diode, "exec /run/sibling-exec/ahv-guest-ctl boot-server", false); err != nil {
		return err
	}
	provider := `trap 'exit 1' TERM INT; ` +
		BusLoadCommand("/run/sibling/sibling_bus.ko/sibling_bus.ko") +
		protectedDiodeLinkCommand() + resolve +
		`insmod /run/sibling/diode_storvsp.ko/diode_storvsp.ko "backends=$storage_dev" luns=0 read_only=true; ` +
		`exec /bin/gcs -sibling-relay -relay-ready /run/sibling-exec/gcs-relay.ready`
	if err := p.startService(setup, &p.diode, provider, true); err != nil {
		return err
	}
	if err := p.start(setup, &p.workload); err != nil {
		return err
	}
	if _, err := p.guest(setup, &p.diode,
		`until [ -f /run/sibling-exec/gcs-relay.ready ]; do sleep 0.1; done`); err != nil {
		return err
	}
	// The relay removes its ready file when its session ends. Retain the
	// observed provider-start completion across workload termination.
	p.providerStarted = true
	if err := p.configure(setup); err != nil {
		return err
	}
	p.pair.interactiveCloser, err = startPairShells(p.pair)
	if err != nil {
		return err
	}
	if err := p.checkServices(); err != nil {
		return err
	}
	if err := p.commitSeal(-1); err != nil {
		return err
	}
	if err := p.backing.SealAdmission(setup); err != nil {
		return err
	}
	// Each selected partition gets its own fresh allowance, not the remaining
	// setup budget. No fallback, changed mask, retry or detached native syscall.
	stopSetup()
	for i, mask := range []*uint64{p.config.DiodePartitionSealMask, p.config.WorkloadPartitionSealMask} {
		if mask == nil {
			continue
		}
		if err := p.commitSeal(i); err != nil {
			return err
		}
		v := &p.diode
		if i == 1 {
			v = &p.workload
		}
		ctx, cancel := context.WithTimeout(p.ctx, protectedPartitionBudget)
		err := v.vm.SealPartition(ctx, *mask)
		cancel()
		_, logErr := fmt.Fprintf(p.log, "partition seal run=%s vm=%s mask=%d error=%v\n",
			p.config.RunID, v.options.ID, *mask, err)
		if err != nil || logErr != nil {
			return errors.Join(err, logErr)
		}
	}
	return p.checkServices()
}

// create records the attempt and real capability before synchronous CreateLCOW.
// Existing CreateLCOW error cleanup is unchanged; unobservable work stays unknown.
func (p *protectedPair) create(ctx context.Context, v *protectedVMAttempt, mode hcsschema.ProtectedSharedBackingMode) error {
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

// start validates the sole matching actual startup receipt before any next
// creation/action. Failed startup preserves checked history without clearing
// uncertainty. The VM and controller remain owned through every native return.
func (p *protectedPair) start(ctx context.Context, v *protectedVMAttempt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.startAttempt = true
	var err error
	if v == &p.workload {
		err = v.vm.StartWithGCSConnectionTimeout(ctx, protectedPairGCSBudget)
	} else {
		err = v.vm.Start(ctx)
	}
	if err != nil {
		p.backing.MarkUnknown()
		p.observeFailedStartup(v)
		return fmt.Errorf("protected start %s (progress uncertain): %w", v.options.ID, err)
	}
	v.started = true
	p.watch(v)
	regions, err := v.vm.SharedMemoryRegions(ctx)
	if err != nil || len(regions) != 1 || regions[0].SectionName != v.region.SectionName {
		p.backing.MarkUnknown()
		return errors.Join(err, fmt.Errorf("protected %s missing exact startup region", v.options.ID))
	}
	if err := p.backing.ObserveStartup(regions[0].ProtectedShared); err != nil {
		return err
	}
	v.region.ProtectedSharedLeaseId = regions[0].ProtectedShared.LeaseId
	gpa, err := uvm.SharedMemoryByteGPA(regions[0].GuestPhysicalAddress, int64(v.region.Length))
	if err != nil {
		p.backing.MarkUnknown()
		return err
	}
	_, err = fmt.Fprintf(p.log, "startup run=%s vm=%s mode=%s lease=%d byte_gpa=%#x installed=true\n",
		p.config.RunID, v.options.ID, v.region.ProtectedSharedBackingMode, v.region.ProtectedSharedLeaseId, gpa)
	return err
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

// watch cancels forward work on unexpected VM exit without mutating lifecycle
// evidence. close stops and joins these watchers before closing VM handles.
func (p *protectedPair) watch(v *protectedVMAttempt) {
	p.watchers.Add(1)
	// Native exit, not log delivery, triggers loss notification.
	go func() {
		defer p.watchers.Done()
		err := v.vm.WaitNativeExit(p.watchCtx)
		if p.watchCtx.Err() == nil {
			cause := errors.Join(fmt.Errorf("protected VM %s exited", v.options.ID), err, v.vm.ExitError())
			_, logErr := fmt.Fprintf(p.log, "VM ended run=%s vm=%s error=%v\n", p.config.RunID, v.options.ID, cause)
			p.stop(errors.Join(cause, logErr))
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

// stage mounts executable storage once, before diode services start. The
// collector is /run/sibling-exec/ahv-guest-ctl only on the diode; no workload copy
// replaces /usr/bin/ahv-guest-ctl from the verified root.
func (p *protectedPair) stage(ctx context.Context, v *protectedVMAttempt) error {
	names := []string{"sibling_bus.ko"}
	if v == &p.diode {
		names = protectedPairInputs()
	}
	for _, name := range names {
		if err := v.vm.Share(ctx, filepath.Join(p.config.ModuleDirectory, name), "/run/sibling/"+name, true); err != nil {
			return err
		}
	}
	if v == &p.workload {
		return nil
	}
	_, err := p.guest(ctx, v,
		`mkdir /run/sibling-exec; mount -t tmpfs -o exec,size=16m tmpfs /run/sibling-exec; `+
			`for tool in diode_iptables ahv-guest-ctl; do `+
			`cp /run/sibling/$tool/$tool /run/sibling-exec/$tool; chmod 755 /run/sibling-exec/$tool; done`)
	return err
}

// startService retains the concrete process before creation, then owns its sole
// joined Wait. ctx bounds creation, not the process lifetime. Dependencies use
// trapped TERM only after storage cleanup, with signal borrowers joined before Wait.
// A premature exit cancels forward work, not the still-needed root/relay.
func (p *protectedPair) startService(ctx context.Context, v *protectedVMAttempt, script string, dependency bool) error {
	lifetime := p.ctx
	if dependency {
		lifetime = p.dependencyCtx
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	if err := p.ctx.Err(); err != nil {
		return context.Cause(p.ctx)
	}
	command := joinedGuestCommand(lifetime, v.vm, script, p.log)
	if dependency {
		// TERM lets a foreground insmod finish/reap before the shell exits.
		// Cmd's context cancellation would SIGKILL the shell and orphan it.
		command.Context = nil
	}
	command.Host = contextHost{v.vm, ctx}
	command.Log = command.Log.WithField("protected_run", p.config.RunID).WithField("vm", v.options.ID)
	service := &protectedService{command: command, done: make(chan struct{}), dependency: dependency}
	p.services = append(p.services, service)
	if _, err := fmt.Fprintf(p.log, "service run=%s vm=%s dependency=%t command=%s\n",
		p.config.RunID, v.options.ID, dependency, script); err != nil {
		command.Log.WithError(err).Warn("protected service command could not be logged")
	}
	service.attempted = true
	if err := command.Start(); err != nil {
		service.startErr, service.err = err, err
		close(service.done)
		return fmt.Errorf("protected service create %s uncertain: %w", v.options.ID, err)
	}
	// This waiter owns all command callbacks/IO until done, not just guest exit.
	go func() {
		waitErr := command.Process.Wait()
		p.forwardMu.Lock()
		expected := lifetime.Err() != nil || (dependency && p.dependenciesClosing)
		p.forwardMu.Unlock()
		if !expected {
			service.unexpected = errors.Join(fmt.Errorf("protected service on %s exited unexpectedly", v.options.ID), waitErr)
			p.stop(service.unexpected)
		}
		// Retire signal admission before Cmd.Wait can close Process.
		service.mu.Lock()
		service.retiring = true
		service.mu.Unlock()
		service.signals.Wait()
		_, exitErr := command.Process.ExitCode()
		if err := command.Wait(); err != nil {
			command.Log.WithError(err).Debug("protected service command output completed")
		}
		service.err = errors.Join(service.unexpected, waitErr, exitErr, service.signalErr)
		service.exited = exitErr == nil
		_, _ = fmt.Fprintf(p.log, "service ended run=%s vm=%s exited=%t error=%v\n",
			p.config.RunID, v.options.ID, service.exited, service.err)
		close(service.done)
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
	return nil
}

// commitSeal serializes cancellation with one attempt's commitment, never with
// executing native code. Negative index denotes backing admission, not a mask.
func (p *protectedPair) commitSeal(index int) error {
	p.forwardMu.Lock()
	defer p.forwardMu.Unlock()
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
	} else {
		if p.sealAttempt[index] {
			return errors.New("protected partition seal already attempted")
		}
		p.sealAttempt[index] = true
	}
	return nil
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
	if err := p.stage(ctx, &p.workload); err != nil {
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
	p.control = newExportControl(
		// The diode owner outlives every dynamic export operation.
		func(ctx context.Context, script string) (string, error) { return p.guest(ctx, &p.diode, script) })
	if err := p.control.checkProvider(ctx); err != nil {
		return err
	}
	p.backend, err = scsi.NewSiblingHostBackend(p.diode.vm.SCSIManager, p.diode.options.ID, p.control)
	if err != nil {
		return err
	}
	if err := p.workload.vm.ConfigureSiblingStorage(p.backend); err != nil {
		return err
	}
	return p.workload.vm.SCSIManager.EnableProtectedSibling()
}

// IsProtected identifies the opt-in task cleanup contract.
func (p *Pair) IsProtected() bool { return p != nil && p.protected != nil }

// Done notifies the pod to close creation admission and drain normal tasks.
func (p *Pair) Done() <-chan struct{} { return p.done }

// Stop closes protected task admission before notifying pod cleanup.
func (p *Pair) Stop() {
	if p.IsProtected() {
		p.protected.stop(nil)
	}
}

// BeginTask counts creation before its first side effect. A successful create
// transfers this obligation to normal task cleanup, before any watcher starts.
func (p *Pair) BeginTask() error {
	s := p.protected
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	if s.closing {
		return errors.New("protected pair task admission is closed")
	}
	s.tasks++
	return nil
}

// EndTask settles exactly one admitted task only after real resource cleanup.
// Errors are sticky: process exit or metadata removal cannot authorize release.
func (p *Pair) EndTask(err error) {
	s := p.protected
	s.forwardMu.Lock()
	s.taskErr = errors.Join(s.taskErr, err)
	s.tasks--
	if s.closing && s.tasks == 0 {
		close(s.tasksDone)
	}
	s.forwardMu.Unlock()
	if err != nil {
		s.stop(err)
	}
}

var protectedOwners = struct {
	sync.Mutex
	shutdown bool
	pairs    map[*protectedPair]struct{}
}{pairs: make(map[*protectedPair]struct{})}

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

// PrepareProtectedShutdown refuses shim exit while any protected owner is live
// or incomplete, including startup failures with no published sandbox task.
func PrepareProtectedShutdown() error {
	protectedOwners.Lock()
	defer protectedOwners.Unlock()
	if len(protectedOwners.pairs) != 0 {
		return fmt.Errorf("%d protected pair owners remain live or incomplete; retain shim and prepared inputs", len(protectedOwners.pairs))
	}
	protectedOwners.shutdown = true
	return nil
}

// close is the single protected cleanup decision; it is never retried. Tasks
// drain before workload termination. Exports and root drain with diode GCS alive;
// returned cleanup errors do not prevent termination of known participants.
// Both actual VM exits and command/control joins precede native backing release.
// Any uncertainty retains this owner in protectedOwners without a receipt.
func (p *protectedPair) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), protectedCleanupBudget)
	defer cancel()
	select {
	case <-p.startupDone:
	case <-ctx.Done():
		return fmt.Errorf("protected startup still owns resources: %w", ctx.Err())
	}
	var result error
	if p.pair.interactiveCloser != nil {
		result = errors.Join(result, p.pair.interactiveCloser.Close())
	}
	select {
	case <-p.tasksDone:
	case <-ctx.Done():
		return errors.Join(result, fmt.Errorf("protected tasks still own resources: %w", ctx.Err()))
	}
	p.forwardMu.Lock()
	result = errors.Join(result, p.taskErr)
	p.forwardMu.Unlock()
	p.stopWatch()
	p.watchers.Wait()

	// Workload termination can naturally close the relay before we signal it.
	// Mark that EOF expected without canceling its still-needed dependencies.
	p.forwardMu.Lock()
	p.dependenciesClosing = true
	p.forwardMu.Unlock()
	// A returned cleanup operation may have exhausted the shared budget.
	// Still allow one bounded terminal attempt, never replay or detach it.
	if ctx.Err() != nil {
		ctx, cancel = context.WithTimeout(context.Background(), protectedCleanupBudget)
		defer cancel()
	}
	workloadErr := terminateProtectedVM(ctx, &p.workload)
	result = errors.Join(result, workloadErr)
	if workloadErr == nil {
		if p.backend != nil {
			result = errors.Join(result, p.workload.vm.SCSIManager.CloseProtectedSibling(ctx))
		}
		if p.rootAttempt && p.root == nil {
			result = errors.Join(result, errors.New("protected root attachment is unobservable; retain backing"))
		}
		if p.root != nil {
			// An attempted provider starter may still be in insmod if startup
			// never observed relay readiness. A later relay exit does not undo
			// that observation or prevent provider quiescence.
			providerStarting := false
			for _, service := range p.services {
				if service.dependency && service.attempted && !p.providerStarted {
					providerStarting = true
					break
				}
			}
			// Keep direct diode GCS through provider quiescence and the actual
			// RP release. A failed quiescence never authorizes disk detachment.
			if providerStarting {
				result = errors.Join(result, errors.New("protected provider startup completion is unobserved; retain root attachment"))
			} else if _, err := p.guest(ctx, &p.diode,
				`if [ -d /sys/module/diode_storvsp ]; then rmmod diode_storvsp; fi; [ ! -d /sys/module/diode_storvsp ]`); err != nil {
				result = errors.Join(result, err)
			} else {
				result = errors.Join(result, p.root.Release(ctx))
			}
		}
	}
	p.stopDependencyServices(ctx)
	// A failed provider/storage operation or TERM must not leave the diode
	// running merely because it consumed the preceding cleanup allowance.
	if ctx.Err() != nil {
		ctx, cancel = context.WithTimeout(context.Background(), protectedCleanupBudget)
		defer cancel()
	}
	result = errors.Join(result, terminateProtectedVM(ctx, &p.diode))
	p.stopDependencies()
	// External UVM process signals need not succeed for the VM to terminate.
	// terminateProtectedVM closes GCS after exit, releasing waits and callbacks;
	// join those users before retiring VM handles or the shared log.
	result = errors.Join(result, p.joinServices(ctx))
	if result != nil {
		return result
	}
	if p.backing != nil {
		if err := p.backing.BeginTeardown(ctx); err != nil {
			return err
		}
		if err := p.backing.Reclaim(ctx); err != nil {
			return err
		}
		if err := p.backing.Release(ctx); err != nil {
			return err
		}
	}
	// Final resource close does not join logs and follows backing release.
	// Boot-copy deletion only logs errors, so verify our workload VMGS
	// separately without deleting the caller-owned sandbox directory.
	for _, v := range []*protectedVMAttempt{&p.workload, &p.diode} {
		if v.vm != nil {
			result = errors.Join(result, v.vm.CloseAfterNativeExit(ctx))
		}
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
	if p.diode.bundleOwned && result == nil {
		// Only CreateLCOW's two known boot copies belong to this owner.
		// An unexpected directory entry is retained, never recursively deleted.
		if p.diode.createAttempt {
			for _, name := range []string{p.diode.options.GuestStateFilePath, vmutils.DefaultDmVerityRootfsVhd} {
				if err := os.Remove(filepath.Join(p.diode.options.BundleDirectory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
					result = errors.Join(result, err)
				}
			}
		}
		if result == nil {
			result = os.Remove(p.diode.options.BundleDirectory)
		}
	}
	if p.log != nil {
		_, err := fmt.Fprintf(p.log, "cleanup run=%s workload=%s diode=%s error=%v\n",
			p.config.RunID, p.workload.options.ID, p.diode.options.ID, result)
		if logErr := errors.Join(err, p.log.Close()); logErr != nil {
			log.G(ctx).WithError(logErr).Warn("protected cleanup log could not be completed")
		}
	}
	result = errors.Join(result, ctx.Err())
	if result != nil {
		return result
	}
	if err := p.publishReceipt(); err != nil {
		return err
	}
	protectedOwners.Lock()
	delete(protectedOwners.pairs, p)
	protectedOwners.Unlock()
	return nil
}

// terminateProtectedVM observes native exit before closing the existing GCS
// connection to release outstanding RPC waits. Terminate/connection errors are
// diagnostic after confirmed exit; neither submission nor handle closure proves
// exit. Unobservable creation or failed exit observation still denies release.
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
	// UtilityVM's background waiter closes exitCh, not the external GCS
	// bridge. Close it here so service Wait does not need a process-exit RPC
	// from a guest that has already terminated. No VM handles are closed yet.
	if err := v.vm.CloseGCSConnection(); err != nil {
		log.G(ctx).WithField("vm", v.options.ID).WithError(err).Warn("protected VM exited with GCS close error")
	}
	return nil
}

// stopDependencyServices requests a trapped TERM, never cancellation's SIGKILL.
// Each signal is counted before dispatch and joined before Process can close.
func (p *protectedPair) stopDependencyServices(ctx context.Context) {
	for _, service := range p.services {
		if !service.dependency || service.startErr != nil {
			continue
		}
		service.mu.Lock()
		if service.retiring {
			service.mu.Unlock()
			continue
		}
		service.signals.Add(1)
		service.mu.Unlock()
		options, err := signals.ValidateSigstrLCOW("TERM", true)
		if err == nil {
			_, err = service.command.Process.Signal(ctx, options)
		}
		if hcsv2.IsAlreadyStopped(err) {
			err = nil
		}
		service.signalErr = err
		service.signals.Done()
	}
}

// joinServices joins actual command/control users after participant termination
// attempts. Completed process/signal errors are diagnostics, not VM-exit evidence;
// an unfinished callback still retains its owners and prevents backing release.
func (p *protectedPair) joinServices(ctx context.Context) error {
	for _, service := range p.services {
		select {
		case <-service.done:
			if service.err != nil {
				service.command.Log.WithError(service.err).Warn("protected service cleanup completed with diagnostic errors")
			}
		case <-ctx.Done():
			return fmt.Errorf("protected service has not drained: %w", ctx.Err())
		}
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
		_, err := p.guest(ctx, &p.diode, protectedDiodeNetworkCommand(uplink))
		return err
	})
	// The workload can discover its NIC only after the provider starts.
	group.Go(func() error {
		output, err := p.guest(ctx, &p.workload, workloadNICCommand())
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

// protectedDiodeNetworkCommand configures only the stock provider and NAT.
// It uses staged iptables, never demo/benchmark services or a second tmpfs mount.
func protectedDiodeNetworkCommand(uplink *Uplink) string {
	return `insmod /run/sibling/diode_netvsp.ko/diode_netvsp.ko; ` +
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
