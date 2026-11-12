//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/internal/cmd"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcsv2 "github.com/Microsoft/hcsshim/internal/hcs/v2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/sibling"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
)

const (
	protectedSetupBudget         = 5 * time.Minute
	protectedCombinedSetupBudget = 10 * time.Minute
	protectedWorkloadGCSBudget   = 7 * time.Minute
	protectedCleanupBudget       = 2 * time.Minute
	protectedCombinedBytes       = 32 * 1024 * 1024
)

type protectedSiblingProfile uint8

const (
	protectedSiblingDirectRoot protectedSiblingProfile = iota
	protectedSiblingMediatedRoot
)

// protectedSiblingVM owns one attempt, including options before Create returns.
// region selects startup mode before create and retains complete immutable
// settings at dispatch; its actual lease follows the checked startup receipt.
// attempted with vm nil is unobservable, never proof that native preparation
// did no work.
type protectedSiblingVM struct {
	options     *uvm.OptionsLCOW
	region      hcsschema.SharedMemoryRegion
	vm          *uvm.UtilityVM
	role        string
	attempted   bool
	started     bool
	drained     bool
	closed      bool
	bundleOwned bool
}

// protectedSiblingService retains even a failed creation attempt. done closes
// only after creation and any successful-start Wait have joined all borrowers.
// A failed creation or unobserved exit never authorizes backing/root release.
type protectedSiblingService struct {
	process *cmd.Cmd
	done    chan struct{}
	err     error
}

// protectedSiblingPair is the sole serial owner of the two attempts, backing,
// boot copies and host network releases. Only cancellation/watchers and GCS
// commands run concurrently; they never mutate lifecycle progress. forwardMu
// serializes cancellation with seal-attempt commitment, not native execution.
// cleanup has its own independent budget and joins shell/command borrowers.
type protectedSiblingPair struct {
	profile     protectedSiblingProfile
	memory      *sibling.ProtectedBacking
	workers     []*protectedSiblingVM
	cpuGroups   *cpuGroupAssignments
	uplinkClose func() error
	ctx         context.Context
	cancel      context.CancelCauseFunc
	watchCtx    context.Context
	stopWatch   context.CancelFunc
	watchers    sync.WaitGroup
	services    []*protectedSiblingService
	shells      *protectedSiblingShellServer
	parent      context.Context
	forwardMu   sync.Mutex
	run         string
	seals       [2]protectedPartitionSeal
	// stop cancels forward work only; mediated dependencies drain separately.
	mediated *protectedSiblingDependencies
}

// setupBudget selects runProtectedSibling's outer startup allowance; legacy
// profiles and the independent partition-seal budget keep their old default.
func (p *protectedSiblingPair) setupBudget() time.Duration {
	if p.profile == protectedSiblingMediatedRoot {
		return protectedCombinedSetupBudget
	}
	return protectedSetupBudget
}

// gcsTimeout selects runProtectedSibling's early-attesting workload override.
// Zero means use UtilityVM.Start unchanged, including its process default.
func (p *protectedSiblingPair) gcsTimeout(role string) time.Duration {
	if p.profile == protectedSiblingMediatedRoot && role == workloadRole {
		return protectedWorkloadGCSBudget
	}
	return 0
}

// protectedPartitionSeal is serial-owner evidence, not native partition state.
// selected distinguishes omission from zero. Times are UTC wall-clock strings
// for HV-event correlation; dispatched follows S4's submission-attempt evidence,
// recorded before optional-export lookup. Lookup failure can therefore report
// dispatched without entering native code; it proves neither execution nor
// effects. Dispatched errors are conservatively uncertain here. No retry,
// rollback or pair atomicity exists.
type protectedPartitionSeal struct {
	role       string
	vmID       string
	selected   bool
	mask       uint64
	state      string
	attemptAt  string
	finishedAt string
	dispatched bool
	err        error
}

// validateProtectedPartitionCLI rejects protected-only flags on ordinary runs
// and invalid pause combinations before any resource acquisition. cli.Uint64Flag
// parsing owns malformed/overflow rejection; IsSet independently owns selection,
// so explicit zero and all future bits remain intact. Marker preflight uses
// Lstat, including dangling links, but does not claim either path yet.
func validateProtectedPartitionCLI(c *cli.Context) error {
	selected := c.IsSet(diodePartitionSealMaskArgName) || c.IsSet(workloadPartitionSealMaskArgName)
	pause := c.IsSet(partitionSealPausePrefixArgName)
	if !c.Bool(protectedSharedMemoryArgName) && (selected || pause) {
		return errors.New("partition seal masks/pause require --protected-shared-memory")
	}
	if pause {
		if !selected || c.String(partitionSealPausePrefixArgName) == "" {
			return errors.New("--partition-seal-pause-prefix requires a nonempty prefix and at least one selected partition mask")
		}
		return preflightProtectedSiblingPause(c.String(partitionSealPausePrefixArgName))
	}
	return nil
}

// stop completes a sticky forward-cancellation transition under the dispatch
// gate. Once it returns, no later attempt can commit. An already committed
// synchronous native operation remains owned until return and may have effects;
// this lock is never held across native/GCS work, close, or watcher joins.
// Mediated relay/storage dependencies deliberately survive this transition so
// workload borrowers can finish shutdown before their provider is destroyed.
func (p *protectedSiblingPair) stop(cause error) {
	p.forwardMu.Lock()
	p.cancel(cause)
	p.forwardMu.Unlock()
}

// reportSeal emits an observation with exact decimal/hex mask and run/VM role
// identity, plus attempted/completed UTC times. Omitted masks are not meaningful.
// The serial pair owner alone reads/writes evidence; output is not HV inventory.
func (p *protectedSiblingPair) reportSeal(s *protectedPartitionSeal) {
	fmt.Printf("protected partition seal: run=%s role=%s vm=%s selected=%t mask=%d mask_hex=%#016x state=%s dispatched=%t attempt_at=%q finished_at=%q observed_at=%s error=%q\n",
		p.run, s.role, s.vmID, s.selected, s.mask, s.mask, s.state, s.dispatched,
		s.attemptAt, s.finishedAt, time.Now().UTC().Format(time.RFC3339Nano), fmt.Sprint(s.err))
}

// sealPartitions attempts selected diode then workload, after the optional pause.
// Each operation receives a fresh budget excluding pause wall time. The gate
// checks parent/pair liveness immediately before committing an attempt; stop or
// exit completed before that gate prevents it. Cancellation after commitment
// can race submission: S4 checks ctx again and reports a submission attempt,
// recorded before wrapper export lookup. A missing HcsSystemControl export can
// therefore report dispatched without native entry; execution/effects are not
// established by dispatched alone.
// No native syscall is abandoned for a timeout; callers retain both VM owners
// through return. First error (even pre-dispatch) prevents every later call.
func (p *protectedSiblingPair) sealPartitions() error {
	for i := range p.seals {
		s := &p.seals[i]
		if !s.selected {
			continue
		}
		ctx, cancel := context.WithTimeout(p.ctx, protectedSetupBudget)
		p.forwardMu.Lock()
		if err := p.parent.Err(); err != nil {
			p.cancel(context.Cause(p.parent))
		}
		if err := p.ctx.Err(); err != nil {
			p.forwardMu.Unlock()
			cancel()
			return context.Cause(p.ctx)
		}
		s.attemptAt = time.Now().UTC().Format(time.RFC3339Nano)
		p.forwardMu.Unlock()
		// Commitment is NOT submission-attempt evidence. S4's return
		// contract supplies that evidence, not proof of native entry/effects.
		err := p.workers[i].vm.SealPartition(ctx, s.mask)
		cancel()
		s.finishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		fmt.Printf("protected partition seal attempt: run=%s role=%s vm=%s mask=%d mask_hex=%#016x at=%s returned_at=%s\n",
			p.run, s.role, s.vmID, s.mask, s.mask, s.attemptAt, s.finishedAt)
		s.err = err
		var sealErr *uvm.PartitionSealError
		s.dispatched = err == nil || (errors.As(err, &sealErr) && sealErr.Dispatched)
		if s.dispatched {
			s.state = "dispatched"
			p.reportSeal(s)
		}
		s.state = "completed"
		if err != nil {
			s.state = "failed"
			if s.dispatched || !errors.As(err, &sealErr) {
				s.state = "uncertain"
			}
		}
		p.reportSeal(s)
		if err != nil {
			return fmt.Errorf("protected partition seal run=%s role=%s vm=%s mask=%#016x state=%s (no retry/rollback): %w",
				p.run, s.role, s.vmID, s.mask, s.state, err)
		}
	}
	return nil
}

// Retention deliberately has no finalizer or implicit Close. This preserves
// necessary references only while this process lives; process exit and native
// cleanup determine actual lifetime. It is not persistence or reclaim proof.
var protectedSiblingRetained struct {
	sync.Mutex
	pairs []*protectedSiblingPair
}

// classifyProtectedSiblingProfile describes the intended profiles for
// runProtectedSibling without acquiring native resources. Root mediation and
// relay are a single opt-in profile, selected by values rather than presence;
// legacy geometry and exact optional partition-mask selection stay unchanged.
func classifyProtectedSiblingProfile(c *cli.Context) (protectedSiblingProfile, error) {
	profile := protectedSiblingDirectRoot
	if !c.Bool(protectedSharedMemoryArgName) {
		return profile, errors.New("protected profile requires --protected-shared-memory")
	}
	root, relay := c.Bool(siblingStorageRootArgName), c.Bool(siblingGCSRelayArgName)
	if root != relay {
		return profile, errors.New("protected root mediation and GCS relay must be selected together")
	}
	if root {
		profile = protectedSiblingMediatedRoot
	}
	if !useGCS || c.GlobalInt(countArgName) != 2 || c.GlobalInt(parallelArgName) != 2 ||
		!c.Bool(securityHardwareFlag) || !c.Bool(siblingInteractiveArgName) ||
		!c.Bool(siblingDiodeUplinkArgName) || c.String(siblingBusGuestModuleArgName) == "" ||
		strings.ToLower(c.String(rootFSTypeArgName)) != "none" {
		return profile, errors.New("protected shared memory requires --gcs --count 2 --parallel 2, --security-hardware, --root-fs-type none, --sibling-interactive, --sibling-diode-uplink and --sibling-bus-guest-module")
	}
	for _, name := range []string{
		sharedMemoryGuestModuleArgName, sharedMemoryTwoUVMArgName, sharedMemoryMappingOnlyArgName, sharedMemoryGuestInventoryArgName,
		sharedMemoryObserveArgName, sharedMemoryNameArgName,
		validateStorageBackendsArgName, unikraftPackageArgName,
		siblingOpenShellBundleArgName, baselineNICArgName, baselinePairArgName, baselineVsockArgName,
		networkBenchmarkScriptArgName, networkBenchmarkServerArgName, networkBenchmarkPortArgName,
		networkBenchmarkTimeoutArgName, networkBenchmarkNoSMTArgName, networkBenchmarkIdleArgName, networkBenchmarkSingleVPArgName,
		storageBenchmarkScriptArgName, storageBenchmarkDiskArgName, storageBenchmarkOutputArgName,
		storageBenchmarkTimeoutArgName, storageBenchmarkIOArgName, storageBenchmarkSyncIOArgName,
		storageBenchmarkSizeArgName, storageBenchmarkSmokeArgName, storageBenchmarkStatsArgName,
		storageBenchmarkLatencyArgName, storageBenchmarkThroughputArgName, storageBenchmarkIdleArgName,
		execCommandLineArgName, execFileArgName, scsiMountsArgName, vpmemMountsArgName,
		shareFilesArgName, noVerityBoot, siblingTestsArgName, benchSecondsArgName,
	} {
		if c.IsSet(name) {
			return profile, fmt.Errorf("--%s is incompatible with --%s", name, protectedSharedMemoryArgName)
		}
	}
	if profile == protectedSiblingDirectRoot && c.IsSet(siblingStorageBackendsArgName) {
		return profile, errors.New("protected direct-root mode does not support storage exports")
	}
	if profile == protectedSiblingMediatedRoot && c.String(siblingStorageBackendsArgName) == "" {
		return profile, errors.New("protected mediated root requires a storage backend plan")
	}
	size := c.Uint64(sharedMemorySizeArgName)
	if err := sibling.ValidateProtectedBackingSize(size); err != nil {
		return profile, fmt.Errorf("protected --shared-memory-size must be page-aligned transport bytes in %d..%d", sibling.ProtectedBackingMinBytes, sibling.ProtectedBackingMaxBytes)
	}
	if profile == protectedSiblingMediatedRoot && size != protectedCombinedBytes {
		return profile, errors.New("protected mediated root requires 32 MiB (8192 pages)")
	}
	return profile, nil
}

// preflightProtectedSiblingProfile checks file inputs for runProtectedSibling
// without allocating backing, boot copies or VMs.
// File checks establish input shape, not image authenticity or native authority.
func preflightProtectedSiblingProfile(c *cli.Context) (protectedSiblingProfile, error) {
	profile, err := classifyProtectedSiblingProfile(c)
	if err != nil {
		return profile, err
	}
	// Missing artifacts are input errors, not a reason to allocate protected
	// backing and discover the mismatch after root access has been revoked.
	module := c.String(siblingBusGuestModuleArgName)
	paths := []string{
		module, filepath.Join(filepath.Dir(module), siblingNetModuleName(diodeRole)),
		filepath.Join(filepath.Dir(module), "diode_tcpbulk"),
		filepath.Join(filepath.Dir(module), "diode_vsock_test"),
		filepath.Join(filepath.Dir(module), iperfGuestName),
		filepath.Join(filepath.Dir(module), "demo.sh"),
		filepath.Join(filepath.Dir(module), "covert_udp"),
		filepath.Join(filepath.Dir(module), "diode_tcpdump"),
		filepath.Join(filepath.Dir(module), "diode_tc"),
		filepath.Join(filepath.Dir(module), "diode_iptables"),
		filepath.Join(filepath.Dir(module), "ahv-guest-ctl"),
		filepath.Join(filepath.Dir(module), pageMetadataCollector),
	}
	if profile == protectedSiblingMediatedRoot {
		if _, err := loadSiblingStoragePlan(c); err != nil {
			return profile, err
		}
		paths = append(paths, filepath.Join(filepath.Dir(module), "diode_storvsp.ko"))
		for i := 0; i < 2; i++ {
			options, err := createLCOWOptions(context.Background(), c, fmt.Sprintf("uvmboot-%d", i))
			if err != nil {
				return profile, err
			}
			if options.GuestStateFilePath == "" || !options.SecurityPolicyEnabled ||
				options.HclEnabled == nil || *options.HclEnabled || options.AllowOvercommit ||
				options.EnableDeferredCommit || !options.DmVerityMode || options.SiblingRoot != (i == 1) ||
				options.Appliance != nil || !options.UseGuestConnection ||
				len(options.SharedMemoryRegions) != 0 || len(options.SiblingCommunicationEndpoints) != 0 {
				return profile, errors.New("protected combined profile requires direct SNP Linux options with only the workload root mediated")
			}
			if err := uvm.VerifyOptions(context.Background(), options); err != nil {
				return profile, err
			}
			paths = append(paths, filepath.Join(options.BootFilesPath, options.GuestStateFilePath),
				filepath.Join(options.BootFilesPath, options.DmVerityRootFsVhd))
		}
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return profile, fmt.Errorf("inspect protected guest artifact %q: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return profile, fmt.Errorf("protected guest artifact %q is not a regular file", path)
		}
	}
	return profile, nil
}

// validateProtectedSiblingCLI preflights both runProtectedSibling profiles before
// any resource acquisition, including the concrete controller ABI.
func validateProtectedSiblingCLI(c *cli.Context) error {
	if _, err := preflightProtectedSiblingProfile(c); err != nil {
		return err
	}
	return sibling.ValidateProtectedControllerABI()
}

// runProtectedSibling owns the default-off experiment from preflight to bounded
// cleanup. Legacy direct-root startup remains serial. Combined startup checks
// diode Bootstrap/Install before creating Import, configures the unstarted
// workload's relay, and exports its owned bundle root from the diode. Early
// diode services overlap workload native Start/GCS handshake; both the actual
// Import receipt and explicit relay readiness precede networking and seals.
// Tools/shares are staged once per role; only the diode receives the host-staged
// AHV collector. Its pair-owned boot-server starts before workload Start and
// waits for CID4 independently. The verified workload root already contains the
// client. The marked image requires its complete batch before original init/GCS;
// the unmarked image permits an explicit one-shot fetch after boot for debugging.
// Forward cancellation preserves dependencies through workload termination,
// relay/provider drainage and root unplug; the workload bundle survives until
// that attachment is released. Only then may native backing reclaim and owner
// release follow. Errors/uncertainty retain owners, never ordinary fallbacks.
// Independent optional masks/pause keep their existing exact semantics.
// Compilation and lab execution are separate manual prerequisites.
func runProtectedSibling(c *cli.Context) (resultErr error) {
	if err := validateProtectedPartitionCLI(c); err != nil {
		return err
	}
	if err := validateProtectedSiblingCLI(c); err != nil {
		return err
	}
	profile, err := classifyProtectedSiblingProfile(c)
	if err != nil {
		return err
	}
	var rootPlan *siblingStoragePlan
	if profile == protectedSiblingMediatedRoot {
		rootPlan, err = loadSiblingStoragePlan(c)
		if err != nil {
			return err
		}
	}
	// Populate cli v1's lazy maps before guest/shell goroutines read settings.
	_ = c.IsSet("help")
	_ = c.GlobalIsSet("help")
	parent, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopSignals()
	ctx, cancel := context.WithCancelCause(context.Background())
	watchCtx, stopWatch := context.WithCancel(context.Background())
	group, err := guid.NewV4()
	if err != nil {
		cancel(nil)
		stopWatch()
		return err
	}
	p := &protectedSiblingPair{
		ctx: ctx, cancel: cancel, parent: parent, watchCtx: watchCtx, stopWatch: stopWatch,
		run: group.String(), profile: profile,
	}
	for i, name := range []string{diodePartitionSealMaskArgName, workloadPartitionSealMaskArgName} {
		role := diodeRole
		if i == 1 {
			role = workloadRole
		}
		p.seals[i] = protectedPartitionSeal{
			role: role, vmID: fmt.Sprintf("uvmboot-%d", i), selected: c.IsSet(name),
			mask: c.Uint64(name), state: "omitted",
		}
		if p.seals[i].selected {
			p.seals[i].state = "pending"
		}
		p.reportSeal(&p.seals[i])
	}
	// Route parent cancellation through the same gate as VM/service/stop.
	// Keep it live throughout pause, and join it with all other watchers.
	p.watchers.Add(1)
	go func() {
		defer p.watchers.Done()
		select {
		case <-parent.Done():
			p.stop(context.Cause(parent))
		case <-watchCtx.Done():
		}
	}()
	// Cancellation starts cleanup; inspecting the sticky cause afterward also
	// captures a VM/service failure that won the race with our normal stop.
	// Independent cleanup errors never transfer or erase native ownership.
	defer func() {
		p.stop(nil)
		// A protocol stop during pause/pre-dispatch is normal shutdown, not
		// a seal failure. Never suppress a native error or another cause.
		if resultErr == context.Canceled && p.shells != nil && context.Cause(ctx) == context.Canceled {
			select {
			case <-p.shells.stopped:
				resultErr = nil
			default:
			}
		}
		for i := range p.seals {
			s := &p.seals[i]
			if s.state == "pending" {
				s.state = "unattempted"
				s.err = resultErr
			}
			p.reportSeal(s)
		}
		resultErr = errors.Join(resultErr, p.cleanup())
		if cause := context.Cause(ctx); cause != nil && cause != context.Canceled {
			resultErr = errors.Join(resultErr, cause)
		}
		if resultErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("partition outcomes run=%s: diode=%s workload=%s; independent calls, no rollback",
				p.run, p.seals[0].state, p.seals[1].state))
		}
	}()
	lps, err := parseCPUGroupLPs(c.String(cpuGroupLPsArgName))
	if err != nil {
		return err
	}
	priorities, err := parseCPUGroupPriorities(c.String(cpuGroupPrioritiesArgName))
	if err != nil || (c.IsSet(cpuGroupPrioritiesArgName) && len(priorities) == 0) {
		return errors.Join(err, errors.New("invalid protected CPU group priorities"))
	}
	// Reuse existing options/copy machinery, but allocate no boot directories
	// until both role configurations have passed preflight. Only directories
	// explicitly acquired below belong to this pair, never annotation paths.
	for i, role := range []string{diodeRole, workloadRole} {
		options, err := createLCOWOptions(ctx, c, fmt.Sprintf("uvmboot-%d", i))
		if err != nil {
			return err
		}
		v := &protectedSiblingVM{options: options, role: role}
		p.workers = append(p.workers, v)
		p.seals[i].vmID = options.ID
		if options.GuestStateFilePath == "" || !options.SecurityPolicyEnabled ||
			options.HclEnabled == nil || *options.HclEnabled || options.AllowOvercommit ||
			options.EnableDeferredCommit || !options.DmVerityMode ||
			options.SiblingRoot != (profile == protectedSiblingMediatedRoot && i == 1) ||
			options.Appliance != nil || !options.UseGuestConnection ||
			len(options.SharedMemoryRegions) != 0 || len(options.SiblingCommunicationEndpoints) != 0 {
			return errors.New("protected route requires SNP dm-verity roots, the selected root route and no preconfigured shared regions/endpoints")
		}
		if err := uvm.VerifyOptions(ctx, options); err != nil {
			return fmt.Errorf("protected %s options: %w", options.ID, err)
		}
		for _, path := range []string{
			filepath.Join(options.BootFilesPath, options.GuestStateFilePath),
			filepath.Join(options.BootFilesPath, options.DmVerityRootFsVhd),
		} {
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("protected boot artifact %q: %w", path, err)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("protected boot artifact %q is not a regular file", path)
			}
		}
	}
	p.cpuGroups, err = prepareCPUGroups(ctx, lps, 2, hostCPUGroupOperations, priorities...)
	if err != nil {
		return err
	}
	for _, v := range p.workers {
		v.options.CPUGroupID, err = p.cpuGroups.groupForVM(v.options.ID)
		if err != nil {
			return err
		}
		v.options.BundleDirectory, err = newLCOWBundleDirectory(v.options.ID)
		if err != nil {
			return err
		}
		v.bundleOwned = true
	}
	p.memory, err = sibling.NewProtectedBacking("uvmboot-protected-"+group.String(), c.Uint64(sharedMemorySizeArgName))
	if err != nil {
		return err
	}
	for i, v := range p.workers {
		mode := hcsschema.ProtectedSharedBackingBootstrap
		if i == 1 {
			mode = hcsschema.ProtectedSharedBackingImport
		}
		v.region = hcsschema.SharedMemoryRegion{
			ProtectedSharedBackingMode: mode,
		}
		endpoint, err := siblingCommunicationEndpoint(v.options.ID, group.String())
		if err != nil {
			return err
		}
		endpoint.SharedMemorySectionName = p.memory.SectionName()
		v.options.SiblingCommunicationEndpoints = []hcsschema.SiblingCommunicationEndpoint{endpoint}
	}
	setupCtx, stopSetup := context.WithTimeout(ctx, p.setupBudget())
	defer stopSetup()
	if profile == protectedSiblingMediatedRoot {
		if err := p.bootstrapMediated(setupCtx, c, rootPlan); err != nil {
			return err
		}
	} else {
		// Native Bootstrap's actual full-init Install receipt precedes Import.
		for _, v := range p.workers {
			if err := p.start(setupCtx, v); err != nil {
				return err
			}
		}
	}
	for _, v := range p.workers {
		if _, err := waitForSiblingCommunicationRoute(setupCtx, v.vm, v.options.SiblingCommunicationEndpoints[0]); err != nil {
			return err
		}
	}
	uplink, release, err := sibling.AttachUplink(setupCtx, p.workers[0].vm)
	if err != nil {
		return err
	}
	p.uplinkClose = release
	configs := make([]siblingNetConfig, 2)
	for i, v := range p.workers {
		configs[i], err = siblingNetConfigFor(v.role, true)
		if err != nil {
			return err
		}
		if v.role == workloadRole && len(configs[i].dns) == 0 {
			return errors.New("protected workload requires an available host DNS resolver")
		}
		if profile == protectedSiblingDirectRoot {
			if err := stageProtectedSiblingTools(setupCtx, c, v); err != nil {
				return err
			}
		}
	}
	// Both starts are complete. Discovery can now wait for the real peer, with
	// failures canceling and joining the other guest command before cleanup.
	networkCtx, cancelNetwork := context.WithCancel(setupCtx)
	results := make(chan error, 2)
	for i, v := range p.workers {
		go protectedSiblingNetwork(networkCtx, c.String(siblingBusGuestModuleArgName),
			v, configs[i], uplink, results)
	}
	var networkErr error
	for range p.workers {
		if err := <-results; err != nil {
			networkErr = errors.Join(networkErr, err)
			cancelNetwork()
		}
	}
	cancelNetwork()
	if networkErr != nil {
		return networkErr
	}
	// A real stock-vsock echo in each direction checks the installed transport,
	// rather than treating a dmesg timing line as a usable socket connection.
	if err := p.checkSockets(setupCtx); err != nil {
		return err
	}
	for _, service := range []string{
		"exec /run/dtb-exec/ipf -s -p 5301",
		"while :; do /run/dtb-exec/dtb sink 5001 || exit; done",
		"while :; do /run/dtb-exec/dtb sink 5002 || exit; done",
	} {
		if err := p.startService(p.workers[0], service); err != nil {
			return err
		}
	}
	if err := protectedSiblingGuest(setupCtx, p.workers[0],
		"set -eu; "+guestWaitFor(`grep -qE ':14B5 [[:xdigit:]]+:[[:xdigit:]]+ 0A ' /proc/net/tcp`, "iperf listener")+
			guestWaitFor(`grep -qE ':1389 [[:xdigit:]]+:[[:xdigit:]]+ 0A ' /proc/net/tcp`, "TCP sink 5001")+
			guestWaitFor(`grep -qE ':138A [[:xdigit:]]+:[[:xdigit:]]+ 0A ' /proc/net/tcp`, "TCP sink 5002")); err != nil {
		return err
	}
	if err := protectedSiblingGuest(setupCtx, p.workers[1],
		"set -eu; ping -c 2 -W 2 10.200.0.1; ip route show default | grep -q 'via 10.200.0.1 dev dvsc0'"); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	// Acquire all listeners before publishing readiness or closing admission.
	// A competing pipe owner fails before these irreversible controls. Stop
	// and accept errors immediately cancel setup/pause through the same gate.
	p.shells, err = newProtectedSiblingShellServer(p.ctx, p.workers, p.stop)
	if err != nil {
		return err
	}
	fmt.Printf("protected sibling: checked network ready at %s; sealing backing lease=%d pages=%d once\n",
		time.Now().UTC().Format(time.RFC3339Nano), p.memory.Diagnostics().LeaseID, p.memory.Diagnostics().PageCount)
	if err := p.memory.SealAdmission(setupCtx); err != nil {
		return err
	}
	stopSetup()
	if prefix := c.String(partitionSealPausePrefixArgName); prefix != "" {
		if err := p.pausePartitionSeals(prefix); err != nil {
			return err
		}
	}
	if err := p.sealPartitions(); err != nil {
		return err
	}
	fmt.Println("protected sibling: backing admission sealed; independent partition outcomes recorded; attach diode|workload or stop")
	return p.interactive()
}

// start creates/starts exactly one owned attempt with real borrowed controller
// resources. Bootstrap selects lease zero; Import uses only the actual prior
// startup lease. No Initialize/Install Modify is sent. A failed create/start or
// invalid post-start observation makes uncertainty sticky, even if worker-side
// automatic cleanup ran. Native startup precedes GCS tool use.
func (p *protectedSiblingPair) start(ctx context.Context, v *protectedSiblingVM) error {
	if err := p.create(ctx, v); err != nil {
		return err
	}
	return p.startCreated(ctx, v)
}

// create retains a native attempt before dispatch. Import can be created only
// from Bootstrap's checked full initialization and lease; creation never grants
// native startup authority or allows uncertainty to be cleared.
func (p *protectedSiblingPair) create(ctx context.Context, v *protectedSiblingVM) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	region, err := p.memory.Region(v.region.ProtectedSharedBackingMode)
	if err != nil {
		return err
	}
	v.region = region
	v.options.SharedMemoryRegions = []hcsschema.SharedMemoryRegion{v.region}
	v.options.ProtectedSharedResources = []hcsv2.OperationResource{p.memory.Resource()}
	// Native Start auto-initializes. Deny content/release BEFORE even Create,
	// including failure paths where a returned VM/receipt becomes unavailable.
	p.memory.MarkCreateAttempt()
	v.attempted = true
	v.vm, err = uvm.CreateLCOW(ctx, v.options)
	if err != nil {
		p.memory.MarkUnknown()
		return fmt.Errorf("protected %s create (native ownership unobservable): %w", v.options.ID, err)
	}
	return nil
}

// startCreated starts the retained attempt and validates the real receipt/GPA.
// UtilityVM.Start includes the GCS handshake, not merely native-running state.
// Failed startup retains exact observed prefixes and sticky native uncertainty.
func (p *protectedSiblingPair) startCreated(ctx context.Context, v *protectedSiblingVM) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var startErr error
	if connectionTimeout := p.gcsTimeout(v.role); connectionTimeout != 0 {
		startErr = v.vm.StartWithGCSConnectionTimeout(ctx, connectionTimeout)
	} else {
		startErr = v.vm.Start(ctx)
	}
	if startErr != nil {
		p.memory.MarkUnknown()
		// Native failure cleanup may already have destroyed the observable
		// owner. Preserve any structurally valid initialization history for
		// teardown, but never clear uncertainty or authorize reclaim from it.
		p.observeFailedStartup(v)
		return fmt.Errorf("protected %s start (native progress uncertain): %w", v.options.ID, startErr)
	}
	v.started = true
	p.watch(v)
	regions, err := v.vm.SharedMemoryRegions(ctx)
	if err != nil || len(regions) != 1 || regions[0].SectionName != v.region.SectionName {
		p.memory.MarkUnknown()
		return errors.Join(err, fmt.Errorf("protected %s missing exact startup region", v.options.ID))
	}
	info := regions[0].ProtectedShared
	// Retain valid initialization history before any later observation fails.
	// These cached properties are not a live mapping inventory or scrub proof.
	if err := p.memory.ObserveStartup(info); err != nil {
		return fmt.Errorf("protected %s startup receipt: %w", v.options.ID, err)
	}
	v.region.ProtectedSharedLeaseId = info.LeaseId
	gpa, err := uvm.SharedMemoryByteGPA(regions[0].GuestPhysicalAddress, int64(v.region.Length))
	if err != nil {
		p.memory.MarkUnknown()
		return err
	}
	fmt.Printf("protected sibling: vm=%s role=%s mode=%s lease=%d initialized=%d installed=true byte_gpa=%#x at=%s\n",
		v.options.ID, v.role, v.region.ProtectedSharedBackingMode, info.LeaseId,
		info.InitializedPages, gpa, time.Now().UTC().Format(time.RFC3339Nano))
	return nil
}

// bootstrapMediated binds the small ordering helper to concrete native operations
// for runProtectedSibling. No callback substitutes for native receipt validation.
func (p *protectedSiblingPair) bootstrapMediated(ctx context.Context, c *cli.Context, plan *siblingStoragePlan) error {
	diode, workload := p.workers[0], p.workers[1]
	return protectedSiblingBootstrap(ctx, protectedSiblingBootstrapOps{
		// bootstrap establishes the actual lease before any Import creation.
		bootstrap: func(ctx context.Context) error { return p.start(ctx, diode) },
		// create retains the workload bundle and its Import attempt.
		create: func(ctx context.Context) error { return p.create(ctx, workload) },
		// configure replaces the direct listener before the first workload Start.
		configure: func(context.Context) error { return workload.vm.ConfigureGCSRelay(diode.vm) },
		// attach acquires only the workload-owned root copy, retaining failures.
		attach: func(ctx context.Context) error { return p.prepareMediatedRoot(ctx, c, plan) },
		// stageDiode runs once, before the early service can use its tools.
		stageDiode: func(ctx context.Context) error { return stageProtectedSiblingTools(ctx, c, diode) },
		// startServer creates a separate foreground owner, never a peer/socket
		// readiness wait or a command hidden behind the relay's terminal exec.
		startServer: func(context.Context) error {
			return p.startService(diode, "exec /run/dtb-exec/ahv-guest-ctl boot-server")
		},
		// startDependencies creates the owned foreground service without peer waits.
		startDependencies: func(ctx context.Context) error { return p.mediated.start(ctx) },
		// startWorkload allows native offers while the diode service awaits its peer.
		startWorkload: func(ctx context.Context) error { return p.startCreated(ctx, workload) },
		// ready is additional to the actual Import receipt and GCS handshake.
		ready: func(ctx context.Context) error { return p.mediated.waitReady(ctx) },
		// stageWorkload uses only its now-connected relayed GCS, never the diode tmpfs.
		stageWorkload: func(ctx context.Context) error { return stageProtectedSiblingTools(ctx, c, workload) },
	})
}

// protectedSiblingOwnedRoot selects CreateLCOW's fixed bundle copy from a
// preflighted root plan, never the caller-owned template. It leaves the input
// plan unchanged; the pair keeps the workload owner until diode release succeeds.
func protectedSiblingOwnedRoot(workload *protectedSiblingVM, plan *siblingStoragePlan) (*siblingStoragePlan, error) {
	if workload == nil || !workload.bundleOwned || workload.options == nil ||
		workload.options.BundleDirectory == "" || plan == nil || len(plan.Disks) != 1 {
		return nil, errors.New("protected root requires an owned workload bundle and one root export")
	}
	owned := &siblingStoragePlan{Version: plan.Version, Disks: append([]siblingStorageDisk(nil), plan.Disks...)}
	owned.Disks[0].HostPath = filepath.Join(workload.options.BundleDirectory, vmutils.DefaultDmVerityRootfsVhd)
	return owned, nil
}

// prepareMediatedRoot retains the attachment attempt before calling the existing
// SCSI helper. An attach error can hide partial native progress: the sentinel
// has no release authority, so cleanup retains both VM/bundle owners. Successful
// mounts keep their real Release callback even if later command/share setup fails.
func (p *protectedSiblingPair) prepareMediatedRoot(ctx context.Context, c *cli.Context, plan *siblingStoragePlan) error {
	diode, workload := p.workers[0], p.workers[1]
	owned, err := protectedSiblingOwnedRoot(workload, plan)
	if err != nil {
		return err
	}
	p.mediated = newProtectedSiblingDependencies(p.stop, protectedSiblingDependencyOps{
		// quiesce also covers failure before any provider starter was dispatched.
		quiesce: func(ctx context.Context) error { return protectedSiblingQuiesceProvider(ctx, diode) },
	}, workload, nil)
	// The production SCSI helper supplies the actual slot and release owner;
	// errors with no returned mount must retain the attempt rather than guess.
	if err := p.mediated.attachRoot(ctx, owned.Disks[0], func(ctx context.Context, disk siblingStorageDisk) (siblingStorageAttachment, error) {
		return attachSiblingStorageDisk(ctx, diode.vm, disk)
	}); err != nil {
		return err
	}
	root := p.mediated.root
	if root.release == nil || root.controller >= uint(len(guestrequest.ScsiControllerGuids)) {
		return errors.New("protected root attachment lacks valid release/controller identity")
	}
	report := siblingStorageBackendReport{
		DiskID: "workload-root", Role: "root", HostPath: owned.Disks[0].HostPath,
		ReadOnly: true, DiodeVM: diode.options.ID, WorkloadVM: workload.options.ID,
		ControllerID: guestrequest.ScsiControllerGuids[root.controller],
		Controller:   root.controller, LUN: root.lun, ExportLUN: 0, State: "attached-only",
	}
	module := c.String(siblingBusGuestModuleArgName)
	storage := filepath.Join(filepath.Dir(module), "diode_storvsp.ko")
	if err := diode.vm.Share(ctx, storage, "/run/diode-storage-module", true); err != nil {
		return err
	}
	command, ready, err := protectedSiblingRelayCommands(p.run,
		"/run/sibling-bus-module/"+filepath.Base(module), "/run/diode-storage-module/diode_storvsp.ko",
		owned, []siblingStorageBackendReport{report})
	if err != nil {
		return err
	}
	configureProtectedSiblingRelay(p.mediated, p, diode, command, ready)
	return nil
}

// observeFailedStartup retains only validated cached identity/initialization
// history after failed Start. A separate five-second observation budget avoids
// losing known prefixes to cancellation; unavailable or contradictory history
// stays unknown. It never proves participant absence, drain or safe reclaim.
// The serial pair owner calls this only while retaining the real controller.
func (p *protectedSiblingPair) observeFailedStartup(v *protectedSiblingVM) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	regions, err := v.vm.SharedMemoryRegions(ctx)
	if err != nil || len(regions) != 1 || regions[0].SectionName != v.region.SectionName {
		return
	}
	info := regions[0].ProtectedShared
	if err := p.memory.ObserveFailedStartup(info); err != nil {
		return
	}
	v.region.ProtectedSharedLeaseId = info.LeaseId
}

// watch observes a successfully started VM until pair cleanup cancels watchers.
// An unexpected exit cancels every forward operation, including peer startup and
// guest readiness, through the seal-attempt gate. It never changes backing state.
// cleanup joins the goroutine before closing VM handles; WaitCtx's own errors
// are retained as the cause.
func (p *protectedSiblingPair) watch(v *protectedSiblingVM) {
	p.watchers.Add(1)
	go func() {
		defer p.watchers.Done()
		err := v.vm.WaitCtx(p.watchCtx)
		if p.watchCtx.Err() == nil {
			p.stop(errors.Join(fmt.Errorf("protected VM %s exited", v.options.ID), err, v.vm.ExitError()))
		}
	}()
}

// protectedSiblingGuest executes a noninteractive setup/check command under ctx.
// A nonzero exit, transport failure or incomplete stream drain fails readiness.
// It owns no backing view and ignores ordinary marker success. The caller owns
// the VM throughout; long-lived services must use the separate lifetime method.
// Existing cmd cancellation kills the guest process, but cannot abandon an
// already executing synchronous native/GCS call or release its borrowed owners.
// Opt-in Wait joins all command-owned callbacks before readiness/return; there
// is no detached Kill that can subsequently borrow this VM.
func protectedSiblingGuest(ctx context.Context, v *protectedSiblingVM, command string) error {
	process := cmd.CommandContext(ctx, v.vm, "sh", "-c", command)
	process.JoinBackgroundOperations = true
	process.CopyAfterExitTimeout = 5 * time.Second
	process.Stdout, process.Stderr = os.Stdout, os.Stderr
	if err := process.Run(); err != nil {
		return fmt.Errorf("protected guest %s: %w", v.options.ID, err)
	}
	return ctx.Err()
}

// stageProtectedSiblingTools borrows existing merged artifacts through file
// shares and checks copying/chmod into executable tmpfs. Missing demo/filter
// tools fail instead of silently degrading the interactive experiment. The AHV
// collector is delivered only to the diode; staging itself never collects.
// The workload boot client is already in its verified root, not delivered here.
// Shares stay VM-owned; no independent boot stack or guest harness is created.
func stageProtectedSiblingTools(ctx context.Context, c *cli.Context, v *protectedSiblingVM) error {
	module := c.String(siblingBusGuestModuleArgName)
	if err := v.vm.Share(ctx, module, "/run/sibling-bus-module", true); err != nil {
		return err
	}
	artifacts := protectedSiblingToolArtifacts(v.role)
	metadataStage, err := stagePageMetadata(ctx, c, v.vm, v.role)
	if err != nil {
		return err
	}
	for _, a := range artifacts {
		if err := v.vm.Share(ctx, filepath.Join(filepath.Dir(module), a.host), a.root, true); err != nil {
			return fmt.Errorf("share required protected tool %s: %w", a.host, err)
		}
	}
	if netModule := siblingNetModuleName(v.role); netModule != "" {
		if err := v.vm.Share(ctx, filepath.Join(filepath.Dir(module), netModule), "/run/diode-net-module", true); err != nil {
			return err
		}
	}
	return protectedSiblingGuest(ctx, v, protectedSiblingToolCommand(artifacts, metadataStage))
}

type protectedSiblingTool struct {
	host, root, destination string
}

// protectedSiblingToolArtifacts is the shared staging contract for both
// profiles. Only the diode receives the host-staged AHV collector/server CLI.
func protectedSiblingToolArtifacts(role string) []protectedSiblingTool {
	artifacts := []protectedSiblingTool{
		{"diode_tcpbulk", "/run/diode-tcpbulk", "dtb"},
		{"diode_vsock_test", "/run/diode-vsock-test", "vsock-test"},
		{iperfGuestName, iperfGuestShare, "ipf"},
		{"demo.sh", "/run/diode-demo", "demo.sh"},
		{"covert_udp", "/run/diode-covert", "covert"},
		{"diode_tcpdump", "/run/diode-tcpdump", "tcpdump"},
		{"diode_tc", "/run/diode-tc", "tc"},
		{"diode_iptables", "/run/diode-iptables", "ipt"},
	}
	if role == diodeRole {
		artifacts = append(artifacts, protectedSiblingTool{"ahv-guest-ctl", "/run/ahv-tools", "ahv-guest-ctl"})
	}
	return artifacts
}

// protectedSiblingToolCommand builds checked copies on one executable tmpfs.
// runProtectedSibling calls staging once per guest; restaging the diode would
// hide live early-service tools. Copying the AHV CLI never invokes it.
func protectedSiblingToolCommand(artifacts []protectedSiblingTool, metadataStage string) string {
	command := "set -eu; mkdir -p /run/dtb-exec; mount -t tmpfs -o exec,size=16m tmpfs /run/dtb-exec; "
	command += metadataStage
	for _, a := range artifacts {
		command += "cp " + shellSingleQuote(a.root+"/"+a.host) + " /run/dtb-exec/" + a.destination +
			"; chmod 755 /run/dtb-exec/" + a.destination + "; "
	}
	return command
}

// protectedSiblingNetwork configures one role using existing discovery, stock
// interface, protocol/CID and uplink helpers under strict shell error handling.
// results receives exactly one error; the caller cancels and joins both roles.
// No long-running service inherits this setup context, and no diagnostic module
// or raw backing GPA is passed to the guest. NAT readiness uses actual queries,
// not the ordinary best-effort command or linux_diode_boot_stage text.
func protectedSiblingNetwork(ctx context.Context, module string, v *protectedSiblingVM,
	net siblingNetConfig, uplink *sibling.Uplink, results chan<- error) {
	command := "set -eu; " + siblingBusLoadCommand("/run/sibling-bus-module/"+filepath.Base(module))
	if name := siblingNetModuleName(v.role); name != "" {
		command += "insmod /run/diode-net-module/" + name + "; "
	}
	command += siblingInstanceDiscoveryCommand() + siblingVsockReadyCommand(v.role)
	peerCID := 3
	if v.role == workloadRole {
		peerCID = 4
		command += siblingStockNICCommand(net.ifName)
	}
	command += fmt.Sprintf(`[ "$sb_peer" = %d ]; `, peerCID)
	command += guestWaitFor("[ -e /sys/class/net/"+net.ifName+" ]", net.ifName) +
		"ip addr add " + net.address + " dev " + net.ifName + "; ip link set " + net.ifName + " up; "
	if net.gateway != "" {
		command += "ip route replace default via " + net.gateway + " dev " + net.ifName + "; " +
			net.commandDNS() + " || exit 1; "
		// The ordinary helper handles read-only /etc through a bind/overlay.
		// Check the resulting file, not just its compound command's exit.
		for _, server := range net.dns {
			command += "grep -qFx " + shellSingleQuote("nameserver "+server) + " /etc/resolv.conf; "
		}
	}
	command += guestWaitFor(`[ "$(cat /sys/class/net/`+net.ifName+`/carrier)" = 1 ]`, "sibling carrier")
	if v.role == workloadRole {
		// An RP NIC would bypass the diode regardless of the intended route.
		// Device identity, not interface naming, distinguishes sibling NICs.
		command += `root_nics=0; for n in /sys/class/net/*; do if [ -e "$n/device" ]; then ` +
			`d=$(readlink -f "$n/device"); case ${d##*/} in bus*-relid*) :;; *) root_nics=$((root_nics+1));; esac; fi; done; ` +
			`[ "$root_nics" -eq 0 ]; `
	}
	if v.role == diodeRole {
		// Tools were staged with checked copying before this helper. Unlike
		// ordinary best-effort NAT setup, readiness requires carrier and
		// successful rule installation/queries. Demo -block inserts ahead of
		// the initially permissive FORWARD policy.
		command += siblingDiodeUplinkCommand(&diodeUplink{address: uplink.Address, gateway: uplink.Gateway}, guestWaitFor) +
			guestWaitFor(`[ "$(cat /sys/class/net/$up/carrier)" = 1 ]`, "diode uplink carrier") +
			`echo 1 >/proc/sys/net/ipv4/ip_forward; ` +
			`$ipt iptables -w -P FORWARD ACCEPT; ` +
			`$ipt iptables -w -t nat -A POSTROUTING -s 10.200.0.0/30 -o "$up" -j MASQUERADE; ` +
			`$ipt iptables -w -t nat -C POSTROUTING -s 10.200.0.0/30 -o "$up" -j MASQUERADE; ` +
			`$ipt iptables -w -L FORWARD -n; [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]; ` +
			`ip route show default | grep -q "via ` + uplink.Gateway + ` dev $up"; ` +
			`ip -4 addr show dev "$up" | grep -qF ` + shellSingleQuote(uplink.Address) + `; `
	}
	results <- protectedSiblingGuest(ctx, v, command)
}

// checkSockets runs the existing bounded stock-vsock exchange on both roles
// concurrently. Listener children are bounded by their guest command and pair
// lifetime, not relied on as long-lived demo services. Failure cancels the peer
// and both commands are joined before returning any error.
func (p *protectedSiblingPair) checkSockets(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	for _, v := range p.workers {
		// Each result is published only after the command and its streams
		// have drained; neither role can outlive this readiness barrier.
		go func(v *protectedSiblingVM) {
			results <- protectedSiblingGuest(ctx, v, "set -eu; "+siblingInstanceDiscoveryCommand()+siblingVsockProofCommand(v.role))
		}(v)
	}
	var result error
	for range p.workers {
		if err := <-results; err != nil {
			result = errors.Join(result, err)
			cancel()
		}
	}
	return result
}

// startService gives a long-lived guest server the pair's lifetime context,
// separate from bounded setup. cleanup observes Wait within its own deadline,
// retaining the process/owner if unavailable; any premature exit cancels the
// experiment. Creation is not socket readiness: the boot-server may still await
// the peer while workload native boot proceeds; root/relay readiness is separate.
// service.done is published only after creation and, on success, command-owned
// cancellation/stdio callbacks and Process.Close have completed;
// an in-flight native/GCS call can delay it beyond the cleanup budget.
func (p *protectedSiblingPair) startService(v *protectedSiblingVM, command string) error {
	process := cmd.CommandContext(p.ctx, v.vm, "sh", "-c", command)
	process.JoinBackgroundOperations = true
	process.CopyAfterExitTimeout = 5 * time.Second
	process.Stdout, process.Stderr = os.Stdout, os.Stderr
	service := &protectedSiblingService{process: process, done: make(chan struct{})}
	return p.startOwnedService(service, v.options.ID, command, protectedSiblingDependencyOps{
		// start creates only the process; the foreground server owns CID waits.
		start: func(context.Context) error { return process.Start() },
		// wait joins streams/cancellation and separately reports observed exit.
		wait: func() (bool, error) {
			err := process.Wait()
			return process.ExitState.ExitCode() != -1, err
		},
	})
}

// startOwnedService registers the borrower before synchronous creation for
// startService. The per-instance start/wait callbacks share the dependency
// fixture's ownership contract; neither creation nor joined Wait proves exit.
// No fallible registration follows successful creation. Failure retains the
// attempt and cancels forward startup, including a pending workload GCS wait.
func (p *protectedSiblingPair) startOwnedService(service *protectedSiblingService, vmID, command string,
	ops protectedSiblingDependencyOps) error {
	if err := p.ctx.Err(); err != nil {
		return context.Cause(p.ctx)
	}
	p.services = append(p.services, service)
	if err := ops.start(p.ctx); err != nil {
		service.err = fmt.Errorf("protected service on %s creation outcome uncertain: %w", vmID, err)
		close(service.done)
		p.stop(service.err)
		return service.err
	}
	// The owner is already registered if cancellation/exit races this launch.
	go func() {
		exited, err := ops.wait()
		if !exited {
			err = errors.Join(err, errors.New("protected service exit unobserved"))
		}
		if p.ctx.Err() == nil {
			p.stop(errors.Join(fmt.Errorf("protected service on %s exited: %s", vmID, command), err))
		} else if exited {
			err = protectedSiblingStopError(err)
		}
		service.err = err
		close(service.done)
	}()
	return context.Cause(p.ctx)
}

// interactive serves the existing attach/stop protocol through a pair-owned
// cancellable server, without container commands or global stop state. All
// handlers remain owned until cleanup joins them before touching VM/backing
// ownership. The server must already be available before readiness/pause and is
// reused here without reacquiring names. This method issues no partition calls.
func (p *protectedSiblingPair) interactive() error {
	if p.shells == nil {
		return errors.New("protected interactive listeners were not acquired")
	}
	err := p.shells.wait()
	p.stop(nil)
	return err
}

// cleanup uses an independent bounded budget to drain attempts, explicitly
// reclaim, verify scrub, then close VMs/release copies/capabilities. Combined
// dependencies drain before BeginTeardown; legacy keeps its prior Remove order.
// VM handles stay owned through reclaim; CloseCtx can delete boot files.
// Progress is exact and serialized. Unknown startup/control progress or missing VM
// ownership is retained, not repaired from a cached zero prefix. It still tries
// every known participant after other failures. In-process retention does not
// promise resources survive process exit or native fallback cleanup.
func (p *protectedSiblingPair) cleanup() error {
	ctx, cancel := context.WithTimeout(context.Background(), protectedCleanupBudget)
	defer cancel()
	p.stop(nil)
	p.stopWatch()
	p.watchers.Wait()
	var result error
	safe := true
	m := p.memory
	// Close and join attached shells before native teardown can invalidate
	// their borrowed VM. Failed drainage retains every owner; termination
	// below remains a best-effort way to end execution, never release proof.
	if p.profile == protectedSiblingDirectRoot && p.shells != nil {
		if err := p.shells.close(ctx); err != nil {
			result = errors.Join(result, err)
			safe = false
		}
	}
	if p.profile == protectedSiblingDirectRoot && m != nil && m.Diagnostics().InitializedPages != 0 {
		if err := m.BeginTeardown(ctx); err != nil {
			result = errors.Join(result, err)
			safe = false
		}
	}
	if p.profile == protectedSiblingMediatedRoot {
		drained, err := protectedSiblingDrain(ctx, protectedSiblingDrainOps{
			// Join borrowers while their relay/provider paths remain live.
			joinForward: func(ctx context.Context) error {
				var err error
				if p.shells != nil {
					err = p.shells.close(ctx)
				}
				return errors.Join(err, p.joinServices(ctx))
			},
			// Expected EOF must be marked before terminating its workload peer.
			beginClosing: func() {
				if p.mediated != nil {
					p.mediated.beginClosing()
				}
			},
			// Native termination retains the workload and bundle, without Remove.
			terminateWorkload: func(ctx context.Context) (bool, error) {
				return p.terminateRole(ctx, workloadRole)
			},
			// No disk release is authorized by unjoined forward borrowers.
			drainDependencies: func(ctx context.Context, workloadDrained bool) error {
				if p.mediated == nil {
					return nil
				}
				return p.mediated.drain(ctx, workloadDrained)
			},
			// Always try diode native termination, even after dependency failure.
			terminateDiode: func(ctx context.Context) (bool, error) {
				return p.terminateRole(ctx, diodeRole)
			},
		})
		result = errors.Join(result, err)
		safe = safe && drained
		// Provider I/O and every participant must be drained before changing
		// protected mapping/backing state. Reclaim still uses its native gate.
		if safe && m != nil && m.Diagnostics().InitializedPages != 0 {
			if err := m.BeginTeardown(ctx); err != nil {
				result = errors.Join(result, err)
				safe = false
			}
		}
	} else {
		for _, v := range p.workers {
			if v.vm == nil {
				if v.attempted {
					safe = false
					result = errors.Join(result, fmt.Errorf("%s create ownership unobservable", v.options.ID))
				}
				continue
			}
			if v.started && v.region.ProtectedSharedLeaseId != 0 && ctx.Err() == nil {
				remove := v.region
				remove.ProtectedSharedOperation = hcsschema.ProtectedSharedRemove
				_, err := v.vm.ModifyProtectedShared(ctx, remove, m.Resource())
				// Remove's cache alone is not drain/reclaim proof. Even failed
				// Remove may be safely superseded by observed VM termination.
				if err != nil {
					result = errors.Join(result, fmt.Errorf("%s Remove: %w", v.options.ID, err))
				}
			}
			terminateErr := v.vm.Terminate(ctx)
			if terminateErr != nil {
				result = errors.Join(result, fmt.Errorf("%s terminate: %w", v.options.ID, terminateErr))
			}
			waitErr := v.vm.WaitCtx(ctx)
			if waitErr != nil {
				result = errors.Join(result, fmt.Errorf("%s wait for termination: %w", v.options.ID, waitErr))
				safe = false
				continue
			}
			// Observed termination, not a cached Remove flag, establishes that
			// guest execution ended. Reclaim's actual native participant gate
			// still decides whether backing ownership has drained.
			v.drained = true
		}
		if err := p.joinServices(ctx); err != nil {
			result = errors.Join(result, err)
			safe = false
		}
	}
	if m != nil {
		if m.Diagnostics().Unknown {
			result = errors.Join(result, errors.New("unknown protected progress; retain controller/backing and necessary owners in-process only"))
			safe = false
		}
		if safe {
			if err := m.Reclaim(ctx); err != nil {
				result = errors.Join(result, err)
				safe = false
			}
		}
		if safe {
			if err := m.Release(ctx); err != nil {
				result = errors.Join(result, err)
				safe = false
			}
		}
		if safe {
			for _, v := range p.workers {
				if v.vm != nil && v.drained {
					if err := v.vm.CloseCtx(ctx); err != nil {
						result = errors.Join(result, fmt.Errorf("%s close after reclaim: %w", v.options.ID, err))
						safe = false
					} else {
						v.closed = true
					}
				}
			}
		}
	}
	if safe {
		var releaseErr error
		if p.uplinkClose != nil {
			releaseErr = errors.Join(releaseErr, p.uplinkClose())
		}
		for _, v := range p.workers {
			if v.bundleOwned && (!v.attempted || v.closed) {
				releaseErr = errors.Join(releaseErr, os.RemoveAll(v.options.BundleDirectory))
			}
		}
		if p.cpuGroups != nil {
			releaseErr = errors.Join(releaseErr, p.cpuGroups.close(ctx))
		}
		result = errors.Join(result, releaseErr)
		if releaseErr != nil {
			safe = false
		}
	}
	if !safe {
		protectedSiblingRetained.Lock()
		protectedSiblingRetained.pairs = append(protectedSiblingRetained.pairs, p)
		protectedSiblingRetained.Unlock()
		result = errors.Join(result, errors.New("protected pair not fully released; retained references last only until launcher exit"))
		if m != nil {
			history := m.Diagnostics()
			result = errors.Join(result, fmt.Errorf("retained protected history: lease=%d initialized=%d sealed=%d teardown=%d reclaimed=%d zero-verified-bytes=%d unknown=%t",
				history.LeaseID, history.InitializedPages, history.SealedPages, history.TeardownPages,
				history.ReclaimedPages, history.ZeroVerifiedBytes, history.Unknown))
		}
	} else if m != nil && m.Diagnostics().CreateAttempted {
		history := m.Diagnostics()
		fmt.Printf("protected sibling cleanup: lease=%d reclaimed=%d zero-verified-bytes=%d resources released\n",
			history.LeaseID, history.ReclaimedPages, history.ZeroVerifiedBytes)
	}
	return errors.Join(result, ctx.Err())
}

// terminateRole observes native drainage for the combined cleanup without
// removing protected mappings early or closing/deleting a retained VM bundle.
// Missing create ownership is uncertain, not a successfully drained attempt.
func (p *protectedSiblingPair) terminateRole(ctx context.Context, role string) (bool, error) {
	for _, v := range p.workers {
		if v.role != role {
			continue
		}
		if v.vm == nil {
			if v.attempted {
				return false, fmt.Errorf("%s create ownership unobservable", v.options.ID)
			}
			return true, nil
		}
		terminateErr := v.vm.Terminate(ctx)
		waitErr := v.vm.WaitCtx(ctx)
		if waitErr == nil {
			v.drained = true
		}
		var result error
		if terminateErr != nil {
			result = fmt.Errorf("%s terminate: %w", v.options.ID, terminateErr)
		}
		if waitErr != nil {
			result = errors.Join(result, fmt.Errorf("%s wait for termination: %w", v.options.ID, waitErr))
		}
		return v.drained, result
	}
	return true, nil
}

// joinServices retains forward command borrowers until Wait completes; a
// cleanup timeout prevents dependency release and keeps all necessary owners.
func (p *protectedSiblingPair) joinServices(ctx context.Context) error {
	var result error
	for _, service := range p.services {
		select {
		case <-service.done:
			// Expected nonzero stop is normalized only after confirmed exit.
			// Creation uncertainty and joined transport/stream errors remain.
			result = errors.Join(result, service.err)
		case <-ctx.Done():
			result = errors.Join(result, errors.New("protected guest service exit unobserved"), ctx.Err())
		}
	}
	return result
}
