//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/computecore"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcsv2 "github.com/Microsoft/hcsshim/internal/hcs/v2"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/urfave/cli"
	"golang.org/x/sys/windows"
)

const (
	protectedModeFlag         = "protected-shared-proof"
	protectedTimeoutFlag      = "protected-shared-timeout"
	protectedCleanupFlag      = "protected-shared-cleanup-timeout"
	proofCopyAfterExitTimeout = 5 * time.Second
	// Private VID v1 lifecycle opcodes, not trusted HV completion operations.
	psInitialize = 1
	psSeal       = 2
	psTeardown   = 3
	psReclaim    = 4
	psQuery      = 5
	// HVSTATUS_TO_NTSTATUS(HV_STATUS_OPERATION_DENIED).
	psAdmissionDenied uint32 = 0xc0350008
)

// psRequest mirrors VID_PROTECTED_SHARED_REQUEST (80 bytes). The test selector
// tail is always zero: this launcher cannot assert trusted completion or use
// component-test controls.
type psRequest struct {
	Version, Flags                 uint32
	LeaseId, PageIndex, LifetimeId uint64
	PageCount, Operation           uint32
	Reserved                       uint64
	Test                           [32]byte
}

// psSnapshot is the complete fixed 2632-byte HV v1 metadata snapshot.
type psSnapshot struct {
	SpaPage, LifetimeId, MutationSequence, ShareCount             uint64
	Size, Version, State, Initialization, RootProtection, Reclaim uint32
	RegistrationCount, Complete, PageType, PageOwnership          uint32
	Registrations                                                 [64]hcsschema.ProtectedSharedRegistrationInfo
}

// psResult mirrors VID_PROTECTED_SHARED_RESULT including the unused test tail.
// Version zero is unframed failure, never proof of zero work.
type psResult struct {
	Version, Size, Status, PagesProcessed                      uint32
	LeaseId, PageCount, InitializedPages, PreparedParticipants uint64
	SnapshotValid, Reserved                                    uint32
	MapSequence, LastMapPagesProcessed                         uint64
	LastMapStatus, ReservedMap                                 uint32
	Snapshot                                                   psSnapshot
	TestObservation                                            [80]byte
}

// proofStep is a launcher-only operation description. Page units are 4 KiB.
// It contains no backing PFNs, guest memory emulation or security bypass.
type proofStep struct {
	Kind        string
	Participant string
	Index       uint64
	Count       uint32
}

// proofResult preserves native control prefixes/status on failure. Framed=false
// means no valid native control receipt; other phases use the independent query
// validity in Snapshots. Present snapshots are complete individual pages.
type proofResult struct {
	Framed               bool
	Initialized          uint64
	Processed            uint32
	Status               uint32
	LeaseId              uint64
	PreparedParticipants uint64
	ZeroVerifiedBytes    uint64
	Snapshots            []hcsschema.ProtectedSharedRegionInfo
}

// proofOperations is the approved launcher-only injection boundary. Tests check
// sequencing/ownership through this interface, never claim MM/HV protection.
type proofOperations interface {
	Run(context.Context, proofStep) (proofResult, error)
}

// proofEvidence serializes complete JSON-line records from concurrent guest
// commands. The caller owns Writer through completion. Write/short-write errors
// are sticky, but do not stop native cleanup or turn a safe cleanup into a leak.
type proofEvidence struct {
	mu       sync.Mutex
	writer   io.Writer
	runID    string
	sequence uint64
	err      error
}

// record writes one escaped envelope under the evidence lock. Embedded guest
// newlines cannot create launcher records. Every write is checked, including
// short writes without an error; failures remain observable through failure.
func (e *proofEvidence) record(kind string, data any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sequence++
	record := struct {
		Version  uint32
		Run      string
		Sequence uint64
		Kind     string
		Data     any
	}{1, e.runID, e.sequence, kind, data}
	b, err := json.Marshal(record)
	if err == nil {
		line := append(append([]byte("PROTECTED-EVIDENCE "), b...), '\n')
		var n int
		n, err = e.writer.Write(line)
		if n != len(line) {
			err = errors.Join(err, io.ErrShortWrite)
		}
	}
	e.err = errors.Join(e.err, err)
}

// failure returns accumulated evidence errors without clearing them. It is safe
// while guest commands are recording; callers must still wait for those commands.
func (e *proofEvidence) failure() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

// finish emits a final receipt only after successful forward work and cleanup
// with no earlier missing record. Failure of this final write also fails the run.
func (e *proofEvidence) finish(mode string, err error) error {
	if err = errors.Join(err, e.failure()); err != nil {
		return err
	}
	e.record("pass", map[string]any{"Mode": mode, "Cleanup": "complete"})
	return e.failure()
}

// recordedProof adds checked evidence to the existing launcher-only interface.
// Native errors and progress remain separate from logging errors so cleanup can
// continue reclaiming known-safe backing even when the evidence sink has failed.
type recordedProof struct {
	operations proofOperations
	evidence   *proofEvidence
}

// Run records the completed native operation and its context state, returning
// the original native result/error. Forward dispatch separately observes sticky
// evidence errors; deferred cleanup aggregates them only after safe cleanup.
func (p *recordedProof) Run(ctx context.Context, step proofStep) (proofResult, error) {
	result, err := p.operations.Run(ctx, step)
	p.evidence.record("phase", struct {
		Step         proofStep
		Result       proofResult
		Error        string
		ContextError string
	}{step, result, proofErrorText(err), proofErrorText(ctx.Err())})
	return result, err
}

// EvidenceError exposes sticky writer failures without changing native progress.
func (p *recordedProof) EvidenceError() error {
	return p.evidence.failure()
}

// proofEvidenceError reads optional launcher evidence state. Plain U2 operation
// fixtures need no writer and remain independent of the native memory subsystem.
func proofEvidenceError(ops proofOperations) error {
	if recorded, ok := ops.(interface{ EvidenceError() error }); ok {
		return recorded.EvidenceError()
	}
	return nil
}

// proofErrorText supplies an explicit empty success/error string in JSON records.
func proofErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// executeProtectedProof runs a fresh M1, M2/control or one M3 lifetime. Every
// successfully initialized prefix is reclaimed only after participant cleanup.
// Cleanup uses its own uncancelled deadline. Unknown progress or failed cleanup
// prevents final resource release and is returned as failure, not a lab pass.
// Valid forward progress/ownership is recorded before observing cancellation.
// The original context is never rechecked after entering the cleanup budget.
func executeProtectedProof(ctx context.Context, ops proofOperations, mode string, pages uint64, cleanupTimeout time.Duration) (err error) {
	if pages == 0 || cleanupTimeout <= 0 {
		return errors.New("invalid protected proof bounds")
	}
	switch mode {
	case "m1", "m2", "m2-control", "m3-a", "m3-b":
	default:
		return errors.New("invalid protected proof mode")
	}
	participants := []string{"a", "b"}
	if mode == "m2" || mode == "m2-control" {
		participants = append(participants, "c")
	}
	var initialized uint64
	var uncertain bool
	var attempted []string
	opened := false
	// Resources stay owned on every failure, including partial prepare/start.
	defer func() {
		if !opened {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		var cleanupErr error
		safe := true
		// Accumulate every cleanup error without skipping other owned VMs.
		call := func(step proofStep) error {
			_, e := ops.Run(cleanupCtx, step)
			// This is the cleanup budget, not the original forward deadline.
			// A native success after this independent budget expires still
			// cannot produce a successful bounded-cleanup receipt.
			e = errors.Join(e, cleanupCtx.Err())
			cleanupErr = errors.Join(cleanupErr, e)
			return e
		}
		for i := uint64(0); i < initialized; i += 4 {
			if call(proofStep{Kind: "teardown", Index: i, Count: uint32(min(uint64(4), initialized-i))}) != nil {
				safe = false
			}
		}
		for _, id := range attempted {
			_ = call(proofStep{Kind: "remove", Participant: id})
			if call(proofStep{Kind: "terminate", Participant: id}) != nil {
				safe = false
			}
		}
		// A failed explicit removal is still reported, but successful target
		// termination plus controller-observed retirement can safely finish
		// reclamation. Do not strand known backing merely because a worker's
		// hidden/install state was uncertain after a failed response.
		if call(proofStep{Kind: "removed"}) != nil {
			safe = false
		}
		if uncertain {
			cleanupErr = errors.Join(cleanupErr, errors.New("unframed initialization: backing progress uncertain"))
			safe = false
		}
		if safe {
			for i := uint64(0); i < initialized; i += 4 {
				if call(proofStep{Kind: "reclaim", Index: i, Count: uint32(min(uint64(4), initialized-i))}) != nil {
					safe = false
					break
				}
			}
		}
		if safe && initialized != 0 {
			if call(proofStep{Kind: "restored"}) != nil {
				safe = false
			}
		}
		if safe {
			_ = call(proofStep{Kind: "release"})
		}
		err = errors.Join(err, cleanupErr, proofEvidenceError(ops))
	}()
	// Ordinary phase calls stop at the first failure; only the deferred cleanup
	// dispatcher continues after errors using its independent deadline.
	call := func(step proofStep) error {
		_, e := ops.Run(ctx, step)
		return errors.Join(e, ctx.Err(), proofEvidenceError(ops))
	}
	// Opening can acquire resources while cancellation/evidence failure arrives.
	// Record successful ownership before observing either completion condition.
	_, err = ops.Run(ctx, proofStep{Kind: "open"})
	opened = err == nil
	if err = errors.Join(err, ctx.Err(), proofEvidenceError(ops)); err != nil {
		return err
	}
	if err = call(proofStep{Kind: "positive"}); err != nil {
		return err
	}
	for _, id := range participants {
		attempted = append(attempted, id)
		if err = call(proofStep{Kind: "prepare", Participant: id}); err != nil {
			return err
		}
	}
	if err = call(proofStep{Kind: "prepared"}); err != nil {
		return err
	}
	for initialized < pages {
		count := uint32(min(uint64(4), pages-initialized))
		r, e := ops.Run(ctx, proofStep{Kind: "initialize", Index: initialized, Count: count})
		// Consume framed progress BEFORE examining the status. The cumulative
		// prefix must agree exactly; never infer zero work from an HRESULT.
		if !r.Framed || r.Processed > count || r.Initialized != initialized+uint64(r.Processed) {
			uncertain = true
			return errors.Join(e, ctx.Err(), proofEvidenceError(ops), errors.New("invalid initialization prefix"))
		}
		initialized = r.Initialized
		e = errors.Join(e, ctx.Err(), proofEvidenceError(ops))
		if e != nil {
			return e
		}
		if r.Processed != count {
			return errors.New("incomplete successful initialization")
		}
	}
	for _, kind := range []string{"ready", "negative-ready"} {
		if err = call(proofStep{Kind: kind}); err != nil {
			return err
		}
	}
	for _, id := range []string{"a", "b"} {
		if err = call(proofStep{Kind: "install", Participant: id}); err != nil {
			return err
		}
	}
	if err = call(proofStep{Kind: "two"}); err != nil {
		return err
	}
	if mode == "m2-control" {
		// Fresh lifetime, identical C preparation/request, but admission is
		// still open. No retired registration is reused to bypass the seal.
		return call(proofStep{Kind: "install", Participant: "c"})
	}
	for i := uint64(0); i < pages; i += 4 {
		if err = call(proofStep{Kind: "seal", Index: i, Count: uint32(min(uint64(4), pages-i))}); err != nil {
			return err
		}
	}
	for _, kind := range []string{"locked", "negative-sealed", "exchange"} {
		if err = call(proofStep{Kind: kind}); err != nil {
			return err
		}
	}
	if mode == "m2" {
		return call(proofStep{Kind: "deny", Participant: "c"})
	}
	if mode == "m3-a" || mode == "m3-b" {
		first, survivor := "a", "b"
		if mode == "m3-b" {
			first, survivor = survivor, first
		}
		if err = call(proofStep{Kind: "terminate", Participant: first}); err != nil {
			return err
		}
		if err = call(proofStep{Kind: "survivor", Participant: survivor}); err != nil {
			return err
		}
	}
	return nil
}

// proofVM retains exactly one independently created UVM and its immutable
// preparation. Removed/terminated owners are not interchangeable with peers.
type proofVM struct {
	vm         *uvm.UtilityVM
	options    *uvm.OptionsLCOW
	region     hcsschema.SharedMemoryRegion
	gpn        uint64
	bindings   []hcsschema.ProtectedSharedRegistrationInfo
	terminated bool
	removed    bool
}

// acceptRemoval preserves a failed action or nested query as failure. Removal's
// OS action has no native result frame; its owner flags and independent query
// must nevertheless be valid before this launcher records successful removal.
func (v *proofVM) acceptRemoval(info *hcsschema.ProtectedSharedRegionInfo, actionErr error) error {
	err := errors.Join(actionErr, uvm.ValidateProtectedSharedInfo(info,
		v.region.ProtectedSharedLeaseId, uint64(v.region.Length)/4096, 0, 0, false))
	if err != nil {
		return err
	}
	if !info.Removed || info.OperationHresult != 0 {
		return errors.New("missing successful protected removal receipt")
	}
	v.removed = true
	return nil
}

// realProof owns the only launcher controller and the host section. Calls are
// serialized except for the two independent guest exchange commands.
type realProof struct {
	evidence         *proofEvidence
	cli              *cli.Context
	pages            uint64
	runID            string
	section          *sharedMemorySection
	controller       windows.Handle
	control          *windows.LazyProc
	resource         hcsv2.OperationResource
	lease            uint64
	initialized      uint64
	prepareUncertain bool
	lifetimes        []uint64
	spas             []uint64
	vms              map[string]*proofVM
}

// controlPages calls the actual private vid.dll wrapper. All output is retained
// on failure after strict fixed-size framing checks; no test flags are forwarded.
// The synchronous kernel call cannot be abandoned while buffers/handles are in use.
func (p *realProof) controlPages(operation uint32, index uint64, count uint32) (psResult, error) {
	var result psResult
	request := psRequest{Version: 1, Flags: 1, LeaseId: p.lease, PageIndex: index, PageCount: count, Operation: operation}
	if operation != psInitialize && index < uint64(len(p.lifetimes)) {
		request.LifetimeId = p.lifetimes[index]
	}
	ok, _, callErr := p.control.Call(uintptr(p.controller), uintptr(unsafe.Pointer(&request)), uintptr(unsafe.Pointer(&result)))
	runtime.KeepAlive(p)
	if result.Version != 1 || result.Size != uint32(unsafe.Sizeof(result)) ||
		result.LeaseId != p.lease || result.PageCount != p.pages ||
		result.InitializedPages > p.pages || result.PagesProcessed > count ||
		result.Reserved != 0 || result.ReservedMap != 0 || result.SnapshotValid > 1 ||
		result.LastMapPagesProcessed > p.pages {
		return psResult{}, fmt.Errorf("invalid VID result frame (API=%d error=%v)", ok, callErr)
	}
	if ok == 0 || result.Status != 0 {
		return result, fmt.Errorf("VID operation %d: status=%#08x processed=%d API=%d: %v",
			operation, result.Status, result.PagesProcessed, ok, callErr)
	}
	if operation != psQuery && result.PagesProcessed != count {
		return result, errors.New("short successful VID lifecycle batch")
	}
	return result, nil
}

// snapshots queries every initialized page through the independent controller.
// Lifetimes and SPAs are fixed on first observation, rejected on later mismatch.
// This is a bounded collection of per-page snapshots, not an atomic region view.
func (p *realProof) snapshots(ctx context.Context) ([]hcsschema.ProtectedSharedRegionInfo, error) {
	var pages []hcsschema.ProtectedSharedRegionInfo
	seenSPAs := make(map[uint64]bool)
	seenLifetimes := make(map[uint64]bool)
	for i := uint64(0); i < p.initialized; i++ {
		if err := ctx.Err(); err != nil {
			return pages, err
		}
		r, err := p.controlPages(psQuery, i, 1)
		if err != nil {
			return pages, err
		}
		s := r.Snapshot
		if s.Size != 2632 || s.Version != 1 || s.RegistrationCount > 64 || s.Complete != 1 || r.SnapshotValid != 1 {
			return pages, errors.New("missing complete native page snapshot")
		}
		info := hcsschema.ProtectedSharedRegionInfo{
			Version: 1, LeaseId: r.LeaseId, PageCount: r.PageCount,
			InitializedPages: r.InitializedPages, PreparedParticipants: r.PreparedParticipants,
			QueryResultValid: true, SnapshotValid: true, Complete: true,
			PageIndex: i, NextPageIndex: i + 1, RegionComplete: p.pages == 1,
			MapSequence: r.MapSequence, LastMapPagesProcessed: r.LastMapPagesProcessed, LastMapStatus: r.LastMapStatus,
			SpaPage: s.SpaPage, LifetimeId: s.LifetimeId, MutationSequence: s.MutationSequence, ShareCount: s.ShareCount,
			State: s.State, Initialization: s.Initialization, RootProtection: s.RootProtection,
			Reclaim: s.Reclaim, PageType: s.PageType, PageOwnership: s.PageOwnership,
			Registrations: append([]hcsschema.ProtectedSharedRegistrationInfo(nil), s.Registrations[:s.RegistrationCount]...),
		}
		if err := uvm.ValidateProtectedSharedInfo(&info, p.lease, p.pages, i, p.lifetimes[i], true); err != nil {
			return pages, err
		}
		if p.lifetimes[i] != 0 && p.spas[i] != s.SpaPage {
			return pages, errors.New("protected backing identity changed")
		}
		if seenSPAs[s.SpaPage] || seenLifetimes[s.LifetimeId] {
			return pages, errors.New("duplicate protected page identity")
		}
		seenSPAs[s.SpaPage], seenLifetimes[s.LifetimeId] = true, true
		p.lifetimes[i], p.spas[i] = s.LifetimeId, s.SpaPage
		pages = append(pages, info)
	}
	return pages, nil
}

// inventory requires exactly the known bindings, with terminal history retained.
// Only quiescent snapshots are accepted; pending/removing is a retryable error
// for the caller's bounded wait, never silently counted as installed.
func (p *realProof) inventory(pages []hcsschema.ProtectedSharedRegionInfo) error {
	for i, page := range pages {
		var expected []hcsschema.ProtectedSharedRegistrationInfo
		var count uint64
		for _, v := range p.vms {
			if len(v.bindings) == 0 {
				continue
			}
			b := v.bindings[i]
			wantState := uint32(1)
			if v.removed || v.terminated {
				wantState = 3
			} else {
				count++
			}
			found := false
			for _, r := range page.Registrations {
				if r.RegistrationId == b.RegistrationId && r.PartitionId == b.PartitionId &&
					r.GpaPage == b.GpaPage && r.SharePermission == b.SharePermission && r.State == wantState {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("page %d missing expected binding/state", i)
			}
			expected = append(expected, b)
		}
		if len(page.Registrations) != len(expected) || page.ShareCount != count {
			return fmt.Errorf("page %d inventory/count mismatch", i)
		}
	}
	return nil
}

// removedSnapshots waits for partition cleanup to retire all prepared attachments
// and registrations, retaining known successful identities in terminal history.
// Invalid/stale frames fail immediately; only valid not-yet-drained inventories
// are retried under ctx's deadline. The returned prefix remains diagnostic on error.
func (p *realProof) removedSnapshots(ctx context.Context) ([]hcsschema.ProtectedSharedRegionInfo, error) {
	if p.prepareUncertain {
		return nil, errors.New("failed create left preparation completion unobservable; retain controller")
	}
	for {
		pages, err := p.snapshots(ctx)
		if err != nil {
			return pages, err
		}
		drained := true
		if p.lease != 0 {
			r, err := p.controlPages(psQuery, 0, 1)
			if err != nil {
				return pages, err
			}
			drained = r.PreparedParticipants == 0
		}
		for i, page := range pages {
			if page.ShareCount != 0 || page.PreparedParticipants != 0 {
				drained = false
			}
			for _, r := range page.Registrations {
				if r.State != 3 {
					drained = false
				}
			}
			// Failed installations can contribute extra terminal history, but
			// successful bindings must never disappear from this lifetime.
			for _, v := range p.vms {
				if len(v.bindings) == 0 {
					continue
				}
				b := v.bindings[i]
				found := false
				for _, r := range page.Registrations {
					if r.RegistrationId == b.RegistrationId && r.PartitionId == b.PartitionId &&
						r.GpaPage == b.GpaPage && r.SharePermission == b.SharePermission {
						found = true
					}
				}
				if !found {
					return pages, errors.New("successful binding missing from terminal history")
				}
			}
		}
		if drained {
			return pages, nil
		}
		select {
		case <-ctx.Done():
			return pages, fmt.Errorf("participant cleanup incomplete: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// guest executes through the existing GCS command transport and captures output.
// Only the supplied, created VM is touched; protected bytes are never host-read.
// After process exit, the existing command transport closes lingering streams
// after five seconds and returns its drain error. We wait for both relays before
// reading their buffers; no live native syscall or borrowed resource is abandoned.
func (p *realProof) guest(ctx context.Context, id, command string) (string, error) {
	v := p.vms[id]
	if v == nil || v.vm == nil || v.terminated {
		return "", errors.New("guest command requires a live owned VM")
	}
	var stdout, stderr bytes.Buffer
	c := cmd.CommandContext(ctx, v.vm, "sh", "-c", command)
	c.CopyAfterExitTimeout = proofCopyAfterExitTimeout
	// The transport drains the two streams concurrently. Keep separate writers
	// and join only after Run has waited for both streams.
	c.Stdout, c.Stderr = &stdout, &stderr
	err := c.Run()
	output := stdout.String() + stderr.String()
	p.evidence.record("guest", map[string]any{"Participant": id, "Output": output, "Error": proofErrorText(err)})
	return output, err
}

// prepare creates/starts one SNP UVM, retaining its owner before any subsequent
// error. Starting hidden backing prepares it but does not install a GPA mapping.
func (p *realProof) prepare(ctx context.Context, id string) error {
	options, err := createLCOWOptions(ctx, p.cli, "protected-"+p.runID+"-"+id)
	if err != nil {
		return err
	}
	v := &proofVM{options: options}
	p.vms[id] = v
	if options.HclEnabled == nil || *options.HclEnabled || options.GuestStateFilePath == "" ||
		len(options.AssignedDevices) != 0 || len(options.SiblingCommunicationEndpoints) != 0 {
		return errors.New("proof requires independent paravisor-free SNP VMs without assigned backing devices")
	}
	v.region = hcsschema.SharedMemoryRegion{SectionName: p.section.hcsName, Length: int32(p.pages*4096),
		AllowGuestWrite: true, HiddenFromGuest: true, ProtectedShared: true, ProtectedSharedControllerUri: p.resource.URI}
	options.SharedMemoryRegions = []hcsschema.SharedMemoryRegion{v.region}
	options.ProtectedSharedResources = []hcsv2.OperationResource{p.resource}
	v.vm, err = uvm.CreateLCOW(ctx, options)
	if err != nil {
		// HCS may have admitted preparation before a failed create receipt.
		// There is no returned VM owner to observe; do not infer attachment
		// drainage or voluntarily release this controller on that error.
		p.prepareUncertain = true
		return err
	}
	if err = v.vm.Start(ctx); err != nil {
		return err
	}
	info, err := v.vm.ProtectedSharedInfo(ctx, v.region, 0, 0, false)
	p.evidence.record("prepare", map[string]any{"Participant": id, "Frame": info, "Error": proofErrorText(err)})
	if err != nil {
		return err
	}
	if !info.Prepared || info.Installed || info.Removed || info.InitializedPages != 0 ||
		!info.OperationResultValid || info.OperationHresult != 0 || info.OperationStatus != 0 ||
		!info.QueryResultValid || info.QueryHresult != 0 || info.QueryStatus != 0 || info.SnapshotValid {
		return errors.New("preparation was not a framed unmapped, uninitialized region")
	}
	if p.lease != 0 && info.LeaseId != p.lease {
		return errors.New("participants did not prepare the same controller lease")
	}
	p.lease = info.LeaseId
	v.region.ProtectedSharedLeaseId = p.lease
	regions, err := v.vm.SharedMemoryRegions(ctx)
	if err != nil {
		return err
	}
	if len(regions) != 1 {
		return errors.New("proof requires exactly one region")
	}
	address, err := uvm.SharedMemoryByteGPA(int64(regions[0].GuestPhysicalAddress), int64(v.region.Length))
	if err != nil {
		return err
	}
	v.gpn = address / 4096
	p.evidence.record("vm", map[string]any{"Participant": id, "ID": v.vm.ID(),
		"Runtime": fmt.Sprint(v.vm.RuntimeID()), "GPA": address, "LeaseId": p.lease})
	return v.vm.Share(ctx, p.cli.String(sharedMemoryGuestModuleArgName), "/run/protected-module", true)
}

// install correlates the serialized map attempt with the controller sequence.
// The designated M2 negative case accepts ONLY actual protected-admission denial,
// zero prefix and unchanged inventory; earlier VA/setup failures are inconclusive.
func (p *realProof) install(ctx context.Context, id string, deny bool) error {
	v := p.vms[id]
	before, err := p.snapshots(ctx)
	if err != nil {
		return err
	}
	request := v.region
	request.HiddenFromGuest = false
	request.ProtectedSharedOperation = hcsschema.ProtectedSharedInstall
	info, mapErr := v.vm.ModifyProtectedShared(ctx, request, p.resource)
	p.evidence.record("worker", map[string]any{"Participant": id, "Frame": info, "Error": proofErrorText(mapErr)})
	if info != nil && info.Installed {
		v.region.HiddenFromGuest = false
	}
	after, err := p.snapshots(ctx)
	if err != nil {
		return errors.Join(mapErr, err)
	}
	if len(after) != int(p.pages) || len(before) != len(after) ||
		before[0].MapSequence == math.MaxUint64 ||
		after[0].MapSequence != before[0].MapSequence+1 {
		return errors.Join(mapErr, errors.New("uncorrelated controller-wide map attempt"))
	}
	if err := uvm.ValidateProtectedSharedInfo(info, p.lease, p.pages, 0, p.lifetimes[0], true); err != nil {
		return errors.Join(mapErr, err)
	}
	p.evidence.record("map", map[string]any{"Participant": id, "Sequence": after[0].MapSequence,
		"Status": after[0].LastMapStatus, "Processed": after[0].LastMapPagesProcessed, "Error": proofErrorText(mapErr)})
	if deny {
		if mapErr == nil || info == nil || !info.OperationResultValid || info.Installed ||
			info.OperationHresult & 0x80000000 == 0 ||
			after[0].LastMapStatus != psAdmissionDenied || after[0].LastMapPagesProcessed != 0 {
			return errors.New("M2 INCONCLUSIVE/FAIL: not a zero-prefix protected-admission denial")
		}
		for i := range after {
			if after[i].ShareCount != before[i].ShareCount ||
				!reflect.DeepEqual(after[i].Registrations, before[i].Registrations) {
				return errors.New("M2 denial changed count or registration inventory")
			}
		}
		return nil
	}
	if mapErr != nil {
		return mapErr
	}
	if info == nil || !info.Installed || after[0].LastMapStatus != 0 || after[0].LastMapPagesProcessed != p.pages {
		return errors.New("incomplete protected installation")
	}
	var bindings []hcsschema.ProtectedSharedRegistrationInfo
	for i, page := range after {
		var added []hcsschema.ProtectedSharedRegistrationInfo
		for _, r := range page.Registrations {
			existing := false
			for _, old := range before[i].Registrations {
				if old.RegistrationId == r.RegistrationId {
					existing = true
				}
			}
			if !existing {
				added = append(added, r)
			}
		}
		if len(added) != 1 || added[0].State != 1 || added[0].GpaPage != v.gpn+uint64(i) {
			return errors.New("installation did not publish exactly the expected GPA binding")
		}
		for _, other := range p.vms {
			if len(other.bindings) != 0 && other.bindings[i].PartitionId == added[0].PartitionId {
				return errors.New("participants are not distinct partition incarnations")
			}
		}
		if i != 0 && added[0].PartitionId != bindings[0].PartitionId {
			return errors.New("participant identity changed across pages")
		}
		bindings = append(bindings, added[0])
	}
	v.bindings = bindings
	return p.inventory(after)
}

// hostProbe tests the existing host mapping with fault-reporting Windows APIs.
// After revocation ONLY named negative probes may attempt access. Both denial
// statuses and zero byte counts are required; probe output never formats data.
func (p *realProof) hostProbe(negative bool) error {
	if p.section == nil || p.section.view == 0 || p.section.size < 4096 ||
		p.section.protected != negative {
		return errors.New("host probe phase/mapping mismatch")
	}
	process, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	var data [8]byte
	var read, written uintptr
	address := p.section.view + 256
	readErr := windows.ReadProcessMemory(process, address, &data[0], 8, &read)
	writeData := []byte("BADWRITE")
	if !negative {
		writeData = []byte("HOSTKEEP")
	}
	writeErr := windows.WriteProcessMemory(process, address, &writeData[0], 8, &written)
	p.evidence.record("host", map[string]any{"Negative": negative,
		"ReadStatus": proofWin32Status(readErr), "ReadBytes": read,
		"WriteStatus": proofWin32Status(writeErr), "WriteBytes": written})
	if negative {
		// Both APIs report actual access failure. Unrelated setup errors (such
		// as invalid handles) are not accepted as proof of CPU denial.
		denied := func(e error) bool {
			return errors.Is(e, windows.ERROR_PARTIAL_COPY) || errors.Is(e, windows.ERROR_NOACCESS)
		}

		if !denied(readErr) || !denied(writeErr) || read != 0 || written != 0 {
			return errors.New("direct host negative probe failed acceptance")
		}
		return nil
	}
	if readErr != nil || writeErr != nil || read != 8 || written != 8 {
		return errors.New("direct host positive control failed")
	}
	return p.section.expect(256, []byte("HOSTKEEP"))
}

// proofWin32Status preserves the raw unsigned Windows error for probe evidence.
// Zero denotes success; non-Windows errors use an explicit unknown sentinel.
func proofWin32Status(err error) uint32 {
	if err == nil {
		return 0
	}
	var status syscall.Errno
	if errors.As(err, &status) {
		return uint32(status)
	}
	return math.MaxUint32
}

// exchange generates a challenge only after the caller's explicit seal barrier
// and delivers it via GCS. Concurrent module loads prove fresh A->B->A causality,
// verify the host-denied write sentinel and report through guest output.
// Both commands use finite post-exit stream drains; both finish before cleanup.
func (p *realProof) exchange(ctx context.Context) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	challenge := hex.EncodeToString(nonce[:])
	p.evidence.record("challenge", map[string]any{"Token": challenge})
	results := make(chan error, 2)
	for _, id := range []string{"a", "b"} {
		// Each command owns its output buffer; only its result crosses back to
		// the coordinator. Both goroutines finish before cleanup may stop VMs.
		go func(id string) {
			v := p.vms[id]
			module := "/run/protected-module/" + filepath.Base(p.cli.String(sharedMemoryGuestModuleArgName))
			command := fmt.Sprintf("set -eu; insmod %s gpa=%#x length=%#x decrypted=1 protected_mode=1 role=%s challenge=%s; dmesg | grep -F 'hcs-shmem-diag:'",
				shellSingleQuote(module), v.gpn*4096, p.pages*4096, shellSingleQuote(id), shellSingleQuote(challenge))
			output, err := p.guest(ctx, id, command)
			if err == nil && !bytes.Contains([]byte(output), []byte("protected exchange "+id+" "+challenge+" complete; host sentinel unchanged")) {
				err = errors.New("missing fresh guest exchange/sentinel receipt")
			}
			if err == nil {
				p.evidence.record("exchange-receipt", map[string]any{"Participant": id, "Token": challenge})
			}
			results <- err
		}(id)
	}
	return errors.Join(<-results, <-results)
}

// Run performs one real launcher step. recordedProof writes its phase evidence.
// It is serialized by executeProtectedProof; guest exchange is the sole parallel
// phase. Returned native prefixes remain valid on failure when Framed is true.
func (p *realProof) Run(ctx context.Context, step proofStep) (out proofResult, err error) {
	if err = ctx.Err(); err != nil {
		return out, err
	}
	switch step.Kind {
	case "open":
		if runtime.GOARCH != "amd64" || unsafe.Sizeof(psRequest{}) != 80 || unsafe.Sizeof(psSnapshot{}) != 2632 || unsafe.Sizeof(psResult{}) != 2792 {
			return out, errors.New("unsupported private VID v1 native layout")
		}
		dll := windows.NewLazySystemDLL("vid.dll")
		create := dll.NewProc("VidCreateProtectedSharedController")
		p.control = dll.NewProc("VidControlProtectedShared")
		if err = create.Find(); err != nil {
			return out, err
		}
		if err = p.control.Find(); err != nil {
			return out, err
		}
		handle, _, e := create.Call()
		p.controller = windows.Handle(handle)
		if p.controller == windows.InvalidHandle || p.controller == 0 {
			return out, fmt.Errorf("create VID controller: %v", e)
		}
		p.section, err = createSharedMemorySection("protected-"+p.runID, p.pages*4096)
		if err != nil {
			return out, errors.Join(err, windows.CloseHandle(p.controller))
		}
		p.resource = hcsv2.OperationResource{Type: computecore.HcsResourceTypeFile,
			URI: "hcs:/ProtectedShared/" + p.runID, Handle: syscall.Handle(p.controller)}
	case "positive":
		err = p.hostProbe(false)
	case "prepare":
		err = p.prepare(ctx, step.Participant)
	case "prepared":
		var r psResult
		r, err = p.controlPages(psQuery, 0, 1)
		out = proofResult{Framed: r.Version == 1, Initialized: r.InitializedPages,
			Processed: r.PagesProcessed, Status: r.Status, LeaseId: r.LeaseId,
			PreparedParticipants: r.PreparedParticipants}
		if err == nil && (r.InitializedPages != 0 || r.SnapshotValid != 0 || r.PreparedParticipants != uint64(len(p.vms))) {
			err = errors.New("preparation barrier not satisfied")
		}
	case "initialize", "seal", "teardown", "reclaim":
		operation := map[string]uint32{"initialize": psInitialize, "seal": psSeal, "teardown": psTeardown, "reclaim": psReclaim}[step.Kind]
		if operation == psInitialize {
			// Block all ordinary positive reads BEFORE possible partial revocation.
			p.section.protected = true
		}
		var r psResult
		r, err = p.controlPages(operation, step.Index, step.Count)
		out = proofResult{Framed: r.Version == 1, Initialized: r.InitializedPages,
			Processed: r.PagesProcessed, Status: r.Status, LeaseId: r.LeaseId,
			PreparedParticipants: r.PreparedParticipants}
		if out.Framed {
			p.initialized = r.InitializedPages
		}
	case "removed":
		out.Snapshots, err = p.removedSnapshots(ctx)
	case "ready", "two", "locked":
		out.Snapshots, err = p.snapshots(ctx)
		if err != nil {
			break
		}
		err = p.inventory(out.Snapshots)
		for _, page := range out.Snapshots {
			switch step.Kind {
			case "ready":
				if page.State != 1 || page.Initialization != 2 || page.RootProtection != 1 || page.ShareCount != 0 || len(page.Registrations) != 0 {
					err = errors.Join(err, errors.New("root denial/readiness barrier failed"))
				}
			case "two", "locked":
				state := uint32(1)
				if step.Kind == "locked" {
					state = 2
				}
				if page.State != state || page.RootProtection != 1 || page.ShareCount != 2 || len(page.Registrations) != 2 {
					err = errors.Join(err, errors.New("two-participant explicit-seal inventory failed"))
				}
			}
		}
	case "negative-ready", "negative-sealed":
		err = p.hostProbe(true)
	case "install", "deny":
		err = p.install(ctx, step.Participant, step.Kind == "deny")
		var snapshotErr error
		out.Snapshots, snapshotErr = p.snapshots(ctx)
		err = errors.Join(err, snapshotErr)
	case "exchange":
		err = p.exchange(ctx)
	case "remove":
		v := p.vms[step.Participant]
		if v == nil || v.vm == nil || v.terminated || v.removed || v.region.ProtectedSharedLeaseId == 0 {
			break
		}
		request := v.region
		request.ProtectedSharedOperation = hcsschema.ProtectedSharedRemove
		var info *hcsschema.ProtectedSharedRegionInfo
		info, err = v.vm.ModifyProtectedShared(ctx, request, p.resource)
		p.evidence.record("remove", map[string]any{"Participant": step.Participant, "Frame": info, "Error": proofErrorText(err)})
		err = v.acceptRemoval(info, err)
	case "terminate":
		v := p.vms[step.Participant]
		if v == nil || v.vm == nil || v.terminated {
			break
		}
		if err = v.vm.Terminate(ctx); err != nil {
			break
		}
		if err = v.vm.WaitCtx(ctx); err != nil {
			break
		}
		v.terminated = true
		err = v.vm.CloseCtx(ctx)
	case "survivor":
		// Partition destruction can finish asynchronously. Wait for the exact
		// departed binding's terminal history without waiting under kernel locks.
		for {
			out.Snapshots, err = p.snapshots(ctx)
			if err == nil {
				err = p.inventory(out.Snapshots)
			}
			if err == nil {
				for _, page := range out.Snapshots {
					if page.State != 2 || page.RootProtection != 1 || page.ShareCount != 1 {
						err = errors.New("survivor must remain installed in the locked lifetime")
					}
				}
			}
			if err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return out, errors.Join(err, ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			break
		}
		token := hex.EncodeToString(nonce[:])
		p.evidence.record("survivor-challenge", map[string]any{"Participant": step.Participant, "Token": token})
		command := "set -eu; printf '%s' " + shellSingleQuote(token) + " > /sys/module/hcs_shmem_diag/parameters/local_probe; dmesg | grep -F 'protected local " + token + " complete'"
		var output string
		output, err = p.guest(ctx, step.Participant, command)
		if err == nil && !strings.Contains(output, "protected local "+token+" complete") {
			err = errors.New("missing fresh survivor receipt")
		}
		if err == nil {
			p.evidence.record("survivor-receipt", map[string]any{"Participant": step.Participant, "Token": token})
		}
	case "restored":
		// Every reclaim batch succeeded and participants are gone. Only now
		// reopen ordinary host reads and verify EVERY byte, not just the seed.
		p.section.protected = false
		for offset := uint64(0); offset < p.pages*4096; offset += 4096 {
			var data []byte
			data, err = p.section.read(offset, 4096)
			if err != nil {
				break
			}
			if !bytes.Equal(data, make([]byte, 4096)) {
				err = errors.New("reclaimed backing was not wholly zeroed")
				break
			}
			out.ZeroVerifiedBytes += 4096
		}
		if err == nil {
			err = p.hostProbe(false)
		}
	case "release":
		// A never-initialized section requires no scrub. After explicit reclaim,
		// close the controller before the host view. Kernel-owned references keep
		// pins/backing alive until asynchronous final lease cleanup completes.
		p.section.protected = false
		err = windows.CloseHandle(p.controller)
		if err == nil {
			p.controller = 0
			err = p.section.Close()
		}
		if err == nil {
			for _, v := range p.vms {
				if v.options != nil && v.options.BundleDirectory != "" {
					err = errors.Join(err, os.RemoveAll(v.options.BundleDirectory))
				}
			}
		}
	default:
		err = fmt.Errorf("unknown protected proof step %q", step.Kind)
	}
	return out, err
}

// runProtectedSharedCLI validates the isolated lab mode, then executes one fresh
// lifetime with bounded operation and cleanup contexts. It never uses runMany or
// existing VM IDs and never treats marker output as overriding lifecycle errors.
func runProtectedSharedCLI(c *cli.Context) error {
	mode := c.String(protectedModeFlag)
	switch mode {
	case "m1", "m2", "m2-control", "m3-a", "m3-b":
	default:
		return fmt.Errorf("unknown protected proof mode %q", mode)
	}
	if !useGCS || !c.Bool(securityHardwareFlag) || c.String(rootFSTypeArgName) != "none" ||
		c.String(sharedMemoryGuestModuleArgName) == "" || lcowUseTerminal ||
		c.Bool(sharedMemoryTwoUVMArgName) || c.Bool(sharedMemoryMappingOnlyArgName) ||
		c.Bool(sharedMemoryGuestInventoryArgName) || c.IsSet(execCommandLineArgName) ||
		c.IsSet(execFileArgName) || c.IsSet(sharedMemoryNameArgName) ||
		len(c.StringSlice(scsiMountsArgName)) != 0 || len(c.StringSlice(vpmemMountsArgName)) != 0 ||
		len(c.StringSlice(shareFilesArgName)) != 0 || len(c.StringSlice(annotationsArgName)) != 0 {
		return errors.New("protected proof requires GCS, SNP, root-fs-type none, module; no ordinary proof/exec/mount/annotation options")
	}
	if c.GlobalInt(countArgName) != 1 || c.GlobalInt(parallelArgName) != 1 ||
		c.GlobalIsSet(resourcePartitionArgName) || c.GlobalBool(enableDeferredCommitArgName) ||
		c.GlobalBool(allowOvercommitArgName) {
		return errors.New("protected proof owns its VM count/identities; no resource partition, overcommit or deferred commit")
	}
	size := c.Uint64(sharedMemorySizeArgName)
	if size == 0 || size%4096 != 0 || size > 16*1024*1024 || size > math.MaxInt32 {
		return errors.New("protected proof size must be page aligned, 4096..16777216 bytes; no 1-GiB probe")
	}
	timeout, cleanup := c.Duration(protectedTimeoutFlag), c.Duration(protectedCleanupFlag)
	if timeout <= 0 || timeout > 10*time.Minute || cleanup <= 0 || cleanup > 10*time.Minute {
		return errors.New("protected proof and cleanup timeouts must be in (0,10m]")
	}
	if _, err := os.Stat(c.String(sharedMemoryGuestModuleArgName)); err != nil {
		return err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	p := &realProof{cli: c, pages: size / 4096, runID: hex.EncodeToString(id[:]), vms: make(map[string]*proofVM),
		lifetimes: make([]uint64, size/4096), spas: make([]uint64, size/4096)}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	p.evidence = &proofEvidence{writer: os.Stdout, runID: p.runID}
	p.evidence.record("run", map[string]any{"Mode": mode, "Pages": p.pages, "Claim": "CPU-ONLY-NOT-ATTESTATION"})
	if err := p.evidence.failure(); err != nil {
		return err
	}
	err := executeProtectedProof(ctx, &recordedProof{operations: p, evidence: p.evidence}, mode, p.pages, cleanup)
	return p.evidence.finish(mode, err)
}
