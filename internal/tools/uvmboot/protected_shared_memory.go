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
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/sys/windows"
)

const (
	protectedModeFlag         = "protected-shared-proof"
	protectedTimeoutFlag      = "protected-shared-timeout"
	protectedCleanupFlag      = "protected-shared-cleanup-timeout"
	proofCopyAfterExitTimeout = 5 * time.Second
	// Private VID v2 lifecycle opcodes; trusted HV lifecycle stays v1.
	psInitialize = 1
	psSeal       = 2
	psTeardown   = 3
	psReclaim    = 4
	// Native preflight contention only; neither status authorizes release.
	psDeviceBusy  uint32 = 0x80000011
	psObjectInUse uint32 = 0xc0350019
)

// psRequest mirrors the exact 48-byte private VID v2 request. LifetimeId stays
// zero: VID resolves trusted exact descriptors from its retained backing list.
type psRequest struct {
	Version, Flags                 uint32
	LeaseId, PageIndex, LifetimeId uint64
	PageCount, Operation           uint32
	Reserved                       uint64
}

// psResult mirrors the exact 40-byte private VID v2 operation receipt.
// Version zero is unframed failure, never proof of zero work.
type psResult struct {
	Version, Size, Status, PagesProcessed uint32
	LeaseId, PageCount, InitializedPages  uint64
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
// means no valid native control receipt; Install/Remove use actual HRESULT and
// local ownership instead. No page state or inventory is exported.
type proofResult struct {
	Framed            bool
	Initialized       uint64
	Processed         uint32
	Status            uint32
	LeaseId           uint64
	ZeroVerifiedBytes uint64
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
// Completion text is diagnostic, not operator acceptance or logger coverage.
func (e *proofEvidence) finish(mode string, err error) error {
	if err = errors.Join(err, e.failure()); err != nil {
		return err
	}
	e.record("complete", map[string]any{"Mode": mode, "Cleanup": "complete"})
	return e.failure()
}

// proofErrorText supplies an explicit empty success/error string in JSON records.
func proofErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// executeProtectedProof runs one fresh M1 lifetime through its concrete owner.
// pages is the section's 4-KiB page count; cleanupTimeout is a separate budget.
// Every successfully initialized prefix is reclaimed only after participant cleanup.
// Cleanup uses its own uncancelled deadline. Unknown progress or failed cleanup
// prevents final resource release and is returned as failure, not a lab pass.
// Valid forward progress/ownership is recorded before observing cancellation.
// The original context is never rechecked after entering the cleanup budget.
// A/B/C are owned before preparation; only A/B install before all pages seal.
// C's first install must then be denied before repeated host probes and the
// fresh A/B exchange. C remains a prepared owner requiring cleanup on denial.
func executeProtectedProof(ctx context.Context, p *realProof, pages uint64, cleanupTimeout time.Duration) (err error) {
	if pages == 0 || cleanupTimeout <= 0 {
		return errors.New("invalid protected proof bounds")
	}
	participants := []string{"a", "b", "c"}
	var initialized uint64
	var uncertain bool
	var attempted []string
	opened := false
	// Keep resources owned until cleanup proves voluntary release is safe,
	// including failures during partial prepare/start.
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
			_, e := p.Run(cleanupCtx, step)
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
			if call(proofStep{Kind: "remove", Participant: id}) != nil {
				safe = false
			}
			if call(proofStep{Kind: "terminate", Participant: id}) != nil {
				safe = false
			}
		}
		// Local cleanup outcomes are not drain proof. Failure retains resources;
		// even successful removal/termination requires actual reclaim receipts.
		if p.prepareUncertain {
			cleanupErr = errors.Join(cleanupErr, errors.New("failed create left preparation unobservable; retain backing"))
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
		err = errors.Join(err, cleanupErr, p.evidence.failure())
	}()
	// Ordinary phase calls stop at the first failure; only the deferred cleanup
	// dispatcher continues after errors using its independent deadline.
	call := func(step proofStep) error {
		_, e := p.Run(ctx, step)
		return errors.Join(e, ctx.Err(), p.evidence.failure())
	}
	// Opening can acquire resources while cancellation/evidence failure arrives.
	// Record successful ownership before observing either completion condition.
	_, err = p.Run(ctx, proofStep{Kind: "open"})
	opened = err == nil
	if err = errors.Join(err, ctx.Err(), p.evidence.failure()); err != nil {
		return err
	}
	if err = call(proofStep{Kind: "positive"}); err != nil {
		return err
	}
	for _, id := range participants {
		// Own each attempt before acquisition: a failed start or missing receipt
		// cannot remove that participant from the independent cleanup walk.
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
		r, e := p.Run(ctx, proofStep{Kind: "initialize", Index: initialized, Count: count})
		// Consume framed progress BEFORE examining the status. The cumulative
		// prefix must agree exactly; never infer zero work from an HRESULT.
		if !r.Framed || r.Processed > count || r.Initialized != initialized+uint64(r.Processed) {
			uncertain = true
			return errors.Join(e, ctx.Err(), p.evidence.failure(), errors.New("invalid initialization prefix"))
		}
		initialized = r.Initialized
		e = errors.Join(e, ctx.Err(), p.evidence.failure())
		if e != nil {
			return e
		}
		if r.Processed != count {
			return errors.New("incomplete successful initialization")
		}
	}
	if err = call(proofStep{Kind: "negative-ready"}); err != nil {
		return err
	}
	for _, id := range []string{"a", "b"} {
		if err = call(proofStep{Kind: "install", Participant: id}); err != nil {
			return err
		}
	}
	for i := uint64(0); i < pages; i += 4 {
		if err = call(proofStep{Kind: "seal", Index: i, Count: uint32(min(uint64(4), pages-i))}); err != nil {
			return err
		}
	}
	// C has only a backing pin/lifetime reference, never a guest mapping or
	// loaded diagnostic. All page seals and the host probe precede its first
	// genuine Install; only a fully classified denial permits A/B to exchange.
	if err = call(proofStep{Kind: "negative-sealed"}); err != nil {
		return err
	}
	if err = call(proofStep{Kind: "post-seal-C-install-denial", Participant: "c"}); err != nil {
		return err
	}
	for _, kind := range []string{"negative-post-c-denial", "exchange"} {
		if err = call(proofStep{Kind: kind}); err != nil {
			return err
		}
	}
	return nil
}

// proofVM retains one region's immutable preparation and its UVM reference.
// M1 and primary entries own independently created UVMs; the late entry borrows
// A with no options or separate termination/Close authority. Removed/terminated
// owners are not interchangeable with peers.
type proofVM struct {
	vm         *uvm.UtilityVM
	options    *uvm.OptionsLCOW
	region     hcsschema.SharedMemoryRegion
	gpn        uint64
	terminated bool
	removed    bool
	// freshPrepared records a validated native uninitialized preparation.
	// The partition-seal adapter uses absence to retain uncertain backing;
	// it does not change M1's existing ownership/cleanup dispatcher.
	freshPrepared bool
}

// acceptRemoval checks the real action HRESULT and cached local owner flags.
// Removal has no native lifecycle frame; a failed action/read remains failure
// and cannot authorize releasing controller/backing. Calls are serialized.
func (v *proofVM) acceptRemoval(info *hcsschema.ProtectedSharedRegionInfo, actionErr error) error {
	err := errors.Join(actionErr, uvm.ValidateProtectedSharedOperationResult(info,
		v.region.ProtectedSharedLeaseId, uint64(v.region.Length)/4096))
	if err != nil {
		return err
	}
	if !info.Removed || info.Prepared || info.Installed ||
		info.OperationResultValid || info.OperationHresult != 0 {
		return errors.New("missing successful protected removal receipt")
	}
	v.removed = true
	return nil
}

// realProof owns one lifetime's controller and host section for either plain or
// SNP boot. M1 uses one instance; partition-seal uses separate primary/late
// instances, with late VM borrowing enforced by its adapter.
// snp is immutable after CLI preflight; it selects only boot
// and guest mapping options, never lifecycle authority. Calls are serialized
// except for the two independent guest exchange commands.
type realProof struct {
	evidence         *proofEvidence
	cli              *cli.Context
	snp              bool
	pages            uint64
	runID            string
	section          *sharedMemorySection
	controller       windows.Handle
	control          *windows.LazyProc
	resource         hcsv2.OperationResource
	lease            uint64
	initialized      uint64
	reclaimed        uint64
	prepareUncertain bool
	vms              map[string]*proofVM
	// lateSlot is metadata only, reserved exclusively by partition-seal in A.
	// Empty preserves M1's original single-region preparation requirement.
	lateSlot string
}

// guestMode returns the selected diagnostic boot label, not attestation or
// runtime certification. The immutable snp selection can be read concurrently;
// this method acquires no resources and has no side effects.
func (p *realProof) guestMode() string {
	if p.snp {
		return "snp"
	}
	return "plain"
}

// controlPages calls the actual private vid.dll wrapper. All output is retained
// on failure after strict v2 size/version/identity/count/prefix checks. Optional
// lifetime remains zero; no identity discovery or synthetic progress is used.
// Even a short success-shaped batch returns its validated prefix with an error;
// only invalid framing discards output and makes progress uncertain.
// DLL FALSE with a nonnegative native Status is accepted only for this intact
// bounded short batch, not a full-success/Boolean contradiction. Native Status
// is never rewritten; Run consumes the prefix before error/cancellation/evidence.
// The synchronous kernel call cannot be abandoned while buffers/handles are in use.
func (p *realProof) controlPages(operation uint32, index uint64, count uint32) (psResult, error) {
	var result psResult
	if operation < psInitialize || operation > psReclaim || p.lease == 0 ||
		count == 0 || count > 4 || index >= p.pages || uint64(count) > p.pages-index {
		return result, errors.New("invalid VID operation range/identity")
	}
	request := psRequest{Version: 2, Flags: 1, LeaseId: p.lease, PageIndex: index, PageCount: count, Operation: operation}
	ok, _, callErr := p.control.Call(uintptr(p.controller), uintptr(unsafe.Pointer(&request)), uintptr(unsafe.Pointer(&result)))
	runtime.KeepAlive(p)
	// The matched DLL reports an intact short-success receipt through FALSE
	// and a separate operation error. Counts/identity/prefix must still pass
	// every framing guard below before that receipt can establish ownership.
	shortSuccess := result.Status&0x80000000 == 0 && result.PagesProcessed < count
	if result.Version != 2 || result.Size != uint32(unsafe.Sizeof(result)) ||
		result.LeaseId != p.lease || result.PageCount != p.pages ||
		result.InitializedPages > p.pages || result.PagesProcessed > count ||
		(operation == psInitialize && result.InitializedPages != index+uint64(result.PagesProcessed)) ||
		(operation != psInitialize && result.InitializedPages != p.initialized) ||
		(ok != 0 && ok != 1) ||
		(((ok == 0) != (result.Status&0x80000000 != 0)) &&
			!(ok == 0 && shortSuccess)) {
		return psResult{}, fmt.Errorf("invalid VID result frame (API=%d error=%v)", ok, callErr)
	}
	if shortSuccess {
		return result, fmt.Errorf("incomplete VID lifecycle batch: operation=%d status=%#08x processed=%d requested=%d API=%d: %v",
			operation, result.Status, result.PagesProcessed, count, ok, callErr)
	}
	if ok == 0 || result.Status != 0 {
		return result, fmt.Errorf("VID operation %d: status=%#08x processed=%d API=%d: %v",
			operation, result.Status, result.PagesProcessed, ok, callErr)
	}
	return result, nil
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

// prepare creates/starts one UVM in the immutable CLI-selected boot mode for
// participant id. Calls are serialized; ctx bounds HCS/start/module delivery.
// Options (including any SNP bundle) and then the VM are retained before later
// failures for cleanup. Plain requires direct vmlinux/vhd boot and virtual
// primary backing with no state file/paravisor; SNP requires state-file boot,
// explicitly disabled HCL and non-overcommit primary backing.
// Starting protected hidden backing prepares it but does not install a GPA mapping.
// This applies equally to A/B/C: M1's C only receives the module share here and
// never executes it. Its early attachment retains pins, not an HV guest binding.
// Requires a cached native preparation receipt before accepting the lease/GPA;
// GPA is checked in bytes before retaining a 4-KiB page index. Missing framing
// or failed creation returns an error with ownership/uncertainty preserved.
// Both modes borrow the same retained controller and share the module via GCS.
// Only partition-seal sets lateSlot: A reserves an additional ordinary-hidden
// one-page name/GPA slot, without opening backing or preparing a late owner.
// Its primary response is selected by exact name; M1 still requires one region.
// Structurally valid preparation ownership is consumed even when status fails.
// freshPrepared is set only after the full fresh, uninitialized receipt passes;
// a partial/unknown preparation must not be interpreted as zero initialized work.
// An early receipt query is diagnostic only, bounded to five seconds within
// startup, and never substitutes for post-Start receipt validation.
func (p *realProof) prepare(ctx context.Context, id string) error {
	options, err := createLCOWOptions(ctx, p.cli, "protected-"+p.runID+"-"+id)
	if err != nil {
		return err
	}
	v := &proofVM{options: options}
	p.vms[id] = v
	// Validate the built options, not just raw flags: defaults and backing
	// policy must not silently select a different boot path or device policy.
	if len(options.AssignedDevices) != 0 || len(options.SiblingCommunicationEndpoints) != 0 ||
		options.EnableDeferredCommit || options.ResourcePartitionID != nil {
		return errors.New("proof requires independent VMs without assigned devices, sibling endpoints, deferred commit or resource partitions")
	}
	if p.snp {
		if options.HclEnabled == nil || *options.HclEnabled || options.GuestStateFilePath == "" ||
			options.PreferredRootFSType != uvm.PreferredRootFSTypeNA || options.AllowOvercommit {
			return errors.New("SNP proof requires state-file boot, explicitly disabled HCL and non-overcommit backing")
		}
	} else if options.GuestStateFilePath != "" || options.UseGuestStateFile || options.BundleDirectory != "" ||
		(options.HclEnabled != nil && *options.HclEnabled) || options.SecurityPolicyEnabled ||
		options.DmVerityMode || !options.KernelDirect || options.KernelFile != vmutils.UncompressedKernelFile ||
		options.PreferredRootFSType != uvm.PreferredRootFSTypeVHD || options.RootFSFile != vmutils.VhdFile ||
		!options.AllowOvercommit || options.FullyPhysicallyBacked {
		return errors.New("plain proof requires direct vmlinux/vhd boot, no SNP state/policy/paravisor and virtual backing")
	}
	v.region = hcsschema.SharedMemoryRegion{SectionName: p.section.hcsName, Length: int32(p.pages * 4096),
		AllowGuestWrite: true, HiddenFromGuest: true, ProtectedShared: true, ProtectedSharedControllerUri: p.resource.URI}
	options.SharedMemoryRegions = []hcsschema.SharedMemoryRegion{v.region}
	if p.lateSlot != "" && id == "a" {
		options.SharedMemoryRegions = append(options.SharedMemoryRegions, hcsschema.SharedMemoryRegion{
			SectionName: p.lateSlot, Length: 4096, AllowGuestWrite: true, HiddenFromGuest: true,
		})
	}
	options.ProtectedSharedResources = []hcsv2.OperationResource{p.resource}
	v.vm, err = uvm.CreateLCOW(ctx, options)
	if err != nil {
		// HCS may have admitted preparation before a failed create receipt.
		// There is no returned VM owner to observe; do not infer attachment
		// drainage or voluntarily release this controller on that error.
		p.prepareUncertain = true
		return err
	}
	p.evidence.record("startup", map[string]any{
		"Participant": id, "ID": v.vm.ID(), "Runtime": fmt.Sprint(v.vm.RuntimeID()),
		"BootFilesPath": options.BootFilesPath, "KernelFile": options.KernelFile,
		"RootFSFile": options.RootFSFile, "ConsolePipe": options.ConsolePipe,
		"Stage": "before-start",
	})
	if err = v.vm.StartWithHCSStartObserver(ctx, func(startCtx context.Context) {
		p.evidence.record("prepare-observation", map[string]any{
			"Participant": id, "Stage": "after-hcs-start-query-begin",
		})
		queryCtx, cancel := context.WithTimeout(startCtx, 5*time.Second)
		defer cancel()
		started := time.Now()
		info, queryErr := v.vm.ProtectedSharedOperationResult(queryCtx, v.region)
		p.evidence.record("prepare-observation", map[string]any{
			"Participant": id, "Stage": "after-hcs-start-query-end",
			"Frame": info, "Error": proofErrorText(queryErr),
			"ContextError": proofErrorText(queryCtx.Err()),
			"Elapsed":      time.Since(started).String(), "DiagnosticOnly": true,
		})
	}); err != nil {
		return err
	}
	info, err := v.vm.ProtectedSharedOperationResult(ctx, v.region)
	// Retain any structurally valid owner identity before examining the action
	// or context error. A failed preparation read never proves no backing pins.
	if uvm.ValidateProtectedSharedOperationResultStructure(info, p.lease, p.pages) == nil {
		p.lease = info.LeaseId
		v.region.ProtectedSharedLeaseId = p.lease
		if info.Installed {
			v.region.HiddenFromGuest = false
		}
	}
	p.evidence.record("prepare", map[string]any{"Participant": id, "Frame": info, "Error": proofErrorText(err)})
	if err != nil {
		return err
	}
	if !info.Prepared || info.Installed || info.Removed || info.InitializedPages != 0 ||
		!info.OperationResultValid || info.OperationHresult != 0 || info.OperationStatus != 0 ||
		info.PagesProcessed != 0 {
		return errors.New("preparation was not a framed unmapped, uninitialized region")
	}
	if p.lease != 0 && info.LeaseId != p.lease {
		return errors.New("participants did not prepare the same controller lease")
	}
	p.lease = info.LeaseId
	v.region.ProtectedSharedLeaseId = p.lease
	v.freshPrepared = true
	regions, err := v.vm.SharedMemoryRegions(ctx)
	if err != nil {
		return err
	}
	mapped, err := selectProtectedProofRegion(regions, v.region.SectionName, p.lateSlot, id)
	if err != nil {
		return err
	}
	address, err := uvm.SharedMemoryByteGPA(int64(mapped.GuestPhysicalAddress), int64(v.region.Length))
	if err != nil {
		return err
	}
	v.gpn = address / 4096
	p.evidence.record("vm", map[string]any{"Participant": id, "ID": v.vm.ID(),
		"Runtime": fmt.Sprint(v.vm.RuntimeID()), "GPA": address, "LeaseId": p.lease,
		"GuestMode": p.guestMode(), "GuestStateFileBoot": options.GuestStateFilePath != "",
		"KernelDirect": options.GuestStateFilePath == "" && options.KernelDirect,
		"KernelFile":   options.KernelFile, "RootFSFile": options.RootFSFile,
		"AllowOvercommit": options.AllowOvercommit, "FullyPhysicallyBacked": options.FullyPhysicallyBacked,
		"HclEnabled": options.HclEnabled, "DmVerityMode": options.DmVerityMode})
	return v.vm.Share(ctx, p.cli.String(sharedMemoryGuestModuleArgName), "/run/protected-module", true)
}

// selectProtectedProofRegion selects exactly one primary section response.
// Without a late slot it retains the single-region contract. Only A may have
// the additional named ordinary-hidden slot, which current native properties
// omit until conversion (SharedRegionManager::QueryRegions reports protected or
// mapped regions only). No duplicate, missing primary, unexpected or already
// protected late response is accepted. Returned data is a borrowed cached
// property snapshot, not evidence that either GPA is installed.
func selectProtectedProofRegion(regions []hcsschema.SharedMemoryRegionInfo, primary, late, id string) (*hcsschema.SharedMemoryRegionInfo, error) {
	expected := 1
	if late != "" && id == "a" {
		expected = 2
	}
	if len(regions) != 1 && (expected != 2 || len(regions) != 2) {
		return nil, errors.New("proof returned unexpected region count")
	}
	var found *hcsschema.SharedMemoryRegionInfo
	lateFound := false
	for i := range regions {
		r := &regions[i]
		switch {
		case r.SectionName == primary:
			if found != nil {
				return nil, errors.New("duplicate primary section response")
			}
			found = r
		case expected == 2 && r.SectionName == late:
			if lateFound || r.ProtectedShared != nil {
				return nil, errors.New("late slot is duplicate or already protected")
			}
			if _, err := uvm.SharedMemoryByteGPA(int64(r.GuestPhysicalAddress), 4096); err != nil {
				return nil, err
			}
			lateFound = true
		default:
			return nil, errors.New("unexpected proof section response")
		}
	}
	if found == nil {
		return nil, errors.New("missing named proof section response")
	}
	return found, nil
}

// attemptInstall submits the genuine Install request for the prepared participant
// id using its retained lease and byte-length region. The caller serializes
// action/read pairs and keeps p.resource borrowed through completion. It returns
// raw action and independent receipt errors without classifying success/denial.
// Any Installed flag updates local mapping ownership before cancellation,
// evidence or error checks, even for malformed receipts, so cleanup can remove
// unexpected mappings. No flag proves live native state or absence of progress.
func (p *realProof) attemptInstall(ctx context.Context, id string) uvm.ProtectedSharedModifyOutcome {
	v := p.vms[id]
	request := v.region
	request.HiddenFromGuest = false
	request.ProtectedSharedOperation = hcsschema.ProtectedSharedInstall
	outcome := v.vm.ModifyProtectedSharedWithOutcome(ctx, request, p.resource)
	if outcome.Receipt != nil && outcome.Receipt.Installed {
		v.region.HiddenFromGuest = false
	}
	return outcome
}

// install requires the real Install action and complete cached local ownership
// success for prepared participant id. Calls are serialized and borrow the
// controller through completion; page/lease identity comes from p. Ownership is
// retained before recording evidence, including on failure. Errors do not imply
// zero native mapping progress; this is not a native lifecycle receipt/query.
func (p *realProof) install(ctx context.Context, id string) error {
	outcome := p.attemptInstall(ctx, id)
	info := outcome.Receipt
	mapErr := errors.Join(outcome.ActionError, outcome.ReceiptError)
	p.evidence.record("worker", map[string]any{"Participant": id, "Frame": info, "Error": proofErrorText(mapErr)})
	if err := uvm.ValidateProtectedSharedOperationResult(info, p.lease, p.pages); err != nil {
		return errors.Join(mapErr, err)
	}
	if mapErr != nil {
		return mapErr
	}
	if info == nil || !info.Installed || !info.Prepared || info.Removed ||
		info.OperationResultValid || info.OperationHresult != 0 {
		return errors.New("incomplete protected installation")
	}
	return nil
}

// validatePostSealInstallDenial accepts only an issued Install's exact HV denial
// with independent valid compact receipt, matching nonzero lease and 4-KiB page
// count, and a live forward context (contextErr nil). It preserves outcome and
// owns no resources; the caller serializes action/read pairs and must retain
// participant ownership for cleanup even on error. This classifies cached
// evidence, not native protection or precise rejection attribution.
func validatePostSealInstallDenial(outcome uvm.ProtectedSharedModifyOutcome, lease, pages uint64, contextErr error) error {
	if contextErr != nil {
		return fmt.Errorf("post-seal installation context: %w", contextErr)
	}
	if !outcome.Dispatched {
		return errors.New("post-seal installation was not dispatched")
	}
	if outcome.ReceiptError != nil {
		return fmt.Errorf("post-seal installation receipt: %w", outcome.ReceiptError)
	}
	if lease == 0 || pages == 0 {
		return errors.New("missing post-seal installation identity")
	}
	info := outcome.Receipt
	if err := uvm.ValidateProtectedSharedOperationResultStructure(info, lease, pages); err != nil {
		return err
	}
	// Install has no native lifecycle receipt. InitializedPages is cached from
	// installation, not a live observation that the sealed lifetime is uninitialized.
	if !info.Prepared || info.Installed || info.Removed || info.OperationResultValid ||
		info.OperationHresult != uint32(windows.ERROR_HV_OPERATION_DENIED) {
		return errors.New("post-seal installation did not report the exact unmapped HV denial")
	}
	// HCS SystemError/HcsError and ResultError wrappers expose a single cause
	// ending in syscall.Errno. Do not use errors.Is/As to search an error tree:
	// an expected status beside a transport/cancellation failure is not a pass.
	actionErr := outcome.ActionError
	if actionErr == nil {
		return errors.New("post-seal installation action unexpectedly succeeded")
	}
	for actionErr != nil {
		if status, ok := actionErr.(syscall.Errno); ok {
			if status == windows.ERROR_HV_OPERATION_DENIED {
				return nil
			}
			break
		}
		if _, joined := actionErr.(interface{ Unwrap() []error }); joined {
			break
		}
		actionErr = errors.Unwrap(actionErr)
	}
	return fmt.Errorf("post-seal installation lacks the exact failed HCS action: %w",
		outcome.ActionError)
}

// hostProbe tests the existing host mapping with fault-reporting Windows APIs.
// After revocation ONLY named negative probes may attempt access. Both denial
// statuses and zero byte counts are required on every page. Positive controls
// seed/check offset 256 in each page; probe output never formats protected data.
func (p *realProof) hostProbe(negative bool) error {
	if p.section == nil || p.section.view == 0 || p.pages == 0 ||
		p.pages > 4096 || p.section.size != p.pages*4096 ||
		p.section.protected != negative {
		return errors.New("host probe phase/mapping mismatch")
	}
	process, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	writeData := []byte("BADWRITE")
	if !negative {
		writeData = []byte("HOSTKEEP")
	}
	for page := uint64(0); page < p.pages; page++ {
		offset := page*4096 + 256
		address := p.section.view + uintptr(offset)
		var data [8]byte
		var read, written uintptr
		readErr := windows.ReadProcessMemory(process, address, &data[0], 8, &read)
		writeErr := windows.WriteProcessMemory(process, address, &writeData[0], 8, &written)
		p.evidence.record("host", map[string]any{"Negative": negative, "PageIndex": page, "Offset": offset,
			"ReadStatus": proofWin32Status(readErr), "ReadBytes": read,
			"WriteStatus": proofWin32Status(writeErr), "WriteBytes": written})
		if negative {
			// Unrelated setup failures cannot stand in for direct CPU denial.
			denied := func(e error) bool {
				return errors.Is(e, windows.ERROR_PARTIAL_COPY) || errors.Is(e, windows.ERROR_NOACCESS)
			}
			if !denied(readErr) || !denied(writeErr) || read != 0 || written != 0 {
				return fmt.Errorf("direct host negative probe failed acceptance on page %d", page)
			}
			continue
		}
		if readErr != nil || writeErr != nil || read != 8 || written != 8 {
			return fmt.Errorf("direct host positive control failed on page %d: %w",
				page, errors.Join(readErr, writeErr, errors.New("expected full 8-byte read/write")))
		}
		if err := p.section.expect(offset, []byte("HOSTKEEP")); err != nil {
			return err
		}
	}
	return nil
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
// and delivers it via GCS to the two owned VMs under ctx. Commands use each
// retained GPA in bytes and the section byte length, with decrypted=0 for plain
// backing and decrypted=1 for SNP; neither converts guest-private page state.
// Concurrent module loads prove fresh A->B->A causality,
// verify distinct page-indexed exchanges and every host-denied write sentinel,
// and report the complete verified page count through guest output.
// Randomness, transport or missing causal receipts return errors. Both commands
// use finite post-exit stream drains and finish before cleanup can touch owners.
func (p *realProof) exchange(ctx context.Context) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	challenge := hex.EncodeToString(nonce[:])
	p.evidence.record("challenge", map[string]any{"Token": challenge, "Pages": p.pages})
	decrypted := 0
	if p.snp {
		decrypted = 1
	}
	results := make(chan error, 2)
	for _, id := range []string{"a", "b"} {
		// Each command owns its output buffer; only its result crosses back to
		// the coordinator. Both goroutines finish before cleanup may stop VMs.
		go func(id string) {
			v := p.vms[id]
			module := "/run/protected-module/" + filepath.Base(p.cli.String(sharedMemoryGuestModuleArgName))
			command := fmt.Sprintf("set -eu; insmod %s gpa=%#x length=%#x decrypted=%d protected_mode=1 role=%s challenge=%s; dmesg | grep -F 'hcs-shmem-diag:'",
				shellSingleQuote(module), v.gpn*4096, p.pages*4096, decrypted, shellSingleQuote(id), shellSingleQuote(challenge))
			output, err := p.guest(ctx, id, command)
			if err == nil {
				err = validateProtectedExchangeReceipt(output, id, challenge, p.pages)
			}
			if err == nil {
				p.evidence.record("exchange-receipt", map[string]any{
					"Participant": id, "Token": challenge, "Pages": p.pages})
			}
			results <- err
		}(id)
	}
	return errors.Join(<-results, <-results)
}

// validateProtectedExchangeReceipt requires the fresh guest's all-page completion
// and sentinel count. Old first-page-only output cannot satisfy this protocol.
// It checks unauthenticated diagnostics only and neither touches nor owns backing.
func validateProtectedExchangeReceipt(output, participant, challenge string, pages uint64) error {
	if (participant != "a" && participant != "b") || pages == 0 || pages > 4096 {
		return errors.New("invalid protected exchange receipt identity")
	}
	expected := fmt.Sprintf("hcs-shmem-diag: protected exchange %s %s complete; pages=%d; host sentinels unchanged",
		participant, challenge, pages)
	for _, line := range strings.Split(output, "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), expected) {
			return nil
		}
	}
	return fmt.Errorf("missing fresh guest exchange/sentinel receipt for %d pages", pages)
}

// Run performs and records one real launcher step, returning native progress
// separately from sticky evidence errors. Missing diagnostic output never blocks
// known-safe cleanup; missing native framing still prevents release.
// It is serialized by executeProtectedProof or partition-seal's concrete adapter;
// guest exchange is the sole parallel phase. Actual v2 prefixes remain valid
// on failure when Framed is true.
// Cached worker receipts establish only local ownership; no page state is read.
// Reclaim retries only known, framed zero-prefix preflight contention inside a
// required deadline. Actual reclaim completion alone permits restored access.
// The prepared barrier requires all three independent owners on the same lease.
// The post-seal C step records separate raw action/receipt errors, then accepts
// only the classifier's exact denial with a live context. Expected
// rejection leaves C owned; even unexpected installation never bypasses cleanup.
func (p *realProof) Run(ctx context.Context, step proofStep) (out proofResult, err error) {
	// Record the real dispatch outcome without changing its ownership/prefix.
	// Forward work observes writer failure only after consuming that outcome.
	defer func() {
		p.evidence.record("phase", struct {
			Step         proofStep
			Result       proofResult
			Error        string
			ContextError string
		}{step, out, proofErrorText(err), proofErrorText(ctx.Err())})
	}()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	switch step.Kind {
	case "open":
		if err = validateProtectedSharedNativeLayout(); err != nil {
			return out, err
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
		// Read cached preparation receipts only. No participant count or HV
		// snapshot is inferred, and no native control framing is fabricated.
		if len(p.vms) != 3 || p.lease == 0 {
			return out, errors.New("preparation barrier requires A/B/C and a lease")
		}
		for _, id := range []string{"a", "b", "c"} {
			v := p.vms[id]
			if v == nil || v.vm == nil || v.terminated || v.removed ||
				v.region.ProtectedSharedLeaseId != p.lease {
				return out, errors.New("preparation barrier missing a live matching owner")
			}
			var info *hcsschema.ProtectedSharedRegionInfo
			info, err = v.vm.ProtectedSharedOperationResult(ctx, v.region)
			if err != nil {
				break
			}
			if err = uvm.ValidateProtectedSharedOperationResult(info, p.lease, p.pages); err != nil {
				break
			}
			if !info.Prepared || info.Installed || info.Removed ||
				!info.OperationResultValid || info.InitializedPages != 0 ||
				info.OperationHresult != 0 || info.OperationStatus != 0 || info.PagesProcessed != 0 {
				err = errors.New("preparation barrier not satisfied")
				break
			}
		}
	case "initialize", "seal", "teardown", "reclaim":
		operation := map[string]uint32{"initialize": psInitialize, "seal": psSeal, "teardown": psTeardown, "reclaim": psReclaim}[step.Kind]
		if operation == psInitialize {
			// Block all ordinary positive reads BEFORE possible partial revocation.
			p.section.protected = true
		}
		var r psResult
		if operation == psReclaim {
			if _, bounded := ctx.Deadline(); !bounded {
				return out, errors.New("reclaim requires a cleanup deadline")
			}
			if step.Index != p.reclaimed {
				return out, errors.New("reclaim would repeat successful prefix")
			}
		}
		for {
			if contextErr := ctx.Err(); contextErr != nil {
				err = errors.Join(err, contextErr)
				break
			}
			r, err = p.controlPages(operation, step.Index, step.Count)
			if operation != psReclaim || err == nil || r.Version != 2 ||
				r.PagesProcessed != 0 || (r.Status != psDeviceBusy && r.Status != psObjectInUse) {
				break
			}
			// Preserve backing and retry only rejected, no-progress preflight.
			// Unknown status, partial success and malformed framing stop here.
			select {
			case <-ctx.Done():
				err = errors.Join(err, ctx.Err())
				out = proofResult{Framed: true, Initialized: r.InitializedPages,
					Processed: r.PagesProcessed, Status: r.Status, LeaseId: r.LeaseId}
				return out, err
			case <-time.After(50 * time.Millisecond):
			}
		}
		out = proofResult{Framed: r.Version == 2, Initialized: r.InitializedPages,
			Processed: r.PagesProcessed, Status: r.Status, LeaseId: r.LeaseId}
		if out.Framed {
			p.initialized = r.InitializedPages
			if operation == psReclaim {
				p.reclaimed += uint64(r.PagesProcessed)
			}
		}
	case "negative-ready", "negative-sealed", "negative-post-c-denial":
		err = p.hostProbe(true)
	case "install":
		err = p.install(ctx, step.Participant)
	case "post-seal-C-install-denial":
		// Keep the raw action and independent observation apart. attemptInstall
		// retains any reported mapping ownership before classification/writes;
		// Installed=false is cached evidence, not zero partial native progress.
		v := p.vms[step.Participant]
		outcome := p.attemptInstall(ctx, step.Participant)
		contextErr := ctx.Err()
		err = validatePostSealInstallDenial(outcome, p.lease, p.pages, contextErr)
		p.evidence.record("post-seal-install", map[string]any{
			"Participant": step.Participant, "ID": v.vm.ID(), "Runtime": fmt.Sprint(v.vm.RuntimeID()),
			"LeaseId": p.lease, "GPA": v.gpn * 4096, "PageIndex": uint64(0), "PageCount": p.pages,
			"Operation": hcsschema.ProtectedSharedInstall, "Dispatched": outcome.Dispatched,
			"ActionError": proofErrorText(outcome.ActionError), "ActionStatus": proofWin32Status(outcome.ActionError),
			"ReceiptError": proofErrorText(outcome.ReceiptError), "Frame": outcome.Receipt,
			"ContextError": proofErrorText(contextErr), "Error": proofErrorText(err),
			"LocalHiddenFromGuest": v.region.HiddenFromGuest, "ExpectedDenied": err == nil,
			"UnexpectedSuccess": (outcome.Dispatched && outcome.ActionError == nil) ||
				(outcome.Receipt != nil && outcome.Receipt.Installed),
		})
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
	case "restored":
		// Every reclaim batch succeeded and participants are gone. Only now
		// reopen ordinary reads and verify every initialized byte, not just
		// the seeds. A never-initialized tail still holds its original sentinels.
		if p.reclaimed != p.initialized {
			return out, errors.New("backing not authorized for host reuse")
		}
		p.section.protected = false
		for offset := uint64(0); offset < p.initialized*4096; offset += 4096 {
			var data []byte
			data, err = p.section.read(offset, 4096)
			if err != nil {
				break
			}
			if !bytes.Equal(data, make([]byte, 4096)) {
				err = fmt.Errorf("reclaimed backing was not wholly zeroed on page %d", offset/4096)
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
		if p.prepareUncertain || p.reclaimed != p.initialized {
			return out, errors.New("backing release not authorized")
		}
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

// validateProtectedSharedNativeLayout checks the existing exact AMD64 VID v2
// request/result sizes and every field offset before either mode acquires a
// controller. It performs no native work and never changes either wire layout.
func validateProtectedSharedNativeLayout() error {
	if runtime.GOARCH != "amd64" || unsafe.Sizeof(psRequest{}) != 48 || unsafe.Sizeof(psResult{}) != 40 ||
		unsafe.Offsetof(psRequest{}.Version) != 0 || unsafe.Offsetof(psRequest{}.Flags) != 4 ||
		unsafe.Offsetof(psRequest{}.LeaseId) != 8 || unsafe.Offsetof(psRequest{}.PageIndex) != 16 ||
		unsafe.Offsetof(psRequest{}.LifetimeId) != 24 || unsafe.Offsetof(psRequest{}.PageCount) != 32 ||
		unsafe.Offsetof(psRequest{}.Operation) != 36 || unsafe.Offsetof(psRequest{}.Reserved) != 40 ||
		unsafe.Offsetof(psResult{}.Version) != 0 || unsafe.Offsetof(psResult{}.Size) != 4 ||
		unsafe.Offsetof(psResult{}.Status) != 8 || unsafe.Offsetof(psResult{}.PagesProcessed) != 12 ||
		unsafe.Offsetof(psResult{}.LeaseId) != 16 || unsafe.Offsetof(psResult{}.PageCount) != 24 ||
		unsafe.Offsetof(psResult{}.InitializedPages) != 32 {
		return errors.New("unsupported private VID v2 native layout")
	}
	return nil
}

// runProtectedSharedCLI validates raw M1/partition-seal mode/boot/override combinations
// before native acquisition. Omitted/false hardware security selects plain
// direct-kernel/vhd boot with virtual backing; true selects SNP state-file/none
// boot. Incompatible explicit inputs fail rather than being silently ignored.
// Size is page-aligned bytes (4096..16 MiB); forward/independent cleanup budgets
// are positive and at most ten minutes, not VM lifetime or forced-release timers.
// It dispatches M1 unchanged (three VMs/one lifetime) or partition-seal (two
// VMs/two independent lifetimes and an installed hvtest prerequisite).
// It owns the evidence stream through conservative
// cleanup, returning validation, operation, cleanup or evidence errors. It never
// uses runMany/existing VM IDs or lets markers override lifecycle errors.
// CLI/global settings remain serialized and immutable during the proof.
func runProtectedSharedCLI(c *cli.Context) error {
	mode := c.String(protectedModeFlag)
	if mode != "m1" && mode != "partition-seal" {
		return fmt.Errorf("unknown protected proof mode %q", mode)
	}
	// The command defaults to warning-only logs; retain startup progress without
	// requiring -debug or reducing an explicitly enabled trace level.
	previousLevel := logrus.GetLevel()
	if previousLevel < logrus.InfoLevel {
		logrus.SetLevel(logrus.InfoLevel)
		defer logrus.SetLevel(previousLevel)
	}
	snp := c.Bool(securityHardwareFlag)
	if !useGCS ||
		c.String(sharedMemoryGuestModuleArgName) == "" || lcowUseTerminal ||
		c.Bool(sharedMemoryTwoUVMArgName) || c.Bool(sharedMemoryMappingOnlyArgName) ||
		c.Bool(sharedMemoryGuestInventoryArgName) || c.IsSet(execCommandLineArgName) ||
		c.IsSet(execFileArgName) || c.IsSet(sharedMemoryNameArgName) ||
		len(c.StringSlice(scsiMountsArgName)) != 0 || len(c.StringSlice(vpmemMountsArgName)) != 0 ||
		len(c.StringSlice(shareFilesArgName)) != 0 || len(c.StringSlice(annotationsArgName)) != 0 {
		return errors.New("protected proof requires GCS and module; no ordinary proof/exec/mount/annotation options")
	}
	if c.GlobalInt(countArgName) != 1 || c.GlobalInt(parallelArgName) != 1 ||
		c.GlobalIsSet(resourcePartitionArgName) || c.GlobalBool(enableDeferredCommitArgName) {
		return errors.New("protected proof owns its VM count/identities; no resource partition or deferred commit")
	}
	// Check explicit overrides before opening a controller/section. SNP keeps
	// its existing policy/verity inputs and forced non-overcommit behavior;
	// plain must not inherit those settings or acquire a temporary SNP bundle.
	if snp {
		if c.String(rootFSTypeArgName) != "none" || c.GlobalBool(allowOvercommitArgName) {
			return errors.New("SNP proof requires root-fs-type none and no overcommit")
		}
	} else {
		if !strings.EqualFold(c.String(rootFSTypeArgName), "vhd") ||
			(c.IsSet(kernelDirectArgName) && !c.Bool(kernelDirectArgName)) ||
			(c.IsSet(kernelFileArgName) && !strings.EqualFold(c.String(kernelFileArgName), vmutils.UncompressedKernelFile)) ||
			c.IsSet(securityPolicyArgName) || c.IsSet(securityPolicyEnforcerArgName) || c.IsSet(noVerityBoot) {
			return errors.New("plain proof requires direct vmlinux boot and root-fs-type vhd; no SNP policy/enforcer/verity inputs")
		}
		if c.GlobalIsSet(allowOvercommitArgName) && !c.GlobalBool(allowOvercommitArgName) {
			return errors.New("plain proof requires virtual backing; allow-overcommit=false is incompatible")
		}
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
	p := &realProof{cli: c, snp: snp, pages: size / 4096, runID: hex.EncodeToString(id[:]), vms: make(map[string]*proofVM)}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	p.evidence = &proofEvidence{writer: os.Stdout, runID: p.runID}
	claim := "CPU-ONLY-NOT-ATTESTATION"
	if mode == "partition-seal" {
		claim = "HV-COPY-AND-ADMISSION-NOT-ATTESTATION"
	}
	p.evidence.record("run", map[string]any{"Mode": mode, "GuestMode": p.guestMode(),
		"Pages": p.pages, "Claim": claim})
	if err := p.evidence.failure(); err != nil {
		return err
	}
	var err error
	if mode == "partition-seal" {
		err = executePartitionSealProof(ctx, &realPartitionSealProof{primary: p}, p.pages, cleanup)
	} else {
		err = executeProtectedProof(ctx, p, p.pages, cleanup)
	}
	return p.evidence.finish(mode, err)
}
