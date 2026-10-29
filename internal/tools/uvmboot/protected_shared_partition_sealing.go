//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/Microsoft/hcsshim/internal/computecore"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcsv2 "github.com/Microsoft/hcsshim/internal/hcs/v2"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"golang.org/x/sys/windows"
)

// partitionSealStep describes only this experiment's serialized operations.
// Lifetime is primary or late for region/page work, empty for discovery and
// VM/driver ownership steps; Index/Count are 4-KiB pages, not byte ranges.
type partitionSealStep struct {
	proofStep
	Lifetime string
}

// partitionSealResult carries acquired ownership and validated native progress
// even on error/cancellation. Ownership flags are conservative positive facts,
// never inferred from an error. Uncertain forbids voluntary backing release.
// ControlAttempted distinguishes an unframed native attempt from no dispatch.
type partitionSealResult struct {
	proofResult
	BackingOwned     bool
	VMOwned          bool
	DriverOwned      bool
	Uncertain        bool
	ControlAttempted bool
}

// partitionSealRunner is limited to the new coordinator's steps. Run is
// synchronous and serialized; it retains all acquired concrete owners and
// returns their facts/progress before errors are examined. EvidenceError is
// sticky but must not prevent independent cleanup. No fake implements HV policy.
type partitionSealRunner interface {
	// Run borrows ctx for one serialized step and retains acquired resources.
	// Ownership/progress outputs remain usable on error under their validity
	// flags; the caller must consume them before checking cancellation.
	Run(context.Context, partitionSealStep) (partitionSealResult, error)
	// EvidenceError reports sticky diagnostic failure without changing any
	// owner or preventing known-safe native cleanup.
	EvidenceError() error
}

// partitionSealLifetime records one independent controller/lease's prefixes.
// attempted is region ownership, not VM ownership: the late region borrows A.
// The coordinator alone mutates ledgers; no lifecycle result is synthesized.
type partitionSealLifetime struct {
	pages, lease, initialized, teardown, reclaimed uint64
	backing, uncertain                           bool
	attempted                                    []string
}

// consumeControl retains a valid bounded lifecycle prefix before its operation
// error or context is considered. It rejects missing/contradictory identity or
// progress, making the lifetime unreleasable. Non-initialize receipts keep the
// cumulative initialized count; teardown and reclaim advance separate ledgers.
// Page-lock receipts are checked too, without conflating them with VM seals.
func (l *partitionSealLifetime) consumeControl(s partitionSealStep, r partitionSealResult) error {
	if !r.ControlAttempted {
		return errors.New("lifecycle control was not attempted")
	}
	expected := l.initialized
	if s.Kind == "initialize" {
		expected = s.Index + uint64(r.Processed)
	}
	if !r.Framed || l.lease == 0 || r.LeaseId != l.lease ||
		r.Processed > s.Count || r.Initialized != expected || expected > l.pages {
		l.uncertain = true
		return errors.New("invalid partition experiment lifecycle prefix; retain backing")
	}
	switch s.Kind {
	case "initialize":
		if s.Index != l.initialized {
			l.uncertain = true
			return errors.New("noncontiguous initialization")
		}
		l.initialized = expected
	case "teardown":
		if s.Index == l.teardown {
			l.teardown += uint64(r.Processed)
		}
	case "reclaim":
		if s.Index != l.reclaimed {
			l.uncertain = true
			return errors.New("noncontiguous reclaim")
		}
		l.reclaimed += uint64(r.Processed)
	}
	if r.Processed != s.Count || r.Status != 0 {
		return errors.New("incomplete or failed lifecycle batch")
	}
	return nil
}

// executePartitionSealProof owns exactly two VM acquisitions and independent
// primary/late lifetimes through discovery, seals and page lifetime checks.
// Each before snapshot precedes the entire prepare/CreateLCOW/Start boundary;
// selection must finish before the next VM or any GPA probe. pages is 1..4096;
// cleanupTimeout is an independent positive budget, at most ten minutes.
// Returned progress/ownership is always consumed before cancellation/errors.
// All forward errors stop work; cleanup uses a fresh uncancelled context,
// explicitly removes regions, closes only actually acquired VMs, and releases
// each backing only after trusted reclaim/full-byte zero verification. Unknown
// progress or detach failures retain necessary resources and fail the run.
// This function never reopens a partition seal or emits a completion record.
func executePartitionSealProof(ctx context.Context, runner partitionSealRunner, pages uint64, cleanupTimeout time.Duration) (err error) {
	if pages == 0 || pages > 4096 || cleanupTimeout <= 0 || cleanupTimeout > 10*time.Minute {
		return errors.New("invalid partition-seal experiment bounds")
	}
	primary := &partitionSealLifetime{pages: pages}
	late := &partitionSealLifetime{pages: 1}
	lifetimes := map[string]*partitionSealLifetime{"primary": primary, "late": late}
	ownedVMs := map[string]bool{}
	driverOwned := false

	// Dispatch consumes returned ownership even when acquisition cancelled or
	// partially failed. No later context/evidence check can hide an owned VM.
	dispatch := func(callCtx context.Context, s partitionSealStep) (partitionSealResult, error) {
		r, e := runner.Run(callCtx, s)
		driverOwned = driverOwned || r.DriverOwned
		if s.Kind == "driver" && e == nil && !r.DriverOwned {
			e = errors.New("successful driver open returned no owned handle")
		}
		if s.Kind == "prepare" && r.VMOwned {
			ownedVMs[s.Participant] = true
		}
		if l := lifetimes[s.Lifetime]; l != nil {
			l.backing = l.backing || r.BackingOwned
			l.uncertain = l.uncertain || r.Uncertain
			if r.Uncertain {
				e = errors.Join(e, errors.New("uncertain lifetime ownership/progress"))
			}
			if s.Kind == "open" && e == nil && !r.BackingOwned {
				l.uncertain = true
				e = errors.New("successful lifetime open returned no backing owner")
			}
			if (s.Kind == "prepare" || s.Kind == "late-prepare") && e == nil &&
				(r.LeaseId == 0 || (s.Kind == "prepare" && !r.VMOwned)) {
				l.uncertain = true
				e = errors.New("successful preparation returned unknown ownership")
			}
			if l.lease == 0 && r.LeaseId != 0 {
				l.lease = r.LeaseId
			} else if r.LeaseId != 0 && r.LeaseId != l.lease {
				l.uncertain = true
				e = errors.Join(e, errors.New("lifetime lease changed"))
			}
			if s.Kind == "initialize" || s.Kind == "seal" || s.Kind == "teardown" || s.Kind == "reclaim" {
				e = errors.Join(e, l.consumeControl(s, r))
			}
		}
		return r, e
	}

	// Deferred cleanup uses a separate dispatcher and uncancelled context.
	// Its deadline bounds new requests, never authorizing log-and-free.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		var cleanupErr error
		// Cleanup keeps going across other owners after failures. Evidence
		// failure is sticky, but does not suppress safe native cleanup work.
		// True means this operation completed within the independent budget;
		// it does not certify that the diagnostic writer is still usable.
		call := func(s partitionSealStep) bool {
			_, e := dispatch(cleanupCtx, s)
			e = errors.Join(e, cleanupCtx.Err())
			cleanupErr = errors.Join(cleanupErr, e)
			return e == nil
		}
		safe := map[string]bool{"primary": true, "late": true}
		for _, name := range []string{"primary", "late"} {
			l := lifetimes[name]
			for i := uint64(0); i < l.initialized; i += 4 {
				if !call(partitionSealStep{proofStep: proofStep{Kind: "teardown", Index: i,
					Count: uint32(min(uint64(4), l.initialized-i))}, Lifetime: name}) {
					safe[name] = false
				}
			}
			// Remove prepared-but-unmapped late ownership too. A missing
			// lease/receipt is not equivalent to an absent attachment.
			for _, id := range l.attempted {
				if !call(partitionSealStep{proofStep: proofStep{Kind: "remove", Participant: id}, Lifetime: name}) {
					safe[name] = false
				}
			}
		}
		for _, id := range []string{"a", "b"} {
			if ownedVMs[id] && !call(partitionSealStep{proofStep: proofStep{Kind: "terminate", Participant: id}}) {
				safe["primary"] = false
				if id == "a" {
					safe["late"] = false
				}
			}
		}
		for _, name := range []string{"late", "primary"} {
			l := lifetimes[name]
			if l.uncertain {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("%s ownership/progress uncertain; retaining backing", name))
				safe[name] = false
			}
			if !l.backing || !safe[name] {
				continue
			}
			if l.teardown != l.initialized {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("%s teardown incomplete", name))
				continue
			}
			for l.reclaimed < l.initialized {
				if !call(partitionSealStep{proofStep: proofStep{Kind: "reclaim", Index: l.reclaimed,
					Count: uint32(min(uint64(4), l.initialized-l.reclaimed))}, Lifetime: name}) {
					safe[name] = false
					break
				}
			}
			if safe[name] && l.initialized != 0 {
				var r partitionSealResult
				var e error
				r, e = dispatch(cleanupCtx, partitionSealStep{proofStep: proofStep{Kind: "zero"}, Lifetime: name})
				if r.ZeroVerifiedBytes != l.initialized*4096 {
					e = errors.Join(e, errors.New("incomplete initialized-byte zero verification"))
				}
				e = errors.Join(e, cleanupCtx.Err())
				cleanupErr = errors.Join(cleanupErr, e)
				safe[name] = e == nil
			}
			if safe[name] {
				// Never-initialized backing needs established detach facts,
				// not a fabricated zero-progress lifecycle receipt.
				call(partitionSealStep{proofStep: proofStep{Kind: "release"}, Lifetime: name})
			}
		}
		if driverOwned {
			call(partitionSealStep{proofStep: proofStep{Kind: "close-driver"}})
		}
		err = errors.Join(err, cleanupErr, runner.EvidenceError())
	}()

	// Forward calls preserve acquisitions/prefixes first, then stop on either
	// operation, context or sticky evidence failure. M1 uses no such seam.
	call := func(s partitionSealStep) error {
		_, e := dispatch(ctx, s)
		return errors.Join(e, ctx.Err(), runner.EvidenceError())
	}
	if err = call(partitionSealStep{proofStep: proofStep{Kind: "driver"}}); err != nil {
		return err
	}
	if err = call(partitionSealStep{proofStep: proofStep{Kind: "open"}, Lifetime: "primary"}); err != nil {
		return err
	}
	if err = call(partitionSealStep{proofStep: proofStep{Kind: "seed"}, Lifetime: "primary"}); err != nil {
		return err
	}
	for _, id := range []string{"a", "b"} {
		if err = call(partitionSealStep{proofStep: proofStep{Kind: "snapshot-before", Participant: id}}); err != nil {
			return err
		}
		primary.attempted = append(primary.attempted, id)
		if err = call(partitionSealStep{proofStep: proofStep{Kind: "prepare", Participant: id}, Lifetime: "primary"}); err != nil {
			return err
		}
		if err = call(partitionSealStep{proofStep: proofStep{Kind: "snapshot-after", Participant: id}}); err != nil {
			return err
		}
	}
	for primary.initialized < pages {
		if err = call(partitionSealStep{proofStep: proofStep{Kind: "initialize", Index: primary.initialized,
			Count: uint32(min(uint64(4), pages-primary.initialized))}, Lifetime: "primary"}); err != nil {
			return err
		}
	}
	for _, id := range []string{"a", "b"} {
		if err = call(partitionSealStep{proofStep: proofStep{Kind: "install", Participant: id}, Lifetime: "primary"}); err != nil {
			return err
		}
	}
	// The initial page lock and later partition seal close different gates.
	// All pages are locked before genuine HV positive controls.
	for i := uint64(0); i < pages; i += 4 {
		if err = call(partitionSealStep{proofStep: proofStep{Kind: "seal", Index: i,
			Count: uint32(min(uint64(4), pages-i))}, Lifetime: "primary"}); err != nil {
			return err
		}
	}
	for _, id := range []string{"a", "b"} {
		if err = call(partitionSealStep{proofStep: proofStep{Kind: "hv-positive", Participant: id}, Lifetime: "primary"}); err != nil {
			return err
		}
	}
	for _, kind := range []string{"partition-seal", "partition-seal-repeat"} {
		for _, id := range []string{"a", "b"} {
			if err = call(partitionSealStep{proofStep: proofStep{Kind: kind, Participant: id}, Lifetime: "primary"}); err != nil {
				return err
			}
		}
	}
	for _, id := range []string{"a", "b"} {
		if err = call(partitionSealStep{proofStep: proofStep{Kind: "hv-negative", Participant: id}, Lifetime: "primary"}); err != nil {
			return err
		}
	}
	// The slot name existed at VM creation, but none of the late backing,
	// controller, pins, prepared owner or lifecycle existed before BOTH seals.
	if err = call(partitionSealStep{proofStep: proofStep{Kind: "open"}, Lifetime: "late"}); err != nil {
		return err
	}
	if err = call(partitionSealStep{proofStep: proofStep{Kind: "seed"}, Lifetime: "late"}); err != nil {
		return err
	}
	late.attempted = append(late.attempted, "a")
	if err = call(partitionSealStep{proofStep: proofStep{Kind: "late-prepare", Participant: "a"}, Lifetime: "late"}); err != nil {
		return err
	}
	if err = call(partitionSealStep{proofStep: proofStep{Kind: "initialize", Count: 1}, Lifetime: "late"}); err != nil {
		return err
	}
	if err = call(partitionSealStep{proofStep: proofStep{Kind: "late-install-denial", Participant: "a"}, Lifetime: "late"}); err != nil {
		return err
	}
	return call(partitionSealStep{proofStep: proofStep{Kind: "exchange"}, Lifetime: "primary"})
}

// realPartitionSealProof adapts the new steps to existing real control/guest
// helpers. primary owns A/B; late owns only backing and a distinct region owner
// borrowing A's VM pointer (no options, termination or Close authority).
// Calls are serialized except for the existing joined guest exchange.
// Snapshots and selected IDs are diagnostic quiet-host correlation only;
// VM-global seal authority comes from the participant's retained HCS VM.
type realPartitionSealProof struct {
	primary, late *realProof
	probe         *protectedSharedHvProbe
	lateName      string
	before        map[string]protectedSharedHvSnapshot
	after         map[string]protectedSharedHvSnapshot
	targets       map[string]uint64
	closedVMs     map[string]bool
}

// EvidenceError returns sticky diagnostic failures without changing ownership
// or interrupting native cleanup. The underlying evidence writer is synchronized.
func (p *realPartitionSealProof) EvidenceError() error {
	return p.primary.evidence.failure()
}

// openLifetime acquires a genuinely new controller/section into q before any
// later error. No VM is created here. Partial acquisition remains owned for
// cleanup; no inline log-and-free path discards failed-close ownership.
// name is a fresh simple section name; pages and immutable boot policy are in q.
func (p *realPartitionSealProof) openLifetime(q *realProof, name string) error {
	// Reuse the exact existing v2 layout check and API discovery before the
	// primary open; late uses the same matched DLL entry points independently.
	if err := validateProtectedSharedNativeLayout(); err != nil {
		return err
	}
	dll := windows.NewLazySystemDLL("vid.dll")
	create := dll.NewProc("VidCreateProtectedSharedController")
	q.control = dll.NewProc("VidControlProtectedShared")
	if err := create.Find(); err != nil {
		return err
	}
	if err := q.control.Find(); err != nil {
		return err
	}
	handle, _, callErr := create.Call()
	q.controller = windows.Handle(handle)
	if q.controller == 0 || q.controller == windows.InvalidHandle {
		q.controller = 0
		return fmt.Errorf("create partition experiment controller: %v", callErr)
	}
	var err error
	q.section, err = createSharedMemorySection(name, q.pages*4096)
	if err != nil {
		return err
	}
	q.resource = hcsv2.OperationResource{Type: computecore.HcsResourceTypeFile,
		URI: "hcs:/ProtectedShared/" + q.runID, Handle: syscall.Handle(q.controller)}
	q.evidence.record("lifetime", map[string]any{"Section": q.section.hcsName,
		"ControllerURI": q.resource.URI, "Pages": q.pages, "CreatedNow": true})
	return nil
}

// prepareLate converts only A's previously ordinary-hidden slot through None
// Update and the new file capability. It retains the borrowed region/lease and
// any Installed flag before error/context checks. Unknown preparation ownership
// is sticky; a failed action never proves no backing pins. No page is sealed,
// no VM is acquired, and the late owner may never terminate or close A.
func (p *realPartitionSealProof) prepareLate(ctx context.Context) error {
	q := p.late
	a := p.primary.vms["a"]
	if a == nil || a.vm == nil || a.terminated || q.section.hcsName != p.primary.lateSlot {
		return errors.New("late conversion requires the reserved slot in live owned A")
	}
	v := &proofVM{vm: a.vm, region: hcsschema.SharedMemoryRegion{
		SectionName: q.section.hcsName, Length: 4096, AllowGuestWrite: true,
		HiddenFromGuest: true, ProtectedShared: true, ProtectedSharedControllerUri: q.resource.URI,
		ProtectedSharedOperation: hcsschema.ProtectedSharedNone,
	}}
	q.vms["a"] = v
	outcome := v.vm.ModifyProtectedSharedWithOutcome(ctx, v.region, q.resource)
	info := outcome.Receipt
	// Consume usable identity before the action error. A malformed frame
	// cannot certify absence of an owner; any reported mapping stays owned.
	if info != nil && info.Installed {
		v.region.HiddenFromGuest = false
	}
	structureErr := uvm.ValidateProtectedSharedOperationResultStructure(info, 0, 1)
	if structureErr == nil {
		q.lease = info.LeaseId
		v.region.ProtectedSharedLeaseId = q.lease
	}
	q.prepareUncertain = outcome.Dispatched && (outcome.ReceiptError != nil || structureErr != nil ||
		!info.Prepared || info.Removed || info.Installed || !info.OperationResultValid ||
		info.InitializedPages != 0 || info.PagesProcessed != 0)
	err := errors.Join(outcome.ActionError, outcome.ReceiptError, structureErr)
	if err == nil && (!outcome.Dispatched || !info.Prepared || info.Installed || info.Removed ||
		!info.OperationResultValid || info.OperationHresult != 0 || info.OperationStatus != 0 ||
		info.PagesProcessed != 0 || info.InitializedPages != 0) {
		err = errors.New("late conversion lacks a fresh uninitialized preparation receipt")
	}
	q.evidence.record("late-preparation", map[string]any{"Section": v.region.SectionName,
		"LeaseId": q.lease, "Frame": info, "Dispatched": outcome.Dispatched,
		"ActionError": proofErrorText(outcome.ActionError), "ReceiptError": proofErrorText(outcome.ReceiptError),
		"Error": proofErrorText(err), "BorrowedVM": a.vm.ID()})
	if err != nil {
		return err
	}
	v.freshPrepared = true
	// Freshness comes from the newly created section/controller and this
	// controller's actual preparation receipt, not assumed global uniqueness
	// of a numeric lease ID across independent controllers.
	regions, err := v.vm.SharedMemoryRegions(ctx)
	if err != nil {
		return err
	}
	var found *hcsschema.SharedMemoryRegionInfo
	for i := range regions {
		if regions[i].SectionName == v.region.SectionName {
			if found != nil {
				return errors.New("duplicate late section response")
			}
			found = &regions[i]
		}
	}
	if found == nil {
		return errors.New("missing late section response")
	}
	address, err := uvm.SharedMemoryByteGPA(int64(found.GuestPhysicalAddress), 4096)
	if err == nil {
		v.gpn = address / 4096
	}
	return err
}

// discover snapshots root children before the entire prepare boundary or after
// successful preparation, then selects the sole addition with no removals.
// B requires the validated A target in both snapshots and a distinct addition.
// Calls are serialized; owned snapshots/targets are published only on success
// and discarded for this participant on enumeration, selection, context or
// evidence failure. Diagnostics correlate the expected/actual HCS VM with the
// snapshots, not a trusted identity or ownership capability. No VM is acquired
// or released here, so discovery failure cannot discard cleanup ownership.
func (p *realPartitionSealProof) discover(ctx context.Context, id string, after bool) (err error) {
	var snapshot protectedSharedHvSnapshot
	var selected uint64
	vmID, runtimeID := "", ""
	if v := p.primary.vms[id]; v != nil && v.vm != nil {
		vmID, runtimeID = v.vm.ID(), fmt.Sprint(v.vm.RuntimeID())
	}
	defer func() {
		err = errors.Join(err, ctx.Err())
		if err != nil {
			selected = 0
		}
		p.primary.evidence.record("partition-discovery", map[string]any{
			"Participant": id, "ExpectedID": "protected-" + p.primary.runID + "-" + id,
			"ID": vmID, "Runtime": runtimeID, "AfterPrepare": after,
			"Before": p.before[id], "Snapshot": snapshot, "SelectedID": selected,
			"DiagnosticOnly": true, "RequiresQuietIsolatedHost": true,
			"Error": proofErrorText(err),
		})
		err = errors.Join(err, ctx.Err(), p.EvidenceError())
		// Commit diagnostic state only after validation, context and sticky
		// evidence checks. VM cleanup ownership is independent of this state.
		if err != nil {
			delete(p.before, id)
			delete(p.after, id)
			delete(p.targets, id)
		} else if after {
			p.after[id] = snapshot
			p.targets[id] = selected
		} else {
			p.before[id] = snapshot
		}
	}()
	delete(p.targets, id)
	if !after {
		delete(p.before, id)
		delete(p.after, id)
	}
	if id != "a" && id != "b" {
		return errors.New("partition discovery requires participant A or B")
	}
	snapshot, err = p.probe.children(ctx)
	if err != nil {
		return fmt.Errorf("partition discovery %s after-prepare=%t: %w", id, after, err)
	}
	// A is a retained baseline fact for B, not an ordering heuristic. Check
	// even the before phase so a missing A prevents B's acquisition entirely.
	if id == "b" {
		a := p.targets["a"]
		if a == 0 {
			return errors.New("B discovery requires a validated A target")
		}
		if _, retained := snapshot[a]; !retained {
			return errors.New("B discovery snapshot lost known A; require a quiet isolated host")
		}
		if after {
			if _, retained := p.before[id][a]; !retained {
				return errors.New("B discovery baseline lacks known A")
			}
		}
	}
	if !after {
		return nil
	}
	// Only a complete, validated difference supplies GPA diagnostics. Native
	// sealing never consumes this numeric ID or either snapshot.
	selected, err = uniqueProtectedSharedHvAddedChild(p.before[id], snapshot)
	if err != nil {
		return fmt.Errorf("partition discovery %s: %w", id, err)
	}
	if id == "b" && selected == p.targets["a"] {
		return errors.New("partition discovery requires distinct A/B targets")
	}
	return nil
}

// sealPartition submits the participant's VM-global, payload-free seal every
// time, including repeats. It borrows the live owned VM, not region metadata or
// a discovered numeric target. Evidence records the actual operation error and
// repeat distinction, never a cached receipt. Failure/timeout/cancellation does
// not prove that the irreversible native operation had no effect.
func (p *realPartitionSealProof) sealPartition(ctx context.Context, id string, repeat bool) error {
	v := p.primary.vms[id]
	if v == nil || v.vm == nil || v.terminated || p.closedVMs[id] {
		return errors.New("partition seal requires a live owned participant VM")
	}
	err := v.vm.SealPartition(ctx)
	p.primary.evidence.record("partition-seal", map[string]any{
		"Participant": id, "ID": v.vm.ID(), "Runtime": fmt.Sprint(v.vm.RuntimeID()),
		"URI": "hcs:/VirtualMachine/SealPartition", "Repeat": repeat,
		"Error": proofErrorText(err), "ContextError": proofErrorText(ctx.Err()),
		"FailureDoesNotEstablishUnsealed": true,
	})
	return err
}

// probePages performs real HV-copy controls at offset 256 on every primary
// page of id. Positive controls read HOSTKEEP, write/read a distinct known
// VM/page-specific value, restore/read HOSTKEEP, after page locks but before seals.
// Negative reads/BADWRITE accept only the existing exact native policy denial.
// All calls are synchronous with owned VM/driver alive. No returned bytes are
// ever logged, including unexpected successes; comparisons stay in memory.
// Target IDs must have passed the adapter's quiet-host discovery correlation;
// this diagnostic validity does not establish trusted partition identity.
func (p *realPartitionSealProof) probePages(ctx context.Context, id string, negative bool) error {
	q := p.primary
	v := q.vms[id]
	keep := [8]byte{'H', 'O', 'S', 'T', 'K', 'E', 'E', 'P'}
	bad := [8]byte{'B', 'A', 'D', 'W', 'R', 'I', 'T', 'E'}
	for page := uint64(0); page < q.pages; page++ {
		// The bounded page index fits two bytes. Distinct synthetic values
		// exercise each VM/page without ever formatting returned data.
		changed := [8]byte{'H', 'V', 'C', 'P', 'A', byte(page), byte(page >> 8), 0x5a}
		if id == "b" {
			changed[4] = 'B'
		}
		target := protectedSharedHvTarget{partitionID: p.targets[id],
			partitionIDValid: p.targets[id] != 0, pageGPA: (v.gpn + page) * 4096}
		// Each substep records framing/status/validity only, not data. Stop
		// immediately on transport/unrelated failure or unexpected success.
		access := func(phase string, write bool, value [8]byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			var r protectedSharedHvProbeResult
			operation := "HvReadGpa"
			if write {
				operation = "HvWriteGpa"
				r = p.probe.write(target, 256, value)
			} else {
				r = p.probe.read(target, 256)
			}
			var err error
			if negative {
				err = r.requirePolicyDenial()
			} else {
				err = r.requirePositive()
				if err == nil && !write && (!r.dataValid || r.data != value) {
					err = errors.New("HV positive synthetic sentinel mismatch")
				}
			}
			q.evidence.record("hv-copy", map[string]any{
				"Participant": id, "ID": v.vm.ID(), "Runtime": fmt.Sprint(v.vm.RuntimeID()),
				"HypervisorPartitionId": target.partitionID, "Section": v.region.SectionName, "LeaseId": q.lease,
				"Phase": phase, "Negative": negative, "PageIndex": page, "GPA": target.pageGPA + 256,
				"VP": 0, "VTL": 0, "Operation": operation, "Write": write,
				"TransportError": proofErrorText(r.transportError), "TransportStatus": proofWin32Status(r.transportError),
				"NativeStatusValid": r.nativeStatusValid, "NativeStatus": r.nativeStatus,
				"AccessResultValid": r.accessResultValid, "ResultCode": r.resultCode,
				"BytesProcessed": r.bytesProcessed, "DataValid": r.dataValid, "Error": proofErrorText(err),
			})
			return errors.Join(err, ctx.Err(), q.evidence.failure())
		}
		if negative {
			if err := access("post-seal-read", false, [8]byte{}); err != nil {
				return err
			}
			if err := access("post-seal-write", true, bad); err != nil {
				return err
			}
			continue
		}
		for _, control := range []struct {
			phase string
			write bool
			value [8]byte
		}{
			{"pre-seal-read", false, keep}, {"pre-seal-write", true, changed},
			{"pre-seal-readback", false, changed}, {"pre-seal-restore", true, keep},
			{"pre-seal-verify", false, keep},
		} {
			if err := access(control.phase, control.write, control.value); err != nil {
				return err
			}
		}
	}
	return nil
}

// zeroLifetime enables host reads only after every initialized page has a
// trusted reclaim receipt, then checks every initialized byte for zero.
// A mismatch/error returns the verified prefix for diagnostics, never release
// authority. It does not reseed the reclaimed section or inspect protected data.
// ctx bounds new host-read calls using the independent cleanup deadline.
func zeroLifetime(ctx context.Context, q *realProof) (proofResult, error) {
	out := proofResult{}
	if q.section == nil || q.reclaimed != q.initialized || q.initialized == 0 {
		return out, errors.New("zero verification requires a reclaimed initialized lifetime")
	}
	q.section.protected = false
	var zero [4096]byte
	for page := uint64(0); page < q.initialized; page++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		data, err := q.section.read(page*4096, 4096)
		if err != nil {
			return out, err
		}
		if !bytes.Equal(data, zero[:]) {
			return out, fmt.Errorf("reclaimed lifetime not wholly zero on page %d", page)
		}
		out.ZeroVerifiedBytes += 4096
	}
	return out, nil
}

// terminateOwned stops, waits and closes only primary's actually owned VM id.
// The late borrowed pointer is never passed here. Termination and Close have
// separate ledgers so a close failure cannot become a skipped close success.
// Failure retains backing and options; successful objects are never closed twice.
func (p *realPartitionSealProof) terminateOwned(ctx context.Context, id string) error {
	v := p.primary.vms[id]
	if v == nil || v.vm == nil || p.closedVMs[id] {
		return nil
	}
	if !v.terminated {
		if err := v.vm.Terminate(ctx); err != nil {
			return err
		}
		if err := v.vm.WaitCtx(ctx); err != nil {
			return err
		}
		v.terminated = true
	}
	if err := v.vm.CloseCtx(ctx); err != nil {
		return err
	}
	p.closedVMs[id] = true
	return nil
}

// releaseLifetime closes q's controller then section only after the coordinator
// established detach, teardown/reclaim and zero verification (when initialized).
// It additionally checks concrete ownership facts, including A's borrowed late
// region and its actual primary VM close. Partial opens with no attachments need
// no synthetic native receipt. Failed/unknown ownership retains necessary backing.
func (p *realPartitionSealProof) releaseLifetime(q *realProof) error {
	if q.prepareUncertain || q.reclaimed != q.initialized || (q.section != nil && q.section.protected) {
		return errors.New("lifetime release lacks known reclaim/ownership")
	}
	for id, v := range q.vms {
		if v.vm != nil && (!v.removed || !p.closedVMs[id]) {
			return errors.New("lifetime still has an undrained attachment or VM owner")
		}
	}
	if q.controller != 0 {
		if err := windows.CloseHandle(q.controller); err != nil {
			return err
		}
		q.controller = 0
	}
	if q.section != nil {
		if err := q.section.Close(); err != nil {
			return err
		}
	}
	// Only primary holds options/bundles. Late deliberately has none, even
	// though it borrows A's VM, avoiding duplicate boot-file ownership.
	var err error
	for _, v := range q.vms {
		if v.options != nil && v.options.BundleDirectory != "" {
			err = errors.Join(err, os.RemoveAll(v.options.BundleDirectory))
		}
	}
	return err
}

// Run performs one concrete new-mode step and records ownership before returning
// its error. Existing realProof helpers still issue the real VID/HCS/GCS calls;
// no third VM or mocked native protection is introduced. Lifecycle receipts are
// preserved on failure. Driver/backing acquisition and all actions are serialized.
// Discovery brackets the entire existing preparation call, never just Start;
// repeats submit VM-global seals without a region action or receipt query.
// Cleanup steps observe only their supplied independent context, not forward ctx.
func (p *realPartitionSealProof) Run(ctx context.Context, s partitionSealStep) (out partitionSealResult, err error) {
	q := p.primary
	if s.Lifetime == "late" {
		q = p.late
	}
	// Publish acquired owner/lease facts before exposing a step error. The
	// snapshot and diagnostic write cannot erase already retained resources
	// when cancellation or evidence failure accompanies an acquisition.
	defer func() {
		out.DriverOwned = p.probe != nil && p.probe.handle != 0
		if q != nil && s.Lifetime != "" {
			out.BackingOwned = q.controller != 0 || q.section != nil
			out.Uncertain = q.prepareUncertain
			if out.LeaseId == 0 {
				out.LeaseId = q.lease
			}
		}
		if s.Kind == "prepare" {
			v := p.primary.vms[s.Participant]
			out.VMOwned = v != nil && v.vm != nil
		}
		p.primary.evidence.record("partition-phase", struct {
			Step         partitionSealStep
			Result       partitionSealResult
			Error        string
			ContextError string
		}{s, out, proofErrorText(err), proofErrorText(ctx.Err())})
	}()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	switch s.Kind {
	case "driver":
		p.probe, err = openProtectedSharedHvProbe()
		if err != nil {
			return out, err
		}
		p.before = make(map[string]protectedSharedHvSnapshot)
		p.after = make(map[string]protectedSharedHvSnapshot)
		p.targets = make(map[string]uint64)
		p.closedVMs = make(map[string]bool)
		p.lateName = "protected-" + p.primary.runID + "-late"
		var sessionID uint32
		if err = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID); err != nil {
			return out, err
		}
		_, p.primary.lateSlot, err = sharedMemorySectionNames(p.lateName, sessionID)
	case "open":
		name := "protected-" + p.primary.runID
		if s.Lifetime == "late" {
			p.late = &realProof{evidence: p.primary.evidence, cli: p.primary.cli, snp: p.primary.snp,
				pages: 1, runID: p.primary.runID + "-late", vms: make(map[string]*proofVM)}
			q, name = p.late, p.lateName
		}
		err = p.openLifetime(q, name)
	case "seed":
		err = q.hostProbe(false)
	case "snapshot-before", "snapshot-after":
		err = p.discover(ctx, s.Participant, s.Kind == "snapshot-after")
	case "prepare":
		err = q.prepare(ctx, s.Participant)
		v := q.vms[s.Participant]
		if v != nil && v.vm != nil && !v.freshPrepared {
			q.prepareUncertain = true
		}
	case "initialize", "seal", "teardown", "reclaim":
		out.ControlAttempted = true
		out.proofResult, err = q.Run(ctx, s.proofStep)
	case "install":
		// Retain actual Installed ownership first, even on a malformed
		// observation. Unknown mapping ownership is sticky for this mode;
		// a failed receipt is never substituted with zero mapping progress.
		outcome := q.attemptInstall(ctx, s.Participant)
		info := outcome.Receipt
		structureErr := uvm.ValidateProtectedSharedOperationResultStructure(info, q.lease, q.pages)
		if outcome.ReceiptError != nil || structureErr != nil {
			q.prepareUncertain = true
		}
		err = errors.Join(outcome.ActionError, outcome.ReceiptError,
			uvm.ValidateProtectedSharedOperationResult(info, q.lease, q.pages))
		if err == nil && (!outcome.Dispatched || !info.Installed || !info.Prepared || info.Removed ||
			info.OperationResultValid || info.OperationHresult != 0) {
			err = errors.New("incomplete primary installation ownership")
		}
		q.evidence.record("worker", map[string]any{"Participant": s.Participant,
			"Frame": info, "ActionError": proofErrorText(outcome.ActionError),
			"ReceiptError": proofErrorText(outcome.ReceiptError), "Error": proofErrorText(err)})
	case "hv-positive", "hv-negative":
		err = p.probePages(ctx, s.Participant, s.Kind == "hv-negative")
	case "partition-seal", "partition-seal-repeat":
		err = p.sealPartition(ctx, s.Participant, s.Kind == "partition-seal-repeat")
	case "late-prepare":
		err = p.prepareLate(ctx)
	case "late-install-denial":
		v := q.vms["a"]
		outcome := q.attemptInstall(ctx, "a")
		// attemptInstall consumes even a malformed Installed flag first.
		// An unexpected mapping cannot be hidden behind another error.
		if outcome.ReceiptError != nil ||
			uvm.ValidateProtectedSharedOperationResultStructure(outcome.Receipt, q.lease, 1) != nil {
			q.prepareUncertain = true
		}
		err = validatePostSealInstallDenial(outcome, q.lease, 1, ctx.Err())
		if !v.region.HiddenFromGuest || (outcome.Receipt != nil && outcome.Receipt.Installed) {
			err = errors.Join(err, errors.New("fresh late region unexpectedly installed"))
		}
		q.evidence.record("late-install-denial", map[string]any{"ID": v.vm.ID(),
			"Runtime": fmt.Sprint(v.vm.RuntimeID()), "Section": v.region.SectionName,
			"LeaseId": q.lease, "PageCount": 1, "GPA": v.gpn * 4096,
			"Operation": hcsschema.ProtectedSharedInstall, "Dispatched": outcome.Dispatched,
			"Frame": outcome.Receipt, "ActionError": proofErrorText(outcome.ActionError),
			"ReceiptError": proofErrorText(outcome.ReceiptError), "ExpectedDenied": err == nil,
			"LocalHiddenFromGuest": v.region.HiddenFromGuest, "Error": proofErrorText(err)})
	case "exchange":
		err = p.primary.exchange(ctx)
	case "remove":
		v := q.vms[s.Participant]
		if v != nil && v.vm != nil && !v.removed && v.region.ProtectedSharedLeaseId == 0 {
			err = errors.New("cannot explicitly remove unknown prepared ownership")
		} else {
			out.proofResult, err = q.Run(ctx, s.proofStep)
		}
	case "terminate":
		err = p.terminateOwned(ctx, s.Participant)
	case "zero":
		out.proofResult, err = zeroLifetime(ctx, q)
	case "release":
		// A framed zero-prefix initialization still disables ordinary host
		// reads. Only established zero work and detached owners permit release.
		if q.initialized == 0 && !q.prepareUncertain && q.section != nil {
			q.section.protected = false
		}
		err = p.releaseLifetime(q)
	case "close-driver":
		err = p.probe.Close()
	default:
		err = fmt.Errorf("unknown partition-seal step %q", s.Kind)
	}
	return out, err
}
