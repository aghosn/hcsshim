//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"golang.org/x/sys/windows"
)

const (
	hostSource   = "21a1d2ec9aa4d8a5c33ec1a15a2f513546969ab8"
	nativeSource = "9079ddd2cce7476ad9aa538a4525fe9116e7eaa2"
)

const help = `sealtest-host: Windows AMD64 lab diagnostic (elevated; matching hvtest required)
  inventory [--session FILE [--case CASE ... --phase before|after]]
  prepare --session FILE --partition-id ID --case CASE --confirm-workload --host-build ID --native-build ID
          [--fixtures V2_EXPORT | --generation ID --guest-build ID] [case options]
  probe --session FILE --case CASE --phase before|after [case selectors]
        [--expected-mask MASK --seal-receipt EVIDENCE_ID (after only)]
  cleanup --session FILE --case CASE --phase before|after [case selectors]

Cases: map-contiguous, map-sparse, parent-visibility-share,
  parent-visibility-private, parent-ghcb-map (--cpu VP),
  create-port, connect-workload-receiver, connect-workload-sender
  (each requires --port-type event|message).

Prepare BOTH phases before the seal; phase always describes later execution.
Map/visibility require --fixtures. Other preparations record --generation and --guest-build.
Use --host-build and --native-build to record the actual CLI and matching driver/HV build receipts.
Port preparation requires --port-id, --sint and --port-vp, plus --event-base
for event. Create-port also needs --after-port-id. Connect cases instead need
--connection-id and --after-connection-id. Use only reserved diagnostic IDs
and known unused routes; --confirm-workload confirms the explicit association
on a quiet disposable host, not attested identity.

Run the before control and clean up its owned mapping/alias/port/connection
before sealing. The receiving fixture for a connect case is kept until its
after probe. Select a GHCB VP from live inventory; an existing parent alias
is not a control. Record the seal command's successful native completion separately.
An expected mask and receipt label are correlation, not an independent query.
Release applies to safe host backing only. Guest reservations are never reclaimed.
Do not retry uncertain calls; stop both sides. If the driver loses retained
uncertain state, reboot the host before another allocator run.
`

type options struct {
	command, session, phase                                  string
	sel                                                      selection
	partition                                                uint64
	fixtures, generation, hostBuild, nativeBuild, guestBuild string
	confirm                                                  bool
	mask                                                     uint32
	receipt                                                  string
	port                                                     portSpec
}

// valid restricts Port/ConnectionId to unscoped diagnostic IDs and v1 bounded routes.
func (p portSpec) valid(s selection) bool {
	if s.bits() != 8 {
		return p == (portSpec{})
	}
	goodID := func(id uint32) bool { return id > 0 && id < 0xffffff }
	if p.SINT == 0 || p.SINT >= 16 || p.VP >= 2048 || !goodID(p.Port[0]) ||
		(s.PortType == "event" && p.EventBase >= 2048) ||
		(s.PortType == "message" && p.EventBase != 0) {
		return false
	}
	if s.Case == createPort {
		return goodID(p.Port[1]) && p.Port[1] != p.Port[0] && p.Connection == ([2]uint32{})
	}
	return p.Port[1] == 0 && goodID(p.Connection[0]) && goodID(p.Connection[1]) &&
		p.Connection[0] != p.Connection[1]
}

// parse rejects selectors and misplaced or incomplete arguments before any
// session or device can be opened.
func parse(args []string) (options, error) {
	o := options{sel: selection{CPU: -1}}
	if len(args) == 0 {
		return o, errors.New("missing command")
	}
	o.command = args[0]
	f := flag.NewFlagSet(o.command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.session, "session", "", "session journal")
	f.StringVar(&o.sel.Case, "case", "", "one catalogue case")
	f.IntVar(&o.sel.CPU, "cpu", -1, "GHCB VP index")
	f.StringVar(&o.sel.PortType, "port-type", "", "event or message")
	var mask, port, afterPort, conn, afterConn, sint, vp, base uint
	switch o.command {
	case "inventory", "probe", "cleanup":
		f.StringVar(&o.phase, "phase", "", "before or after")
		if o.command == "probe" {
			f.UintVar(&mask, "expected-mask", 0, "observed seal mask")
			f.StringVar(&o.receipt, "seal-receipt", "", "successful native completion evidence label")
		}
	case "prepare":
		f.Uint64Var(&o.partition, "partition-id", 0, "explicit diagnostic child ID")
		f.StringVar(&o.fixtures, "fixtures", "", "guest v2 export")
		f.StringVar(&o.generation, "generation", "", "guest generation")
		f.StringVar(&o.hostBuild, "host-build", "", "matched host build identifier")
		f.StringVar(&o.nativeBuild, "native-build", "", "matched native driver/HV build evidence identifier")
		f.StringVar(&o.guestBuild, "guest-build", "", "matched guest build identifier")
		f.BoolVar(&o.confirm, "confirm-workload", false, "confirm disposable workload association")
		f.UintVar(&port, "port-id", 0, "reserved receiving port")
		f.UintVar(&afterPort, "after-port-id", 0, "reserved create-port after ID")
		f.UintVar(&conn, "connection-id", 0, "reserved before connection")
		f.UintVar(&afterConn, "after-connection-id", 0, "reserved after connection")
		f.UintVar(&sint, "sint", 0, "reserved target SINT")
		f.UintVar(&vp, "port-vp", 0, "selected receiving VP")
		f.UintVar(&base, "event-base", 0, "reserved event flag")
	default:
		return o, fmt.Errorf("unknown command %q", o.command)
	}
	if err := f.Parse(args[1:]); err != nil {
		return o, err
	}
	seen := map[string]bool{}
	f.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	if f.NArg() != 0 {
		return o, errors.New("unexpected positional arguments")
	}
	if o.command == "inventory" && o.sel.Case == "" {
		if seen["case"] || seen["phase"] || seen["port-type"] || seen["cpu"] || (seen["session"] && o.session == "") {
			return o, errors.New("inventory selectors require a mapping case, session and phase")
		}
		return o, nil
	}
	if o.session == "" || !o.sel.valid() ||
		seen["cpu"] != (o.sel.Case == ghcbMap) ||
		seen["port-type"] != (o.sel.bits() == 8) {
		return o, errors.New("require --session and one valid --case with only its applicable selectors")
	}
	if o.command != "prepare" {
		if o.phase != "before" && o.phase != "after" {
			return o, errors.New("require --phase before or after")
		}
		if o.command == "inventory" && o.sel.bits() != 1 {
			return o, errors.New("selected inventory query requires a mapping case")
		}
		if o.command == "probe" && o.phase == "after" {
			if mask == 0 || mask&^0x2f != 0 || mask&uint(o.sel.bits()) == 0 || !label(o.receipt) {
				return o, errors.New("after probe requires a valid expected mask containing the case bit and a successful seal receipt label")
			}
			o.mask = uint32(mask)
		} else if seen["expected-mask"] || seen["seal-receipt"] {
			return o, errors.New("mask and seal receipt are only valid for an after probe")
		}
		return o, nil
	}
	if o.partition == 0 || o.partition == self || !label(o.hostBuild) || !label(o.nativeBuild) || !o.confirm {
		return o, errors.New("prepare requires explicit child, --host-build, --native-build and --confirm-workload")
	}
	if o.sel.bits() <= 2 {
		if o.fixtures == "" || seen["generation"] || seen["guest-build"] {
			return o, errors.New("map and visibility preparation require --fixtures with embedded generation/build")
		}
	} else if seen["fixtures"] || !label(o.generation) || !label(o.guestBuild) {
		return o, errors.New("non-page preparation requires --generation and --guest-build")
	}
	portFlags := []string{"port-id", "after-port-id", "connection-id", "after-connection-id", "sint", "port-vp", "event-base"}
	for _, name := range portFlags {
		required := false
		if o.sel.bits() == 8 {
			switch name {
			case "after-port-id":
				required = o.sel.Case == createPort
			case "connection-id", "after-connection-id":
				required = o.sel.Case != createPort
			case "event-base":
				required = o.sel.PortType == "event"
			default:
				required = true
			}
		}
		if seen[name] != required {
			return o, fmt.Errorf("missing or inapplicable --%s", name)
		}
	}
	for _, n := range []uint{port, afterPort, conn, afterConn, sint, vp, base} {
		if n > 0xffffff {
			return o, errors.New("port field out of range")
		}
	}
	o.port = portSpec{[2]uint32{uint32(port), uint32(afterPort)}, [2]uint32{uint32(conn), uint32(afterConn)}, uint32(sint), uint32(vp), uint32(base)}
	if !o.port.valid(o.sel) {
		return o, errors.New("invalid or reused port/connection selectors")
	}
	return o, nil
}

// endpoints places the workload at the selected role; self is never supplied
// by the operator. Both connect directions use the same validated ownership path.
func endpoints(s selection, partition uint64) (receiving, sending uint64) {
	if s.Case == connectSender {
		return self, partition
	}
	return partition, self
}

// portTypeCode maps vetted event/message selectors to the native discriminant.
func portTypeCode(s selection) uint32 {
	if s.PortType == "event" {
		return 2
	}
	return 1
}

// portInput encodes HV_INPUT_CREATE_PORT for the reserved diagnostic port.
// The VTL and proximity fields remain zero (VTL0 and no preference).
func portInput(p *prepared, receiving, sending uint64, port uint32) []byte {
	input := make([]byte, 56)
	le.PutUint64(input, receiving)
	le.PutUint32(input[8:], port)
	le.PutUint64(input[16:], sending)
	le.PutUint32(input[24:], portTypeCode(p.Selection))
	le.PutUint32(input[32:], p.Port.SINT)
	le.PutUint32(input[36:], p.Port.VP)
	if p.Selection.PortType == "event" {
		le.PutUint16(input[40:], uint16(p.Port.EventBase))
		le.PutUint16(input[42:], 1)
	}
	return input
}

// portCollides reserves separate object IDs and routes among prepared cases.
// The operator is responsible for collision-free use outside this journal.
func portCollides(a, b *prepared, partition uint64) bool {
	if a.Selection.bits() != 8 || b.Selection.bits() != 8 {
		return false
	}
	ar, as := endpoints(a.Selection, partition)
	br, bs := endpoints(b.Selection, partition)
	if ar == br {
		for _, x := range a.Port.Port {
			for _, y := range b.Port.Port {
				if x != 0 && x == y {
					return true
				}
			}
		}
		if a.Port.SINT == b.Port.SINT && a.Port.VP == b.Port.VP &&
			(a.Selection.PortType == "message" || b.Selection.PortType == "message" || a.Port.EventBase == b.Port.EventBase) {
			return true
		}
	}
	if as == bs {
		for _, x := range a.Port.Connection {
			for _, y := range b.Port.Connection {
				if x != 0 && x == y {
					return true
				}
			}
		}
	}
	return false
}

// rawStep journals one closed raw request and preserves its native observation
// separately from framing. Ownership updates are committed with its verdict.
func rawStep(d device, j *journal, p *prepared, phase, op string, page *uint32, code uint32, input []byte, count uint32,
	kind string, evaluate func(observation) (string, error)) error {
	if err := d.activeChild(j.Partition); err != nil {
		return j.stop(fmt.Errorf("workload membership or state could not be revalidated: %w", err))
	}
	return j.mutate(p.Selection, phase, op, page, func(a *attempt) (string, error) {
		o, err := d.raw(code, input, count, kind)
		a.Raw = &o
		if err != nil {
			return "inconclusive", err
		}
		return evaluate(o)
	})
}

// fullSuccess requires complete progress for REP, without manufacturing a
// progress observation for a non-REP request.
func fullSuccess(o observation) bool {
	return o.FrameValid && o.Status != nil && *o.Status == 0 && (o.Requested == 0 ||
		(o.Progress != nil && *o.Progress == o.Requested))
}

// requireSuccess never treats a native resource or authority failure as a control.
func requireSuccess(o observation) error {
	if !fullSuccess(o) {
		if !o.FrameValid || o.Status == nil {
			return fmt.Errorf("native prerequisite has no valid status: call=%#x", o.Call)
		}
		return fmt.Errorf("native prerequisite failed: call=%#x status=%#x (see result for REP progress)", o.Call, *o.Status)
	}
	return nil
}

// prepare records the pair once, with separate intents for backing, vacancy,
// and the one receiving fixture needed by each connection case.
func prepare(d device, j *journal, p *prepared) error {
	if p.Selection.bits() == 1 {
		for i := range p.Phase {
			ph := &p.Phase[i]
			if err := j.mutate(p.Selection, phaseName(i), "allocate", nil, func(a *attempt) (string, error) {
				r, wire, err := d.backing(opAllocate, 0, *ph.Backing)
				a.HelperWire = &wire
				if err != nil {
					return "inconclusive", err
				}
				a.Backing = &r
				ph.Backing = &r.binding
				ph.rememberBacking(r)
				return "allocated", nil
			}); err != nil {
				return err
			}
		}
		for i := range p.Phase {
			ph := &p.Phase[i]
			for k, gpa := range ph.Fixture.GPAs {
				index := uint32(k)
				if err := rawStep(d, j, p, phaseName(i), "vacate-target", &index, callUnmap, unmapInput(j.Partition, gpa), 1, "",
					func(o observation) (string, error) {
						if err := requireSuccess(o); err != nil {
							return "inconclusive", err
						}
						ph.Holes |= 1 << index
						return "target-vacant", nil
					}); err != nil {
					return err
				}
			}
		}
	}
	if p.Selection.Case == connectReceiver || p.Selection.Case == connectSender {
		receiver, sender := endpoints(p.Selection, j.Partition)
		if err := rawStep(d, j, p, "prepare", "create-receiving-fixture", nil, callCreatePort, portInput(p, receiver, sender, p.Port.Port[0]), 0, "",
			func(o observation) (string, error) {
				if err := requireSuccess(o); err != nil {
					return "inconclusive", err
				}
				p.ReceivingOwned = true
				return "owned-receiving-fixture", nil
			}); err != nil {
			return err
		}
	}
	p.Complete = true
	return j.commit()
}

// queryBacking verifies the authoritative binding and state against the
// journal before a mutation. A missing or changed record stops the session.
func queryBacking(d device, j *journal, ph *phaseRecord) (backingReply, error) {
	q, _, err := d.backing(opQuery, 0, *ph.Backing)
	if err != nil {
		return q, j.stop(fmt.Errorf("could not revalidate recorded backing: %w", err))
	}
	if q.State != ph.BackingState || q.Sequence != ph.Sequence || q.Known != ph.Known || q.Maybe != ph.Maybe {
		return q, j.stop(errors.New("backing state changed outside the session"))
	}
	return q, nil
}

// mapProbe requires the exact still-ready driver binding, never a new allocation.
func mapProbe(d device, j *journal, p *prepared, index int) error {
	ph := &p.Phase[index]
	q, err := queryBacking(d, j, ph)
	if err != nil {
		return err
	}
	if q.State != stateReady {
		return j.stop(errors.New("mapping backing is no longer ready"))
	}
	return j.mutate(p.Selection, phaseName(index), "map", nil, func(a *attempt) (string, error) {
		r, wire, err := d.backing(opMap, 0, *ph.Backing)
		a.HelperWire = &wire
		if err != nil {
			return "inconclusive", err
		}
		a.Backing = &r
		ph.Consumed = true
		ph.rememberBacking(r)
		if index == 0 && r.State == stateMapped {
			ph.Control = true
			return "expected-success", nil
		}
		if r.State == stateNoEffect {
			if index == 1 {
				return "seal-denied", nil
			}
			return "rejection-observed", errControlDenied
		}
		if index == 1 && fullSuccess(r.Native) {
			return "unexpected-success", errors.New("after mapping accepted; backing quarantined")
		}
		return "inconclusive", errors.New("mapping did not establish the required control or denial; backing quarantined")
	})
}

// ghcbInput encodes the HvVpApi.h map/unmap layouts, selecting explicit VTL0
// without supplying a parent mapping location.
func ghcbInput(partition uint64, cpu int, mapPage bool) []byte {
	n := 16
	if mapPage {
		n = 24
	}
	input := make([]byte, n)
	le.PutUint64(input, partition)
	le.PutUint32(input[8:], uint32(cpu))
	le.PutUint16(input[12:], 2)
	input[14] = 0x10 // UseTargetVtl=1, TargetVtl=0.
	return input
}

// probe dispatches one catalogue operation. An owned resource is published
// only for a successful before result with all required observations.
func probe(d device, j *journal, p *prepared, i int) error {
	if p.Selection.bits() == 1 {
		return mapProbe(d, j, p, i)
	}
	ph := &p.Phase[i]
	var input []byte
	var code, count uint32
	var kind string
	rcv, snd := endpoints(p.Selection, j.Partition)
	switch p.Selection.Case {
	case visibilityShare, visibilityPrivate:
		code, count = callVisibility, 1
		input = make([]byte, 24)
		le.PutUint64(input, j.Partition)
		if p.Selection.Case == visibilityShare {
			le.PutUint32(input[8:], 3)
		}
		le.PutUint64(input[16:], ph.Fixture.GPAs[0]/pageSize)
	case ghcbMap:
		code, kind = callMapGHCB, "parent-map-location-page"
		input = ghcbInput(j.Partition, p.Selection.CPU, true)
	case createPort:
		code, input = callCreatePort, portInput(p, rcv, snd, p.Port.Port[i])
	case connectReceiver, connectSender:
		code, input = callConnect, make([]byte, 72)
		le.PutUint64(input, snd)
		le.PutUint32(input[8:], p.Port.Connection[i])
		le.PutUint64(input[16:], rcv)
		le.PutUint32(input[24:], p.Port.Port[0])
		le.PutUint32(input[32:], portTypeCode(p.Selection))
	default:
		return errors.New("invalid probe case")
	}
	return rawStep(d, j, p, phaseName(i), "probe", nil, code, input, count, kind, func(o observation) (string, error) {
		ph.Consumed = true
		if i == 1 {
			if *o.Status == 0 {
				return "unexpected-success", errors.New("after request accepted; no rollback attempted")
			}
			if *o.Status == statusDenied && (count == 0 || *o.Progress == 0) && !o.OutputValid {
				return "seal-denied", nil
			}
			return "inconclusive", errors.New("after request did not produce the required denial")
		}
		if err := requireSuccess(o); err != nil {
			return "inconclusive", err
		}
		if kind != "" && !o.OutputValid {
			return "inconclusive", errors.New("missing or invalid parent alias location after native success")
		}
		ph.Control, ph.Owned, ph.Clean = true, p.Selection.bits() >= 4, p.Selection.bits() == 2
		return "expected-success", nil
	})
}

// cleanupBacking consults the driver before changing anything. It cannot
// reclaim guest reservations, stale bindings or an uncertain mapping.
func cleanupBacking(d device, j *journal, p *prepared, index int) error {
	ph := &p.Phase[index]
	r, err := queryBacking(d, j, ph)
	if err != nil {
		return err
	}
	if r.State == stateQuarantined {
		return errors.New("mapping state changed or is quarantined; no cleanup authorized")
	}
	for page := uint32(0); page < 2; page++ {
		if r.Known&(1<<page) == 0 {
			continue
		}
		if index != 0 || !ph.Control || r.State != stateMapped {
			return errors.New("not an owned before-control mapping")
		}
		if err := j.mutate(p.Selection, phaseName(index), "unmap-owned", &page, func(a *attempt) (string, error) {
			next, wire, err := d.backing(opUnmap, page, *ph.Backing)
			a.HelperWire = &wire
			if err != nil {
				return "inconclusive", err
			}
			a.Backing = &next
			ph.rememberBacking(next)
			if (next.State != stateMapped && next.State != stateUnmapped) ||
				next.Known != r.Known&^(1<<page) || next.Sequence != r.Sequence+1 {
				return "inconclusive", errors.New("owned unmap did not prove synchronized removal")
			}
			r = next
			return "owned-page-unmapped", nil
		}); err != nil {
			return err
		}
	}
	if r.State != stateReady && r.State != stateUnmapped && r.State != stateNoEffect {
		return errors.New("native state does not authorize release")
	}
	return j.mutate(p.Selection, phaseName(index), "release", nil, func(a *attempt) (string, error) {
		released, wire, err := d.backing(opRelease, 0, *ph.Backing)
		a.HelperWire = &wire
		if err != nil {
			return "inconclusive", err
		}
		a.Backing = &released
		if released.Sequence != r.Sequence {
			return "inconclusive", errors.New("release reply changed the recorded native attempt")
		}
		ph.rememberBacking(released)
		ph.Clean = true
		return "backing-released", nil
	})
}

// objectInput supplies the exact recorded partition and object ID for cleanup.
func objectInput(partition uint64, id uint32) []byte {
	input := make([]byte, 16)
	le.PutUint64(input, partition)
	le.PutUint32(input[8:], id)
	return input
}

// cleanup removes only recorded ownership. No action reverts visibility or
// restores a guest page. The connect fixture outlives the before connection.
func cleanup(d device, j *journal, p *prepared, i int) error {
	if p.Selection.bits() == 1 {
		return cleanupBacking(d, j, p, i)
	}
	ph := &p.Phase[i]
	r, s := endpoints(p.Selection, j.Partition)
	var code uint32
	var input []byte
	if i == 1 {
		if !p.ReceivingOwned || !ph.Consumed {
			return errors.New("no recorded after-phase receiving fixture to delete")
		}
		code, input = callDeletePort, objectInput(r, p.Port.Port[0])
	} else {
		if !ph.Owned || !ph.Control || ph.Clean {
			return errors.New("no recorded before-phase object to clean up")
		}
		switch p.Selection.Case {
		case ghcbMap:
			code, input = callUnmapGHCB, ghcbInput(j.Partition, p.Selection.CPU, false)
		case createPort:
			code, input = callDeletePort, objectInput(r, p.Port.Port[0])
		case connectSender, connectReceiver:
			code, input = callDisconnect, objectInput(s, p.Port.Connection[0])
		default:
			return errors.New("no cleanup for selected case")
		}
	}
	return rawStep(d, j, p, phaseName(i), "cleanup-owned", nil, code, input, 0, "", func(o observation) (string, error) {
		if err := requireSuccess(o); err != nil {
			return "inconclusive", err
		}
		if i == 1 {
			p.ReceivingOwned = false
		}
		ph.Owned, ph.Clean = false, true
		return "owned-resource-removed", nil
	})
}

// inventory never allocates backing or dispatches a resource admission call.
// Selected mapping records are queried even when the journal has tainted intent.
func inventory(d device, j *journal, o options, i int) error {
	caps, wire, err := d.backing(opCapabilities, 0, binding{})
	if err != nil {
		return err
	}
	children, err := d.children()
	if err != nil {
		return err
	}
	sort.Slice(children, func(i, j int) bool { return children[i] < children[j] })
	out := map[string]any{"children": children, "capabilities": caps, "backing_utility_wire": wire,
		"host_source_base": hostSource, "native_source_base": nativeSource}
	if j != nil {
		out["session"] = &j.sessionData
		if o.sel.Case != "" {
			p := j.Cases[o.sel.key()]
			r, queryWire, queryErr := d.backing(opQuery, 0, *p.Phase[i].Backing)
			out["query_utility_wire"] = queryWire
			if queryErr == nil {
				out["recorded_backing"] = r
			} else {
				out["query_error"] = queryErr.Error()
				err = queryErr
			}
		}
	}
	return errors.Join(err, json.NewEncoder(os.Stdout).Encode(out))
}

// run resolves all local prerequisites before opening hvtest. It never
// creates, seals or silently selects a VM, and never resumes interrupted writes.
func run(o options) error {
	if err := requireHost(); err != nil {
		return err
	}
	var j *journal
	var p *prepared
	i := 0
	if o.phase == "after" {
		i = 1
	}
	var pair [2]*guestFixture
	if o.command == "prepare" && o.fixtures != "" {
		x, fixtures, err := loadFixtures(o.fixtures, o.sel.Case)
		if err != nil {
			return err
		}
		o.generation, o.guestBuild, pair = x.Generation, x.GuestBuild, fixtures
	}
	if o.session != "" {
		var err error
		j, err = openJournal(o.session, o.command == "prepare", o.command == "inventory")
		if err != nil {
			return fmt.Errorf("session: %w", err)
		}
		defer j.file.Close()
		if o.command != "inventory" && j.Tainted {
			return errors.New("session has uncertain effects; stop both sides, inventory only")
		}
		p = j.Cases[o.sel.key()]
		switch o.command {
		case "prepare":
			if j.Schema == 0 {
				j.sessionData = sessionData{Schema: schemaVersion, Partition: o.partition, Generation: o.generation,
					HostBuild: o.hostBuild, NativeBuild: o.nativeBuild, GuestBuild: o.guestBuild, Cases: map[string]*prepared{}}
			}
			if j.Partition != o.partition || j.Generation != o.generation ||
				j.HostBuild != o.hostBuild || j.NativeBuild != o.nativeBuild || j.GuestBuild != o.guestBuild || p != nil || j.Mask != 0 {
				return errors.New("session identity mismatch, already prepared case, or after phase started")
			}
			p = &prepared{Selection: o.sel, Port: o.port}
			for _, existing := range j.Cases {
				if portCollides(existing, p, j.Partition) {
					return errors.New("port, route or connection already reserved")
				}
				for _, old := range existing.Phase {
					if old.Fixture == nil {
						continue
					}
					for _, fresh := range pair {
						if fresh == nil {
							continue
						}
						if old.Fixture.ID == fresh.ID {
							return errors.New("fixture ID already used")
						}
						for _, a := range old.Fixture.GPAs {
							for _, b := range fresh.GPAs {
								if a == b {
									return errors.New("fixture GPA already used")
								}
							}
						}
					}
				}
			}
			for index := range p.Phase {
				p.Phase[index].Fixture = pair[index]
			}
		case "probe", "cleanup":
			if p == nil || !p.Complete {
				return errors.New("missing complete preparation for selected case")
			}
			if o.command == "probe" {
				if p.Phase[i].Consumed || p.Phase[i].Clean {
					return errors.New("phase is already consumed or cleaned")
				}
				if i == 1 && (!p.Phase[0].Control || !p.Phase[0].Clean ||
					(p.Selection.bits() == 1 && p.Phase[0].BackingState != stateReleased)) {
					return errors.New("after requires a successful matching before control and completed cleanup")
				}
				if (i == 0 && j.Mask != 0) ||
					(i == 1 && j.Mask != 0 && (o.mask != j.Mask || o.receipt != j.SealReceipt)) {
					return errors.New("phase or seal receipt conflicts with the session")
				}
				if (p.Selection.Case == connectSender || p.Selection.Case == connectReceiver) && !p.ReceivingOwned {
					return errors.New("missing owned receiving fixture")
				}
			} else if p.Phase[i].Clean || (p.Selection.bits() != 1 &&
				(i == 0 && !p.Phase[i].Owned || i == 1 && (!p.ReceivingOwned || !p.Phase[i].Consumed))) {
				return errors.New("no eligible resource to clean up")
			}
		case "inventory":
			if o.sel.Case != "" && (p == nil || p.Phase[i].Backing == nil) {
				return errors.New("missing selected mapping binding")
			}
		}
	}
	d, err := openDevice()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(windows.Handle(d))
	if o.command == "inventory" {
		return inventory(d, j, o, i)
	}
	if err := d.activeChild(j.Partition); err != nil {
		return j.stop(fmt.Errorf("workload membership or state could not be revalidated: %w", err))
	}
	switch o.command {
	case "prepare":
		if p.Selection.bits() == 1 {
			caps, _, err := d.backing(opCapabilities, 0, binding{})
			if err != nil {
				return err
			}
			if j.Instance != ([16]byte{}) && j.Instance != caps.Instance {
				return j.stop(errors.New("backing driver instance changed"))
			}
			if caps.Used > 4 {
				return errors.New("need four free host backing pages in the matching driver instance")
			}
			j.Instance = caps.Instance
			for index := range p.Phase {
				b := j.bindFixture(p.Phase[index].Fixture)
				p.Phase[index].Backing = &b
			}
		}
		j.Cases[p.Selection.key()] = p
		if err := j.validate(); err != nil {
			return err
		}
		if err := j.commit(); err != nil {
			return err
		}
		return prepare(d, j, p)
	case "probe":
		if i == 1 {
			j.Mask, j.SealReceipt = o.mask, o.receipt
		}
		return probe(d, j, p, i)
	case "cleanup":
		return cleanup(d, j, p, i)
	}
	return errors.New("invalid command")
}

// main exits before opening a device on help or argument validation failures.
func main() {
	o, err := parse(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) || (len(os.Args) == 2 && (os.Args[1] == "--help" || os.Args[1] == "-h")) {
		fmt.Print(help)
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprint(os.Stderr, help)
		os.Exit(2)
	}
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
