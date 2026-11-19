//go:build windows

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

const schemaVersion = 2
const maxJournal = 8 << 20

const (
	mapContiguous     = "map-contiguous"
	mapSparse         = "map-sparse"
	visibilityShare   = "parent-visibility-share"
	visibilityPrivate = "parent-visibility-private"
	ghcbMap           = "parent-ghcb-map"
	createPort        = "create-port"
	connectReceiver   = "connect-workload-receiver"
	connectSender     = "connect-workload-sender"
)

type selection struct {
	Case     string `json:"case"`
	CPU      int    `json:"cpu"`
	PortType string `json:"port_type,omitempty"`
}

// bits maps the closed host catalogue to the one relevant seal group.
func (s selection) bits() uint32 {
	switch s.Case {
	case mapContiguous, mapSparse:
		return 1
	case visibilityShare, visibilityPrivate:
		return 2
	case ghcbMap:
		return 4
	case createPort, connectReceiver, connectSender:
		return 8
	}
	return 0
}

// valid keeps CPU and port selectors out of unrelated calls.
func (s selection) valid() bool {
	if s.bits() == 0 {
		return false
	}
	if s.Case == ghcbMap {
		return s.CPU >= 0 && s.CPU < 2048 && s.PortType == ""
	}
	if s.bits() == 8 {
		return s.CPU == -1 && (s.PortType == "event" || s.PortType == "message")
	}
	return s.CPU == -1 && s.PortType == ""
}

// key distinguishes controls that must not qualify one another.
func (s selection) key() string {
	return fmt.Sprintf("%s/%d/%s", s.Case, s.CPU, s.PortType)
}

type guestFixture struct {
	ID           string   `json:"id"`
	Case         string   `json:"case"`
	Phase        string   `json:"phase"`
	Purpose      string   `json:"purpose"`
	InitialState string   `json:"initial_state"`
	GPAs         []uint64 `json:"gpas"`
}

type fixtureExport struct {
	Schema     uint32         `json:"schema_version"`
	Generation string         `json:"generation"`
	GuestBuild string         `json:"guest_build"`
	Fixtures   []guestFixture `json:"fixtures"`
}

type portSpec struct {
	Port       [2]uint32 `json:"port_ids"`
	Connection [2]uint32 `json:"connection_ids"`
	SINT       uint32    `json:"sint"`
	VP         uint32    `json:"vp"`
	EventBase  uint32    `json:"event_base"`
}

type phaseRecord struct {
	Fixture      *guestFixture `json:"fixture,omitempty"`
	Backing      *binding      `json:"backing,omitempty"`
	BackingState uint32        `json:"backing_state,omitempty"`
	Holes        uint32        `json:"vacant_mask,omitempty"`
	Consumed     bool          `json:"consumed"`
	Control      bool          `json:"successful_before_control"`
	Owned        bool          `json:"owned_resource"`
	Clean        bool          `json:"clean"`
}

type prepared struct {
	Selection      selection      `json:"selection"`
	Port           portSpec       `json:"port"`
	ReceivingOwned bool           `json:"receiving_port_owned"`
	Complete       bool           `json:"prepared"`
	Phase          [2]phaseRecord `json:"phases"`
}

type attempt struct {
	ID           uint64        `json:"attempt_id"`
	Operation    string        `json:"operation"`
	Selection    selection     `json:"selection"`
	Phase        string        `json:"phase"`
	Page         *uint32       `json:"page_index,omitempty"`
	Partition    uint64        `json:"partition_id"`
	Generation   string        `json:"generation"`
	HostBuild    string        `json:"host_build"`
	GuestBuild   string        `json:"guest_build"`
	HostSource   string        `json:"host_source_base"`
	NativeSource string        `json:"native_source_base"`
	Mask         uint32        `json:"expected_mask"`
	SealReceipt  string        `json:"seal_receipt,omitempty"`
	Raw          *observation  `json:"raw_utility,omitempty"`
	HelperWire   *observation  `json:"backing_utility_wire,omitempty"`
	Backing      *backingReply `json:"backing_reply,omitempty"`
	Verdict      string        `json:"verdict"`
	Failure      string        `json:"error,omitempty"`
}

type journal struct {
	file *os.File
	size int
	sessionData
}

type sessionData struct {
	Schema      uint32               `json:"schema_version"`
	Partition   uint64               `json:"partition_id"`
	Generation  string               `json:"generation"`
	HostBuild   string               `json:"host_build"`
	GuestBuild  string               `json:"guest_build"`
	Mask        uint32               `json:"expected_mask,omitempty"`
	SealReceipt string               `json:"seal_receipt,omitempty"`
	Instance    [16]byte             `json:"driver_instance"`
	Tainted     bool                 `json:"tainted"`
	Cases       map[string]*prepared `json:"cases"`
	Last        *attempt             `json:"attempt,omitempty"`
}

// label bounds operator correlation strings and excludes whitespace/control
// characters from the identifiers used in evidence and digest generation.
func label(s string) bool {
	if s == "" || len(s) > 160 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || strings.ContainsRune("._:-", c)) {
			return false
		}
	}
	return true
}

// uniqueJSON rejects duplicate fields before typed decoding; encoding/json
// otherwise accepts later fields and matches object keys case-insensitively.
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name := strings.ToLower(key.(string))
			if seen[name] {
				return fmt.Errorf("duplicate JSON field %q", name)
			}
			seen[name] = true
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for d.More() {
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = d.Token()
	return err
}

// strictJSON accepts a single schema object and rejects unknown fields.
func strictJSON(data []byte, target any) error {
	scan := json.NewDecoder(bytes.NewReader(data))
	scan.UseNumber()
	if err := uniqueJSON(scan, 0); err != nil {
		return err
	}
	decode := json.NewDecoder(bytes.NewReader(data))
	decode.DisallowUnknownFields()
	if err := decode.Decode(target); err != nil {
		return err
	}
	if _, err := decode.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

// phaseName reports the execution phase, not when preparation is performed.
func phaseName(index int) string {
	if index == 0 {
		return "before"
	}
	return "after"
}

// fixtureValid checks v2 purpose, initial state and immutable GPA shape.
func fixtureValid(f guestFixture) bool {
	if !label(f.ID) || (f.Phase != "before" && f.Phase != "after") {
		return false
	}
	for _, gpa := range f.GPAs {
		// Architectural upper bound; native validates the partition's limit.
		if gpa == 0 || gpa%pageSize != 0 || gpa >= 1<<52 {
			return false
		}
	}
	switch f.Case {
	case mapContiguous, mapSparse:
		if f.Purpose != "host-ram-map" || f.InitialState != "private-quiesced" || len(f.GPAs) != 2 {
			return false
		}
		a, b := f.GPAs[0], f.GPAs[1]
		if f.Case == mapContiguous {
			return b == a+pageSize
		}
		return a+pageSize < b || b+pageSize < a
	case visibilityShare:
		return f.Purpose == visibilityShare && f.InitialState == "private-quiesced" && len(f.GPAs) == 1
	case visibilityPrivate:
		return f.Purpose == visibilityPrivate && f.InitialState == "shared-quiesced" && len(f.GPAs) == 1
	}
	return false
}

// loadFixtures validates the export as a whole before selecting its explicit
// before/after pair. Reserved GPAs and fixture IDs never repeat in an export.
func loadFixtures(path, which string) (fixtureExport, [2]*guestFixture, error) {
	var x fixtureExport
	var pair [2]*guestFixture
	f, err := os.Open(path)
	if err != nil {
		return x, pair, err
	}
	defer f.Close()
	const maxFixtures = 64 << 10
	data, err := io.ReadAll(io.LimitReader(f, maxFixtures+1))
	if err != nil {
		return x, pair, err
	}
	if len(data) > maxFixtures {
		return x, pair, errors.New("fixture export too large")
	}
	if err := strictJSON(data, &x); err != nil {
		return x, pair, fmt.Errorf("fixture export: %w", err)
	}
	if x.Schema != schemaVersion || !label(x.Generation) || !label(x.GuestBuild) {
		return x, pair, errors.New("require v2 fixture export with guest generation and build")
	}
	ids, slots, pages := map[string]bool{}, map[string]bool{}, map[uint64]bool{}
	for i := range x.Fixtures {
		f := &x.Fixtures[i]
		slot := f.Case + "/" + f.Phase
		if !fixtureValid(*f) || ids[f.ID] || slots[slot] {
			return x, pair, fmt.Errorf("invalid or duplicate fixture %q", f.ID)
		}
		ids[f.ID], slots[slot] = true, true
		for _, gpa := range f.GPAs {
			if pages[gpa] {
				return x, pair, errors.New("overlapping fixture GPAs")
			}
			pages[gpa] = true
		}
		if f.Case == which {
			if f.Phase == "before" {
				pair[0] = f
			} else {
				pair[1] = f
			}
		}
	}
	if pair[0] == nil || pair[1] == nil {
		return x, pair, errors.New("need both before and after fixtures for the selected case")
	}
	return x, pair, nil
}

// bindFixture hashes canonical v2 typed JSON (UTF-8, no trailing newline)
// and combines it with the partition and driver epoch outside the digest.
func (s *sessionData) bindFixture(f *guestFixture) binding {
	payload, _ := json.Marshal(struct {
		Generation string        `json:"generation"`
		Fixture    *guestFixture `json:"fixture"`
	}{s.Generation, f})
	c := uint32(1)
	if f.Case == mapSparse {
		c = 2
	}
	phase := uint32(1)
	if f.Phase == "after" {
		phase = 2
	}
	return binding{Instance: s.Instance, Partition: s.Partition, Case: c, Phase: phase,
		GPAs: [2]uint64{f.GPAs[0], f.GPAs[1]}, Digest: sha256.Sum256(payload)}
}

// validate rejects corrupted selectors, reused pages and backing bindings before
// any dispatcher uses the current journal snapshot.
func (s *sessionData) validate() error {
	if s.Schema != schemaVersion || s.Partition == 0 || s.Partition == self ||
		!label(s.Generation) || !label(s.HostBuild) || !label(s.GuestBuild) || s.Cases == nil ||
		(s.Mask == 0) != (s.SealReceipt == "") || s.Mask&^0x2f != 0 {
		return errors.New("invalid or obsolete session schema/identity")
	}
	if s.Last != nil && (s.Last.ID == 0 || s.Last.Generation != s.Generation ||
		s.Last.Partition != s.Partition || (s.Last.Verdict == "pending" && !s.Tainted)) {
		return errors.New("invalid session attempt record")
	}
	pages, ids := map[uint64]bool{}, map[string]bool{}
	for key, p := range s.Cases {
		if p == nil || !p.Selection.valid() || key != p.Selection.key() {
			return errors.New("invalid session case key")
		}
		bits := p.Selection.bits()
		if !p.Port.valid(p.Selection) || (p.ReceivingOwned && (bits != 8 || p.Selection.Case == createPort)) {
			return errors.New("invalid session port fixture")
		}
		for i, ph := range p.Phase {
			if bits > 2 {
				if ph.Fixture != nil || ph.Backing != nil || ph.Holes != 0 || ph.BackingState != 0 {
					return errors.New("unexpected page fixture")
				}
			} else {
				f := ph.Fixture
				if f == nil || !fixtureValid(*f) || f.Case != p.Selection.Case || f.Phase != phaseName(i) || ids[f.ID] {
					return errors.New("invalid or reused session fixture")
				}
				ids[f.ID] = true
				for _, gpa := range f.GPAs {
					if pages[gpa] {
						return errors.New("overlapping session GPAs")
					}
					pages[gpa] = true
				}
				if bits == 1 {
					if ph.Backing == nil || ph.Holes > 3 || (p.Complete && ph.Holes != 3) {
						return errors.New("incomplete mapping binding")
					}
					b := *ph.Backing
					b.Cookie = 0
					if b != s.bindFixture(f) || b.Instance == ([16]byte{}) ||
						(ph.Backing.Cookie == 0) != (ph.BackingState == 0) ||
						(p.Complete && ph.Backing.Cookie == 0) {
						return errors.New("changed mapping binding")
					}
				} else if ph.Backing != nil || ph.Holes != 0 || ph.BackingState != 0 {
					return errors.New("unexpected backing state")
				}
			}
			if (ph.Control && (i != 0 || !ph.Consumed)) || (ph.Owned && (i != 0 || !ph.Control || ph.Clean || bits < 4)) {
				return errors.New("invalid one-shot or ownership state")
			}
		}
	}
	return nil
}

// openJournal holds the actual file exclusively across validation, IOCTLs and
// commit. A torn last line fails closed; no writer truncates history.
func openJournal(path string, create, readOnly bool) (*journal, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.GENERIC_READ)
	if !readOnly {
		access |= windows.GENERIC_WRITE
	}
	flags := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	fresh := false
	var h windows.Handle
	if create {
		h, err = windows.CreateFile(name, access, 0, nil, windows.CREATE_NEW, flags, 0)
		fresh = err == nil
		if !fresh && !errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return nil, err
		}
	}
	if !fresh {
		h, err = windows.CreateFile(name, access, 0, nil, windows.OPEN_EXISTING, flags, 0)
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	j := &journal{file: f}
	success := false
	defer func() {
		if !success {
			f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("session must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxJournal+1))
	if err != nil {
		return nil, err
	}
	j.size = len(data)
	if !fresh {
		if len(data) == 0 || len(data) > maxJournal || data[len(data)-1] != '\n' {
			return nil, errors.New("missing or interrupted session journal; do not retry mutations")
		}
		last := data[:len(data)-1]
		last = last[bytes.LastIndexByte(last, '\n')+1:]
		if err := strictJSON(last, &j.sessionData); err != nil {
			return nil, fmt.Errorf("session snapshot: %w", err)
		}
		if err := j.validate(); err != nil {
			return nil, err
		}
	}
	success = true
	return j, nil
}

// commit appends a durable snapshot while retaining the previous intent if a
// completion cannot be delivered. A subsequent command rejects a torn line.
func (j *journal) commit() error {
	data, err := json.Marshal(&j.sessionData)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if j.size+len(data) > maxJournal {
		return errors.New("session journal limit reached")
	}
	n, err := j.file.Write(data)
	j.size += n
	if err != nil {
		return err
	}
	return j.file.Sync()
}

// mutate commits intent before a single synchronous mutation, then separately
// commits the observation and ownership changes. Any inconclusive result taints
// the whole session; the callback cannot authorize an automatic retry.
func (j *journal) mutate(s selection, phase, operation string, page *uint32, run func(*attempt) (string, error)) error {
	id := uint64(1)
	if j.Last != nil {
		id = j.Last.ID + 1
	}
	if j.Tainted || id == 0 {
		return errors.New("interrupted or tainted session; stop both sides")
	}
	a := &attempt{ID: id, Operation: operation, Selection: s, Phase: phase, Page: page,
		Partition: j.Partition, Generation: j.Generation, HostBuild: j.HostBuild, GuestBuild: j.GuestBuild,
		HostSource: hostSource, NativeSource: nativeSource, Mask: j.Mask, SealReceipt: j.SealReceipt, Verdict: "pending"}
	j.Last, j.Tainted = a, true
	if err := j.commit(); err != nil {
		return fmt.Errorf("persist mutation intent: %w", err)
	}
	if _, err := fmt.Fprintf(os.Stderr, "dispatch attempt=%d case=%s phase=%s cpu=%d generation=%s operation=%s\n",
		id, s.Case, phase, s.CPU, j.Generation, operation); err != nil {
		return err
	}
	var err error
	a.Verdict, err = run(a)
	if err != nil {
		a.Failure = err.Error()
	} else {
		j.Tainted = false
	}
	saveErr := j.commit()
	if printErr := json.NewEncoder(os.Stdout).Encode(a); printErr != nil {
		return errors.Join(saveErr, err, printErr)
	}
	if saveErr != nil {
		return errors.Join(err, fmt.Errorf("persist completion; stop both sides: %w", saveErr))
	}
	if j.Tainted {
		return fmt.Errorf("stop both sides; keep evidence and triage or recreate the VM: %w", err)
	}
	return nil
}
