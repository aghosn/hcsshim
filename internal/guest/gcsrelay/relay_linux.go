//go:build linux

// Package gcsrelay mediates a single GCS session through the sibling diode VM.
package gcsrelay

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim/internal/guest/prot"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/sirupsen/logrus"
)

const (
	// RootControlPort is the root's opt-in mediated GCS endpoint.
	RootControlPort uint32 = guestresource.GCSRelayControlPort
	// FirstIOPort separates mediated stdio from the diode's own GCS ports.
	FirstIOPort uint32 = guestresource.GCSRelayIOPortStart

	localCID       uint32 = 4
	workloadCID    uint32 = 3
	rootCID        uint32 = 2
	headerSize            = prot.MessageHeaderSize
	maxInspectBody        = 16 << 20
	maxIOPorts            = 1024
)

type dependencies struct {
	listen       func(uint32, uint32) (net.Listener, error)
	dial         func(context.Context, uint32, uint32) (net.Conn, error)
	workloadPeer func(net.Conn) bool
	acceptTTL    time.Duration
}

func nativeDependencies() dependencies {
	return dependencies{
		listen: listenVSock,
		dial:   dialVSock,
		workloadPeer: func(c net.Conn) bool {
			addr, ok := c.RemoteAddr().(*vsock.Addr)
			return ok && addr.CID == workloadCID
		},
		acceptTTL: 2 * time.Minute,
	}
}

// Run listens on LOCAL CID4 at the standard GCS port and connects to CID2 at
// RootControlPort. It serves one workload CID3 session; loss is fatal, with no
// reconnection, replay, or direct fallback. The caller must exit on an error.
func Run(ctx context.Context, readyPath string) error {
	return run(ctx, readyPath, nativeDependencies())
}

func run(ctx context.Context, readyPath string, d dependencies) error {
	if readyPath == "" {
		return errors.New("gcsrelay: readiness path is required")
	}
	listener, err := d.listen(localCID, prot.LinuxGcsVsockPort)
	if err != nil {
		return fmt.Errorf("gcsrelay: control listen: %w", err)
	}
	defer listener.Close()
	stopListener := context.AfterFunc(ctx, func() { listener.Close() })
	defer stopListener()
	root, err := d.dial(ctx, rootCID, RootControlPort)
	if err != nil {
		return fmt.Errorf("gcsrelay: root control dial: %w", err)
	}
	defer root.Close()
	stopRoot := context.AfterFunc(ctx, func() { root.Close() })
	defer stopRoot()
	// Exclusive creation avoids following or overwriting an existing readiness
	// file. A stale marker is an explicit startup failure.
	file, err := os.OpenFile(readyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("gcsrelay: create readiness: %w", err)
	}
	defer func() {
		if err := os.Remove(readyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			logrus.WithError(err).Error("gcsrelay: remove readiness")
		}
	}()
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return fmt.Errorf("gcsrelay: set readiness permissions: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("gcsrelay: close readiness: %w", err)
	}
	workload, err := listener.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("gcsrelay: control accept: %w", err)
	}
	defer workload.Close()
	if !d.workloadPeer(workload) {
		return errors.New("gcsrelay: control peer is not workload CID3")
	}
	if err := listener.Close(); err != nil {
		return fmt.Errorf("gcsrelay: close control listener: %w", err)
	}
	return relaySession(ctx, root, workload, d)
}

type ioPort struct {
	port     uint32
	listener net.Listener
	root     net.Conn
	workload net.Conn
	timer    *time.Timer
	pending  bool
}

type session struct {
	ctx      context.Context
	cancel   context.CancelFunc
	d        dependencies
	mu       sync.Mutex
	ports    map[uint32]*ioPort
	requests map[uint64][]*ioPort
	wg       sync.WaitGroup
	errors   chan error
}

func relaySession(ctx context.Context, root, workload net.Conn, d dependencies) error {
	ctx, cancel := context.WithCancel(ctx)
	s := &session{
		ctx: ctx, cancel: cancel, d: d,
		ports: make(map[uint32]*ioPort), requests: make(map[uint64][]*ioPort),
		errors: make(chan error, 1),
	}
	defer func() {
		cancel()
		root.Close()
		workload.Close()
		s.mu.Lock()
		for _, p := range s.ports {
			s.closePortLocked(p)
		}
		s.mu.Unlock()
		s.wg.Wait()
	}()
	s.launch(func() error { return s.forward(root, workload, true) })
	s.launch(func() error { return s.forward(workload, root, false) })
	select {
	case <-ctx.Done():
		select {
		case err := <-s.errors:
			return fmt.Errorf("gcsrelay: session lost: %w", err)
		default:
		}
		return ctx.Err()
	case err := <-s.errors:
		return fmt.Errorf("gcsrelay: session lost: %w", err)
	}
}

func (s *session) launch(f func() error) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := f(); err != nil {
			select {
			case s.errors <- err:
			default:
			}
			s.cancel()
		}
	}()
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) != 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func (s *session) forward(src io.Reader, dst io.Writer, requests bool) error {
	for {
		var header [headerSize]byte
		if _, err := io.ReadFull(src, header[:]); err != nil {
			return fmt.Errorf("control header: %w", err)
		}
		kind := prot.MessageIdentifier(binary.LittleEndian.Uint32(header[:4]))
		size := binary.LittleEndian.Uint32(header[4:8])
		id := binary.LittleEndian.Uint64(header[8:])
		if size < headerSize {
			return fmt.Errorf("invalid control frame size %d", size)
		}
		bodySize := int64(size - headerSize)
		inspect := requests && kind == prot.ComputeSystemExecuteProcessV1 ||
			!requests && kind == prot.ComputeSystemResponseExecuteProcessV1
		if inspect {
			if bodySize > maxInspectBody {
				return fmt.Errorf("execute frame exceeds inspection limit: %d", bodySize)
			}
			body := make([]byte, int(bodySize))
			if _, err := io.ReadFull(src, body); err != nil {
				return fmt.Errorf("execute body: %w", err)
			}
			if requests {
				if err := s.setupIO(id, body); err != nil {
					return err
				}
			}
			if err := writeAll(dst, header[:]); err != nil {
				return err
			}
			if err := writeAll(dst, body); err != nil {
				return err
			}
			if !requests {
				if err := s.execResponse(id, body); err != nil {
					return err
				}
			}
		} else {
			if err := writeAll(dst, header[:]); err != nil {
				return err
			}
			if _, err := io.CopyN(dst, src, bodySize); err != nil {
				return err
			}
		}
	}
}

func (s *session) setupIO(id uint64, body []byte) error {
	// Required objects must not silently decode null/missing settings as zero
	// ports. Unknown fields are preserved in the original frame, not rebuilt.
	var envelope struct {
		Settings *struct {
			VsockStdioRelaySettings *prot.ExecuteProcessVsockStdioRelaySettings
		}
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("execute %d: malformed JSON: %w", id, err)
	}
	if envelope.Settings == nil || envelope.Settings.VsockStdioRelaySettings == nil {
		return fmt.Errorf("execute %d: missing stdio settings", id)
	}
	settings := envelope.Settings.VsockStdioRelaySettings
	// Decode the actual protocol type above, including encoding/json's merge
	// semantics for repeated objects. This second view rejects null ports,
	// which encoding/json otherwise treats as an omitted uint32.
	var rawEnvelope struct {
		Settings struct {
			VsockStdioRelaySettings map[string]json.RawMessage
		}
	}
	if err := json.Unmarshal(body, &rawEnvelope); err != nil {
		return fmt.Errorf("execute %d: invalid stdio object: %w", id, err)
	}
	fields := rawEnvelope.Settings.VsockStdioRelaySettings
	if fields == nil {
		return fmt.Errorf("execute %d: null stdio settings", id)
	}
	for name, value := range fields {
		if strings.EqualFold(name, "StdIn") || strings.EqualFold(name, "StdOut") || strings.EqualFold(name, "StdErr") {
			if strings.TrimSpace(string(value)) == "null" {
				return fmt.Errorf("execute %d: null stdio port %s", id, name)
			}
		}
	}
	var entries []*ioPort
	s.mu.Lock()
	if _, exists := s.requests[id]; exists {
		s.mu.Unlock()
		return fmt.Errorf("execute %d: duplicate pending request ID", id)
	}
	seen := make(map[uint32]bool)
	for _, port := range []uint32{settings.StdIn, settings.StdOut, settings.StdErr} {
		if port == 0 {
			continue
		}
		if port < FirstIOPort || port == ^uint32(0) || seen[port] || s.ports[port] != nil {
			s.mu.Unlock()
			return fmt.Errorf("execute %d: duplicate or out-of-range IO port %#x", id, port)
		}
		seen[port] = true
		entries = append(entries, &ioPort{port: port, pending: true})
	}
	if len(s.ports)+len(entries) > maxIOPorts {
		s.mu.Unlock()
		return errors.New("gcsrelay: concurrent IO port limit exceeded")
	}
	s.mu.Unlock()
	// This pump is the sole installer. Do not publish resources until the
	// complete setup succeeds; rollback owns all partially created resources.
	cleanup := true
	defer func() {
		if cleanup {
			for _, p := range entries {
				if p.listener != nil {
					p.listener.Close()
				}
				if p.root != nil {
					p.root.Close()
				}
			}
		}
	}()
	for _, p := range entries {
		var err error
		p.listener, err = s.d.listen(localCID, p.port)
		if err != nil {
			return fmt.Errorf("execute %d: IO listen %#x: %w", id, p.port, err)
		}
		p.root, err = s.d.dial(s.ctx, rootCID, p.port)
		if err != nil {
			return fmt.Errorf("execute %d: root IO dial %#x: %w", id, p.port, err)
		}
	}
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return s.ctx.Err()
	}
	if len(entries) != 0 {
		s.requests[id] = entries
	}
	for _, p := range entries {
		s.ports[p.port] = p
		p.timer = time.AfterFunc(s.d.acceptTTL, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if !p.pending {
				return
			}
			logrus.WithFields(logrus.Fields{"request": id, "port": p.port}).
				Error("gcsrelay: pending IO accept expired; failing session")
			s.closePortLocked(p)
			select {
			case s.errors <- fmt.Errorf("IO accept %#x expired", p.port):
			default:
			}
			s.cancel()
		})
		s.launch(func() error { return s.serveIO(id, p) })
	}
	s.mu.Unlock()
	cleanup = false
	return nil
}

func (s *session) closePortLocked(p *ioPort) {
	p.pending = false
	if p.timer != nil {
		p.timer.Stop()
	}
	if p.listener != nil {
		p.listener.Close()
	}
	if p.root != nil {
		p.root.Close()
	}
	if p.workload != nil {
		p.workload.Close()
	}
	if s.ports[p.port] == p {
		delete(s.ports, p.port)
	}
}

func (s *session) execResponse(id uint64, body []byte) error {
	var response struct{ Result *int32 }
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("execute response %d: malformed JSON: %w", id, err)
	}
	if response.Result == nil {
		return fmt.Errorf("execute response %d: missing Result", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.requests[id] {
		if *response.Result != 0 && p.pending {
			s.closePortLocked(p)
		}
	}
	delete(s.requests, id)
	return nil
}

func (s *session) serveIO(id uint64, p *ioPort) error {
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closePortLocked(p)
		// An absent response must not retain a completed request forever.
		allDone, ownRequest := true, false
		for _, entry := range s.requests[id] {
			if entry == p {
				ownRequest = true
			}
			if s.ports[entry.port] == entry {
				allDone = false
			}
		}
		if ownRequest && allDone {
			delete(s.requests, id)
		}
	}()
	conn, err := p.listener.Accept()
	s.mu.Lock()
	if !p.pending || s.ctx.Err() != nil {
		s.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		return nil
	}
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("IO accept %#x: %w", p.port, err)
	}
	if !s.d.workloadPeer(conn) {
		s.mu.Unlock()
		conn.Close()
		return fmt.Errorf("IO port %#x: peer is not workload CID3", p.port)
	}
	p.pending = false
	p.timer.Stop()
	p.workload = conn
	err = p.listener.Close()
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("IO listener close %#x: %w", p.port, err)
	}
	return copyDuplex(s.ctx, p.root, conn)
}

func copyDuplex(ctx context.Context, a, b net.Conn) error {
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	results := make(chan error, 2)
	copyOne := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			} else {
				err = errors.New("gcsrelay: connection does not support half-close")
			}
		}
		results <- err
	}
	go copyOne(a, b)
	go copyOne(b, a)
	first := <-results
	if first != nil {
		a.Close()
		b.Close()
	}
	second := <-results
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(first, second)
}
