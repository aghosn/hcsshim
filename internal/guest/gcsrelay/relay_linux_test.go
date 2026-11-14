//go:build linux

package gcsrelay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Microsoft/hcsshim/internal/guest/prot"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/linuxkit/virtsock/pkg/vsock"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// startLoggingTest runs the real outer relay with existing local-socket fakes.
// Cleanup cancels and joins the run, including any independently blocked logs.
func startLoggingTest(t *testing.T, logging bool) (*ioHarness, func(), <-chan struct{}) {
	t.Helper()
	h := &ioHarness{}
	d := h.dependencies(t)
	ctx, cancel := context.WithCancel(context.Background())
	path := filepath.Join(t.TempDir(), "ready")
	done := make(chan struct{})
	var runErr error
	// Exercise production readiness and concurrent log/control acceptance.
	go func() {
		runErr = runWithLogging(ctx, path, d, logging)
		close(done)
	}()
	var once sync.Once
	// Joining is idempotent so scenarios can explicitly test shutdown.
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("outer relay did not join workers")
			}
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return h, stop, done
		}
		select {
		case <-done:
			t.Fatalf("relay exited before readiness: %v", runErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("relay never became ready")
		}
		time.Sleep(time.Millisecond)
	}
}

// logTestEndpoints snapshots fully set-up endpoints after readiness. Deadlines
// keep a broken forwarding implementation from hanging the test process.
func logTestEndpoints(t *testing.T, h *ioHarness, port, rootPort uint32) (net.Conn, *net.TCPConn) {
	t.Helper()
	h.mu.Lock()
	listener, root := h.listeners[port], h.roots[rootPort]
	h.mu.Unlock()
	if listener == nil || root == nil {
		t.Fatal("missing relay endpoint")
	}
	workload, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { workload.Close() })
	workload.SetDeadline(time.Now().Add(3 * time.Second))
	root.SetDeadline(time.Now().Add(3 * time.Second))
	return workload, root
}

// TestLogRelayForwardsBeforeControl verifies raw fragmented/coalesced diagnostics
// and EOF reach the root before GCS connects, preventing the boot dependency cycle.
func TestLogRelayForwardsBeforeControl(t *testing.T) {
	h, _, _ := startLoggingTest(t, true)
	workload, root := logTestEndpoints(t, h, guestresource.LinuxLogVsockPort, guestresource.GCSRelayLogPort)
	input := bytes.Repeat([]byte("not JSON\x00\xff\nkernel diagnostic\n{\"log\":1}\n"), 4096)
	// Fragment writes independently of record boundaries; the relay must not parse.
	go func() {
		for _, chunk := range [][]byte{input[:1], input[1:7], input[7:]} {
			if err := writeAll(workload, chunk); err != nil {
				return
			}
		}
		workload.Close()
	}()
	got, err := io.ReadAll(root)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("early log bytes/EOF changed: %q %v", got, err)
	}
}

// TestLogRelayDoesNotForwardRootData verifies the independent log leg is one-way:
// root application bytes must not enter the workload's inherited output socket.
func TestLogRelayDoesNotForwardRootData(t *testing.T) {
	h, _, _ := startLoggingTest(t, true)
	workload, root := logTestEndpoints(t, h, guestresource.LinuxLogVsockPort, guestresource.GCSRelayLogPort)
	if err := writeAll(root, []byte("root application bytes")); err != nil {
		t.Fatal(err)
	}
	workload.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := workload.Read(make([]byte, 1)); err == nil {
		t.Fatal("root bytes were forwarded to workload output")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("log leg failed before forwarding: %v", err)
	}
}

// TestLogRelayDisabledHasNoEndpoints checks Run compatibility: ordinary relay
// readiness must not bind or dial either dedicated log endpoint.
func TestLogRelayDisabledHasNoEndpoints(t *testing.T) {
	h, _, _ := startLoggingTest(t, false)
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.listeners) != 1 || len(h.roots) != 1 ||
		h.listeners[guestresource.LinuxLogVsockPort] != nil || h.roots[guestresource.GCSRelayLogPort] != nil {
		t.Fatal("default relay acquired log endpoints")
	}
}

// TestLogRelayFailureLeavesControlAlive forces an established root write failure,
// then exchanges control frames both ways: logs must not enter session.launch.
func TestLogRelayFailureLeavesControlAlive(t *testing.T) {
	var diagnostics bytes.Buffer
	logger := logrus.StandardLogger()
	output := logger.Out
	logger.SetOutput(&diagnostics)
	t.Cleanup(func() { logger.SetOutput(output) })
	h, stop, _ := startLoggingTest(t, true)
	logs, sink := logTestEndpoints(t, h, guestresource.LinuxLogVsockPort, guestresource.GCSRelayLogPort)
	sink.SetLinger(0)
	sink.Close()
	// A reset is observed on a later write; send until the log leg is closed.
	logClosed := make(chan struct{})
	go func() {
		defer close(logClosed)
		for {
			if err := writeAll(logs, bytes.Repeat([]byte("failure"), 1024)); err != nil {
				return
			}
		}
	}()
	select {
	case <-logClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("failed log stream stayed open")
	}
	workload, root := logTestEndpoints(t, h, prot.LinuxGcsVsockPort, RootControlPort)
	input := frame(prot.ComputeSystemGetPropertiesV1, 7, "unmodified")
	if err := writeAll(root, input); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(input))
	if _, err := io.ReadFull(workload, got); err != nil || !bytes.Equal(input, got) {
		t.Fatalf("log failure terminated control request: %v", err)
	}
	if err := writeAll(workload, input); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(root, got); err != nil || !bytes.Equal(input, got) {
		t.Fatalf("log failure terminated control response: %v", err)
	}
	stop()
	if count := bytes.Count(diagnostics.Bytes(), []byte("gcsrelay: log stream stopped")); count != 1 {
		t.Fatalf("established log failure reported %d times: %s", count, diagnostics.String())
	}
}

// TestLogRelayControlShutdownJoins verifies control loss closes and joins logs
// blocked in accept/read/write, rather than leaving an independently lived worker.
func TestLogRelayControlShutdownJoins(t *testing.T) {
	for _, state := range []string{"accept", "read", "write"} {
		t.Run(state, func(t *testing.T) {
			h, _, done := startLoggingTest(t, true)
			var logs net.Conn
			if state != "accept" {
				logs, _ = logTestEndpoints(t, h, guestresource.LinuxLogVsockPort, guestresource.GCSRelayLogPort)
			}
			workload, root := logTestEndpoints(t, h, prot.LinuxGcsVsockPort, RootControlPort)
			input := frame(prot.ComputeSystemGetPropertiesV1, 8, "before control shutdown")
			if err := writeAll(root, input); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(workload, make([]byte, len(input))); err != nil {
				t.Fatal(err)
			}
			var sent chan error
			if state == "write" {
				sent = make(chan error, 1)
				// Fill the socket while its root peer intentionally does not drain.
				go func() { sent <- writeAll(logs, make([]byte, 16<<20)) }()
				select {
				case err := <-sent:
					t.Fatalf("sink did not apply pressure: %v", err)
				case <-time.After(100 * time.Millisecond):
				}
			}
			root.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("control shutdown retained log workers")
			}
			if sent != nil {
				select {
				case <-sent:
				case <-time.After(time.Second):
					t.Fatal("control shutdown retained log sender")
				}
			}
			if logs != nil {
				if _, err := logs.Read(make([]byte, 1)); err == nil {
					t.Fatal("control shutdown retained log socket")
				}
			}
		})
	}
}

// TestLogRelaySetupRollback checks every required endpoint failure, including
// later control setup, returns explicitly without readiness or leaked log legs.
func TestLogRelaySetupRollback(t *testing.T) {
	for _, failure := range []string{"log-listen", "log-dial", "control-listen", "control-dial"} {
		t.Run(failure, func(t *testing.T) {
			h := &ioHarness{}
			d := h.dependencies(t)
			listen, dial := d.listen, d.dial
			injected := errors.New(failure)
			// Fail precisely one setup operation, leaving rollback to production.
			d.listen = func(cid, port uint32) (net.Listener, error) {
				if failure == "log-listen" && port == guestresource.LinuxLogVsockPort ||
					failure == "control-listen" && port == prot.LinuxGcsVsockPort {
					return nil, injected
				}
				return listen(cid, port)
			}
			d.dial = func(ctx context.Context, cid, port uint32) (net.Conn, error) {
				if failure == "log-dial" && port == guestresource.GCSRelayLogPort ||
					failure == "control-dial" && port == RootControlPort {
					return nil, injected
				}
				return dial(ctx, cid, port)
			}
			path := filepath.Join(t.TempDir(), "ready")
			if err := runWithLogging(context.Background(), path, d, true); !errors.Is(err, injected) {
				t.Fatalf("setup error: %v", err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed setup advertised readiness")
			}
			for _, listener := range h.listeners {
				if c, err := listener.Accept(); err == nil {
					c.Close()
					t.Fatal("setup rollback leaked listener")
				}
			}
			for _, root := range h.roots {
				root.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := root.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("setup rollback retained root: %v", err)
				}
			}
		})
	}
}

// TestLogRelayPeerAndCancellation covers wrong-peer rejection and blocked
// accept/read/write shutdown. Unbuffered pipes prove sink pressure reaches the
// sender instead of being absorbed in an unbounded application queue.
func TestLogRelayPeerAndCancellation(t *testing.T) {
	for _, state := range []string{"peer", "accept", "read", "write"} {
		t.Run(state, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			root, sink := net.Pipe()
			defer sink.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			accepted := make(chan struct{})
			d := dependencies{workloadPeer: func(net.Conn) bool {
				close(accepted)
				return state != "peer"
			}}
			done := make(chan error, 1)
			// Serve exactly one log session without the control session launcher.
			go func() { done <- serveLog(ctx, listener, root, d) }()
			var sender net.Conn
			var sent chan error
			if state != "accept" {
				sender, err = net.Dial("tcp", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer sender.Close()
				select {
				case <-accepted:
				case <-time.After(time.Second):
					t.Fatal("log peer never checked")
				}
			}
			if state == "write" {
				sent = make(chan error, 1)
				// Exceed TCP buffers while the unbuffered root sink does not read.
				go func() { sent <- writeAll(sender, make([]byte, 16<<20)) }()
				select {
				case err := <-sent:
					t.Fatalf("slow sink did not backpressure sender: %v", err)
				case <-time.After(100 * time.Millisecond):
				}
			}
			if state != "peer" {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("peer/cancellation unexpectedly succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("log worker did not join")
			}
			if sent != nil {
				select {
				case <-sent:
				case <-time.After(time.Second):
					t.Fatal("sender retained by cancelled log leg")
				}
			}
			sink.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := sink.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("log root remained open: %v", err)
			}
		})
	}
}

func frame(kind prot.MessageIdentifier, id uint64, body string) []byte {
	b := make([]byte, headerSize+len(body))
	binary.LittleEndian.PutUint32(b[:4], uint32(kind))
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(b)))
	binary.LittleEndian.PutUint64(b[8:16], id)
	copy(b[16:], body)
	return b
}

type fragmentedReader struct {
	io.Reader
	chunk int
}

func (r fragmentedReader) Read(b []byte) (int, error) {
	if len(b) > r.chunk {
		b = b[:r.chunk]
	}
	return r.Reader.Read(b)
}

func newTestSession(t *testing.T, d dependencies) *session {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{ctx: ctx, cancel: cancel, d: d, ports: make(map[uint32]*ioPort),
		requests: make(map[uint64][]*ioPort), errors: make(chan error, 1)}
	t.Cleanup(func() {
		cancel()
		s.mu.Lock()
		for _, p := range s.ports {
			s.closePortLocked(p)
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func TestForwardPreservesFragmentedAndCoalescedFrames(t *testing.T) {
	for _, requests := range []bool{true, false} {
		for _, chunk := range []int{1, 3, 15, 16, 10000} {
			t.Run(fmt.Sprintf("requests=%t/chunk=%d", requests, chunk), func(t *testing.T) {
				input := frame(prot.ComputeSystemNotificationV1, 99, "{\"ResultInfo\":\"untouched\"}")
				if requests {
					input = append(input, frame(prot.ComputeSystemExecuteProcessV1, 0xfedcba9876543210,
						" { \"Settings\": {\"VsockStdioRelaySettings\":{}}, \"Unknown\":true } ")...)
				} else {
					input = append(input, frame(prot.ComputeSystemResponseExecuteProcessV1, 17,
						" { \"Result\":-1, \"Unknown\":\"untouched\" } ")...)
				}
				input = append(input, frame(prot.ComputeSystemGetPropertiesV1, 42, "raw\x00bytes")...)
				s := newTestSession(t, dependencies{})
				var output bytes.Buffer
				err := s.forward(fragmentedReader{bytes.NewReader(input), chunk}, &output, requests)
				if !errors.Is(err, io.EOF) {
					t.Fatalf("forward: %v", err)
				}
				if !bytes.Equal(input, output.Bytes()) {
					t.Fatal("forward changed original bytes")
				}
			})
		}
	}
}

func TestMalformedExecuteResponseStillForwardsOriginalBytes(t *testing.T) {
	s := newTestSession(t, dependencies{})
	input := frame(prot.ComputeSystemResponseExecuteProcessV1, 15, "{malformed")
	var output bytes.Buffer
	if err := s.forward(bytes.NewReader(input), &output, false); err == nil {
		t.Fatal("malformed response was not explicitly reported")
	}
	if !bytes.Equal(input, output.Bytes()) {
		t.Fatal("response observer altered the workload byte stream")
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := l.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

type ioHarness struct {
	mu        sync.Mutex
	listeners map[uint32]net.Listener
	roots     map[uint32]*net.TCPConn
	events    []string
	failPort  uint32
}

func (h *ioHarness) dependencies(t *testing.T) dependencies {
	t.Helper()
	h.listeners = make(map[uint32]net.Listener)
	h.roots = make(map[uint32]*net.TCPConn)
	return dependencies{
		listen: func(cid, port uint32) (net.Listener, error) {
			if cid != localCID {
				return nil, fmt.Errorf("wrong LOCAL CID %d", cid)
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			t.Cleanup(func() { l.Close() })
			h.mu.Lock()
			h.listeners[port] = l
			h.events = append(h.events, fmt.Sprintf("listen:%x", port))
			h.mu.Unlock()
			return l, nil
		},
		dial: func(ctx context.Context, cid, port uint32) (net.Conn, error) {
			if cid != rootCID {
				return nil, fmt.Errorf("wrong root CID %d", cid)
			}
			h.mu.Lock()
			h.events = append(h.events, fmt.Sprintf("dial:%x", port))
			h.mu.Unlock()
			if port == h.failPort {
				return nil, errors.New("injected root dial failure")
			}
			root, peer := tcpPair(t)
			h.mu.Lock()
			h.roots[port] = peer
			h.mu.Unlock()
			return root, nil
		},
		workloadPeer: func(net.Conn) bool { return true },
		acceptTTL:    time.Minute,
	}
}

type checkingWriter struct {
	bytes.Buffer
	check func()
}

func (w *checkingWriter) Write(b []byte) (int, error) {
	w.check()
	return w.Buffer.Write(b)
}

func execBody(ports ...uint32) string {
	var p [3]uint32
	copy(p[:], ports)
	return fmt.Sprintf(`{"Settings":{"VsockStdioRelaySettings":{"StdIn":%d,"StdOut":%d,"StdErr":%d}}}`,
		p[0], p[1], p[2])
}

func TestExecuteInstallsAllIOBeforeForwarding(t *testing.T) {
	h := &ioHarness{}
	s := newTestSession(t, h.dependencies(t))
	input := frame(prot.ComputeSystemExecuteProcessV1, 123, execBody(FirstIOPort, FirstIOPort+1, FirstIOPort+2))
	out := &checkingWriter{check: func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		want := []string{"listen:60000000", "dial:60000000", "listen:60000001",
			"dial:60000001", "listen:60000002", "dial:60000002"}
		if fmt.Sprint(h.events) != fmt.Sprint(want) {
			t.Fatalf("IO not ready before control write: %v", h.events)
		}
	}}
	if err := s.forward(bytes.NewReader(input), out, true); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if !bytes.Equal(input, out.Bytes()) {
		t.Fatal("execute bytes changed")
	}
}

func TestExecuteSetupFailureDoesNotForwardAndRollsBack(t *testing.T) {
	h := &ioHarness{failPort: FirstIOPort + 1}
	s := newTestSession(t, h.dependencies(t))
	var out bytes.Buffer
	err := s.forward(bytes.NewReader(frame(prot.ComputeSystemExecuteProcessV1, 7,
		execBody(FirstIOPort, FirstIOPort+1))), &out, true)
	if err == nil || out.Len() != 0 {
		t.Fatalf("setup failure forwarded data: err=%v bytes=%d", err, out.Len())
	}
	for _, l := range h.listeners {
		if c, err := l.Accept(); err == nil {
			c.Close()
			t.Fatal("rollback retained listener")
		}
	}
	if len(s.ports) != 0 || len(s.requests) != 0 {
		t.Fatal("rollback retained state")
	}
}

func TestExecuteInspectionMatchesProtocolRepeatedObjectMerge(t *testing.T) {
	h := &ioHarness{}
	s := newTestSession(t, h.dependencies(t))
	body := `{"Settings":{"VsockStdioRelaySettings":{"StdIn":1610612736},"VsockStdioRelaySettings":{"StdOut":1610612737}}}`
	if err := s.setupIO(14, []byte(body)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ports) != 2 || s.ports[FirstIOPort] == nil || s.ports[FirstIOPort+1] == nil {
		t.Fatal("inspection differed from GCS encoding/json object merge")
	}
}

func TestExecuteRejectsInvalidSettingsBeforeForward(t *testing.T) {
	for _, body := range []string{
		`{`, `null`, `{}`, `{"Settings":null}`, `{"Settings":{}}`,
		execBody(FirstIOPort - 1), execBody(^uint32(0)),
		execBody(FirstIOPort, FirstIOPort), `{"Settings":{"VsockStdioRelaySettings":{"StdIn":-1}}}`,
		`{"Settings":{"VsockStdioRelaySettings":{"StdIn":4294967296}}}`,
		`{"Settings":{"VsockStdioRelaySettings":null}}`,
		`{"Settings":{"VsockStdioRelaySettings":{"StdIn":null}}}`,
	} {
		t.Run(body, func(t *testing.T) {
			s := newTestSession(t, dependencies{})
			var out bytes.Buffer
			err := s.forward(bytes.NewReader(frame(prot.ComputeSystemExecuteProcessV1, 7, body)), &out, true)
			if err == nil || out.Len() != 0 {
				t.Fatalf("invalid settings forwarded: err=%v bytes=%d", err, out.Len())
			}
		})
	}
}

func TestExecuteRejectsDuplicateActivePortAndRequest(t *testing.T) {
	h := &ioHarness{}
	s := newTestSession(t, h.dependencies(t))
	if err := s.setupIO(7, []byte(execBody(FirstIOPort))); err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct {
		id   uint64
		port uint32
	}{{7, FirstIOPort + 1}, {8, FirstIOPort}} {
		if err := s.setupIO(attempt.id, []byte(execBody(attempt.port))); err == nil {
			t.Fatal("duplicate accepted")
		}
	}
}

func TestFailedExecuteResponseReleasesUnusedIOAndForwardsUnchanged(t *testing.T) {
	h := &ioHarness{}
	s := newTestSession(t, h.dependencies(t))
	if err := s.setupIO(8, []byte(execBody(FirstIOPort, FirstIOPort+1))); err != nil {
		t.Fatal(err)
	}
	response := frame(prot.ComputeSystemResponseExecuteProcessV1, 8, ` {"Result":-2147467259,"ErrorMessage":"failed"} `)
	var out bytes.Buffer
	if err := s.forward(bytes.NewReader(response), &out, false); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	s.wg.Wait()
	if !bytes.Equal(response, out.Bytes()) || len(s.ports) != 0 || len(s.requests) != 0 {
		t.Fatal("failed response changed bytes or retained IO state")
	}
	select {
	case err := <-s.errors:
		t.Fatalf("unused IO close incorrectly failed session: %v", err)
	default:
	}
}

func TestPendingAcceptExpiresAndCancelsSession(t *testing.T) {
	h := &ioHarness{}
	d := h.dependencies(t)
	d.acceptTTL = 20 * time.Millisecond
	s := newTestSession(t, d)
	if err := s.setupIO(9, []byte(execBody(FirstIOPort))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("pending accept did not expire")
	}
	s.wg.Wait()
	if len(s.ports) != 0 || len(s.requests) != 0 {
		t.Fatal("expired IO retained state")
	}
}

func TestFailedResponsePreservesAcceptedIOAndCompletedStateIsReclaimed(t *testing.T) {
	h := &ioHarness{}
	s := newTestSession(t, h.dependencies(t))
	if err := s.setupIO(11, []byte(execBody(FirstIOPort, FirstIOPort+1))); err != nil {
		t.Fatal(err)
	}
	workload, err := net.Dial("tcp", h.listeners[FirstIOPort].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer workload.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		accepted := !s.ports[FirstIOPort].pending
		s.mu.Unlock()
		if accepted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("workload IO was not accepted")
		}
		time.Sleep(time.Millisecond)
	}
	if err := s.execResponse(11, []byte(`{"Result":-1}`)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	if len(s.ports) != 1 || s.ports[FirstIOPort] == nil || len(s.requests) != 0 {
		s.mu.Unlock()
		t.Fatal("failed response closed accepted IO or kept unused IO")
	}
	s.mu.Unlock()
	root := h.roots[FirstIOPort]
	root.SetDeadline(time.Now().Add(3 * time.Second))
	workload.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeAll(workload, []byte("accepted IO survives")); err != nil {
		t.Fatal(err)
	}
	if err := workload.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(root)
	if err != nil || string(got) != "accepted IO survives" {
		t.Fatalf("accepted IO: %q %v", got, err)
	}
	if err := writeAll(root, []byte("reverse IO")); err != nil {
		t.Fatal(err)
	}
	if err := root.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(workload)
	if err != nil || string(got) != "reverse IO" {
		t.Fatalf("reverse IO: %q %v", got, err)
	}
	s.wg.Wait()
	if len(s.ports) != 0 || len(s.requests) != 0 {
		t.Fatal("completed IO retained state")
	}
	select {
	case err := <-s.errors:
		t.Fatalf("accepted IO unexpectedly failed: %v", err)
	default:
	}
}

func TestIORejectsUnexpectedPeer(t *testing.T) {
	h := &ioHarness{}
	d := h.dependencies(t)
	d.workloadPeer = func(net.Conn) bool { return false }
	s := newTestSession(t, d)
	if err := s.setupIO(12, []byte(execBody(FirstIOPort))); err != nil {
		t.Fatal(err)
	}
	peer, err := net.Dial("tcp", h.listeners[FirstIOPort].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	select {
	case <-s.ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("unexpected peer did not fail session")
	}
	s.wg.Wait()
	if len(s.ports) != 0 {
		t.Fatal("rejected peer retained IO listener")
	}
}

func TestIOPortStateLimit(t *testing.T) {
	s := newTestSession(t, dependencies{})
	for i := uint32(0); i < maxIOPorts; i++ {
		port := FirstIOPort + i
		s.ports[port] = &ioPort{port: port}
	}
	if err := s.setupIO(13, []byte(execBody(FirstIOPort+maxIOPorts))); err == nil {
		t.Fatal("unbounded IO state accepted")
	}
}

func TestDuplexPreservesHalfCloseAndBackpressure(t *testing.T) {
	left, relayLeft := tcpPair(t)
	right, relayRight := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- copyDuplex(context.Background(), relayLeft, relayRight) }()
	request := bytes.Repeat([]byte("request bytes"), 10000)
	sent := make(chan error, 1)
	go func() {
		if err := writeAll(left, request); err != nil {
			sent <- err
			return
		}
		sent <- left.CloseWrite()
	}()
	if err := right.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(right)
	if err != nil || !bytes.Equal(got, request) {
		t.Fatalf("request/EOF: %v (%d bytes)", err, len(got))
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if err := writeAll(right, []byte("response after request EOF")); err != nil {
		t.Fatal(err)
	}
	if err := right.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	left.SetDeadline(time.Now().Add(3 * time.Second))
	got, err = io.ReadAll(left)
	if err != nil || string(got) != "response after request EOF" {
		t.Fatalf("reverse direction lost after half-close: %q %v", got, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("duplex goroutines remained")
	}
}

func TestDuplexCancellationStopsBothDirections(t *testing.T) {
	left, relayLeft := tcpPair(t)
	right, relayRight := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- copyDuplex(ctx, relayLeft, relayRight) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("duplex cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("duplex cancellation leaked goroutines")
	}
	for _, peer := range []net.Conn{left, right} {
		peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("cancelled peer was not closed: %v", err)
		}
	}
}

func TestSessionCancellationClosesPendingListenersAndControl(t *testing.T) {
	h := &ioHarness{}
	d := h.dependencies(t)
	host, root := net.Pipe()
	workload, guest := net.Pipe()
	defer host.Close()
	defer guest.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- relaySession(ctx, root, workload, d) }()
	defer cancel()
	input := frame(prot.ComputeSystemExecuteProcessV1, 10, execBody(FirstIOPort))
	if err := writeAll(host, input); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(input))
	if _, err := io.ReadFull(guest, got); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session cancellation leaked goroutines")
	}
	h.mu.Lock()
	l := h.listeners[FirstIOPort]
	h.mu.Unlock()
	if c, err := l.Accept(); err == nil {
		c.Close()
		t.Fatal("cancellation retained listener")
	}
	if _, err := guest.Read(make([]byte, 1)); err == nil {
		t.Fatal("cancellation retained control socket")
	}
}

func TestControlLossIsExplicit(t *testing.T) {
	host, root := net.Pipe()
	workload, guest := net.Pipe()
	defer guest.Close()
	done := make(chan error, 1)
	go func() { done <- relaySession(context.Background(), root, workload, dependencies{}) }()
	host.Close()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("control loss not explicit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("control loss did not stop session")
	}
}

func TestReadinessAndAcceptCancellation(t *testing.T) {
	// Keep test artifacts inside this package, not the system temp directory.
	dir := fmt.Sprintf(".gcsrelay-test-%d", time.Now().UnixNano())
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "ready")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer, root := net.Pipe()
	defer peer.Close()
	d := dependencies{
		listen: func(cid, port uint32) (net.Listener, error) {
			if cid != localCID || port != prot.LinuxGcsVsockPort {
				return nil, errors.New("incorrect control bind")
			}
			return l, nil
		},
		dial: func(ctx context.Context, cid, port uint32) (net.Conn, error) {
			if cid != rootCID || port != RootControlPort {
				return nil, errors.New("incorrect control dial")
			}
			return root, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, path, d) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		stat, err := os.Stat(path)
		if err == nil {
			var fs unix.Statfs_t
			if err := unix.Statfs(dir, &fs); err != nil {
				t.Fatal(err)
			}
			if stat.Mode().Perm() != 0600 {
				if fs.Type == 0x1021997 && stat.Mode().Perm() == 0777 {
					t.Log("WSL DrvFS without metadata emulates 0777; production uses explicit chmod 0600")
				} else {
					t.Fatalf("readiness permissions: %o", stat.Mode().Perm())
				}
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("readiness never appeared")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("accept did not unblock")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness was not removed: %v", err)
	}
}

func TestNativeSocketHalfCloseAndCloseUnblocksRead(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	a := &socket{file: os.NewFile(uintptr(fds[0]), "gcsrelay-test-a")}
	b := &socket{file: os.NewFile(uintptr(fds[1]), "gcsrelay-test-b")}
	defer a.Close()
	defer b.Close()
	if err := a.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := b.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(a, []byte("native half-close")); err != nil {
		t.Fatal(err)
	}
	if err := a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(b)
	if err != nil || string(got) != "native half-close" {
		t.Fatalf("native half-close: %q %v", got, err)
	}
	if err := writeAll(b, []byte("reverse")); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len("reverse"))
	if _, err := io.ReadFull(a, got); err != nil || string(got) != "reverse" {
		t.Fatalf("native reverse after EOF: %q %v", got, err)
	}
	done := make(chan error, 1)
	go func() { _, err := a.Read(make([]byte, 1)); done <- err }()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("native close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("native close did not unblock read")
	}
}

func TestNativePollableListenerCloseUnblocksAccept(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "gcsrelay-test-listener")
	defer file.Close()
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	l := &socketListener{file: file, addr: &vsock.Addr{CID: localCID}}
	done := make(chan error, 1)
	go func() { _, err := l.Accept(); done <- err }()
	time.Sleep(10 * time.Millisecond)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed accept succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("native Accept did not unblock on close")
	}
}
