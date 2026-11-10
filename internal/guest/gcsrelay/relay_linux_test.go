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
	"github.com/linuxkit/virtsock/pkg/vsock"
	"golang.org/x/sys/unix"
)

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
