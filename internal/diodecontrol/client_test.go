package diodecontrol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func capabilityBody() []byte {
	p := make([]byte, CapabilitiesSize)
	binary.LittleEndian.PutUint16(p[2:], MaxExports)
	binary.LittleEndian.PutUint16(p[4:], 1)
	binary.LittleEndian.PutUint16(p[6:], ExportSize)
	binary.LittleEndian.PutUint32(p[8:], StorageOperations)
	binary.LittleEndian.PutUint32(p[12:], 512)
	return p
}

func exportBody(exports ...Export) []byte {
	p := make([]byte, QuerySize+len(exports)*ExportSize)
	binary.LittleEndian.PutUint16(p, uint16(len(exports)))
	binary.LittleEndian.PutUint16(p[2:], ExportSize)
	for i, e := range exports {
		r := p[QuerySize+i*ExportSize:]
		binary.LittleEndian.PutUint64(r, e.Token)
		binary.LittleEndian.PutUint64(r[8:], e.Sectors)
		binary.LittleEndian.PutUint32(r[16:], e.References)
		binary.LittleEndian.PutUint16(r[20:], e.Controller)
		binary.LittleEndian.PutUint16(r[22:], e.RootLUN)
		r[24], r[25] = e.LUN, e.Flags
	}
	return p
}

func response(request Frame, body []byte, status uint32) Frame {
	return Frame{Header: Header{
		Service: Storage, Operation: request.Header.Operation, Flags: Response,
		Length: uint32(HeaderSize + len(body)), Request: request.Header.Request,
		Session: 77, Status: status,
	}, Body: body}
}

func writeResponse(conn net.Conn, frame Frame) error {
	p, err := frame.MarshalBinary()
	if err != nil {
		return err
	}
	for len(p) > 0 {
		n := min(3, len(p))
		if _, err := conn.Write(p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func fixtureClient(t *testing.T, handle func(Frame) []Frame) *Client {
	t.Helper()
	host, guest := net.Pipe()
	t.Cleanup(func() { _ = host.Close(); _ = guest.Close() })
	go func() {
		defer guest.Close()
		for {
			request, err := ReadFrame(guest)
			if err != nil {
				return
			}

			var replies []Frame
			if request.Header.Service == Storage && request.Header.Operation == Capabilities {
				replies = []Frame{response(request, capabilityBody(), OK)}
			} else {
				replies = handle(request)
			}
			for _, reply := range replies {
				if err := writeResponse(guest, reply); err != nil {
					return
				}
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := NewClient(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestClientPublishTCPPorts(t *testing.T) {
	for _, failure := range []string{"", "mismatch", "unsupported"} {
		t.Run(failure, func(t *testing.T) {
			client := fixtureClient(t, func(request Frame) []Frame {
				if request.Header.Service != Network || request.Header.Operation != PublishTCP {
					t.Errorf("incorrect publication request: %+v", request.Header)
				}
				reply := response(request, append([]byte(nil), request.Body...), OK)
				reply.Header.Service = Network
				switch failure {
				case "mismatch":
					binary.LittleEndian.PutUint16(reply.Body[4:], 11212)
				case "unsupported":
					reply.Header.Status = Unsupported
					reply.Body = nil
					reply.Header.Length = HeaderSize
				}
				return []Frame{reply}
			})
			err := client.PublishTCPPorts(context.Background(), []uint16{11211})
			if (err != nil) != (failure != "") {
				t.Fatalf("publication result: %v", err)
			}
		})
	}
	client := fixtureClient(t, func(Frame) []Frame {
		t.Error("invalid ports reached control transport")
		return nil
	})
	for _, ports := range [][]uint16{{0}, {11211, 11211}, make([]uint16, 17)} {
		if err := client.PublishTCPPorts(context.Background(), ports); err == nil {
			t.Fatalf("accepted invalid ports: %v", ports)
		}
	}
}

var bootExport = Export{Sectors: 4096, Flags: Boot | ReadOnly}

type closeErrorConn struct {
	net.Conn
	err error
}

func (c closeErrorConn) Close() error {
	return errors.Join(c.Conn.Close(), c.err)
}

func TestClientCloseReportsTransportFailure(t *testing.T) {
	host, guest := net.Pipe()
	defer guest.Close()
	closeErr := errors.New("transport close failed")
	client := &Client{
		conn: closeErrorConn{Conn: host, err: closeErr},
		done: make(chan struct{}),
	}
	if err := client.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("transport close error was lost: %v", err)
	}
	select {
	case <-client.Done():
	default:
		t.Fatal("close did not notify the owner")
	}
	if !errors.Is(client.Err(), net.ErrClosed) {
		t.Fatalf("session did not remain closed: %v", client.Err())
	}
	if err := client.Close(); err != nil {
		t.Fatalf("repeated close attempted to close the transport again: %v", err)
	}
}

func TestClientLateReplyDoesNotSatisfyNextRequest(t *testing.T) {
	var delayed Frame
	calls := 0
	client := fixtureClient(t, func(request Frame) []Frame {
		calls++
		if calls == 1 {
			delayed = response(request, exportBody(bootExport), OK)
			return nil
		}
		current := bootExport
		current.Sectors = 8192
		return []Frame{delayed, response(request, exportBody(current), OK)}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.Query(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled query: %v", err)
	}
	ctx2, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	exports, err := client.Query(ctx2)
	if err != nil || len(exports) != 1 || exports[0].Sectors != 8192 {
		t.Fatalf("late response displaced current query: %+v, %v", exports, err)
	}
}

func TestClientLostAddResponseRequiresExactTuple(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "wrong backing"}[conflict], func(t *testing.T) {
			published := false
			client := fixtureClient(t, func(request Frame) []Frame {
				switch request.Header.Operation {
				case Add:
					published = true
					return nil // Mutation applied, but its response was lost.
				case Query:
					if !published {
						return []Frame{response(request, exportBody(bootExport), OK)}
					}
					e := Export{Token: 101, Sectors: 4096, RootLUN: 7, LUN: 1, Flags: ReadOnly}
					if conflict {
						e.RootLUN = 8
					}
					return []Frame{response(request, exportBody(bootExport, e), OK)}
				}
				t.Errorf("unexpected operation: %d", request.Header.Operation)
				return nil
			})
			err := client.Add(context.Background(), 0, 7, 1, 101, true)
			if (err != nil) != conflict {
				t.Fatalf("publication reconciliation: %v", err)
			}
		})
	}
}

func TestClientRemoveDrainsAndRejectsStaleToken(t *testing.T) {
	removes := 0
	client := fixtureClient(t, func(request Frame) []Frame {
		switch request.Header.Operation {
		case Query:
			if removes >= 2 {
				return []Frame{response(request, exportBody(bootExport), OK)}
			}
			flags := byte(0)
			if removes != 0 {
				flags = Retiring
			}
			return []Frame{response(request, exportBody(bootExport,
				Export{Token: 101, Sectors: 4096, RootLUN: 7, LUN: 1, Flags: flags}), OK)}
		case Remove:
			removes++
			status := Pending
			if removes == 2 {
				status = OK
			}
			return []Frame{response(request, nil, status)}
		default:
			t.Errorf("unexpected operation: %d", request.Header.Operation)
			return nil
		}
	})
	if err := client.Remove(context.Background(), 1, 202); err == nil {
		t.Fatal("stale token was accepted")
	}
	if err := client.Remove(context.Background(), 1, 101); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsSessionChange(t *testing.T) {
	client := fixtureClient(t, func(request Frame) []Frame {
		reply := response(request, exportBody(bootExport), OK)
		reply.Header.Session++
		return []Frame{reply}
	})
	if _, err := client.Query(context.Background()); err == nil {
		t.Fatal("accepted a response from another session")
	}
	select {
	case <-client.Done():
	case <-time.After(time.Second):
		t.Fatal("changed session did not close the client")
	}
}

func TestClientPartialWriteCancellationClosesSession(t *testing.T) {
	host, guest := net.Pipe()
	release := make(chan struct{})
	defer close(release)
	defer guest.Close()
	go func() {
		request, err := ReadFrame(guest)
		if err == nil {
			_ = writeResponse(guest, response(request, capabilityBody(), OK))
		}
		<-release // No receiver for the next request.
	}()
	client, err := NewClient(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.Query(ctx); err == nil {
		t.Fatal("blocked request ignored cancellation")
	}
	select {
	case <-client.Done():
	case <-time.After(time.Second):
		t.Fatal("uncertain frame boundary left session usable")
	}
}

type deadlineErrorConn struct {
	net.Conn
	err error
}

func (c deadlineErrorConn) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		return c.err
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func TestClientCancellationClosesTransportIfDeadlineFails(t *testing.T) {
	host, guest := net.Pipe()
	defer guest.Close()
	release := make(chan struct{})
	writing := make(chan struct{})
	defer close(release)
	go func() {
		request, err := ReadFrame(guest)
		if err == nil {
			_ = writeResponse(guest, response(request, capabilityBody(), OK))
		}
		var first [1]byte
		if _, err := guest.Read(first[:]); err != nil {
			return
		}
		close(writing)
		<-release
	}()
	deadlineErr := errors.New("transport deadline failed")
	client, err := NewClient(context.Background(), deadlineErrorConn{Conn: host, err: deadlineErr})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.Query(ctx)
		result <- err
	}()
	select {
	case <-writing:
	case <-time.After(time.Second):
		t.Fatal("request did not reach the transport")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("failed deadline left the writer blocked")
	}
	if !errors.Is(client.Err(), deadlineErr) {
		t.Fatalf("transport deadline failure was lost: %v", client.Err())
	}
}

func TestClientProductionStorage(t *testing.T) {
	fixture := os.Getenv("DIODE_CONTROL_SERVER")
	if fixture == "" {
		t.Skip("set DIODE_CONTROL_SERVER to the production C storage/control harness")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "control.sock")
	address := &net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, fixture, path)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := command.Wait(); err != nil {
			t.Errorf("production C endpoint: %v\n%s", err, output.String())
		} else {
			t.Log(output.String())
		}
	}()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.PublishTCPPorts(ctx, []uint16{11211}); err != nil {
		t.Fatal(err)
	}
	for _, e := range []Export{
		{Token: 101, RootLUN: 7, LUN: 1},
		{Token: 202, RootLUN: 9, LUN: 2, Flags: ReadOnly},
	} {
		if err := client.Add(ctx, 0, uint(e.RootLUN), e.LUN, e.Token, e.Flags&ReadOnly != 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.Add(ctx, 0, 8, 1, 101, false); err == nil {
		t.Fatal("accepted matching token with a different backing")
	}
	if err := client.Remove(ctx, 1, 303); err == nil {
		t.Fatal("accepted stale removal")
	}
	busy, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	if err := client.Quiesce(busy, 0, 7); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("quiesced exported backing: %v", err)
	}
	stop()
	if err := client.Remove(ctx, 1, 101); err != nil {
		t.Fatal(err)
	}
	if err := client.Quiesce(ctx, 0, 7); err != nil {
		t.Fatal(err)
	}
	if err := client.Add(ctx, 0, 7, 1, 303, true); err != nil {
		t.Fatal(err)
	}
	for _, e := range []Export{{LUN: 1, Token: 303}, {LUN: 2, Token: 202}} {
		if err := client.Remove(ctx, e.LUN, e.Token); err != nil {
			t.Fatal(err)
		}
	}
	exports, err := client.Query(ctx)
	if err != nil || len(exports) != 1 || exports[0].LUN != 0 || exports[0].Flags != Boot|ReadOnly {
		t.Fatalf("final production export state: %+v, %v", exports, err)
	}
}
