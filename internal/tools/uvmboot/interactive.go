//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/containerd/console"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

// With --sibling-interactive, the two-UVM run sets up the link, the network
// and NAT, then keeps both UVMs running and serves a shell for each on
// \\.\pipe\sibling-<name> (workload or diode) until "uvmboot stop" or a UVM
// exits. "uvmboot attach <name>" connects to it.
const (
	siblingInteractiveArgName = "sibling-interactive"
	siblingPipePrefix         = `\\.\pipe\sibling-`
	siblingStopPipe           = siblingPipePrefix + "stop"
)

// The client sends frames: a type byte, a little-endian uint16 length, then
// the payload. The server sends raw terminal output.
const (
	frameInput      = 0 // payload: terminal input
	frameResize     = 1 // payload: uint16 width, uint16 height
	frameHello      = 2 // empty request; response is a JSON container result
	frameImageHello = 3 // empty request; pull and run official hello-world
)

// siblingInteractive is set from --sibling-interactive.
var siblingInteractive bool

var (
	siblingStopOnce sync.Once
	siblingStop     = make(chan struct{})
	siblingStopErr  error
)

// listenSiblingStop serves the stop pipe once per process; the first
// connection closes siblingStop.
func listenSiblingStop() error {
	siblingStopOnce.Do(func() {
		l, err := winio.ListenPipe(siblingStopPipe, nil)
		if err != nil {
			siblingStopErr = fmt.Errorf("listen %s: %w", siblingStopPipe, err)
			return
		}
		go func() {
			conn, err := l.Accept()
			if err == nil {
				_ = conn.Close()
			}
			_ = l.Close()
			close(siblingStop)
		}()
	})
	return siblingStopErr
}

func siblingRoleName(role string) string {
	if role == diodeRole {
		return "diode"
	}
	return "workload"
}

// serveSiblingShells serves shells in vm until a stop request or vm exits.
func serveSiblingShells(ctx context.Context, vm *uvm.UtilityVM, role string, allowContainers bool) error {
	if err := listenSiblingStop(); err != nil {
		return err
	}
	name := siblingRoleName(role)
	pipe := siblingPipePrefix + name
	l, err := winio.ListenPipe(pipe, nil)
	if err != nil {
		return fmt.Errorf("listen %s: %w", pipe, err)
	}
	defer l.Close()
	fmt.Printf("sibling interactive: %s ready, attach with: uvmboot-shmem.exe attach %s\n", name, name)

	exited := make(chan struct{})
	go func() {
		_ = vm.WaitCtx(ctx)
		close(exited)
	}()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go siblingShell(ctx, vm, name, conn, allowContainers)
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-siblingStop:
		fmt.Printf("sibling interactive: %s stopping\n", name)
	case <-exited:
		fmt.Printf("sibling interactive: %s exited\n", name)
	}
	return nil
}

// siblingShell runs the ordinary login-shell protocol for one owned connection.
// It preserves the historical detached input relay, which can still borrow vm
// after this function returns. Protected callers instead use siblingShellSession
// with joining enabled and a server that closes connections on cancellation.
func siblingShell(ctx context.Context, vm *uvm.UtilityVM, name string, conn net.Conn, allowContainers bool) {
	siblingShellSession(ctx, vm, name, conn, allowContainers, false)
}

// siblingShellSession consumes the existing attach protocol and owns conn and
// any guest shell until Wait completes. The session and ordinary detached input
// relay borrow vm. joinInput closes both input-pipe ends and joins that reader
// before returning; the protected server must close conn on context cancellation
// to unblock even the initial frame read. Protocol/start failures end this
// session only, with existing client diagnostics and no backing access.
func siblingShellSession(ctx context.Context, vm *uvm.UtilityVM, name string, conn net.Conn, allowContainers, joinInput bool) {
	defer conn.Close()
	typ, payload, err := readFrame(conn)
	if err == nil && (typ == frameHello || typ == frameImageHello) {
		if !allowContainers {
			message := "Unikraft supports workload attach and stop only; container commands require the containerd-owned Linux pair"
			if joinInput {
				message = "Protected sibling pairs support shell attach and stop only; container commands are unavailable"
			}
			response, _ := json.Marshal(siblingHelloResult{ExitCode: -1,
				Error: message})
			_ = writeFrame(conn, typ, response)
			return
		}
		serveSiblingHello(ctx, vm, name, conn, typ, payload)
		return
	}
	if err != nil || typ != frameResize || len(payload) != 4 {
		return
	}
	c := cmd.CommandContext(ctx, vm, "sh")
	c.Log = log.L.Dup()
	c.Spec.Terminal = true
	// Start in the staged tool directory so the demo helpers (./demo.sh and
	// the staged tcpdump/tc/ipt/covert binaries) are right there.
	c.Spec.Cwd = "/run/dtb-exec"
	c.Spec.Env = append(c.Spec.Env, "TERM=xterm-256color", "HOME=/root", "PS1="+name+":\\w# ",
		"PATH=/run/dtb-exec:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	c.Spec.ConsoleSize = &specs.Box{
		Width:  uint(binary.LittleEndian.Uint16(payload)),
		Height: uint(binary.LittleEndian.Uint16(payload[2:])),
	}
	in, inw := io.Pipe()
	if joinInput {
		defer in.Close()
		defer inw.Close()
	}
	c.Stdin = in
	c.Stdout = conn
	if err := c.Start(); err != nil {
		fmt.Fprintf(conn, "sibling interactive: start shell: %v\r\n", err)
		return
	}
	inputDone := make(chan struct{})
	// This reader owns the writer end until EOF. Protected sessions publish
	// completion only after no frame handler can still borrow the guest process.
	go func() {
		defer close(inputDone)
		defer inw.Close()
		for {
			typ, payload, err := readFrame(conn)
			if err != nil {
				// The client went away: end its shell.
				_, _ = c.Process.Kill(ctx)
				return
			}
			switch typ {
			case frameInput:
				if _, err := inw.Write(payload); err != nil {
					return
				}
			case frameResize:
				if len(payload) == 4 {
					_ = c.Process.ResizeConsole(ctx,
						binary.LittleEndian.Uint16(payload), binary.LittleEndian.Uint16(payload[2:]))
				}
			}
		}
	}()
	_ = c.Wait()
	if joinInput {
		// Wait has released the guest process. Closing both directions also
		// unblocks a frame reader currently writing to the stdin relay, not
		// only a reader waiting for the next client frame.
		_ = conn.Close()
		_ = in.Close()
		_ = inw.Close()
		<-inputDone
	}
}

// protectedSiblingShellServer owns only the protected route's pipe listeners,
// accepted connections and handlers. It never uses the ordinary global stop
// state. mu serializes acceptance with cancellation; wg includes accept loops
// until they can no longer publish handlers. The pair retains this owner through
// close's bounded join, and retains VM/backing ownership if that join fails.
type protectedSiblingShellServer struct {
	ctx       context.Context
	cancel    context.CancelCauseFunc
	listeners []net.Listener
	mu        sync.Mutex
	closing   bool
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
	done      chan struct{}
	stopped   chan struct{}
	closeErr  error
}

// newProtectedSiblingShellServer exclusively acquires the existing stop and
// role pipe names, then starts cancellable accept/connection ownership for the
// two already-started workers. Failure closes acquisitions before returning no
// server. Success borrows both VMs until close joins all handlers; caller must
// invoke close even after wait returns. No guest work or readiness is implied.
func newProtectedSiblingShellServer(parent context.Context, workers []*protectedSiblingVM) (*protectedSiblingShellServer, error) {
	if len(workers) != 2 || workers[0].vm == nil || workers[1].vm == nil ||
		workers[0].role != diodeRole || workers[1].role != workloadRole {
		return nil, errors.New("protected shell server requires the owned diode/workload pair")
	}
	ctx, cancel := context.WithCancelCause(parent)
	s := &protectedSiblingShellServer{
		ctx: ctx, cancel: cancel, conns: make(map[net.Conn]struct{}),
		done: make(chan struct{}), stopped: make(chan struct{}),
	}
	for _, path := range []string{siblingStopPipe, siblingPipePrefix + "diode", siblingPipePrefix + "workload"} {
		listener, err := winio.ListenPipe(path, nil)
		if err != nil {
			cancel(nil)
			for _, owned := range s.listeners {
				err = errors.Join(err, owned.Close())
			}
			return nil, fmt.Errorf("acquire protected interactive pipe %s: %w", path, err)
		}
		s.listeners = append(s.listeners, listener)
	}
	// All accept loops are counted before Wait begins. A loop keeps its
	// reference while adding handlers, so zero cannot race a later Add.
	s.wg.Add(4)
	go s.acceptStop()
	for i, v := range workers {
		go s.acceptShells(s.listeners[i+1], v)
	}
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		// Serialize the close sweep with publication; handlers accepted
		// after cancellation are closed without acquiring VM ownership.
		s.mu.Lock()
		s.closing = true
		for _, listener := range s.listeners {
			s.closeErr = errors.Join(s.closeErr, listener.Close())
		}
		for conn := range s.conns {
			s.closeErr = errors.Join(s.closeErr, conn.Close())
		}
		s.mu.Unlock()
	}()
	// A single completion publication covers accept loops, cancellation's
	// close sweep and every shell handler, including its joined input reader.
	go func() {
		s.wg.Wait()
		close(s.done)
	}()
	fmt.Println("protected sibling interactive: attach diode|workload or stop")
	return s, nil
}

// acceptStop accepts one existing-protocol stop connection and cancels this
// server only. Cancellation closes the listener to unblock Accept. An actual
// accept/connection-close failure is a server error, not a successful stop.
func (s *protectedSiblingShellServer) acceptStop() {
	defer s.wg.Done()
	conn, err := s.listeners[0].Accept()
	if err != nil {
		if s.ctx.Err() == nil {
			s.cancel(fmt.Errorf("protected stop accept: %w", err))
		}
		return
	}
	if err := conn.Close(); err != nil {
		s.cancel(fmt.Errorf("protected stop connection: %w", err))
		return
	}
	close(s.stopped)
	s.cancel(nil)
}

// acceptShells publishes each connection under the cancellation lock before
// launching its handler. v and its VM remain pair-owned until close joins.
// No connection may escape cancellation's close sweep; unexpected accept
// failures cancel the whole server rather than silently losing attach.
func (s *protectedSiblingShellServer) acceptShells(listener net.Listener, v *protectedSiblingVM) {
	defer s.wg.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.ctx.Err() == nil {
				s.cancel(fmt.Errorf("protected %s attach accept: %w", v.options.ID, err))
			}
			return
		}
		s.mu.Lock()
		if s.closing || s.ctx.Err() != nil {
			_ = conn.Close()
			s.mu.Unlock()
			return
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		// The handler owns conn and borrows only this role's VM. It withdraws
		// the connection before publishing completion to the pair's join.
		go func(conn net.Conn) {
			defer s.wg.Done()
			siblingShellSession(s.ctx, v.vm, siblingRoleName(v.role), conn, false, true)
			s.mu.Lock()
			delete(s.conns, conn)
			s.mu.Unlock()
		}(conn)
	}
}

// wait observes stop, parent cancellation or an accept failure without
// relinquishing server/VM ownership. An explicit stop returns nil only if no
// failure won cancellation; a racing stop cannot suppress an accept/VM error.
// close must still join all handlers before cleanup.
func (s *protectedSiblingShellServer) wait() error {
	<-s.ctx.Done()
	if cause := context.Cause(s.ctx); cause != context.Canceled {
		return cause
	}
	select {
	case <-s.stopped:
		return nil
	default:
		return context.Cause(s.ctx)
	}
}

// close cancels listeners/connections and joins every owned handler under the
// independent cleanup context. Success proves no shell handler still borrows a
// VM; timeout/error retains this server and all VM/backing owners in the pair.
// It is safe to call again to observe a previously incomplete drain.
func (s *protectedSiblingShellServer) close(ctx context.Context) error {
	s.cancel(nil)
	select {
	case <-s.done:
		return s.closeErr
	case <-ctx.Done():
		return fmt.Errorf("protected shell handlers not drained: %w", ctx.Err())
	}
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, binary.LittleEndian.Uint16(hdr[1:]))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

func writeFrame(w io.Writer, typ byte, payload []byte) error {
	buf := make([]byte, 3+len(payload))
	buf[0] = typ
	binary.LittleEndian.PutUint16(buf[1:], uint16(len(payload)))
	copy(buf[3:], payload)
	_, err := w.Write(buf)
	return err
}

func sizeFrame(sz console.WinSize) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint16(b[:], sz.Width)
	binary.LittleEndian.PutUint16(b[2:], sz.Height)
	return b[:]
}

var siblingAttachCommand = cli.Command{
	Name:      "attach",
	Usage:     "Open a shell in a running interactive sibling UVM",
	ArgsUsage: "workload|diode",
	Action: func(c *cli.Context) error {
		name := c.Args().First()
		if name != "workload" && name != "diode" {
			return errors.New("usage: attach workload|diode")
		}
		timeout := 5 * time.Second
		conn, err := winio.DialPipe(siblingPipePrefix+name, &timeout)
		if err != nil {
			return fmt.Errorf("connect to %s (is the pair running?): %w", name, err)
		}
		defer conn.Close()
		con := console.Current()
		sz, err := con.Size()
		if err != nil {
			return fmt.Errorf("console size: %w", err)
		}
		if err := writeFrame(conn, frameResize, sizeFrame(sz)); err != nil {
			return err
		}
		if err := con.SetRaw(); err != nil {
			return err
		}
		defer func() { _ = con.Reset() }()

		var mu sync.Mutex
		send := func(typ byte, p []byte) error {
			mu.Lock()
			defer mu.Unlock()
			return writeFrame(conn, typ, p)
		}
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := con.Read(buf)
				if n > 0 && send(frameInput, buf[:n]) != nil {
					return
				}
				if err != nil {
					return
				}
			}
		}()
		// Windows has no SIGWINCH, so poll the console size.
		go func() {
			last := sz
			for range time.Tick(500 * time.Millisecond) {
				cur, err := con.Size()
				if err == nil && cur != last {
					last = cur
					if send(frameResize, sizeFrame(cur)) != nil {
						return
					}
				}
			}
		}()
		_, _ = io.Copy(os.Stdout, conn)
		return nil
	},
}

var siblingStopCommand = cli.Command{
	Name:  "stop",
	Usage: "Stop a running interactive sibling pair",
	Action: func(c *cli.Context) error {
		timeout := 5 * time.Second
		conn, err := winio.DialPipe(siblingStopPipe, &timeout)
		if err != nil {
			return fmt.Errorf("connect to %s (is the pair running?): %w", siblingStopPipe, err)
		}
		return conn.Close()
	},
}
