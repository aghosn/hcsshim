//go:build windows

package sibling

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type pairShells struct {
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	listeners []net.Listener
	conns     map[net.Conn]struct{}
	closed    bool
}

func startPairShells(pair *Pair) (*pairShells, error) {
	ctx, cancel := context.WithCancel(context.Background())
	server := &pairShells{ctx: ctx, cancel: cancel, conns: make(map[net.Conn]struct{})}
	for _, peer := range []struct {
		name string
		vm   *uvm.UtilityVM
	}{{"workload", pair.Workload}, {"diode", pair.Diode}} {
		listener, err := winio.ListenPipe(`\\.\pipe\sibling-`+peer.name, &winio.PipeConfig{
			SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)",
		})
		if err != nil {
			return nil, errors.Join(err, server.Close())
		}
		server.listeners = append(server.listeners, listener)
		go server.accept(listener, peer.vm, peer.name)
	}
	return server, nil
}

func (s *pairShells) accept(listener net.Listener, vm *uvm.UtilityVM, name string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		go func() {
			defer func() {
				_ = conn.Close()
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			servePairShell(s.ctx, vm, name, conn)
		}()
	}
}

func (s *pairShells) Close() error {
	s.cancel()
	s.mu.Lock()
	s.closed = true
	listeners := append([]net.Listener(nil), s.listeners...)
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	var result error
	for _, listener := range listeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	for _, conn := range conns {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
			result = errors.Join(result, err)
		}
	}
	return result
}

func readShellFrame(reader io.Reader) (byte, []byte, error) {
	var header [3]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, binary.LittleEndian.Uint16(header[1:]))
	_, err := io.ReadFull(reader, payload)
	return header[0], payload, err
}

func servePairShell(ctx context.Context, vm *uvm.UtilityVM, name string, conn net.Conn) {
	kind, payload, err := readShellFrame(conn)
	if err != nil {
		return
	}
	if kind != 1 || len(payload) != 4 {
		_, _ = fmt.Fprint(conn, "Use run.ps1 container for the containerd-managed image lifecycle.\r\n")
		return
	}
	shellCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := cmd.CommandContext(shellCtx, vm, "sh")
	command.Spec.Terminal = true
	command.Spec.Cwd = "/"
	command.Spec.Env = append(command.Spec.Env, "TERM=xterm-256color", "HOME=/root", "PS1="+name+":\\w# ",
		"PATH=/run/sibling-exec:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	command.Spec.ConsoleSize = &specs.Box{
		Width: uint(binary.LittleEndian.Uint16(payload)), Height: uint(binary.LittleEndian.Uint16(payload[2:])),
	}
	input, writer := io.Pipe()
	defer input.Close()
	command.Stdin, command.Stdout = input, conn
	if err := command.Start(); err != nil {
		_, _ = fmt.Fprintf(conn, "Start sibling shell: %v\r\n", err)
		_ = writer.Close()
		return
	}
	go func() {
		defer writer.Close()
		defer cancel()
		for {
			kind, payload, err := readShellFrame(conn)
			if err != nil {
				return
			}
			switch kind {
			case 0:
				if _, err := writer.Write(payload); err != nil {
					return
				}
			case 1:
				if len(payload) == 4 {
					_ = command.Process.ResizeConsole(shellCtx,
						binary.LittleEndian.Uint16(payload), binary.LittleEndian.Uint16(payload[2:]))
				}
			}
		}
	}()
	_ = command.Wait()
}
