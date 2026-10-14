//go:build windows

package main

import (
	"context"
	"encoding/binary"
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
	frameInput  = 0 // payload: terminal input
	frameResize = 1 // payload: uint16 width, uint16 height
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
func serveSiblingShells(ctx context.Context, vm *uvm.UtilityVM, role string) error {
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
			go siblingShell(ctx, vm, name, conn)
		}
	}()
	select {
	case <-siblingStop:
		fmt.Printf("sibling interactive: %s stopping\n", name)
	case <-exited:
		fmt.Printf("sibling interactive: %s exited\n", name)
	}
	return nil
}

// siblingShell runs a login shell with a TTY in vm for one client.
func siblingShell(ctx context.Context, vm *uvm.UtilityVM, name string, conn net.Conn) {
	defer conn.Close()
	typ, payload, err := readFrame(conn)
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
	c.Stdin = in
	c.Stdout = conn
	if err := c.Start(); err != nil {
		fmt.Fprintf(conn, "sibling interactive: start shell: %v\r\n", err)
		return
	}
	go func() {
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
