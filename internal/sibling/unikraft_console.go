//go:build windows

package sibling

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
)

// CaptureUnikraftConsole records output and checks the existing boot markers.
func CaptureUnikraftConsole(reader io.Reader, output io.Writer, ready chan<- time.Time, expectedIdle string) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 65536)
	snp, offers, provider, reported := false, false, false, false
	idleVerified := false
	relayDetail := ""
	for scanner.Scan() {
		line := scanner.Text()
		if _, err := fmt.Fprintln(output, line); err != nil {
			return err
		}
		if strings.Contains(line, "diode-gcs: IO port ") {
			relayDetail = line
		}
		if strings.Contains(line, "diode-gcs: session failed:") {
			if relayDetail != "" {
				return fmt.Errorf("Unikraft workload management relay failed: %s; %s", relayDetail, line)
			}
			return fmt.Errorf("Unikraft workload management relay failed: %s", line)
		}
		snp = snp || strings.Contains(line, "hyperv: isolation type 2 (SNP), paravisor absent")
		offers = offers || strings.Contains(line, "vmbus: all offers delivered")
		if _, value, ok := strings.Cut(line, "vmbus: idle="); ok {
			fields := strings.Fields(value)
			if len(fields) == 0 || fields[0] != expectedIdle {
				return fmt.Errorf("unikraft idle policy mismatch: expected=%s reported=%q", expectedIdle, value)
			}
			idleVerified = true
		}
		if _, version, ok := strings.Cut(line, "sibling: provider ready protocol="); ok {
			fields := strings.Fields(version)
			if len(fields) == 0 {
				return errors.New("unikraft provider omitted its transport version")
			}
			actual, err := strconv.Atoi(strings.TrimSuffix(fields[0], ";"))
			if err != nil || actual != TransportVersion {
				return fmt.Errorf("unikraft provider transport version mismatch: expected=%d actual=%s", TransportVersion, fields[0])
			}
			provider = true
		}
		if snp && offers && provider && idleVerified && !reported {
			ready <- time.Now()
			reported = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return io.EOF
}

type ownedUnikraftConsole struct {
	cancel    context.CancelFunc
	ready     chan time.Time
	done      chan struct{}
	err       error
	log       *os.File
	closeOnce sync.Once
	closeErr  error
}

func newOwnedUnikraftConsole(pipe, directory, idle string) (*ownedUnikraftConsole, error) {
	listener, err := winio.ListenPipe(pipe, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)",
	})
	if err != nil {
		return nil, err
	}
	log, err := os.Create(filepath.Join(directory, "unikraft-console.log"))
	if err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	ctx, cancel := context.WithCancel(context.Background())
	console := &ownedUnikraftConsole{
		cancel: cancel, ready: make(chan time.Time, 1), done: make(chan struct{}), log: log,
	}
	go func() {
		defer close(console.done)
		stopAccept := context.AfterFunc(ctx, func() { _ = listener.Close() })
		defer stopAccept()
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			console.err = err
			return
		}
		defer conn.Close()
		stopRead := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stopRead()
		console.err = CaptureUnikraftConsole(conn, log, console.ready, idle)
	}()
	return console, nil
}

func (c *ownedUnikraftConsole) Done() <-chan struct{} { return c.done }

func (c *ownedUnikraftConsole) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

func (c *ownedUnikraftConsole) waitReady(ctx context.Context) error {
	select {
	case <-c.ready:
		if err := c.Err(); err != nil {
			return fmt.Errorf("Unikraft console ended during boot: %w", err)
		}
		return nil
	case <-c.done:
		return fmt.Errorf("Unikraft boot markers missing: %w", c.err)
	case <-ctx.Done():
		return fmt.Errorf("wait for Unikraft boot markers: %w", ctx.Err())
	}
}

func (c *ownedUnikraftConsole) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		<-c.done
		c.closeErr = c.log.Close()
		if c.err != nil && !errors.Is(c.err, io.EOF) &&
			!errors.Is(c.err, net.ErrClosed) && !errors.Is(c.err, winio.ErrFileClosed) {
			c.closeErr = errors.Join(c.closeErr, c.err)
		}
	})
	return c.closeErr
}
