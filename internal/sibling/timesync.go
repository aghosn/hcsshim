//go:build windows

package sibling

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/timesync"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/windows"
)

const timesyncRelayReadyPath = "/run/sibling-exec/timesync-relay.ready"

// pairTimesync owns external pumps separately from Cmd's transferred stdin and
// process/output callbacks. Native termination never waits for either owner.
type pairTimesync struct {
	pair          *protectedPair
	command       *cmd.Cmd
	input         *io.PipeReader
	requests      *io.PipeWriter
	responses     *io.PipeReader
	output        *io.PipeWriter
	connected     chan struct{}
	processExited chan struct{}
	providerReady bool // Published by bootstrap before seal/handoff checks.
	workers       sync.WaitGroup
	waitErr       error // Read only after workers join.
	mu            sync.Mutex
	conn          net.Conn
	closed        bool
}

// timesyncCommandHost preserves NewJoinedGuestCommand's creation context and
// ownership, adapting only protocol stdout for completion supervision.
type timesyncCommandHost struct {
	cow.ProcessHost
}

// CreateProcess keeps the actual process owner and all its close/wait methods.
// The adapter changes only the stdout reader exposed to Cmd's relay.
func (h timesyncCommandHost) CreateProcess(ctx context.Context, settings interface{}) (cow.Process, error) {
	process, err := h.ProcessHost.CreateProcess(ctx, settings)
	if err != nil {
		return process, err
	}
	return &timesyncCommandProcess{Process: process}, nil
}

// timesyncCommandProcess borrows the original process; Cmd still owns its
// streams, callbacks and final Close through the unchanged joined path.
type timesyncCommandProcess struct {
	cow.Process
}

// Stdio hides stdout WriterTo because io.Copy prioritizes it over the
// destination's ReaderFrom. GCS currently exposes an ioChannel (Read/Write/Close,
// no WriterTo), but supervision must not silently disappear if that changes.
// Native stdin closability and the independent diagnostic stderr are preserved.
func (p *timesyncCommandProcess) Stdio() (io.Writer, io.Reader, io.Reader) {
	stdin, stdout, stderr := p.Process.Stdio()
	if stdout != nil {
		stdout = struct{ io.Reader }{Reader: stdout}
	}
	return stdin, stdout, stderr
}

// timesyncCommandInput transfers the same interruptible PipeReader to Cmd.
// Its WriterTo observes the entire stdin copy, including native write failure.
type timesyncCommandInput struct {
	*io.PipeReader
	relay *pairTimesync
}

// WriteTo reports protocol stdin completion before Cmd closes native stdin or
// waits for process exit. EOF is loss too: this is a pair-lifetime stream.
func (s *timesyncCommandInput) WriteTo(dst io.Writer) (int64, error) {
	n, err := io.Copy(struct{ io.Writer }{Writer: dst}, struct{ io.Reader }{Reader: s.PipeReader})
	s.relay.fail(errors.Join(errors.New("protected timesync protocol stdin copy ended unexpectedly"), err))
	return n, err
}

// timesyncCommandOutput observes Cmd's stdout copy, rather than waiting for
// process exit to expose its result. Stdio guarantees ReaderFrom dispatch.
type timesyncCommandOutput struct {
	*io.PipeWriter
	relay *pairTimesync
}

// ReadFrom reports stdout EOF/read/write failure and interrupts external pumps
// before Cmd's CloseStdout or any joins. Reader/writer-only views keep this inner
// copy from bypassing supervision through another optimized copy method.
func (s *timesyncCommandOutput) ReadFrom(src io.Reader) (int64, error) {
	n, err := io.Copy(struct{ io.Writer }{Writer: s.PipeWriter}, struct{ io.Reader }{Reader: src})
	s.relay.fail(errors.Join(errors.New("protected timesync protocol stdout copy ended unexpectedly"), err))
	return n, err
}

// startTimesync creates the separate foreground diode relay before workload
// Start, without waiting for its device or native pipe. Creation/acquisition use
// setup budgets; established I/O and exit observation retain the pair lifetime.
// Any terminal process/pump loss stops the pair, independently of I/O drainage.
func (p *protectedPair) startTimesync(setup context.Context) error {
	if err := setup.Err(); err != nil {
		return err
	}
	if err := p.ctx.Err(); err != nil {
		return context.Cause(p.ctx)
	}
	t := &pairTimesync{
		pair: p, connected: make(chan struct{}), processExited: make(chan struct{}),
	}
	t.input, t.requests = io.Pipe()
	t.responses, t.output = io.Pipe()
	p.timesync = t
	command := NewJoinedGuestCommand(setup, p.diode.vm, "/bin/gcs",
		"-sibling-timesync-relay", "-relay-ready", timesyncRelayReadyPath)
	// Only CreateProcess borrows setup. As with startService, the native VM
	// owner stops the foreground process; no expiring RPC context owns it.
	command.Context = nil
	command.Host = timesyncCommandHost{ProcessHost: command.Host}
	command.Stdin = &timesyncCommandInput{PipeReader: t.input, relay: t}
	command.Stdout = &timesyncCommandOutput{PipeWriter: t.output, relay: t}
	command.Stderr = p.log
	command.Log = command.Log.WithField("protected_run", p.config.RunID).WithField("vm", p.diode.options.ID)
	t.command = command
	if err := command.Start(); err != nil {
		// Before creation stdin is ours; after creation it is transferred and
		// Cmd's failed-start path closes it. Pipe Close is safe in both cases.
		t.stopIO()
		_ = t.input.Close()
		return fmt.Errorf("protected timesync process create uncertain: %w", err)
	}
	acquire, cancelAcquire := context.WithTimeout(setup, protectedPairGCSBudget)
	t.workers.Add(3)
	go t.observeProcess()
	go func() {
		defer t.workers.Done()
		<-p.ctx.Done()
		t.stopIO()
	}()
	go func() {
		defer t.workers.Done()
		defer cancelAcquire()
		t.bridge(acquire)
	}()
	return nil
}

// observeProcess reports exit before Cmd.Wait joins any command-owned output or
// stdin work. External pipe closure unblocks those borrowers without guest ack.
func (t *pairTimesync) observeProcess() {
	defer t.workers.Done()
	err := t.command.Process.Wait()
	close(t.processExited)
	t.fail(errors.Join(errors.New("protected timesync process exited unexpectedly"), err))
	t.waitErr = t.command.Wait()
}

// bridge acquires the immutable workload endpoint and pumps complete IC
// records. Acquisition cancellation does not shorten a connected pipe lifetime.
func (t *pairTimesync) bridge(acquire context.Context) {
	name := `\\.\pipe\hcs-timesync-` + strings.ToLower(t.pair.workload.options.TimesyncRelayID.String())
	conn, err := acquireTimesyncPipe(acquire, name)
	if err != nil {
		t.fail(fmt.Errorf("protected timesync pipe acquisition: %w", err))
		return
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = conn.Close()
		return
	}
	t.conn = conn
	close(t.connected)
	t.mu.Unlock()

	var pumps errgroup.Group
	pumps.Go(func() error {
		err := pumpTimesyncRecords(t.requests, conn, timesync.Request)
		t.fail(fmt.Errorf("protected timesync requests: %w", err))
		return err
	})
	pumps.Go(func() error {
		// Stdout is a stream, not message-framed. Reassembly preserves native
		// padding and each response becomes exactly one Windows pipe Write.
		err := pumpTimesyncRecords(conn, t.responses, timesync.Response)
		t.fail(fmt.Errorf("protected timesync responses: %w", err))
		return err
	})
	_ = pumps.Wait()
}

// acquireTimesyncPipe also waits for initial endpoint creation during native
// boot. go-winio retries busy pipes, but a not-yet-created pipe needs this bounded
// wait. Established connection loss is never retried.
func acquireTimesyncPipe(ctx context.Context, name string) (net.Conn, error) {
	for {
		conn, err := winio.DialPipeContext(ctx, name)
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return conn, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// pumpTimesyncRecords forwards validated original records without resampling or
// transaction policy. WriteRecord never retries a short message-pipe write.
func pumpTimesyncRecords(dst io.Writer, src io.Reader, direction timesync.Direction) error {
	for {
		record, err := timesync.ReadRecord(src, direction)
		if err != nil {
			return err
		}
		if err := timesync.WriteRecord(dst, record, direction); err != nil {
			return err
		}
	}
}

// fail requests the existing native stop path before retiring ordinary I/O.
// No joins, native ownership locks or guest acknowledgments occur here.
func (t *pairTimesync) fail(err error) {
	if t.pair.ctx.Err() == nil {
		t.pair.stop(err)
	}
	t.stopIO()
}

// stopIO excludes late connection publication and interrupts external pumps.
// It neither joins Cmd nor closes its transferred stdin reader after success.
func (t *pairTimesync) stopIO() {
	t.mu.Lock()
	t.closed = true
	conn := t.conn
	t.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	_ = t.requests.Close()
	_ = t.responses.Close()
	_ = t.output.Close()
}

// waitReady requires connection and validated device setup, not a fresh sample.
// Guest readiness and native connection may overlap workload boot/GCS startup.
func (t *pairTimesync) waitReady(setup context.Context) error {
	select {
	case <-setup.Done():
		return context.Cause(setup)
	case <-t.connected:
	}
	if _, err := t.pair.guest(setup, &t.pair.diode,
		`until [ -f `+timesyncRelayReadyPath+` ]; do sleep 0.1; done`); err != nil {
		return err
	}
	t.providerReady = true
	return t.check()
}

// check rejects dead or incompletely acquired time services before handoff.
func (t *pairTimesync) check() error {
	if err := t.pair.ctx.Err(); err != nil {
		return context.Cause(t.pair.ctx)
	}
	select {
	case <-t.processExited:
		return errors.New("protected timesync process ended before handoff")
	default:
	}
	select {
	case <-t.connected:
	default:
		return errors.New("protected timesync native pipe is not connected")
	}
	if !t.providerReady {
		return errors.New("protected timesync provider setup is not ready")
	}
	return nil
}

// join retires ordinary time resources after native cleanup and startup
// publication. Cmd.Wait has joined transferred stdin/process/output ownership;
// workers additionally cover the external pumps and pipe acquisition.
func (t *pairTimesync) join() error {
	t.stopIO()
	t.workers.Wait()
	return t.waitErr
}
