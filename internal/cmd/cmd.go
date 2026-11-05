//go:build windows

package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Microsoft/hcsshim/internal/cow"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/windows"
)

var errIOTimeOut = errors.New("timed out waiting for stdio relay")

// CmdProcessRequest stores information on command requests made through this package.
type CmdProcessRequest struct {
	Args     []string
	Workdir  string
	Terminal bool
	Stdin    string
	Stdout   string
	Stderr   string
}

// Cmd represents a command being prepared or run in a process host.
type Cmd struct {
	// Host is the process host in which to launch the process.
	Host cow.ProcessHost

	// The OCI spec for the process.
	Spec *specs.Process

	// Standard IO streams to relay to/from the process.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Log provides a logrus entry to use in logging IO copying status.
	Log *logrus.Entry

	// Context provides a context that terminates the process when it is done.
	Context context.Context

	// JoinBackgroundOperations opts into complete command-owned stdin and
	// cancellation drainage before Wait returns or closes Process. Configure
	// it before Start and do not mutate Cmd while it runs. A nonnil Stdin must
	// implement io.ReadCloser: native process creation transfers that reader
	// to Cmd, including on subsequent relay-setup failure. Earlier errors leave
	// it caller-owned. Close must promptly unblock Read without waiting for
	// input producers, and permit concurrent use.
	// Wait closes the reader when Process.Wait returns, including on failure;
	// callers must separately stop and join any producers of that input.
	// Native stdin must also be closable so the post-exit timeout can interrupt
	// a blocked write without closing Process before callbacks drain.
	//
	// False preserves detached background operations and caller stdin ownership.
	// This is not a hard timeout: executing native/GCS calls cannot be abandoned;
	// retain the host/VM until Wait actually returns, even on cancellation.
	JoinBackgroundOperations bool

	// CopyAfterExitTimeout is the amount of time after process exit we allow the
	// stdout, stderr relays to continue before forcibly closing them if not
	// already completed. This is primarily a safety step against the HCS when
	// it fails to send a close on the stdout, stderr pipes when the process
	// exits and blocks the relay wait groups forever. In joined mode this
	// budget stays active through the background join and also interrupts a
	// blocked native stdin write by closing that stream, rather than closing
	// Process ahead of callback completion. It cannot interrupt a native call.
	CopyAfterExitTimeout time.Duration

	// Process is usable after successful Start (or Attach). On joined
	// relay-setup failure the retained value is already closed, not a process
	// the caller may Wait on or use for further operations.
	Process cow.Process

	// ExitState is filled out after Wait() (or Run() or Output()) completes.
	ExitState *ExitState

	ioGrp     errgroup.Group
	stdinErr  atomic.Value
	allDoneCh chan struct{}

	// Only the opt-in path uses these owners. Relay preflight captures stream
	// owners before launching; every background Add precedes Start's return,
	// before the caller may Wait. Wait closes cancelStopCh when Process.Wait
	// returns and joins background before Process.Close. Callback errors have
	// one writer each and are read only after the join.
	background    sync.WaitGroup
	stdinCloser   io.ReadCloser
	stdinWriter   io.Closer
	cancelStopCh  chan struct{}
	stdinCloseErr error
	cancelErr     error
}

// ExitState contains whether a process has exited and with which exit code.
type ExitState struct {
	exited bool
	code   int
}

// ExitCode returns the exit code of the process, or -1 if the exit code is not known.
func (s *ExitState) ExitCode() int {
	if !s.exited {
		return -1
	}
	return s.code
}

// ExitError is used when a process exits with a non-zero exit code.
type ExitError struct {
	*ExitState
}

func (err *ExitError) Error() string {
	return fmt.Sprintf("process exited with exit code %d", err.ExitCode())
}

// Additional fields to hcsschema.ProcessParameters used by LCOW.
type lcowProcessParameters struct {
	hcsschema.ProcessParameters
	OCIProcess *specs.Process `json:"OciProcess,omitempty"`
}

// escapeArgs makes a Windows-style escaped command line from a set of arguments.
func escapeArgs(args []string) string {
	escapedArgs := make([]string, len(args))
	for i, a := range args {
		escapedArgs[i] = windows.EscapeArg(a)
	}
	return strings.Join(escapedArgs, " ")
}

// Command makes a Cmd for a given command and arguments.
func Command(host cow.ProcessHost, name string, arg ...string) *Cmd {
	cmd := &Cmd{
		Host: host,
		Spec: &specs.Process{
			Args: append([]string{name}, arg...),
		},
		Log:       log.L.Dup(),
		ExitState: &ExitState{},
	}
	if host.OS() == "windows" {
		cmd.Spec.Cwd = `C:\`
	} else {
		cmd.Spec.Cwd = "/"
		cmd.Spec.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	}
	return cmd
}

// CommandContext makes a Cmd for a given command and arguments. After
// it is launched, the process is killed when the context becomes done.
func CommandContext(ctx context.Context, host cow.ProcessHost, name string, arg ...string) *Cmd {
	cmd := Command(host, name, arg...)
	cmd.Context = ctx
	cmd.Log = log.G(ctx)
	return cmd
}

// Attach wires IO relays to a process the caller has already resolved.
// Counterpart of [Command] / [CommandContext] for the destination side
// of live migration: caller obtains `p` via the host's restore path
// (e.g. gcs.Container.OpenProcessWithIO) and Attach binds the
// process's stdio to the supplied destination streams.
func Attach(ctx context.Context, p cow.Process, stdin io.Reader, stdout, stderr io.Writer) (*Cmd, error) {
	cmd := &Cmd{
		Process:              p,
		Stdin:                stdin,
		Stdout:               stdout,
		Stderr:               stderr,
		Log:                  log.G(ctx).WithField("pid", p.Pid()),
		Context:              ctx,
		ExitState:            &ExitState{},
		allDoneCh:            make(chan struct{}),
		CopyAfterExitTimeout: time.Second,
	}
	if err := cmd.startRelay(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// Start creates a process and starts its command-owned relays/cancellation.
// The caller must call Wait exactly once after success and retain Host through
// completion. JoinBackgroundOperations validates transferable stdin before
// creation; creation failure leaves it caller-owned. A later opt-in relay-setup
// error closes transferred input, attempts Kill and closes the acquired process
// synchronously, with no relays launched. Failure does not promise guest exit.
// Native calls cannot be abandoned on context expiration.
func (c *Cmd) Start() error {
	if c.Host == nil {
		return errors.New("empty ProcessHost")
	}
	if c.JoinBackgroundOperations && c.Stdin != nil {
		if _, ok := c.Stdin.(io.ReadCloser); !ok {
			return errors.New("joined command stdin must be a transferred io.ReadCloser")
		}
	}

	// closed in (*Cmd).Wait; signals command execution is done
	c.allDoneCh = make(chan struct{})

	var x interface{}
	if !c.Host.IsOCI() {
		if c.Spec == nil {
			return errors.New("process spec is required for non-OCI ProcessHost")
		}

		wpp := &hcsschema.ProcessParameters{
			CommandLine:      c.Spec.CommandLine,
			User:             c.Spec.User.Username,
			WorkingDirectory: c.Spec.Cwd,
			EmulateConsole:   c.Spec.Terminal,
			CreateStdInPipe:  c.Stdin != nil,
			CreateStdOutPipe: c.Stdout != nil,
			CreateStdErrPipe: c.Stderr != nil,
		}

		if c.Spec.CommandLine == "" {
			if c.Host.OS() == "windows" {
				wpp.CommandLine = escapeArgs(c.Spec.Args)
			} else {
				wpp.CommandArgs = c.Spec.Args
			}
		}

		environment := make(map[string]string)
		for _, v := range c.Spec.Env {
			s := strings.SplitN(v, "=", 2)
			if len(s) == 2 && len(s[1]) > 0 {
				environment[s[0]] = s[1]
			}
		}
		wpp.Environment = environment

		if c.Spec.ConsoleSize != nil {
			wpp.ConsoleSize = []int32{
				int32(c.Spec.ConsoleSize.Height),
				int32(c.Spec.ConsoleSize.Width),
			}
		}
		x = wpp
	} else {
		lpp := &lcowProcessParameters{
			ProcessParameters: hcsschema.ProcessParameters{
				CreateStdInPipe:  c.Stdin != nil,
				CreateStdOutPipe: c.Stdout != nil,
				CreateStdErrPipe: c.Stderr != nil,
			},
			OCIProcess: c.Spec,
		}
		x = lpp
	}
	if c.Context != nil && c.Context.Err() != nil {
		return c.Context.Err()
	}
	p, err := c.Host.CreateProcess(context.TODO(), x)
	if err != nil {
		return err
	}
	c.Process = p
	if c.Log != nil {
		c.Log = c.Log.WithField("pid", p.Pid())
	}

	if err := c.startRelay(); err != nil {
		if c.JoinBackgroundOperations {
			return c.closeFailedJoinedStart(err)
		}
		return err
	}
	return nil
}

// closeFailedJoinedStart unwinds an acquired process after opt-in relay
// preflight fails, before any command goroutine exists. It closes transferred
// stdin, attempts one synchronous Kill with an uncanceled context, then closes
// Process. All errors are returned; guest exit is not established by this
// cleanup. Caller retains Host through return and handles any surviving guest.
func (c *Cmd) closeFailedJoinedStart(setupErr error) error {
	var inputErr error
	if c.stdinCloser != nil {
		inputErr = c.stdinCloser.Close()
	}
	ctx := context.Background()
	if c.Context != nil {
		ctx = context.WithoutCancel(c.Context)
	}
	_, killErr := c.Process.Kill(ctx)
	return errors.Join(setupErr, inputErr, killErr, c.Process.Close())
}

// startRelay borrows Process and wires stdout/stderr relays plus stdin and
// context cancellation. Opt-in setup validates all streams before launching
// any goroutine, adopts stdin and tracks its final CloseStdin and any Kill.
// Setup errors leave no callbacks running; Start unwinds acquired ownership.
// The ordinary path retains its existing detached stdin/cancellation behavior.
func (c *Cmd) startRelay() error {
	p := c.Process
	stdin, stdout, stderr := p.Stdio()
	if c.JoinBackgroundOperations {
		if c.Stdin != nil {
			var ok bool
			c.stdinCloser, ok = c.Stdin.(io.ReadCloser)
			if !ok {
				return errors.New("joined command stdin must be a transferred io.ReadCloser")
			}
			c.stdinWriter, ok = stdin.(io.Closer)
			if !ok {
				return errors.New("joined command requires closable native stdin")
			}
		}
		if (c.Stdout != nil && stdout == nil) || (c.Stderr != nil && stderr == nil) {
			return errors.New("joined command missing requested native output stream")
		}
		if c.Context != nil {
			c.cancelStopCh = make(chan struct{})
		}
	}
	if c.Stdin != nil {
		// Ordinary stdin stays detached because its caller-owned reader
		// cannot reliably be interrupted. Opt-in stdin transfers an
		// interruptible reader and keeps the final CloseStdin in the join.
		if c.JoinBackgroundOperations {
			c.background.Add(1)
		}
		go func() {
			if c.JoinBackgroundOperations {
				defer c.background.Done()
			}
			_, err := relayIO(stdin, c.Stdin, c.Log, "stdin")
			// Report the stdin copy error. If the process has exited, then the
			// caller may never see it, but if the error was due to a failure in
			// stdin read, then it is likely the process is still running.
			if err != nil {
				c.stdinErr.Store(err)
			}
			// Notify the process that there is no more input.
			err = p.CloseStdin(context.TODO())
			if c.JoinBackgroundOperations {
				c.stdinCloseErr = err
			}
			if err != nil && c.Log != nil {
				c.Log.WithError(err).Warn("failed to close Cmd stdin")
			}
		}()
	}

	if c.Stdout != nil {
		c.ioGrp.Go(func() error {
			_, err := relayIO(c.Stdout, stdout, c.Log, "stdout")
			if cErr := p.CloseStdout(context.TODO()); cErr != nil && c.Log != nil {
				c.Log.WithError(cErr).Warn("failed to close Cmd stdout")
			}
			return err
		})
	}

	if c.Stderr != nil {
		c.ioGrp.Go(func() error {
			_, err := relayIO(c.Stderr, stderr, c.Log, "stderr")
			if cErr := p.CloseStderr(context.TODO()); cErr != nil && c.Log != nil {
				c.Log.WithError(cErr).Warn("failed to close Cmd stderr")
			}
			return err
		})
	}

	if c.Context != nil {
		stop := c.allDoneCh
		if c.JoinBackgroundOperations {
			// Stop future cancellation dispatch after process exit, without
			// stopping the output timeout needed while stdin drains.
			stop = c.cancelStopCh
			c.background.Add(1)
		}
		go func() {
			if c.JoinBackgroundOperations {
				defer c.background.Done()
			}
			select {
			case <-c.Context.Done():
				// Process.Kill (via Process.Signal) will not send an RPC if the
				// provided context in is cancelled (bridge.AsyncRPC will end early)
				ctx := c.Context
				if ctx == nil {
					ctx = context.Background()
				}
				kctx := context.WithoutCancel(ctx)
				_, err := c.Process.Kill(kctx)
				if c.JoinBackgroundOperations {
					c.cancelErr = err
				}
			case <-stop:
			}
		}()
	}
	return nil
}

// Wait waits for the process and output relays, then closes Process. Call it
// exactly once after successful Start. A nonzero exit returns ExitError.
// With JoinBackgroundOperations, Wait also closes transferred stdin when the
// process wait returns (including failure), and joins its relay/final CloseStdin
// and the cancellation goroutine, including any dispatched Kill, before
// Process.Close or return. CopyAfterExitTimeout
// closes individual streams in this mode, not Process ahead of that join.
// Executing native/GCS calls can outlast the timeout; the caller must retain
// Host until return. Ordinary stdin/cancellation remain detached and stdin
// stays caller-owned when the option is false.
func (c *Cmd) Wait() error {
	waitErr := c.Process.Wait()
	if waitErr != nil && c.Log != nil {
		c.Log.WithError(waitErr).Warn("process wait failed")
	}
	state := &ExitState{}
	code, exitErr := c.Process.ExitCode()
	if exitErr == nil {
		state.exited = true
		state.code = code
	}
	var errs []error
	if c.JoinBackgroundOperations {
		if c.cancelStopCh != nil {
			close(c.cancelStopCh)
		}
		if c.stdinCloser != nil {
			// This interrupts source reads but does not wait for an external
			// producer such as an interactive frame reader. That producer
			// must be closed/joined separately by the owning session.
			errs = append(errs, c.stdinCloser.Close())
		}
		errs = append(errs, waitErr)
	}

	// Interrupt streams if copying does not finish in the post-wait budget.
	// Ordinary mode closes Process; joined mode closes individual streams
	// while keeping the process owner alive. timeoutErrCh joins this worker's
	// native operations and error publication before final Process.Close.
	timeoutErrCh := make(chan error)
	if c.CopyAfterExitTimeout != 0 {
		go func() {
			defer close(timeoutErrCh)
			t := time.NewTimer(c.CopyAfterExitTimeout)
			defer t.Stop()
			select {
			case <-c.allDoneCh:
			case <-t.C:
				err := errIOTimeOut
				if c.JoinBackgroundOperations {
					err = errors.New("timed out waiting for joined command streams/background operations")
					// Interrupt stream operations without retiring Process
					// while stdin's CloseStdin or cancellation's Kill may
					// still be in flight. This timeout worker is joined
					// through timeoutErrCh before the final Process.Close.
					if c.stdinWriter != nil {
						err = errors.Join(err, c.stdinWriter.Close())
					}
					if c.Stdout != nil {
						err = errors.Join(err, c.Process.CloseStdout(context.Background()))
					}
					if c.Stderr != nil {
						err = errors.Join(err, c.Process.CloseStderr(context.Background()))
					}
				} else {
					// Preserve ordinary timeout-driven process closure.
					c.Process.Close()
				}
				// log the timeout, since we may not return it to the caller
				if c.Log != nil {
					c.Log.WithField("timeout", c.CopyAfterExitTimeout).Warn(err.Error())
				}
				timeoutErrCh <- err
			}
		}()
	} else {
		close(timeoutErrCh)
	}

	errs = append(errs, c.ioGrp.Wait())
	if c.JoinBackgroundOperations {
		c.background.Wait()
		// The join makes these final callback errors safe to read, including
		// failure after copying or after Process.Wait had already returned.
		errs = append(errs, c.stdinCloseErr, c.cancelErr)
	}
	if err, _ := c.stdinErr.Load().(error); err != nil {
		errs = append(errs, err)
	}
	close(c.allDoneCh)
	if err := <-timeoutErrCh; err != nil {
		errs = append(errs, err)
	}

	if c.JoinBackgroundOperations {
		errs = append(errs, c.Process.Close())
	} else {
		c.Process.Close()
	}
	c.ExitState = state
	if exitErr != nil {
		errs = append(errs, exitErr)
	}
	if state.exited && state.code != 0 {
		errs = append(errs, &ExitError{state})
	}

	return errors.Join(errs...)
}

// Run is equivalent to Start followed by Wait.
func (c *Cmd) Run() error {
	err := c.Start()
	if err != nil {
		return err
	}
	return c.Wait()
}

// Output runs a command via Run and collects its stdout into a buffer,
// which it returns.
func (c *Cmd) Output() ([]byte, error) {
	var b bytes.Buffer
	c.Stdout = &b
	err := c.Run()
	return b.Bytes(), err
}
