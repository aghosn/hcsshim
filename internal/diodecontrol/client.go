package diodecontrol

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type CapabilitiesInfo struct {
	Controller, MaxExports, BootExports uint16
	Operations                          uint32
}

type Export struct {
	Token, Sectors      uint64
	References          uint32
	Controller, RootLUN uint16
	LUN, Flags          byte
}

type StatusError struct {
	Operation uint16
	Status    uint32
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("diode operation %d returned status %d", e.Operation, e.Status)
}

type pendingCall struct {
	operation uint16
	reply     chan Frame
}

// Client owns one connection and never reconnects or replays mutations.
// A timed-out response remains correlated until received; subsequent queries
// can establish state in the same session without mistaking that late reply.
type Client struct {
	conn       net.Conn
	mu         sync.Mutex
	pending    map[uint64]pendingCall
	next       uint64
	session    uint64
	err        error
	done       chan struct{}
	send       chan struct{}
	operations chan struct{}
	caps       CapabilitiesInfo
}

func NewClient(ctx context.Context, conn net.Conn) (*Client, error) {
	if conn == nil {
		return nil, errors.New("diode control requires a connection")
	}
	c := &Client{
		conn: conn, pending: make(map[uint64]pendingCall), done: make(chan struct{}),
		send: make(chan struct{}, 1), operations: make(chan struct{}, 1),
	}
	go c.receive()
	frame, err := c.request(ctx, Capabilities, nil)
	if err != nil {
		c.fail(err)
		return nil, err
	}
	p := frame.Body
	c.caps = CapabilitiesInfo{
		Controller:  binary.LittleEndian.Uint16(p),
		MaxExports:  binary.LittleEndian.Uint16(p[2:]),
		BootExports: binary.LittleEndian.Uint16(p[4:]),
		Operations:  binary.LittleEndian.Uint32(p[8:]),
	}
	if c.caps.Controller != 0 || c.caps.Operations != StorageOperations {
		err = errors.New("diode does not provide the required single-controller storage operations")
		c.fail(err)
		return nil, err
	}
	return c, nil
}

func (c *Client) Done() <-chan struct{} { return c.done }

func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Client) Close() error {
	return c.fail(net.ErrClosed)
}

func (c *Client) Capabilities() CapabilitiesInfo { return c.caps }

func (c *Client) fail(err error) error {
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return nil
	}
	c.err = err
	close(c.done)
	c.mu.Unlock()
	return c.conn.Close()
}

func (c *Client) receive() {
	for {
		frame, err := ReadFrame(c.conn)
		if err != nil {
			c.fail(err)
			return
		}
		c.mu.Lock()
		call, ok := c.pending[frame.Header.Request]
		valid := ok && frame.Header.Flags == Response &&
			frame.Header.Service == Storage && frame.Header.Operation == call.operation
		if valid && c.session == 0 && call.operation == Capabilities {
			c.session = frame.Header.Session
		}
		valid = valid && frame.Header.Session == c.session
		if valid {
			delete(c.pending, frame.Header.Request)
		}
		c.mu.Unlock()
		if !valid {
			c.fail(errors.New("uncorrelated diode control response or changed session"))
			return
		}
		call.reply <- frame
	}
}

func acquire(ctx context.Context, gate chan struct{}, done <-chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return net.ErrClosed
	}
}

func (c *Client) request(ctx context.Context, operation uint16, body []byte) (Frame, error) {
	if err := acquire(ctx, c.send, c.done); err != nil {
		return Frame{}, err
	}
	c.mu.Lock()
	if c.err != nil || len(c.pending) >= 32 || c.next == ^uint64(0) {
		err := c.err
		c.mu.Unlock()
		<-c.send
		if err == nil {
			err = errors.New("diode control correlation limit reached")
			c.fail(err)
		}
		return Frame{}, err
	}
	c.next++
	id, session := c.next, c.session
	call := pendingCall{operation: operation, reply: make(chan Frame, 1)}
	c.pending[id] = call
	c.mu.Unlock()
	data, err := (Frame{Header: Header{
		Service: Storage, Operation: operation, Length: uint32(HeaderSize + len(body)),
		Request: id, Session: session,
	}, Body: body}).MarshalBinary()
	if err == nil {
		stopped := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			if err := c.conn.SetWriteDeadline(time.Now()); err != nil {
				c.fail(err)
			}
			close(stopped)
		})
		if deadline, ok := ctx.Deadline(); ok {
			err = c.conn.SetWriteDeadline(deadline)
		}
		for len(data) != 0 && err == nil {
			var n int
			n, err = c.conn.Write(data)
			if n == 0 && err == nil {
				err = io.ErrShortWrite
			}
			data = data[n:]
		}
		if !stop() {
			<-stopped
		}
		err = errors.Join(err, c.conn.SetWriteDeadline(time.Time{}))
	}
	if err != nil {
		c.fail(err) // A partial frame cannot be followed by another request.
		<-c.send
		return Frame{}, err
	}
	<-c.send
	select {
	case frame := <-call.reply:
		if frame.Header.Status != OK {
			return frame, &StatusError{Operation: operation, Status: frame.Header.Status}
		}
		return frame, nil
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	case <-c.done:
		return Frame{}, c.Err()
	}
}

func (c *Client) query(ctx context.Context) ([]Export, error) {
	frame, err := c.request(ctx, Query, nil)
	if err != nil {
		return nil, err
	}
	count := int(binary.LittleEndian.Uint16(frame.Body))
	if count > int(c.caps.MaxExports) {
		return nil, errors.New("diode query exceeds advertised export limit")
	}
	exports := make([]Export, count)
	boots := 0
	for i := range count {
		p := frame.Body[QuerySize+i*ExportSize:]
		exports[i] = Export{
			Token: binary.LittleEndian.Uint64(p), Sectors: binary.LittleEndian.Uint64(p[8:]),
			References: binary.LittleEndian.Uint32(p[16:]),
			Controller: binary.LittleEndian.Uint16(p[20:]), RootLUN: binary.LittleEndian.Uint16(p[22:]),
			LUN: p[24], Flags: p[25],
		}
		e := exports[i]
		if e.Controller != c.caps.Controller || e.RootLUN >= 64 {
			return nil, errors.New("invalid diode root storage address")
		}
		for _, prior := range exports[:i] {
			if prior.RootLUN == e.RootLUN {
				return nil, errors.New("duplicate diode root backing")
			}
		}
		if e.Flags&Boot != 0 {
			boots++
		}
	}
	if boots != int(c.caps.BootExports) {
		return nil, errors.New("diode boot export count changed")
	}
	return exports, nil
}

func (c *Client) Query(ctx context.Context) ([]Export, error) {
	if err := acquire(ctx, c.operations, c.done); err != nil {
		return nil, err
	}
	defer func() { <-c.operations }()
	return c.query(ctx)
}

func mutation(controller, root uint, lun uint8, token uint64, readOnly bool) []byte {
	p := make([]byte, MutationSize)
	binary.LittleEndian.PutUint64(p, token)
	binary.LittleEndian.PutUint16(p[8:], uint16(controller))
	binary.LittleEndian.PutUint16(p[10:], uint16(root))
	p[12] = lun
	if readOnly {
		p[13] = ReadOnly
	}
	return p
}

func validateDynamic(lun uint8, token uint64) error {
	if lun == 0 || lun == 255 || token == 0 {
		return errors.New("dynamic diode exports require LUN 1..254 and a nonzero token")
	}
	return nil
}

func (c *Client) Add(ctx context.Context, controller, root uint, lun uint8, token uint64, readOnly bool) error {
	if err := validateDynamic(lun, token); err != nil {
		return err
	}
	if controller != uint(c.caps.Controller) || root >= 64 {
		return errors.New("invalid diode backing address")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := acquire(ctx, c.operations, c.done); err != nil {
		return err
	}
	defer func() { <-c.operations }()
	confirm := func() (bool, error) {
		exports, err := c.query(ctx)
		if err != nil {
			return false, err
		}
		for _, e := range exports {
			if e.LUN == lun {
				if e.Token == token && e.Controller == uint16(controller) &&
					e.RootLUN == uint16(root) && e.Flags&Retiring == 0 &&
					(e.Flags&ReadOnly != 0) == readOnly {
					return true, nil
				}
				return false, errors.New("diode export tuple conflicts or is retiring")
			}
		}
		return false, nil
	}
	for {
		if found, err := confirm(); found || err != nil {
			return err
		}
		replyCtx, stop := context.WithTimeout(ctx, time.Second)
		_, writeErr := c.request(replyCtx, Add, mutation(controller, root, lun, token, readOnly))
		stop()
		found, err := confirm()
		if found && err == nil {
			return nil
		}
		var status *StatusError
		if err == nil && errors.As(writeErr, &status) && status.Status == Busy {
			if err := retry(ctx); err != nil {
				return err
			}
			continue // Explicitly rejected, and absence confirmed in this session.
		}
		return errors.Join(writeErr, err, fmt.Errorf("diode LUN %d publication was not confirmed", lun))
	}
}

func retry(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) Remove(ctx context.Context, lun uint8, token uint64) error {
	if err := validateDynamic(lun, token); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := acquire(ctx, c.operations, c.done); err != nil {
		return err
	}
	defer func() { <-c.operations }()
	for {
		exports, err := c.query(ctx)
		if err != nil {
			return err
		}
		present := false
		for _, e := range exports {
			if e.LUN != lun {
				continue
			}
			if e.Token != token {
				return errors.New("refusing stale diode export removal")
			}
			present = true
		}
		if !present {
			return nil
		}
		replyCtx, stop := context.WithTimeout(ctx, time.Second)
		_, err = c.request(replyCtx, Remove, mutation(0, 0, lun, token, false))
		stop()
		var status *StatusError
		if err != nil && !errors.Is(err, context.DeadlineExceeded) &&
			(!errors.As(err, &status) || (status.Status != Pending && status.Status != Busy && status.Status != NotFound)) {
			return err
		}
		if err := retry(ctx); err != nil {
			return fmt.Errorf("diode withdrawal unconfirmed; retain backing: %w", err)
		}
	}
}

func (c *Client) Quiesce(ctx context.Context, controller, root uint) error {
	if controller != uint(c.caps.Controller) || root >= 64 {
		return errors.New("invalid diode quiescence address")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := acquire(ctx, c.operations, c.done); err != nil {
		return err
	}
	defer func() { <-c.operations }()
	for {
		_, err := c.request(ctx, Quiesce, mutation(controller, root, 0, 0, false))
		if err == nil {
			return nil
		}
		var status *StatusError
		if !errors.As(err, &status) || (status.Status != Pending && status.Status != Busy) {
			return err
		}
		if err := retry(ctx); err != nil {
			return fmt.Errorf("diode root backing still owned: %w", err)
		}
	}
}
