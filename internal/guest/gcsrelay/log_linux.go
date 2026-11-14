//go:build linux

package gcsrelay

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/sirupsen/logrus"
)

const logCopyBufferSize = 32 << 10

// startLogRelay performs required setup for RunWithLogging, then starts one
// independent log session. The returned stop cancels and joins its worker.
func startLogRelay(ctx context.Context, d dependencies) (func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	listener, err := d.listen(localCID, guestresource.LinuxLogVsockPort)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("gcsrelay: log listen: %w", err)
	}
	root, err := d.dial(ctx, rootCID, guestresource.GCSRelayLogPort)
	if err != nil {
		listener.Close()
		cancel()
		return nil, fmt.Errorf("gcsrelay: root log dial: %w", err)
	}
	done := make(chan struct{})
	// Diagnose established failures here, outside the control-cancelling launcher.
	go func() {
		defer close(done)
		if err := serveLog(ctx, listener, root, d); err != nil && ctx.Err() == nil {
			logrus.WithError(err).Error("gcsrelay: log stream stopped")
		}
	}()
	// The outer relay must join even when the worker is blocked on socket IO.
	return func() { cancel(); <-done }, nil
}

// closeOnLogCancel closes owned sockets on cancellation; its returned cleanup
// joins the cancellation callback as well, so no closer outlives the log task.
func closeOnLogCancel(ctx context.Context, closeResources func()) func() {
	done := make(chan struct{})
	// Signal completion so cleanup can join an already-running closer.
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		closeResources()
	})
	// A stopped callback will never signal done; only join one that did start.
	return func() {
		if !stop() {
			<-done
		}
	}
}

// serveLog admits one workload peer and copies only workload-to-root bytes.
// EOF closes both legs; no reverse pump, queue, replay or second accept exists.
func serveLog(ctx context.Context, listener net.Listener, root net.Conn, d dependencies) error {
	defer listener.Close()
	defer root.Close()
	// Cancellation must wake both pending accept and a backpressured root write.
	join := closeOnLogCancel(ctx, func() { listener.Close(); root.Close() })
	defer join()
	workload, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("log accept: %w", err)
	}
	defer workload.Close()
	// The accepted peer must also wake a pending read during outer shutdown.
	joinWorkload := closeOnLogCancel(ctx, func() { workload.Close() })
	defer joinWorkload()
	if !d.workloadPeer(workload) {
		return fmt.Errorf("log peer is not workload CID3")
	}
	if err := listener.Close(); err != nil {
		return fmt.Errorf("close log listener: %w", err)
	}
	// Hide optional fast paths to guarantee one fixed userspace copy buffer.
	_, err = io.CopyBuffer(struct{ io.Writer }{root}, struct{ io.Reader }{workload}, make([]byte, logCopyBufferSize))
	if err != nil {
		return fmt.Errorf("log copy: %w", err)
	}
	return nil
}
