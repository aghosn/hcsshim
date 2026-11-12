//go:build linux

package gcsrelay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Microsoft/hcsshim/internal/guest/prot"
	"github.com/sirupsen/logrus"
)

type operationCounter struct {
	Frames uint64 `json:"frames"`
	Bytes  uint64 `json:"bytes"`
}

type relayMetrics struct {
	enabled atomic.Bool
	mu      sync.Mutex
	frames  map[string]operationCounter
	rootIO  atomic.Uint64
	guestIO atomic.Uint64
	serial  uint64
}

func (m *relayMetrics) frame(kind prot.MessageIdentifier, size uint32) {
	if m == nil || !m.enabled.Load() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s (%#08x)", kind, uint32(kind))
	counter := m.frames[key]
	counter.Frames++
	counter.Bytes += uint64(size)
	m.frames[key] = counter
}

func (m *relayMetrics) publish(path string, enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if enable {
		m.enabled.Store(true)
	}
	m.serial++
	snapshot := struct {
		Version          int                         `json:"version"`
		PID              int                         `json:"pid"`
		Enabled          bool                        `json:"enabled"`
		Generation       uint64                      `json:"generation"`
		TimeUTC          time.Time                   `json:"time_utc"`
		Operations       map[string]operationCounter `json:"operations"`
		RootToWorkloadIO uint64                      `json:"root_to_workload_io_bytes"`
		WorkloadToRootIO uint64                      `json:"workload_to_root_io_bytes"`
	}{1, os.Getpid(), m.enabled.Load(), m.serial, time.Now().UTC(),
		m.frames, m.rootIO.Load(), m.guestIO.Load()}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".pending", data, 0600); err != nil {
		return err
	}
	return os.Rename(path+".pending", path)
}

func startRelayMetrics(ctx context.Context, path string) (*relayMetrics, func(), error) {
	m := &relayMetrics{frames: make(map[string]operationCounter)}
	if err := m.publish(path, false); err != nil {
		return nil, nil, fmt.Errorf("gcsrelay: initialize metrics: %w", err)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-signals:
				if err := m.publish(path, true); err != nil {
					logrus.WithError(err).Error("gcsrelay: publish metrics")
				}
			}
		}
	}()
	return m, func() {
		signal.Stop(signals)
		cancel()
		<-done
	}, nil
}

type countedStreamWriter struct {
	io.Writer
	counter *atomic.Uint64
}

func (w countedStreamWriter) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	w.counter.Add(uint64(n))
	return n, err
}
