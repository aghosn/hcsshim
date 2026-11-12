//go:build linux

package gcsrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Microsoft/hcsshim/internal/guest/prot"
)

func TestOperationMetricsPreserveFramesAndCountOnlyWhenEnabled(t *testing.T) {
	m := &relayMetrics{frames: make(map[string]operationCounter)}
	s := newTestSession(t, dependencies{metrics: m})
	input := frame(prot.ComputeSystemGetPropertiesV1, 1, "first")
	input = append(input, frame(prot.ComputeSystemGetPropertiesV1, 2, "second")...)
	for _, enabled := range []bool{false, true} {
		m.enabled.Store(enabled)
		var output bytes.Buffer
		if err := s.forward(fragmentedReader{bytes.NewReader(input), 3}, &output, true); !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		if !bytes.Equal(output.Bytes(), input) {
			t.Fatal("accounting changed control bytes")
		}
		if !enabled && len(m.frames) != 0 {
			t.Fatal("ordinary relay unexpectedly counted operations")
		}
	}
	if len(m.frames) != 1 {
		t.Fatal(m.frames)
	}
	for _, counter := range m.frames {
		if counter.Frames != 2 || counter.Bytes != uint64(len(input)) {
			t.Fatalf("incorrect operation counts: %+v", counter)
		}
	}
}

func TestMetricsSnapshotIsConsistentUnderConcurrentUpdates(t *testing.T) {
	m := &relayMetrics{frames: make(map[string]operationCounter)}
	path := filepath.Join(t.TempDir(), "metrics.json")
	if err := m.publish(path, false); err != nil {
		t.Fatal(err)
	}
	if m.enabled.Load() {
		t.Fatal("initial snapshot enabled diagnostics")
	}
	if err := m.publish(path, true); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				m.frame(prot.ComputeSystemGetPropertiesV1, 32)
			}
		}()
	}
	for range 10 {
		if err := m.publish(path, true); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if err := m.publish(path, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Version    int                         `json:"version"`
		Enabled    bool                        `json:"enabled"`
		PID        int                         `json:"pid"`
		Generation uint64                      `json:"generation"`
		Operations map[string]operationCounter `json:"operations"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != 1 || !snapshot.Enabled || snapshot.PID != os.Getpid() || snapshot.Generation != 13 {
		t.Fatalf("bad snapshot: %+v", snapshot)
	}
	for _, counter := range snapshot.Operations {
		if counter.Frames != 400 || counter.Bytes != 12800 {
			t.Fatalf("lost concurrent updates: %+v", counter)
		}
	}
}

type partialMetricsWriter struct{}

func (partialMetricsWriter) Write([]byte) (int, error) { return 2, io.ErrShortWrite }

func TestStreamMetricsCountSuccessfullyWrittenBytes(t *testing.T) {
	var counter atomic.Uint64
	writer := countedStreamWriter{partialMetricsWriter{}, &counter}
	n, err := writer.Write([]byte("four"))
	if n != 2 || !errors.Is(err, io.ErrShortWrite) || counter.Load() != 2 {
		t.Fatalf("counted attempted rather than written bytes: %d %v %d", n, err, counter.Load())
	}

}

func TestSignalEnablesAndPublishesOperationCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	metrics, stop, err := startRelayMetrics(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var snapshot struct {
			Enabled    bool   `json:"enabled"`
			Generation uint64 `json:"generation"`
		}
		if err := json.Unmarshal(data, &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.Enabled && snapshot.Generation == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("signal did not publish an enabled snapshot")
		}
		time.Sleep(time.Millisecond)
	}
	if !metrics.enabled.Load() {
		t.Fatal("signal did not enable operation accounting")
	}
}

func TestMeasuredDuplexAccountsBothDirections(t *testing.T) {
	root, rootRelay := tcpPair(t)
	workload, workloadRelay := tcpPair(t)
	m := &relayMetrics{frames: make(map[string]operationCounter)}
	m.enabled.Store(true)
	done := make(chan error, 1)
	go func() { done <- copyDuplexMeasured(context.Background(), rootRelay, workloadRelay, m) }()
	for _, connection := range []interface{ SetDeadline(time.Time) error }{root, workload} {
		if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeAll(root, []byte("input")); err != nil {
		t.Fatal(err)
	}
	root.CloseWrite()
	if data, err := io.ReadAll(workload); err != nil || string(data) != "input" {
		t.Fatalf("input changed: %q %v", data, err)
	}
	if err := writeAll(workload, []byte("output bytes")); err != nil {
		t.Fatal(err)
	}
	workload.CloseWrite()
	if data, err := io.ReadAll(root); err != nil || string(data) != "output bytes" {
		t.Fatalf("output changed: %q %v", data, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("measured duplex did not complete")
	}
	if m.rootIO.Load() != 5 || m.guestIO.Load() != 12 {
		t.Fatalf("wrong directional bytes: %d / %d", m.rootIO.Load(), m.guestIO.Load())
	}
}
