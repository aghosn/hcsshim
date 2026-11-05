//go:build windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	linuxDiodeStorageReady = "linux_diode_boot_stage: storage_ready"
	linuxDiodeNetworkReady = "linux_diode_boot_stage: network_ready"
)

type linuxDiodeBootTiming struct {
	output         io.Writer
	createStarted  time.Time
	createElapsed  time.Duration
	startRequested time.Time
	storageNeeded  bool
	storageReady   bool
	networkReady   bool
	providerReady  bool
	pending        []byte
	mu             sync.Mutex
}

func (t *linuxDiodeBootTiming) report(stage string, at time.Time) error {
	_, err := fmt.Fprintf(t.output,
		"linux_diode_boot_timing: stage=%s create_ms=%.3f start_to_stage_ms=%.3f create_to_stage_ms=%.3f\n",
		stage, float64(t.createElapsed)/float64(time.Millisecond),
		float64(at.Sub(t.startRequested))/float64(time.Millisecond),
		float64(at.Sub(t.createStarted))/float64(time.Millisecond))
	return err
}

func (t *linuxDiodeBootTiming) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, err := t.output.Write(p)
	if err != nil {
		return n, err
	}
	if n != len(p) {
		return n, io.ErrShortWrite
	}
	data := append(t.pending, p...)
	for {
		end := bytes.IndexByte(data, '\n')
		if end < 0 {
			break
		}
		line := bytes.TrimSuffix(data[:end], []byte{'\r'})
		stage := ""
		switch {
		case bytes.Equal(line, []byte(linuxDiodeStorageReady)) && !t.storageReady:
			t.storageReady, stage = true, "storage_ready"
		case bytes.Equal(line, []byte(linuxDiodeNetworkReady)) && !t.networkReady:
			t.networkReady, stage = true, "network_ready"
		}
		if stage != "" {
			at := time.Now()
			if err := t.report(stage, at); err != nil {
				return n, err
			}
			if !t.providerReady && t.networkReady && (!t.storageNeeded || t.storageReady) {
				t.providerReady = true
				if err := t.report("provider_ready", at); err != nil {
					return n, err
				}
			}
		}
		data = data[end+1:]
	}
	// Only a complete marker can matter; do not retain arbitrary guest lines.
	if len(data) > len(linuxDiodeStorageReady)+1 {
		t.pending = []byte{0}
	} else {
		t.pending = append(t.pending[:0], data...)
	}
	return n, nil
}
