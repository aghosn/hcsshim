//go:build windows

package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestLinuxDiodeTimingTracksBothProvidersAcrossOutputChunks(t *testing.T) {
	for _, storageFirst := range []bool{true, false} {
		var output bytes.Buffer
		now := time.Now()
		timing := &linuxDiodeBootTiming{
			output: &output, storageNeeded: true,
			createStarted: now.Add(-time.Second), createElapsed: 200 * time.Millisecond,
			startRequested: now.Add(-800 * time.Millisecond),
		}
		first, second := linuxDiodeNetworkReady, linuxDiodeStorageReady
		if storageFirst {
			first, second = second, first
		}
		for _, character := range first + "\r\n" {
			if _, err := timing.Write([]byte(string(character))); err != nil {
				t.Fatal(err)
			}
		}
		if timing.providerReady || strings.Contains(output.String(), "stage=provider_ready") {
			t.Fatal("provider ready before both services")
		}
		if _, err := timing.Write([]byte(second + "\n" + first + "\n" + second + "\n")); err != nil {
			t.Fatal(err)
		}
		for _, stage := range []string{"storage_ready", "network_ready", "provider_ready"} {
			if strings.Count(output.String(), "stage="+stage+" ") != 1 {
				t.Fatalf("stage %s not reported exactly once: %s", stage, output.String())
			}
		}
		if !strings.Contains(output.String(), "create_ms=200.000") ||
			!strings.Contains(output.String(), first+"\r\n") {
			t.Fatal("creation duration or guest output was lost")
		}
	}
}

func TestLinuxDiodeTimingNetworkOnlyAndUnrelatedGuestLines(t *testing.T) {
	var output bytes.Buffer
	now := time.Now()
	timing := &linuxDiodeBootTiming{output: &output, createStarted: now, startRequested: now}
	input := strings.Repeat("x", 70000) + linuxDiodeNetworkReady + "\n" +
		"prefix " + linuxDiodeNetworkReady + "\n"
	for offset := 0; offset < len(input); offset += 100 {
		end := min(offset+100, len(input))
		if _, err := timing.Write([]byte(input[offset:end])); err != nil {
			t.Fatal(err)
		}
	}
	if timing.networkReady || len(timing.pending) > len(linuxDiodeStorageReady)+1 ||
		output.String() != input {
		t.Fatal("unrelated/oversized lines changed output or reported readiness")
	}
	if _, err := timing.Write([]byte(linuxDiodeNetworkReady + "\n")); err != nil {
		t.Fatal(err)
	}
	if !timing.providerReady {
		t.Fatal("network-only diode incorrectly requires storage")
	}
}

type timingFailureWriter struct {
	calls int
}

func (w *timingFailureWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls > 1 {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func TestLinuxDiodeTimingPropagatesOutputFailure(t *testing.T) {
	now := time.Now()
	timing := &linuxDiodeBootTiming{
		output: &timingFailureWriter{}, createStarted: now, startRequested: now,
	}
	if _, err := timing.Write([]byte(linuxDiodeNetworkReady + "\n")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("timing output failure was hidden: %v", err)
	}
}

func TestLinuxDiodeNetworkTimingRequiresNATSuccessAndForwarding(t *testing.T) {
	command := siblingDiodeNATCommand(&diodeUplink{address: "172.31.250.2/30", gateway: "172.31.250.1"})
	success := strings.Index(command, "then echo \"diode_net: nat ok")
	marker := strings.Index(command, linuxDiodeNetworkReady)
	failure := strings.Index(command, "else echo 'diode_net: nat failed'")
	if success < 0 || marker < success || failure < marker ||
		!strings.Contains(command[success:marker], `if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]`) {
		t.Fatal("network readiness is not gated by NAT and forwarding")
	}
}
