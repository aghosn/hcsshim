//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBaselineVsockRelayCPUSamplesAreSeparateAndCleanupIsIdempotent(t *testing.T) {
	var output bytes.Buffer
	stop, err := sampleBaselineVsockRelayCPU(os.Getpid(), &output)
	if err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	before := output.String()
	if err := stop(); err != nil || output.String() != before {
		t.Fatalf("CPU sampling cleanup is not idempotent: %v", err)
	}
	var record struct {
		PID     int `json:"pid"`
		Samples []struct {
			TimeUTC   time.Time `json:"time_utc"`
			RuntimeNS uint64    `json:"runtime_ns"`
		} `json:"samples"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(before),
		"network_benchmark_relay_cpu: ")), &record); err != nil {
		t.Fatal(err)
	}
	if record.PID != os.Getpid() || len(record.Samples) < 2 ||
		record.Samples[1].TimeUTC.Before(record.Samples[0].TimeUTC) ||
		record.Samples[1].RuntimeNS < record.Samples[0].RuntimeNS {
		t.Fatalf("missing or non-monotonic process CPU evidence: %+v", record)
	}
	if _, err := sampleBaselineVsockRelayCPU(-1, &output); err == nil {
		t.Fatal("invalid process CPU counter failure was hidden")
	}
}

// The child enters before testing's flag parser, because it receives the real
// Rust relay CLI. It never opens sockets or touches Hyper-V.
func init() {
	if len(os.Args) > 1 && os.Args[1] == "--relay" && os.Getenv("UVMBOOT_TEST_VSOCK_RELAY") != "" {
		if os.Getenv("UVMBOOT_TEST_VSOCK_RELAY") == "failure" {
			os.Exit(7)
		}
		fmt.Println("relay ready; waiting for VM diode and VM workload on HvSocket port 1024")
		for {
			time.Sleep(time.Second)
		}
	}
}

func TestBaselineVsockRelayLifecycle(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("UVMBOOT_TEST_VSOCK_RELAY", "ready")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stop, err := startBaselineVsockRelay(ctx, executable, "diode", "workload", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatalf("cleanup is not idempotent: %v", err)
	}
	t.Setenv("UVMBOOT_TEST_VSOCK_RELAY", "failure")
	if stop, err := startBaselineVsockRelay(ctx, executable, "diode", "workload", false); err == nil || stop != nil {
		t.Fatal("relay startup failure was hidden")
	}
	t.Setenv("UVMBOOT_TEST_VSOCK_RELAY", "ready")
	canceled, abort := context.WithCancel(context.Background())
	abort()
	if _, err := startBaselineVsockRelay(canceled, executable, "diode", "workload", false); err == nil {
		t.Fatal("accepted canceled startup")
	}
}

func TestBaselineVsockRelayReadinessAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	log := &baselineVsockRelayLog{ready: make(chan struct{}), out: &out}
	for _, text := range []string{"relay rea", "dy; waiting for VM ", "diode", "relay ready; waiting for VM "} {
		if _, err := log.Write([]byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-log.ready:
	default:
		t.Fatal("fragmented readiness was not recognized")
	}
}

func TestBaselineVsockValidationAndIsolation(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "benchmark.sh")
	for _, name := range []string{"benchmark.sh", "tun.ko", "diode_tcpbulk", iperfGuestName,
		"diode_iptables", "podctrl/bin/vsock-tun-windows.exe", "podctrl/bin/vsock-tun-linux-musl"} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := benchmarkTestContext(t, "--"+baselineVsockArgName, root,
		"--network-benchmark-script", script, "--network-benchmark-server", "192.0.2.10",
		"--security-hardware")
	if err := c.Parent().Set(countArgName, "2"); err != nil {
		t.Fatal(err)
	}
	if err := c.Parent().Set(parallelArgName, "2"); err != nil {
		t.Fatal(err)
	}
	oldGCS, oldInteractive, oldDebug := useGCS, siblingInteractive, debug
	useGCS, siblingInteractive, debug = true, false, false
	t.Cleanup(func() { useGCS, siblingInteractive, debug = oldGCS, oldInteractive, oldDebug })
	groups := [][]uint32{{8, 24}, {9, 25}}
	if err := validateNetworkBenchmark(c, groups); err != nil {
		t.Fatal(err)
	}
	if err := validateBaselineVsock(c, [][]uint32{{8, 24}, {8, 24}}); err == nil {
		t.Fatal("accepted shared affinity without explicit priority 1,1")
	}
	if err := c.Set(cpuGroupPrioritiesArgName, "1,1"); err != nil {
		t.Fatal(err)
	}
	if err := validateNetworkBenchmark(c, [][]uint32{{8, 24}, {24, 8}}); err != nil {
		t.Fatalf("rejected vsock11 with identical affinity and priority 1,1: %v", err)
	}
	if err := validateBaselineVsock(c, groups); err == nil {
		t.Fatal("accepted explicit priorities in vsockseparate")
	}
	for _, priority := range []string{"2,1", "1,2", "1", "0,0"} {
		if err := c.Set(cpuGroupPrioritiesArgName, priority); err != nil {
			t.Fatal(err)
		}
		if err := validateBaselineVsock(c, [][]uint32{{8, 24}, {8, 24}}); err == nil {
			t.Fatalf("accepted shared priority %s instead of 1,1", priority)
		}
	}
	if err := c.Set(cpuGroupPrioritiesArgName, ""); err != nil {
		t.Fatal(err)
	}
	if err := validateBaselineVsock(c, [][]uint32{{8, 24}, {24, 25}}); err == nil {
		t.Fatal("accepted partially overlapping affinities")
	}
	for _, flag := range []string{sharedMemoryTwoUVMArgName, siblingDiodeUplinkArgName, siblingStorageRootArgName} {
		if err := c.Set(flag, "true"); err != nil {
			t.Fatal(err)
		}
		if err := validateBaselineVsock(c, groups); err == nil {
			t.Fatalf("accepted incompatible %s", flag)
		}
		if err := c.Set(flag, "false"); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(root, "tun.ko")); err != nil {
		t.Fatal(err)
	}
	if err := validateBaselineVsock(c, groups); err == nil || !strings.Contains(err.Error(), "tun.ko") {
		t.Fatalf("matching module requirement was lost: %v", err)
	}
}

func TestBaselineVsockGuestCommands(t *testing.T) {
	c := benchmarkTestContext(t, "--network-benchmark-script", "bench.sh",
		"--network-benchmark-server", "192.0.2.10")
	for _, role := range []string{workloadRole, diodeRole} {
		command := baselineVsockGuestCommand(c, role, &diodeUplink{address: "172.31.250.2/24", gateway: "172.31.250.1"})
		for _, required := range []string{"insmod /run/vsock-tun/tun.ko", "--cid 2 --port 1024", "dev tun0",
			"trap ", "idle=poll", "kill", "wait"} {
			if !strings.Contains(command, required) {
				t.Fatalf("%s missing %s", role, required)
			}
		}
		if strings.Contains(command, "dvsc0") ||
			strings.Contains(command, "sibling_bus.ko") {
			t.Fatalf("%s retained a sibling dependency", role)
		}
		if role == workloadRole && (!strings.Contains(command, "FAIL vsock workload has an external NIC") ||
			!strings.Contains(command, "dev tun0 ") || !strings.Contains(command, "send 192.168.127.1 5001 1")) {
			t.Fatal("missing workload route/bypass check or diode termination")
		}
		if role == diodeRole && (!strings.Contains(command, "MASQUERADE") || !strings.Contains(command, `"$dtb" sink 5001`)) {
			t.Fatal("missing diode forwarding or termination listener")
		}
		if role == diodeRole && strings.Index(command, "ip link set tun0 up") < strings.Index(command, "MASQUERADE") {
			t.Fatal("workload could start before forwarding was configured")
		}
		if strings.Index(command, "mount -t tmpfs") > strings.Index(command, "cp /run/vsock-endpoint") {
			t.Fatal("executable copy would be hidden by tmpfs mount")
		}
	}

}

func TestBaselineVsockGuestShellSyntax(t *testing.T) {
	shell, err := exec.LookPath("wsl.exe")
	if err != nil {
		t.Skip("Requires WSL for Linux shell validation")
	}
	c := benchmarkTestContext(t, "--network-benchmark-script", "bench.sh",
		"--network-benchmark-server", "192.0.2.10")
	for _, role := range []string{workloadRole, diodeRole} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		command := exec.CommandContext(ctx, shell, "--exec", "/bin/sh", "-n")
		command.Stdin = strings.NewReader(baselineVsockGuestCommand(c, role,
			&diodeUplink{address: "172.31.250.2/24", gateway: "172.31.250.1"}))
		output, err := command.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("%s shell syntax: %v: %s", role, err, output)
		}
	}
}
