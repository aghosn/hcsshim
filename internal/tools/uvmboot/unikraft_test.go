//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
)

func unikraftTestManifest(command string) string {
	data, _ := json.Marshal(map[string]any{
		"guest_arch": "x64",
		"guest_configs": []any{map[string]any{
			"image": map[string]any{"snp_linux_direct": map[string]any{
				"processor_count": 1, "memory_page_count": 32768,
				"linux": map[string]string{"command_line": command},
			}},
		}},
	})
	return string(data)
}

func unikraftTestParams() string {
	return "console=ttyS0 libukbus_vmbus.storage_controller=" + guestrequest.ScsiControllerGuids[0] +
		" libukbus_vmbus.storage_luns=3:0:ro,5:1:rw" +
		" libukbus_vmbus.uplink_device=0 libukbus_vmbus.uplink_address=172.31.250.2" +
		" libukbus_vmbus.uplink_gateway=172.31.250.1 libukbus_vmbus.provider_address=10.200.0.1" +
		" libukbus_vmbus.peer_address=10.200.0.2 libukbus_vmbus.provider_mac=02:00:00:00:00:01" +
		" libukbus_vmbus.peer_mac=02:00:00:00:00:02"
}

func TestUnikraftManifestAndStorageAssignments(t *testing.T) {
	cfg, err := parseUnikraftManifest(strings.NewReader(unikraftTestManifest(unikraftTestParams())))
	if err != nil {
		t.Fatal(err)
	}
	root, data := uint8(0), uint8(1)
	plan := &siblingStoragePlan{Version: 1, Disks: []siblingStorageDisk{
		{ID: "root", Role: "root", HostPath: `C:\fixture\root.vhdx`, Access: "read-only", ExportLUN: &root},
		{ID: "data", Role: "data", HostPath: `C:\fixture\data.vhdx`, Access: "read-write", ExportLUN: &data},
	}}
	devices, reports, err := cfg.storageDevices(plan)
	if err != nil {
		t.Fatal(err)
	}
	attachments := devices[cfg.Controller].Attachments
	if cfg.MemoryMB != 128 || len(devices) != 1 || len(attachments) != 2 ||
		attachments["3"].Path != plan.Disks[0].HostPath || !attachments["3"].ReadOnly ||
		attachments["5"].Path != plan.Disks[1].HostPath || attachments["5"].ReadOnly ||
		reports[1].LUN != 5 || reports[1].ExportLUN != 1 {
		t.Fatalf("wrong boot-time mapping: %+v %+v", devices, reports)
	}
	if _, _, err := cfg.storageDevices(nil); err == nil {
		t.Fatal("accepted missing backends")
	}
	plan.Disks[1].Access = "read-only"
	if _, _, err := cfg.storageDevices(plan); err == nil {
		t.Fatal("accepted an access mismatch")
	}
	plan.Disks[1].Access = "read-write"
	*plan.Disks[1].ExportLUN = 7
	if _, _, err := cfg.storageDevices(plan); err == nil {
		t.Fatal("accepted an export mismatch")
	}
}

func TestUnikraftStorageBenchmarkRequiresWritableStorageOnlyFirmware(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"guest.vmgs", "sibling_bus.ko", "diode_storage_test", "fio.sh"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	command := "console=ttyS0 libukbus_vmbus.idle=poll libukbus_vmbus.storage_controller=" +
		guestrequest.ScsiControllerGuids[0] + " libukbus_vmbus.storage_luns=0:1:rw --"
	writeManifest := func(command string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, "launch-manifest.json"),
			[]byte(unikraftTestManifest(command)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeManifest(command)
	oldGCS := useGCS
	useGCS = true
	t.Cleanup(func() { useGCS = oldGCS })
	c := benchmarkTestContext(t, "--security-hardware", "--shared-memory-two-uvm-proof",
		"--shared-memory-size", "33554432", "--sibling-bus-guest-module", filepath.Join(directory, "sibling_bus.ko"),
		"--unikraft-diode-package", directory, "--storage-benchmark-script", filepath.Join(directory, "fio.sh"),
		"--storage-benchmark-idle", "poll")
	for flag, value := range map[string]string{cpusArgName: "2", countArgName: "2", parallelArgName: "2"} {
		if err := c.Parent().Set(flag, value); err != nil {
			t.Fatal(err)
		}
	}
	lun := uint8(1)
	plan := &siblingStoragePlan{Version: 1, Disks: []siblingStorageDisk{
		{ID: "fio-data", Role: "data", Access: "read-write", HostPath: filepath.Join(directory, "data.vhdx"), ExportLUN: &lun},
	}}
	cfg, err := loadUnikraftConfig(c, plan)
	if err != nil || cfg.Network != nil || cfg.Idle != "poll" {
		t.Fatalf("storage-only benchmark rejected: cfg=%+v err=%v", cfg, err)
	}
	for _, invalid := range []string{
		strings.Replace(command, "idle=poll", "idle=halt", 1),
		strings.Replace(command, "0:1:rw", "0:0:ro", 1),
	} {
		writeManifest(invalid)
		if _, err := loadUnikraftConfig(c, plan); err == nil {
			t.Fatalf("accepted incompatible storage firmware: %s", invalid)
		}
	}
	writeManifest(strings.Replace(command, "idle=poll", "idle=halt", 1))
	if err := c.Set(storageBenchmarkDiodeIdleArgName, "halt"); err != nil {
		t.Fatal(err)
	}
	cfg, err = loadUnikraftConfig(c, plan)
	if err != nil || cfg.Idle != "halt" || c.String(storageBenchmarkIdleArgName) != "poll" {
		t.Fatalf("independent Unikraft halt/workload poll rejected: cfg=%+v err=%v", cfg, err)
	}
	if err := c.Set(storageBenchmarkDiodeIdleArgName, "poll"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadUnikraftConfig(c, plan); err == nil {
		t.Fatal("accepted Unikraft halt firmware with a poll diode expectation")
	}
	for _, args := range [][]string{
		{"--storage-benchmark-diode-idle", "halt"},
		{"--storage-benchmark-script", "fixture", "--storage-benchmark-diode-idle", "invalid"},
		{"--storage-benchmark-script", "fixture", "--storage-benchmark-diode-idle", "halt"},
	} {
		if err := validateStorageBenchmark(benchmarkTestContext(t, args...), nil, nil); err == nil {
			t.Fatalf("unsupported storage diode override accepted: %v", args)
		}
	}
}

func TestUnikraftIdleManifest(t *testing.T) {
	for _, mode := range []string{"halt", "poll"} {
		cfg, err := parseUnikraftManifest(strings.NewReader(unikraftTestManifest(
			unikraftTestParams() + " libukbus_vmbus.idle=" + mode + " --")))
		if err != nil || cfg.Idle != mode {
			t.Fatalf("idle mode %s: cfg=%+v err=%v", mode, cfg, err)
		}
	}
	for _, mode := range []string{"spin", "0", "HALT"} {
		_, err := parseUnikraftManifest(strings.NewReader(unikraftTestManifest(
			unikraftTestParams() + " libukbus_vmbus.idle=" + mode + " --")))
		if err == nil {
			t.Fatalf("accepted invalid idle mode %q", mode)
		}
	}
}

func TestUnikraftManifestRejectsUnusableBootConfiguration(t *testing.T) {
	base := unikraftTestParams()
	for name, command := range map[string]string{
		"missing":        "console=ttyS0",
		"partial net":    strings.Replace(base, " libukbus_vmbus.peer_address=10.200.0.2", "", 1),
		"duplicate":      base + " libukbus_vmbus.uplink_device=0",
		"unknown":        base + " libukbus_vmbus.typo=1",
		"late":           base + " -- libukbus_vmbus.uplink_device=0",
		"root duplicate": strings.Replace(base, "3:0:ro,5:1:rw", "3:0:ro,3:1:rw", 1),
		"export dup":     strings.Replace(base, "3:0:ro,5:1:rw", "3:0:ro,5:0:rw", 1),
		"root overflow":  strings.Replace(base, "3:0:ro", "64:0:ro", 1),
		"access":         strings.Replace(base, "3:0:ro", "3:0:read", 1),
		"gateway":        strings.Replace(base, "uplink_gateway=172.31.250.1", "uplink_gateway=172.31.250.9", 1),
		"subnet":         strings.Replace(base, "peer_address=10.200.0.2", "peer_address=10.201.0.2", 1),
		"overlap":        strings.ReplaceAll(strings.ReplaceAll(base, "provider_address=10.200.0.1", "provider_address=172.31.250.5"), "peer_address=10.200.0.2", "peer_address=172.31.250.6"),
		"broadcast":      strings.Replace(base, "uplink_address=172.31.250.2", "uplink_address=172.31.250.255", 1),
		"bad mac":        strings.Replace(base, "peer_mac=02:00:00:00:00:02", "peer_mac=01:00:00:00:00:02", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseUnikraftManifest(strings.NewReader(unikraftTestManifest(command))); err == nil {
				t.Fatal("accepted unusable manifest")
			}
		})
	}
	for _, manifest := range []string{
		unikraftTestManifest(base) + "{}",
		unikraftTestManifest(base) + strings.Repeat(" ", 65537),
		strings.Replace(unikraftTestManifest(base), `"processor_count":1`, `"processor_count":2`, 1),
		strings.Replace(unikraftTestManifest(base), `"memory_page_count":32768`, `"memory_page_count":8192`, 1),
	} {
		if _, err := parseUnikraftManifest(strings.NewReader(manifest)); err == nil {
			t.Fatal("accepted invalid image geometry/trailing JSON")
		}
	}
}

func TestUnikraftIndependentServicesAndWorkloadBootstrap(t *testing.T) {
	all, err := parseUnikraftManifest(strings.NewReader(unikraftTestManifest(unikraftTestParams())))
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{"network", "storage"} {
		t.Run(service, func(t *testing.T) {
			var fields []string
			for _, field := range strings.Fields(unikraftTestParams()) {
				storage := strings.Contains(field, ".storage_")
				if (service == "storage") == storage {
					fields = append(fields, field)
				}
			}
			if _, err := parseUnikraftManifest(strings.NewReader(unikraftTestManifest(strings.Join(fields, " ")))); err != nil {
				t.Fatal(err)
			}
		})
	}
	command, err := unikraftWorkloadCommand("/path with 'quote/bus.ko", all, nil, "test-workload")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"set -eu", `'"'"'`, "hv_netvsc", "10.200.0.2/30", "via '10.200.0.1'",
		"mkdir -p /run/dtb-exec", "mount -t tmpfs", "test-workload"} {
		if !strings.Contains(command, want) {
			t.Fatalf("missing %q", want)
		}
	}
	for _, unwanted := range []string{"echo 16/16", "hv_sock", "ping ", "MASQUERADE", "sink 500", "diode_netvsp"} {
		if strings.Contains(command, unwanted) {
			t.Fatalf("Linux diode assumption remains: %s", unwanted)
		}
	}
}

func TestUnikraftConsoleRequiresSNPAndProvider(t *testing.T) {
	lines := []string{
		"vmbus: idle=halt scheduler=cooperative",
		"hyperv: isolation type 2 (SNP), paravisor absent",
		"vmbus: all offers delivered, 2 channel(s)",
		"sibling: provider ready protocol=4; waiting for Linux workload",
	}
	for omit := -1; omit < len(lines); omit++ {
		var input []string
		for i, line := range lines {
			if i != omit {
				input = append(input, line)
			}
		}
		ready := make(chan time.Time, 1)
		var log bytes.Buffer
		before := time.Now()
		err := captureUnikraftConsole(strings.NewReader(strings.Join(input, "\n")), &log, ready, "halt")
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		select {
		case readyAt := <-ready:
			if omit != -1 {
				t.Fatal("reported incomplete boot as ready")
			}
			if readyAt.Before(before) || readyAt.After(time.Now()) {
				t.Fatal("readiness timestamp is outside console observation")
			}
		default:
			if omit == -1 {
				t.Fatal("did not recognize complete startup")
			}
		}
	}
	for _, version := range []string{"2", "3", "40", ""} {
		input := strings.Replace(strings.Join(lines, "\n"), "protocol=4", "protocol="+version, 1)
		ready := make(chan time.Time, 1)
		err := captureUnikraftConsole(strings.NewReader(input), io.Discard, ready, "halt")
		if err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("accepted incompatible provider version %q: %v", version, err)
		}
		select {
		case <-ready:
			t.Fatalf("reported incompatible provider version %q as ready", version)
		default:
		}
	}
	input := strings.Replace(strings.Join(lines, "\n"), "idle=halt", "idle=poll", 1)
	if err := captureUnikraftConsole(strings.NewReader(input), io.Discard, make(chan time.Time, 1), "halt"); err == nil || errors.Is(err, io.EOF) {
		t.Fatal("accepted firmware reporting a different idle policy")
	}
	pollReady := make(chan time.Time, 1)
	if err := captureUnikraftConsole(strings.NewReader(input), io.Discard, pollReady, "poll"); !errors.Is(err, io.EOF) {
		t.Fatalf("rejected matching poll firmware: %v", err)
	}
	if len(pollReady) != 1 {
		t.Fatal("matching poll firmware did not satisfy startup readiness")
	}
}

func TestUnikraftConsoleTimestampsReadinessOnlyOnce(t *testing.T) {
	input := "vmbus: idle=halt scheduler=cooperative\n" +
		"hyperv: isolation type 2 (SNP), paravisor absent\n" +
		"vmbus: all offers delivered\n" +
		"sibling: provider ready protocol=4; waiting for Linux workload\n"
	ready := make(chan time.Time, 1)
	var output bytes.Buffer
	err := captureUnikraftConsole(strings.NewReader(input+input), &output, ready, "halt")
	if !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if len(ready) != 1 || output.String() != input+input {
		t.Fatal("duplicate readiness changed its timestamp or console output")
	}
}

func TestUnikraftRootOnlyPairUsesStaticManifestAndSharedWorkload(t *testing.T) {
	old := useGCS
	useGCS = true
	t.Cleanup(func() { useGCS = old })
	directory := t.TempDir()
	lun := uint8(0)
	rootPath := filepath.Join(directory, "root.vhdx")
	modulePath := filepath.Join(directory, "sibling_bus.ko")
	manifest := unikraftTestManifest("libukbus_vmbus.storage_controller=" +
		guestrequest.ScsiControllerGuids[0] + " libukbus_vmbus.storage_luns=0:0:ro")
	disk := siblingStorageDisk{ID: "root", Role: "root", HostPath: rootPath,
		Access: "read-only", ExportLUN: &lun}
	data, err := json.Marshal(siblingStoragePlan{Version: 1, Disks: []siblingStorageDisk{disk}})
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"launch-manifest.json": manifest,
		"guest.vmgs":           "fixture",
		"sibling_bus.ko":       "fixture",
		"diode_storage_test":   "fixture",
		"root.vhdx":            "fixture",
		"storage.json":         string(data),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := benchmarkTestContext(t, "--"+unikraftPackageArgName, directory, "--"+securityHardwareFlag,
		"--"+sharedMemoryTwoUVMArgName, "--"+sharedMemorySizeArgName, "33554432",
		"--"+siblingBusGuestModuleArgName, modulePath, "--"+siblingInteractiveArgName,
		"--"+siblingStorageRootArgName, "--"+siblingStorageBackendsArgName, filepath.Join(directory, "storage.json"))
	for name, value := range map[string]string{cpusArgName: "2", countArgName: "2", parallelArgName: "2"} {
		if err := c.GlobalSet(name, value); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := loadSiblingStoragePlan(c)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loadUnikraftConfig(c, plan)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network != nil {
		t.Fatal("root-only appliance unexpectedly enabled networking")
	}
	command, err := unikraftWorkloadCommand("/run/sibling-bus-module/sibling_bus.ko", cfg, plan, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"version mismatch expected=4", "mkdir -p /run/dtb-exec",
		"ready id=root lun=0", "/run/dtb-exec/storage-test"} {
		if !strings.Contains(command, want) {
			t.Fatalf("root-only workload setup missing %q:\n%s", want, command)
		}
	}
	for _, unwanted := range []string{"hv_netvsc", "hv_sock", "diode_storvsp", "diode_netvsp", "echo 16/16"} {
		if strings.Contains(command, unwanted) {
			t.Fatalf("root-only workload setup assumes a Linux diode: %q", unwanted)
		}
	}
	plan.Disks[0].ExportLUN = new(uint8)
	*plan.Disks[0].ExportLUN = 1
	if _, err := loadUnikraftConfig(c, plan); err == nil {
		t.Fatal("accepted a backend plan that does not match the pre-boot manifest")
	}
}

func TestUnikraftWorkloadRejectsContainerControlFrames(t *testing.T) {
	for _, frame := range []byte{frameHello, frameImageHello} {
		t.Run(string(rune('0'+frame)), func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				siblingShell(context.Background(), nil, "workload", server, false)
			}()
			if err := writeFrame(client, frame, nil); err != nil {
				t.Fatal(err)
			}
			kind, data, err := readFrame(client)
			if err != nil || kind != frame {
				t.Fatalf("invalid rejection frame: %d %v", kind, err)
			}
			var result siblingHelloResult
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if result.ExitCode != -1 || !strings.Contains(result.Error, "Unikraft supports workload attach and stop only") {
				t.Fatalf("container fallback was not rejected: %+v", result)
			}
			<-done
		})
	}
}

func TestUnikraftPairPreflight(t *testing.T) {
	old := useGCS
	useGCS = true
	t.Cleanup(func() { useGCS = old })
	directory := t.TempDir()
	params := strings.Fields(unikraftTestParams())
	var network []string
	for _, field := range params {
		if !strings.Contains(field, ".storage_") {
			network = append(network, field)
		}
	}
	for name, contents := range map[string]string{
		"launch-manifest.json": unikraftTestManifest(strings.Join(network, " ") + " libukbus_vmbus.idle=poll"),
		"guest.vmgs":           "fixture",
		"sibling_bus.ko":       "fixture",
		"bench.sh":             "exit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--" + unikraftPackageArgName, directory, "--" + securityHardwareFlag,
		"--" + sharedMemoryTwoUVMArgName, "--" + sharedMemorySizeArgName, "33554432",
		"--" + siblingBusGuestModuleArgName, filepath.Join(directory, "sibling_bus.ko"),
		"--" + siblingDiodeUplinkArgName, "--" + execCommandLineArgName, "run-test"}
	for _, test := range []struct {
		cpus  string
		extra []string
		error string
	}{
		{cpus: "2"},
		{cpus: "2", extra: []string{"--" + sharedMemoryGuestModuleArgName, "marker.ko"}, error: "does not support"},
		{cpus: "0", error: "processor_count"},
		{cpus: "1"},
		{cpus: "4"},
	} {
		context := benchmarkTestContext(t, append(append([]string{}, args...), test.extra...)...)
		if err := context.GlobalSet(cpusArgName, test.cpus); err != nil {
			t.Fatal(err)
		}
		if err := context.GlobalSet(countArgName, "2"); err != nil {
			t.Fatal(err)
		}
		if err := context.GlobalSet(parallelArgName, "2"); err != nil {
			t.Fatal(err)
		}
		_, err := loadUnikraftConfig(context, nil)
		if (err != nil) != (test.error != "") ||
			(err != nil && !strings.Contains(err.Error(), test.error)) {
			t.Fatalf("preflight error = %v, cpus = %s, extra = %v", err, test.cpus, test.extra)
		}
	}
	benchmarkArgs := append(append([]string{}, args[:len(args)-2]...),
		"--network-benchmark-script", filepath.Join(directory, "bench.sh"),
		"--network-benchmark-server", "192.0.2.10")
	c := benchmarkTestContext(t, benchmarkArgs...)
	for name, value := range map[string]string{cpusArgName: "2", countArgName: "2", parallelArgName: "2"} {
		if err := c.GlobalSet(name, value); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadUnikraftConfig(c, nil); err != nil {
		t.Fatal(err)
	}
	if err := validateNetworkBenchmark(c, [][]uint32{{8, 24}, {9, 25}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Set(networkBenchmarkIdleArgName, "halt"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadUnikraftConfig(c, nil); err == nil || !strings.Contains(err.Error(), "does not match benchmark") {
		t.Fatalf("mismatched benchmark firmware was accepted: %v", err)
	}
	if err := c.Set(networkBenchmarkIdleArgName, "poll"); err != nil {
		t.Fatal(err)
	}
	if err := c.Set(networkBenchmarkDiodeIdleArgName, "halt"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "launch-manifest.json"),
		[]byte(unikraftTestManifest(strings.Join(network, " ")+" libukbus_vmbus.idle=halt")), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadUnikraftConfig(c, nil)
	if err != nil || cfg.Idle != "halt" {
		t.Fatalf("mixed Unikraft network idle rejected: cfg=%+v err=%v", cfg, err)
	}
	if err := validateNetworkBenchmark(c, [][]uint32{{8, 24}, {8, 24}}); err != nil {
		t.Fatal(err)
	}
	if networkBenchmarkGuestStateFile(c, "uvmboot-1") != "kernel.vmgs" {
		t.Fatal("Unikraft pair selected the Linux-only network firmware path instead of retaining root mediation")
	}
	if err := c.Set(networkBenchmarkDiodeIdleArgName, "poll"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadUnikraftConfig(c, nil); err == nil {
		t.Fatal("accepted network Unikraft firmware inconsistent with diode idle expectation")
	}
}
