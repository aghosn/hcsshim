//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorageBenchmarkCleanupKeepsGuestAliveUntilDisksReleased(t *testing.T) {
	releaseErr := errors.New("release failed")
	closeErr := errors.New("close failed")
	for _, test := range []struct {
		name        string
		releaseErr  error
		closeErr    error
		cancel      bool
		attachments int
	}{
		{name: "baseline", attachments: 1},
		{name: "paired", attachments: 2},
		{name: "cancelled", cancel: true, attachments: 2},
		{name: "release failure", releaseErr: releaseErr, attachments: 2},
		{name: "close failure", closeErr: closeErr, attachments: 1},
		{name: "both failures", releaseErr: releaseErr, closeErr: closeErr, attachments: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancel {
				cancel()
			}
			alive := true
			nextRelease := test.attachments - 1
			checkContext := func(cleanupCtx context.Context) {
				t.Helper()
				if cleanupCtx.Err() != nil {
					t.Fatal("cleanup inherited cancellation")
				}
				if _, ok := cleanupCtx.Deadline(); !ok {
					t.Fatal("cleanup has no deadline")
				}
			}
			var releases []func(context.Context) error
			for i := 0; i < test.attachments; i++ {
				index := i
				releases = append(releases, func(cleanupCtx context.Context) error {
					checkContext(cleanupCtx)
					if !alive {
						t.Fatal("disk unplug attempted after guest connection closed")
					}
					if nextRelease != index {
						t.Fatal("attachments not released in reverse acquisition order")
					}
					nextRelease--
					return test.releaseErr
				})
			}
			err := closeStorageBenchmark(ctx, func(cleanupCtx context.Context) error {
				checkContext(cleanupCtx)
				if nextRelease != -1 {
					t.Fatal("VM closed before all attachments were released")
				}
				alive = false
				return test.closeErr
			}, releases)
			if alive || nextRelease != -1 {
				t.Fatal("cleanup did not release disks and close the VM")
			}
			for _, expected := range []error{test.releaseErr, test.closeErr} {
				if expected != nil && !errors.Is(err, expected) {
					t.Fatalf("cleanup lost error %v: %v", expected, err)
				}
			}
			if test.releaseErr == nil && test.closeErr == nil && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStorageBenchmarkStandaloneAndMediatedContracts(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "storage-benchmark.sh")
	disk := filepath.Join(dir, "data.vhdx")
	for _, path := range []string{script, disk, filepath.Join(dir, "diode_fio")} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	oldGCS, oldDebug := useGCS, debug
	useGCS, debug = true, false
	t.Cleanup(func() { useGCS, debug = oldGCS, oldDebug })
	args := []string{"--storage-benchmark-script", script, "--storage-benchmark-disk", disk,
		"--storage-benchmark-output", t.TempDir(), "--security-hardware"}
	groups := [][]uint32{{8, 24}}
	c := benchmarkTestContext(t, args...)
	if err := validateStorageBenchmark(c, groups, nil); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{
		{"--shared-memory-size", "2097152"}, {"--shared-memory-two-uvm-proof"},
		{"--sibling-bus-guest-module", script}, {"--storage-benchmark-stats"},
		{"--sibling-diode-uplink"}, {"--network-benchmark-script", script},
		{"--sibling-storage-root"}, {"--sibling-interactive"},
		{"--mount-scsi", disk}, {"--exec", "echo bad"},
		{"--storage-benchmark-io-mib", "0"}, {"--storage-benchmark-size-mib", "1"},
		{"--storage-benchmark-io-mib", "10241"}, {"--storage-benchmark-sync-io-mib", "3"},
		{"--storage-benchmark-timeout", "0s"},
		{"--storage-benchmark-test"},
	} {
		candidate := benchmarkTestContext(t, append(append([]string{}, args...), extra...)...)
		if err := validateStorageBenchmark(candidate, groups, nil); err == nil {
			t.Fatalf("standalone baseline accepted incompatible options %v", extra)
		}
	}
	for _, name := range []string{storageBenchmarkDiskArgName, storageBenchmarkOutputArgName,
		storageBenchmarkStatsArgName, storageBenchmarkTestArgName, storageBenchmarkIOArgName, storageBenchmarkSyncIOArgName} {
		value := "1"
		if name == storageBenchmarkStatsArgName || name == storageBenchmarkTestArgName {
			value = "true"
		}
		if err := validateStorageBenchmark(benchmarkTestContext(t, "--"+name+"="+value), nil, nil); err == nil {
			t.Fatalf("accepted detached benchmark option %s", name)
		}
	}
	pairedArgs := append(append([]string{}, args...), "--shared-memory-two-uvm-proof",
		"--sibling-bus-guest-module", script, "--shared-memory-guest-module", script)
	pair := benchmarkTestContext(t, pairedArgs...)
	if err := pair.Parent().Set(countArgName, "2"); err != nil {
		t.Fatal(err)
	}
	if err := pair.Parent().Set(parallelArgName, "2"); err != nil {
		t.Fatal(err)
	}
	lun := uint8(1)
	plan := &siblingStoragePlan{Version: 1, Disks: []siblingStorageDisk{
		{ID: "fio-data", Role: "data", Access: "read-write", HostPath: disk, ExportLUN: &lun},
	}}
	if err := validateStorageBenchmark(pair, [][]uint32{{9, 25}, {8, 24}}, plan); err != nil {
		t.Fatal(err)
	}
	if err := pair.GlobalSet(vmCPUsArgName, "1,2"); err != nil {
		t.Fatal(err)
	}
	if err := validateStorageBenchmark(pair, [][]uint32{{9, 25}, {8, 24}}, plan); err != nil {
		t.Fatalf("single-VP Linux storage pair rejected: %v", err)
	}
	if requestedVMProcessors(pair, "uvmboot-0") != 1 || requestedVMProcessors(pair, "uvmboot-1") != 2 {
		t.Fatal("storage pair ignored independently requested CPU counts")
	}
	if err := pair.GlobalSet(vmCPUsArgName, "1,3"); err != nil {
		t.Fatal(err)
	}
	if err := validateStorageBenchmark(pair, [][]uint32{{9, 25}, {8, 24}}, plan); err == nil {
		t.Fatal("Linux storage accepted an unsupported VP count")
	}
	if err := pair.Set(unikraftPackageArgName, dir); err != nil {
		t.Fatal(err)
	}
	if err := pair.GlobalSet(vmCPUsArgName, "1,2"); err != nil {
		t.Fatal(err)
	}
	if err := validateStorageBenchmark(pair, [][]uint32{{9, 25}, {8, 24}}, plan); err != nil {
		t.Fatalf("single-VP Unikraft storage pair rejected: %v", err)
	}
	if err := pair.GlobalSet(vmCPUsArgName, "1,1"); err != nil {
		t.Fatal(err)
	}
	if err := validateStorageBenchmark(pair, [][]uint32{{9, 25}, {8, 24}}, plan); err != nil {
		t.Fatalf("Unikraft storage rejected independently selected one-VP workload: %v", err)
	}
	if err := pair.Set(unikraftPackageArgName, ""); err != nil {
		t.Fatal(err)
	}
	if err := pair.Parent().Set(cpusArgName, "2"); err != nil {
		t.Fatal(err)
	}
	plan.Disks[0].Role = "root"
	if err := validateStorageBenchmark(pair, [][]uint32{{9, 25}, {8, 24}}, plan); err == nil {
		t.Fatal("paired benchmark accepted a root export")
	}
	plan.Disks[0].Role = "data"
	plan.Disks[0].HostPath = script
	if err := validateStorageBenchmark(pair, [][]uint32{{9, 25}, {8, 24}}, plan); err == nil {
		t.Fatal("paired benchmark accepted a mismatched disk")
	}
}

func TestStorageBenchmarkSingleVPAndPlacementIdlePreflight(t *testing.T) {
	command := storageBenchmarkPreflight(1, "poll")
	if !strings.Contains(command, `/sys/devices/system/cpu/online)" = 0 ]`) ||
		!strings.Contains(command, "'idle=poll'") || strings.Contains(command, "idle=halt") {
		t.Fatalf("single-VP separate-core preflight is incorrect: %s", command)
	}
}

func TestStorageBenchmarkCommandsUseResolvedAttachmentAndNoNetwork(t *testing.T) {
	c := benchmarkTestContext(t, "--storage-benchmark-script", `C:\some path\it's fio.sh`)
	command := storageBenchmarkPreflight(2, "halt") + storageRPDeviceCommand("test-controller", 7) +
		storageBenchmarkClient(c, `"$storage_dev"`, storageBenchmarkContent{
			ReadSHA256: "read-hash", WriteSHA256: "write-hash",
			SyncReadSHA: "sync-read-hash", SyncWriteSHA: "sync-write-hash",
		})
	execMount := strings.Index(command, "mount -t tmpfs -o exec,nosuid,nodev,size=16m tmpfs /run/dtb-exec;")
	copyTool := strings.Index(command, "cp /run/storage-benchmark-tool/diode_fio")
	if execMount < 0 || copyTool <= execMount {
		t.Fatal("fio must be staged on an executable tmpfs before it is copied or run")
	}
	for _, required := range []string{"SEV-SNP", "idle=halt", "target*/*:0:0:7",
		"storage_count", `"$storage_dev"`, `it's fio.sh`, "diode_fio",
		"10240 128 1024 0 read-hash write-hash sync-read-hash sync-write-hash"} {
		if required == `it's fio.sh` {
			required = `it'"'"'s fio.sh`
		}

		if !strings.Contains(command, required) {
			t.Fatalf("command lacks %q: %s", required, command)
		}
	}
	for _, forbidden := range []string{"mkfs", "/dev/sdb", "iptables", "iperf", "dvsc0", "hcs-shmem-diag"} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("storage command contains %q", forbidden)
		}
	}
}

func TestStorageBenchmarkContentIndependentOfConfiguration(t *testing.T) {
	first, err := prepareStorageBenchmarkContent(t.TempDir(), 32, 4)
	if err != nil {
		t.Fatal(err)
	}

	second, err := prepareStorageBenchmarkContent(t.TempDir(), 32, 4)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.FileMiB != 32 || first.SyncFileMiB != 4 ||
		first.ReadSHA256 == first.WriteSHA256 || first.ReadSHA256 == first.SyncReadSHA {
		t.Fatalf("content is not deterministic, distinct and correctly sized: %+v %+v", first, second)
	}
	if first.ReadSHA256 != "d020b620f102c8a76d23fc32aad44aced6a845909465b148e1d95374d716f329" ||
		first.WriteSHA256 != "480a3cef462f262c65d2ca216cb01a2972beb51d7e32188d9ca1cfbde55b8283" ||
		first.SyncReadSHA != "9dda1b6d5058414976e187b1da1f2fd036dd31e4aa1dac09de104546a4f12268" ||
		first.SyncWriteSHA != "dc18dc8d3916a7e30c88c86789dd333acba3c3503e430a27bec8591e584aadd1" {
		t.Fatal("native content differs from independent Python/QEMU reference")
	}
	for _, hash := range []string{first.ReadSHA256, first.WriteSHA256, first.SyncReadSHA, first.SyncWriteSHA} {
		if len(hash) != 64 {
			t.Fatalf("invalid content SHA256: %q", hash)
		}
	}
	if _, err := prepareStorageBenchmarkContent(filepath.Join(t.TempDir(), "missing"), 32, 4); err == nil {
		t.Fatal("content preparation hid an output failure")
	}
}

func TestStorageBenchmarkExperimentSelection(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "storage-benchmark.sh")
	disk := filepath.Join(dir, "data.vhdx")
	for _, path := range []string{script, disk, filepath.Join(dir, "diode_fio")} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}

	}
	oldGCS, oldDebug := useGCS, debug
	useGCS, debug = true, false
	t.Cleanup(func() { useGCS, debug = oldGCS, oldDebug })
	for _, test := range []struct {
		mode  string
		size  string
		smoke bool
		short bool
	}{
		{mode: "latency", size: "64"}, {mode: "latency", size: "1", smoke: true},
		{mode: "throughput", size: "1024"}, {mode: "throughput", size: "1", smoke: true},
		{mode: "latency", size: "1", short: true}, {mode: "throughput", size: "64", short: true},
	} {
		args := []string{"--storage-benchmark-script", script, "--storage-benchmark-disk", disk,
			"--storage-benchmark-output", t.TempDir(), "--security-hardware",
			"--storage-benchmark-" + test.mode, "--storage-benchmark-size-mib", test.size}
		if test.smoke {
			args = append(args, "--storage-benchmark-smoke")
		}
		if test.short {
			args = append(args, "--storage-benchmark-test")
		}
		c := benchmarkTestContext(t, args...)
		if err := validateStorageBenchmark(c, [][]uint32{{8, 24}}, nil); err != nil {
			t.Fatal(err)
		}
		if command := storageBenchmarkClient(c, `"$storage_dev"`, storageBenchmarkContent{}); !strings.HasSuffix(command, " "+test.mode+"; ") {
			t.Fatalf("experiment selection was not forwarded: %s", command)
		}
		if command := storageBenchmarkClient(c, `"$storage_dev"`, storageBenchmarkContent{}); strings.Contains(command, "STORAGE_TEST=1 /bin/sh") != test.short {
			t.Fatalf("short-test guest mode was not forwarded: %s", command)
		}
		if test.short {
			if err := c.Set(storageBenchmarkSmokeArgName, "true"); err != nil {
				t.Fatal(err)
			}
			if err := validateStorageBenchmark(c, [][]uint32{{8, 24}}, nil); err == nil {
				t.Fatal("short test accepted functional smoke")
			}
			if err := c.Set(storageBenchmarkSmokeArgName, "false"); err != nil {
				t.Fatal(err)
			}
		}
		other := storageBenchmarkLatencyArgName
		if test.mode == "latency" {
			other = storageBenchmarkThroughputArgName
		}
		if err := c.Set(other, "true"); err != nil {
			t.Fatal(err)
		}
		if err := validateStorageBenchmark(c, [][]uint32{{8, 24}}, nil); err == nil {
			t.Fatal("combined native experiments were accepted")
		}
		if err := c.Set(other, "false"); err != nil {
			t.Fatal(err)
		}
		if err := c.Set(storageBenchmarkSizeArgName, "32"); err != nil {
			t.Fatal(err)
		}
		if err := validateStorageBenchmark(c, [][]uint32{{8, 24}}, nil); err == nil {
			t.Fatal("experiment accepted an inconsistent working set")
		}
	}
	for _, mode := range []string{"latency", "throughput"} {
		if err := validateStorageBenchmark(benchmarkTestContext(t, "--storage-benchmark-"+mode), nil, nil); err == nil {
			t.Fatal("experiment selection accepted without a benchmark")
		}
	}

}
