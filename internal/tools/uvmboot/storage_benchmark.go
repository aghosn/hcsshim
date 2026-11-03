//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

const (
	storageBenchmarkScriptArgName     = "storage-benchmark-script"
	storageBenchmarkDiskArgName       = "storage-benchmark-disk"
	storageBenchmarkOutputArgName     = "storage-benchmark-output"
	storageBenchmarkTimeoutArgName    = "storage-benchmark-timeout"
	storageBenchmarkIOArgName         = "storage-benchmark-io-mib"
	storageBenchmarkSyncIOArgName     = "storage-benchmark-sync-io-mib"
	storageBenchmarkSizeArgName       = "storage-benchmark-size-mib"
	storageBenchmarkSmokeArgName      = "storage-benchmark-smoke"
	storageBenchmarkStatsArgName      = "storage-benchmark-stats"
	storageBenchmarkLatencyArgName    = "storage-benchmark-latency"
	storageBenchmarkThroughputArgName = "storage-benchmark-throughput"
)

type storageBenchmarkContent struct {
	FileMiB      int    `json:"file_mib"`
	SyncFileMiB  int    `json:"sync_file_mib"`
	ReadSHA256   string `json:"read_sha256"`
	WriteSHA256  string `json:"write_sha256"`
	SyncReadSHA  string `json:"sync_read_sha256"`
	SyncWriteSHA string `json:"sync_write_sha256"`
	Pattern      string `json:"pattern"`
}

func storageBenchmarkPattern(kind string) []byte {
	pattern := make([]byte, 0, 4096)
	for i := 0; i < 128; i++ {
		block := sha256.Sum256([]byte(fmt.Sprintf("diode-fio-%s-v1:%d", kind, i)))
		pattern = append(pattern, block[:]...)
	}
	return pattern
}

func storageBenchmarkContentHash(pattern []byte, sizeMiB int) string {
	block := bytes.Repeat(pattern, 1024*1024/len(pattern))
	hash := sha256.New()
	for i := 0; i < sizeMiB; i++ {
		hash.Write(block)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func prepareStorageBenchmarkContent(output string, fileMiB, syncMiB int) (storageBenchmarkContent, error) {
	contract := storageBenchmarkContent{
		FileMiB: fileMiB, SyncFileMiB: min(fileMiB, syncMiB),
		Pattern: "version-1 SHA256-derived 4-KiB tiles, repeated; a=initial/read, b=write; compression/deduplication may affect performance",
	}
	for _, kind := range []string{"a", "b"} {
		pattern := storageBenchmarkPattern(kind)
		if err := os.WriteFile(filepath.Join(output, "pattern-"+kind+".bin"), pattern, 0600); err != nil {
			return contract, fmt.Errorf("write deterministic storage pattern: %w", err)
		}
		full := storageBenchmarkContentHash(pattern, fileMiB)
		short := full
		if contract.SyncFileMiB != fileMiB {
			short = storageBenchmarkContentHash(pattern, contract.SyncFileMiB)
		}
		if kind == "a" {
			contract.ReadSHA256, contract.SyncReadSHA = full, short
		} else {
			contract.WriteSHA256, contract.SyncWriteSHA = full, short
		}
	}
	data, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		return contract, fmt.Errorf("encode deterministic storage content contract: %w", err)
	}
	if err := os.WriteFile(filepath.Join(output, "content-contract.json"), data, 0600); err != nil {
		return contract, fmt.Errorf("write deterministic storage content contract: %w", err)
	}
	return contract, nil
}

func closeStorageBenchmark(ctx context.Context, closeVM func(context.Context) error,
	releases []func(context.Context) error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var resultErr error
	for i := len(releases) - 1; i >= 0; i-- {
		resultErr = errors.Join(resultErr, releases[i](cleanupCtx))
	}
	return errors.Join(resultErr, closeVM(cleanupCtx))
}

func validateStorageBenchmark(c *cli.Context, groups [][]uint32, plan *siblingStoragePlan) error {
	if c.String(storageBenchmarkScriptArgName) == "" {
		for _, name := range []string{storageBenchmarkDiskArgName, storageBenchmarkOutputArgName,
			storageBenchmarkTimeoutArgName, storageBenchmarkIOArgName, storageBenchmarkSyncIOArgName,
			storageBenchmarkSizeArgName, storageBenchmarkSmokeArgName, storageBenchmarkStatsArgName,
			storageBenchmarkLatencyArgName, storageBenchmarkThroughputArgName} {
			if c.IsSet(name) {
				return errors.New("storage benchmark options require --storage-benchmark-script")
			}
		}
		return nil
	}
	count := c.GlobalInt(countArgName)
	if !useGCS || !c.Bool(securityHardwareFlag) || c.GlobalUint64(cpusArgName) != 2 ||
		count != c.GlobalInt(parallelArgName) || len(groups) != count ||
		(count != 1 && count != 2) {
		return errors.New("storage benchmark requires SNP, GCS, two VPs and explicit CPU affinity per concurrently launched VM")
	}
	if c.String(networkBenchmarkScriptArgName) != "" || c.Bool(siblingInteractiveArgName) ||
		c.Bool(siblingStorageRootArgName) || c.String(siblingOpenShellBundleArgName) != "" ||
		c.String("unikraft-diode-package") != "" || c.Bool(siblingDiodeUplinkArgName) ||
		c.IsSet(baselineNICArgName) || c.IsSet(baselinePairArgName) ||
		c.IsSet(execCommandLineArgName) || c.IsSet(execFileArgName) ||
		c.IsSet(scsiMountsArgName) || c.IsSet(vpmemMountsArgName) || debug ||
		c.Bool(sharedMemoryMappingOnlyArgName) || c.Bool(sharedMemoryGuestInventoryArgName) {
		return errors.New("storage benchmark cannot combine with networking, root mediation, interactive, custom exec/mounts or diagnostics")
	}
	if count == 1 {
		if plan != nil || c.IsSet(sharedMemorySizeArgName) || c.Bool(sharedMemoryTwoUVMArgName) ||
			c.IsSet(siblingBusGuestModuleArgName) || c.IsSet(sharedMemoryGuestModuleArgName) ||
			c.Bool(storageBenchmarkStatsArgName) {
			return errors.New("standalone storage baseline must not create a diode, sibling link or provider counters")
		}
	} else if plan == nil || !c.Bool(sharedMemoryTwoUVMArgName) ||
		c.String(siblingBusGuestModuleArgName) == "" || c.String(sharedMemoryGuestModuleArgName) == "" ||
		len(plan.Disks) != 1 || plan.Disks[0].Role != "data" || plan.Disks[0].Access != "read-write" ||
		plan.Disks[0].ID != "fio-data" || plan.Disks[0].ExportLUN == nil ||
		*plan.Disks[0].ExportLUN != 1 ||
		!equalStoragePath(plan.Disks[0].HostPath, c.String(storageBenchmarkDiskArgName)) {
		return errors.New("mediated storage benchmark requires exactly one read-write fio-data export at LUN 1 matching its disk")
	}
	for _, path := range []string{c.String(storageBenchmarkScriptArgName),
		c.String(storageBenchmarkDiskArgName),
		filepath.Join(filepath.Dir(c.String(storageBenchmarkScriptArgName)), "diode_fio")} {
		if info, err := os.Stat(path); err != nil {
			return fmt.Errorf("inspect storage benchmark input: %w", err)
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("storage benchmark input is not a regular file: %s", path)
		}
	}
	if filepath.Ext(c.String(storageBenchmarkDiskArgName)) != ".vhdx" {
		return errors.New("storage benchmark requires a disposable VHDX")
	}
	if info, err := os.Stat(c.String(storageBenchmarkOutputArgName)); err != nil || !info.IsDir() {
		return errors.New("storage benchmark requires an existing output directory")
	}
	entries, err := os.ReadDir(c.String(storageBenchmarkOutputArgName))
	if err != nil || len(entries) != 0 {
		return errors.New("storage benchmark output directory must be empty")
	}
	latency := c.Bool(storageBenchmarkLatencyArgName)
	throughput := c.Bool(storageBenchmarkThroughputArgName)
	if latency && throughput {
		return errors.New("select only one storage benchmark experiment per launch")
	}
	fileMiB := c.Int(storageBenchmarkSizeArgName)
	if latency || throughput {
		expected := 64
		if throughput {
			expected = 1024
		}
		if c.Bool(storageBenchmarkSmokeArgName) {
			expected = 1
		}
		if fileMiB != expected {
			return fmt.Errorf("selected storage experiment requires a %d-MiB common working set", expected)
		}
	}
	if c.Duration(storageBenchmarkTimeoutArgName) <= 0 ||
		c.Int(storageBenchmarkIOArgName) < 32 || c.Int(storageBenchmarkIOArgName) > 102400 ||
		c.Int(storageBenchmarkSyncIOArgName) < 4 || c.Int(storageBenchmarkSyncIOArgName) > 1024 ||
		fileMiB < 1 || fileMiB > 2048 || (!latency && !throughput && fileMiB < 32) {
		return errors.New("storage benchmark IO budget, file size or deadline out of range")
	}
	if c.Int(storageBenchmarkIOArgName)%c.Int(storageBenchmarkSizeArgName) != 0 ||
		c.Int(storageBenchmarkSyncIOArgName)%min(c.Int(storageBenchmarkSizeArgName), c.Int(storageBenchmarkSyncIOArgName)) != 0 {
		return errors.New("storage benchmark IO budgets must cover whole working-set passes")
	}
	return nil
}

func equalStoragePath(first, second string) bool {
	a, err := os.Stat(first)
	if err != nil {
		return false
	}
	b, err := os.Stat(second)
	return err == nil && os.SameFile(a, b)
}

func storageBenchmarkClient(c *cli.Context, device string, content storageBenchmarkContent) string {
	smoke := 0
	if c.Bool(storageBenchmarkSmokeArgName) {
		smoke = 1
	}
	mode := ""
	if c.Bool(storageBenchmarkLatencyArgName) {
		mode = " latency"
	} else if c.Bool(storageBenchmarkThroughputArgName) {
		mode = " throughput"
	}
	return fmt.Sprintf(
		`cp /run/storage-benchmark-tool/diode_fio /run/dtb-exec/diode_fio; `+
			`chmod 755 /run/dtb-exec/diode_fio; `+
			`/bin/sh %s %s /run/storage-benchmark-results %d %d %d %d %s %s %s %s%s; `,
		shellSingleQuote("/run/storage-benchmark-script/"+filepath.Base(c.String(storageBenchmarkScriptArgName))), device,
		c.Int(storageBenchmarkIOArgName), c.Int(storageBenchmarkSyncIOArgName),
		c.Int(storageBenchmarkSizeArgName), smoke,
		content.ReadSHA256, content.WriteSHA256, content.SyncReadSHA, content.SyncWriteSHA, mode)
}

func storageBenchmarkPreflight() string {
	return `set -eu; mkdir -p /run/dtb-exec; ` +
		`mount -t tmpfs -o exec,nosuid,nodev,size=16m tmpfs /run/dtb-exec; ` +
		`dmesg | grep -F 'Memory Encryption Features active:' | grep -qw SEV-SNP; ` +
		`[ "$(cat /sys/devices/system/cpu/online)" = 0-1 ]; ` +
		`grep -qw idle=halt /proc/cmdline; `
}

func prepareStorageBenchmark(ctx context.Context, c *cli.Context, vm *uvm.UtilityVM,
	plan *siblingStoragePlan, reports []siblingStorageBackendReport,
	regions int, eventArgs string) (string, func(context.Context) error, error) {
	noCleanup := func(context.Context) error { return nil }
	script := c.String(storageBenchmarkScriptArgName)
	role := ""
	if plan != nil {
		var err error
		role, err = sharedMemoryProofRole(vm.ID())
		if err != nil {
			return "", noCleanup, err
		}
	}
	var content storageBenchmarkContent
	if plan == nil || role == workloadRole {
		var err error
		content, err = prepareStorageBenchmarkContent(c.String(storageBenchmarkOutputArgName),
			c.Int(storageBenchmarkSizeArgName), c.Int(storageBenchmarkSyncIOArgName))
		if err != nil {
			return "", noCleanup, err
		}
	}
	for _, share := range []struct {
		host, guest string
		readOnly    bool
	}{
		{script, "/run/storage-benchmark-script", true},
		{filepath.Join(filepath.Dir(script), "diode_fio"), "/run/storage-benchmark-tool", true},
		{c.String(storageBenchmarkOutputArgName), "/run/storage-benchmark-results", false},
	} {
		if err := vm.Share(ctx, share.host, share.guest, share.readOnly); err != nil {
			return "", noCleanup, fmt.Errorf("share storage benchmark input/results: %w", err)
		}
	}
	command := storageBenchmarkPreflight()
	if plan == nil {
		attachment, err := attachSiblingStorageDisk(ctx, vm, siblingStorageDisk{
			HostPath: c.String(storageBenchmarkDiskArgName), Access: "read-write",
		})
		if err != nil {
			return "", noCleanup, err
		}
		fmt.Printf("storage_benchmark_attachment: baseline vm=%s controller=%d lun=%d path=%q\n",
			vm.ID(), attachment.controller, attachment.lun, c.String(storageBenchmarkDiskArgName))
		command += storageRPDeviceCommand(guestrequest.ScsiControllerGuids[attachment.controller], attachment.lun)
		return command + storageBenchmarkClient(c, `"$storage_dev"`, content), attachment.release, nil
	}
	if regions != 1 || eventArgs == "" {
		return "", noCleanup, errors.New("storage benchmark requires the mapped sibling region and peer event route")
	}
	bus := c.String(siblingBusGuestModuleArgName)
	if err := vm.Share(ctx, bus, "/run/storage-benchmark-bus", true); err != nil {
		return "", noCleanup, err
	}
	command += siblingBusLoadCommand("/run/storage-benchmark-bus/" + filepath.Base(bus))
	command += siblingInstanceCommand()
	provider := ""
	if role == diodeRole {
		provider = "/run/storage-benchmark-provider/diode_storvsp.ko"
		if err := vm.Share(ctx, filepath.Join(filepath.Dir(bus), "diode_storvsp.ko"),
			"/run/storage-benchmark-provider", true); err != nil {
			return "", noCleanup, err
		}
	} else {
		if err := vm.Share(ctx, filepath.Join(filepath.Dir(bus), "diode_storage_test"),
			"/run/diode-storage-test", true); err != nil {
			return "", noCleanup, err
		}
	}
	storageCommand, err := siblingStorageGuestCommand(provider, role, plan, reports,
		c.Bool(storageBenchmarkLatencyArgName) || c.Bool(storageBenchmarkThroughputArgName))
	if err != nil {
		return "", noCleanup, err
	}
	command += storageCommand + "; "
	if role == workloadRole {
		ready := `[ -f /run/storage-benchmark-results/provider-ready ]`
		return command + guestWaitFor(ready, "provider snapshot") +
			storageBenchmarkClient(c, "/run/diode-storage/fio-data", content), noCleanup, nil
	}
	if c.Bool(storageBenchmarkStatsArgName) {
		command += `echo Y >/sys/module/diode_storvsp/parameters/stats_enabled; `
	}
	if c.Bool(storageBenchmarkLatencyArgName) || c.Bool(storageBenchmarkThroughputArgName) {
		command += `[ "$(cat /sys/module/diode_storvsp/parameters/direct_io)" = Y ] || exit 1; ` +
			`echo 'backend_direct_io=1' >/run/storage-benchmark-results/backend-policy.txt; `
	}
	command += `cat /sys/module/diode_storvsp/parameters/stats >/run/storage-benchmark-results/provider-before.txt; ` +
		`cat /sys/module/diode_storvsp/parameters/pipeline_stats >/run/storage-benchmark-results/pipeline-before.txt; ` +
		`touch /run/storage-benchmark-results/provider-ready; `
	command +=
		`until dmesg | grep -qF 'storage channel closed; worker quiesced'; do sleep 1; done; ` +
			`cat /sys/module/diode_storvsp/parameters/stats >/run/storage-benchmark-results/provider-after.txt; ` +
			`cat /sys/module/diode_storvsp/parameters/pipeline_stats >/run/storage-benchmark-results/pipeline-after.txt; ` +
			`echo 'storage_benchmark: provider stopped'; `
	return command, noCleanup, nil
}
