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
	"github.com/Microsoft/hcsshim/internal/sibling"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/uvm/scsi"
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
	storageBenchmarkTestArgName       = "storage-benchmark-test"
	storageBenchmarkStatsArgName      = "storage-benchmark-stats"
	storageBenchmarkLatencyArgName    = "storage-benchmark-latency"
	storageBenchmarkThroughputArgName = "storage-benchmark-throughput"
	storageBenchmarkIdleArgName       = "storage-benchmark-idle"
	storageBenchmarkDiodeIdleArgName  = "storage-benchmark-diode-idle"
)

func storageBenchmarkDiodeIdlePolicy(c *cli.Context) string {
	if idle := c.String(storageBenchmarkDiodeIdleArgName); idle != "" {
		return idle
	}
	return c.String(storageBenchmarkIdleArgName)
}

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
			storageBenchmarkSizeArgName, storageBenchmarkSmokeArgName, storageBenchmarkTestArgName, storageBenchmarkStatsArgName,
			storageBenchmarkLatencyArgName, storageBenchmarkThroughputArgName, storageBenchmarkIdleArgName, storageBenchmarkDiodeIdleArgName} {
			if c.IsSet(name) {
				return errors.New("storage benchmark options require --storage-benchmark-script")
			}
		}
		return nil
	}
	count := c.GlobalInt(countArgName)
	if c.IsSet(storageBenchmarkDiodeIdleArgName) {
		if idle := c.String(storageBenchmarkDiodeIdleArgName); count != 2 || (idle != "poll" && idle != "halt") {
			return errors.New("storage benchmark diode idle override requires a paired benchmark and poll or halt")
		}
	}
	unikraft := c.String(unikraftPackageArgName) != ""
	if err := validateBenchmarkVMResources(c); err != nil {
		return err
	}
	if !useGCS || !c.Bool(securityHardwareFlag) ||
		count != c.GlobalInt(parallelArgName) || len(groups) != count ||
		(count != 1 && count != 2) {
		return errors.New("storage benchmark requires SNP, GCS and explicit CPU affinity")
	}
	if c.String(networkBenchmarkScriptArgName) != "" || c.Bool(siblingInteractiveArgName) ||
		c.Bool(siblingStorageRootArgName) || c.String(siblingOpenShellBundleArgName) != "" ||
		c.Bool(siblingDiodeUplinkArgName) ||
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
		c.String(siblingBusGuestModuleArgName) == "" || (!unikraft && c.String(sharedMemoryGuestModuleArgName) == "") ||
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
	if c.Bool(storageBenchmarkTestArgName) && ((!latency && !throughput) || c.Bool(storageBenchmarkSmokeArgName)) {
		return errors.New("short storage test requires latency or throughput without smoke")
	}
	if idle := c.String(storageBenchmarkIdleArgName); idle != "poll" && idle != "halt" {
		return errors.New("storage benchmark idle must be poll or halt")
	}
	if unikraft && c.Bool(storageBenchmarkStatsArgName) {
		return errors.New("Linux provider counters are unavailable for Unikraft storage")
	}
	fileMiB := c.Int(storageBenchmarkSizeArgName)
	if latency || throughput {
		expected := 64
		if throughput {
			expected = 1024
			if c.Bool(storageBenchmarkTestArgName) {
				expected = 64
			}
		} else if c.Bool(storageBenchmarkTestArgName) {
			expected = 1
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
	testEnvironment := ""
	if c.Bool(storageBenchmarkTestArgName) {
		testEnvironment = "STORAGE_TEST=1 "
	}
	if c.Bool(storageBenchmarkLatencyArgName) {
		mode = " latency"
	} else if c.Bool(storageBenchmarkThroughputArgName) {
		mode = " throughput"
	}
	return fmt.Sprintf(
		`cp /run/storage-benchmark-tool/diode_fio /run/dtb-exec/diode_fio; `+
			`chmod 755 /run/dtb-exec/diode_fio; `+
			`%s/bin/sh %s %s /run/storage-benchmark-results %d %d %d %d %s %s %s %s%s; `,
		testEnvironment,
		shellSingleQuote("/run/storage-benchmark-script/"+filepath.Base(c.String(storageBenchmarkScriptArgName))), device,
		c.Int(storageBenchmarkIOArgName), c.Int(storageBenchmarkSyncIOArgName),
		c.Int(storageBenchmarkSizeArgName), smoke,
		content.ReadSHA256, content.WriteSHA256, content.SyncReadSHA, content.SyncWriteSHA, mode)
}

func storageBenchmarkPreflight(cpus uint64, idle string) string {
	online := "0"
	if cpus > 1 {
		online = fmt.Sprintf("0-%d", cpus-1)
	}
	return `set -eu; mkdir -p /run/dtb-exec; ` +
		`mount -t tmpfs -o exec,nosuid,nodev,size=16m tmpfs /run/dtb-exec; ` +
		`dmesg | grep -F 'Memory Encryption Features active:' | grep -qw SEV-SNP; ` +
		`[ "$(cat /sys/devices/system/cpu/online)" = ` + online + ` ]; ` +
		`grep -qw ` + shellSingleQuote("idle="+idle) + ` /proc/cmdline; `
}

func runProductionStorageBenchmark(ctx context.Context, c *cli.Context, groups [][]uint32, priorities []uint32) (resultErr error) {
	resources, err := resolvedVMResources(c)
	if err != nil {
		return err
	}
	resources = append([]sibling.VMResources(nil), resources...)
	if len(groups) != len(resources) || (len(priorities) != 0 && len(priorities) != len(resources)) {
		return errors.New("storage runtime requires affinity and, when selected, priority for every VM")
	}
	for i := range resources {
		resources[i].CPUGroupLPs = groups[i]
		if len(priorities) != 0 {
			resources[i].CPUGroupPriority = &priorities[i]
		}
	}
	if err := sibling.ValidateVMResources(resources); err != nil {
		return err
	}
	config := &sibling.Config{Version: 1, Standalone: len(resources) == 1, VMResources: resources}
	if !config.Standalone {
		config.ModuleDirectory = filepath.Dir(c.String(siblingBusGuestModuleArgName))
		config.SharedMemoryBytes = 32 << 20
		config.WorkloadGuestStateFile = siblingStorageRootVMGS
		config.MediateGCS = true
		config.UnikraftPackage = c.String(unikraftPackageArgName)
	}
	id := fmt.Sprintf("uvmboot-%d", len(resources)-1)
	options, err := createLCOWOptions(ctx, c, id)
	if err != nil {
		return err
	}
	pair, err := sibling.Start(ctx, options, config)
	if err != nil {
		return fmt.Errorf("start production storage runtime; boot state retained at %s: %w", options.BundleDirectory, err)
	}
	var releases []func(context.Context) error
	defer func() {
		closeErr := closeStorageBenchmark(ctx, func(context.Context) error { return pair.Close() }, releases)
		resultErr = errors.Join(resultErr, closeErr)
		if closeErr == nil {
			resultErr = errors.Join(resultErr, os.RemoveAll(options.BundleDirectory))
		}
	}()
	vm := pair.Workload
	if uint64(vm.ProcessorCount()) != requestedVMProcessors(c, id) {
		return fmt.Errorf("storage workload requested %d VPs, HCS assigned %d", requestedVMProcessors(c, id), vm.ProcessorCount())
	}
	content, err := prepareStorageBenchmarkContent(c.String(storageBenchmarkOutputArgName),
		c.Int(storageBenchmarkSizeArgName), c.Int(storageBenchmarkSyncIOArgName))
	if err != nil {
		return err
	}
	if err := shareStorageBenchmark(ctx, c, vm); err != nil {
		return err
	}
	const device = "/run/diode-storage/fio-data"
	disk, err := vm.SCSIManager.AddVirtualDisk(ctx, c.String(storageBenchmarkDiskArgName),
		false, vm.ID(), device, &scsi.MountConfig{BlockDev: true})
	if err != nil {
		return fmt.Errorf("attach benchmark disk through production storage manager: %w", err)
	}
	releases = append(releases, disk.Release)
	fmt.Printf("storage_benchmark_attachment: production vm=%s controller=%d lun=%d path=%q\n",
		vm.ID(), disk.Controller(), disk.LUN(), c.String(storageBenchmarkDiskArgName))
	metadata, err := json.Marshal(config)
	if err != nil {
		return err
	}
	fmt.Printf("storage_benchmark_runtime: %s\n", metadata)
	if !config.Standalone {
		policy := "backend_path=production-unikraft-raw-scsi\n"
		if config.UnikraftPackage == "" {
			if err := pair.Diode.Share(ctx, c.String(storageBenchmarkOutputArgName), "/run/storage-benchmark-results", false); err != nil {
				return err
			}
			check := `set -eu; [ "$(cat /sys/module/diode_storvsp/parameters/direct_io)" = N ]; `
			if c.Bool(storageBenchmarkStatsArgName) {
				check += `echo Y >/sys/module/diode_storvsp/parameters/stats_enabled; ` +
					storageBenchmarkProviderSnapshot("before")
			}
			if err := execViaGCS(ctx, pair.Diode, c, check); err != nil {
				return fmt.Errorf("verify production Linux backend policy: %w", err)
			}
			policy = "backend_path=production-linux-buffered-scsi\n"
		}
		if err := os.WriteFile(filepath.Join(c.String(storageBenchmarkOutputArgName), "backend-policy.txt"), []byte(policy), 0600); err != nil {
			return err
		}
	}
	command := storageBenchmarkPreflight(requestedVMProcessors(c, id), c.String(storageBenchmarkIdleArgName)) +
		storageBenchmarkClient(c, shellSingleQuote(device), content)
	resultErr = execViaGCS(ctx, vm, c, command)
	if c.Bool(storageBenchmarkStatsArgName) {
		resultErr = errors.Join(resultErr, execViaGCS(ctx, pair.Diode, c, storageBenchmarkProviderSnapshot("after")))
	}
	return resultErr
}

func storageBenchmarkProviderSnapshot(phase string) string {
	return `set -eu; cat /sys/module/diode_storvsp/parameters/stats >/run/storage-benchmark-results/provider-` + phase + `.txt; ` +
		`cat /sys/module/diode_storvsp/parameters/pipeline_stats >/run/storage-benchmark-results/pipeline-` + phase + `.txt; `
}

func shareStorageBenchmark(ctx context.Context, c *cli.Context, vm *uvm.UtilityVM) error {
	for _, share := range []struct {
		host, guest string
		readOnly    bool
	}{
		{c.String(storageBenchmarkScriptArgName), "/run/storage-benchmark-script", true},
		{filepath.Join(filepath.Dir(c.String(storageBenchmarkScriptArgName)), "diode_fio"), "/run/storage-benchmark-tool", true},
		{c.String(storageBenchmarkOutputArgName), "/run/storage-benchmark-results", false},
	} {
		if err := vm.Share(ctx, share.host, share.guest, share.readOnly); err != nil {
			return fmt.Errorf("share storage benchmark input/results: %w", err)
		}
	}
	return nil
}

func prepareStorageBenchmark(ctx context.Context, c *cli.Context, vm *uvm.UtilityVM,
	plan *siblingStoragePlan, reports []siblingStorageBackendReport,
	regions int, eventArgs string) (string, func(context.Context) error, error) {
	noCleanup := func(context.Context) error { return nil }
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
	if err := shareStorageBenchmark(ctx, c, vm); err != nil {
		return "", noCleanup, err
	}
	command := storageBenchmarkPreflight(requestedVMProcessors(c, vm.ID()), c.String(storageBenchmarkIdleArgName))
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
		if c.String(unikraftPackageArgName) != "" {
			command += `echo 'backend_path=unikraft-raw-scsi' >/run/storage-benchmark-results/backend-policy.txt; `
			return command + storageBenchmarkClient(c, "/run/diode-storage/fio-data", content), noCleanup, nil
		}
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
