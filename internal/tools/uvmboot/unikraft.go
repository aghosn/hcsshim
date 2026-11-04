//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/urfave/cli"
)

const unikraftPackageArgName = "unikraft-diode-package"

func validateUnikraftPair(c *cli.Context) error {
	if c.String(unikraftPackageArgName) == "" {
		return nil
	}
	if !useGCS || !c.Bool(securityHardwareFlag) ||
		!c.Bool(sharedMemoryTwoUVMArgName) ||
		c.GlobalInt(countArgName) != 2 || c.GlobalInt(parallelArgName) != 2 ||
		c.String(siblingBusGuestModuleArgName) == "" ||
		c.Uint64(sharedMemorySizeArgName) != 2*1024*1024 {
		return fmt.Errorf("--%s requires --gcs --count 2 --parallel 2, hardware SNP, a sibling-bus module and a 2 MiB two-UVM shared section", unikraftPackageArgName)
	}
	for _, name := range []string{
		sharedMemoryGuestModuleArgName, sharedMemoryMappingOnlyArgName,
		sharedMemoryGuestInventoryArgName, siblingDiodeUplinkArgName,
		siblingInteractiveArgName, siblingOpenShellBundleArgName,
		baselineNICArgName, baselinePairArgName, networkBenchmarkScriptArgName,
		execCommandLineArgName, execFileArgName, cpuGroupLPsArgName,
	} {
		if c.IsSet(name) {
			return fmt.Errorf("--%s cannot be combined with --%s", unikraftPackageArgName, name)
		}
	}
	for _, name := range []string{"unikraftboot.exe", "guest.vmgs", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(c.String(unikraftPackageArgName), name)); err != nil {
			return fmt.Errorf("inspect Unikraft package: %w", err)
		}
	}
	return nil
}

func runUnikraftProvider(ctx context.Context, packageDir, group string, section *sharedMemorySection) error {
	data, err := os.ReadFile(filepath.Join(packageDir, "manifest.json"))
	if err != nil {
		return err
	}
	var manifest struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("decode Unikraft package manifest: %w", err)
	}
	command := exec.CommandContext(ctx, filepath.Join(packageDir, "unikraftboot.exe"),
		"-vmgs", filepath.Join(packageDir, "guest.vmgs"),
		"-sha256", manifest.Files["guest.vmgs"],
		"-output", filepath.Join(packageDir, "results"),
		"-timeout", "180s", "-sibling-group", group,
		"-sibling-section", section.hcsName,
		"-sibling-length", fmt.Sprint(section.size))
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("Unikraft provider: %w", err)
	}
	return nil
}

func unikraftWorkloadCommand(module string) string {
	return `set -eu; ` +
		`unbind() { for dev in /sys/bus/vmbus/drivers/sibling_bus/*-*; do ` +
		`[ -L "$dev" ] || continue; printf '%s' "${dev##*/}" > /sys/bus/vmbus/drivers/sibling_bus/unbind; done; }; ` +
		`unload() { unbind || return 1; n=0; ` +
		`while grep -q '^sibling_bus ' /proc/modules; do ` +
		`rmmod sibling_bus && return 0; n=$((n+1)); [ "$n" -lt 30 ] || return 1; sleep 1; done; }; ` +
		`cleanup() { rc=$?; trap - EXIT; ` +
		`if grep -q '^sibling_bus ' /proc/modules; then ` +
		`unload || rc=1; fi; dmesg; exit "$rc"; }; trap cleanup EXIT; ` +
		`insmod ` + shellSingleQuote(module) + `; ` +
		`i=0; until dmesg | grep -q 'echo 16/16 ok'; do ` +
		`i=$((i+1)); [ "$i" -lt 120 ] || { echo 'FAIL: Linux sibling echo timeout' >&2; exit 1; }; ` +
		`sleep 1; done; ` +
		`unload; trap - EXIT; dmesg; ` +
		`echo 'PASS: Linux workload verified 16/16 echoes and unloaded the sibling adapter'`
}
