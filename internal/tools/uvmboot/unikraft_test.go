//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnikraftPairValidation(t *testing.T) {
	old := useGCS
	useGCS = true
	t.Cleanup(func() { useGCS = old })
	pack := t.TempDir()
	for _, name := range []string{"unikraftboot.exe", "guest.vmgs", "manifest.json", "sibling_bus.ko"} {
		if err := os.WriteFile(filepath.Join(pack, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	valid := []string{"--" + unikraftPackageArgName, pack,
		"--" + securityHardwareFlag, "--" + sharedMemoryTwoUVMArgName,
		"--" + siblingBusGuestModuleArgName, filepath.Join(pack, "sibling_bus.ko"),
		"--" + sharedMemorySizeArgName, "2097152"}
	context := benchmarkTestContext(t, valid...)
	if err := context.GlobalSet(countArgName, "2"); err != nil {
		t.Fatal(err)
	}
	if err := context.GlobalSet(parallelArgName, "2"); err != nil {
		t.Fatal(err)
	}
	if err := validateUnikraftPair(context); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--" + unikraftPackageArgName, pack},
		append(append([]string{}, valid...), "--"+siblingDiodeUplinkArgName),
		append(append([]string{}, valid...), "--"+sharedMemoryMappingOnlyArgName),
	} {
		context := benchmarkTestContext(t, args...)
		if err := context.GlobalSet(countArgName, "2"); err != nil {
			t.Fatal(err)
		}
		if err := context.GlobalSet(parallelArgName, "2"); err != nil {
			t.Fatal(err)
		}
		if err := validateUnikraftPair(context); err == nil {
			t.Fatal("accepted incomplete or incompatible mixed-pair options")
		}
	}
}

func TestUnikraftWorkloadCommand(t *testing.T) {
	command := unikraftWorkloadCommand("/run/path with 'quote/sibling_bus.ko")
	for _, required := range []string{
		"set -eu", "insmod '/run/path with ", `'"'"'`,
		"echo 16/16 ok",
	} {
		if !strings.Contains(command, required) {
			t.Fatalf("missing %q: %s", required, command)
		}
	}
	for _, required := range []string{
		`[ "$i" -lt 120 ]`, "rmmod sibling_bus",
		"trap cleanup EXIT", "dmesg", "exit 1",
		"PASS: Linux workload verified 16/16 echoes",
	} {
		if !strings.Contains(command, required) {
			t.Fatalf("missing %q: %s", required, command)
		}
	}
	for _, forbidden := range []string{"hcs_shmem_diag", "diode_netvsp", "iptables", "iperf", "echo 15/16"} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("unexpected dependency %q", forbidden)
		}
	}
}
