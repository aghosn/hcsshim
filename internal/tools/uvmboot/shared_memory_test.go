//go:build windows

package main

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
	"github.com/urfave/cli"
)

// TestProtectedSiblingRejectsUnsupportedUpstreamModes keeps diagnostics and
// unsupported families out of protected startup before any artifact/native work.
func TestProtectedSiblingRejectsUnsupportedUpstreamModes(t *testing.T) {
	previousGCS := useGCS
	useGCS = true
	defer func() { useGCS = previousGCS }()
	for _, test := range []struct{ name, value string }{
		{baselineVsockArgName, "runtime"},
		{networkBenchmarkSingleVPArgName, "true"},
		{storageBenchmarkIdleArgName, "halt"},
	} {
		t.Run(test.name+"="+test.value, func(t *testing.T) {
			global := flag.NewFlagSet("global", flag.ContinueOnError)
			global.Int(countArgName, 2, "")
			global.Int(parallelArgName, 2, "")
			local := flag.NewFlagSet("lcow", flag.ContinueOnError)
			for _, option := range lcowCommand.Flags {
				option.Apply(local)
			}
			for name, value := range map[string]string{
				protectedSharedMemoryArgName: "true",
				securityHardwareFlag:         "true",
				siblingInteractiveArgName:    "true",
				siblingDiodeUplinkArgName:    "true",
				siblingBusGuestModuleArgName: "missing-fixture-module",
				rootFSTypeArgName:            "none",
				test.name:                    test.value,
			} {
				if err := local.Set(name, value); err != nil {
					t.Fatal(err)
				}
			}
			c := cli.NewContext(nil, local, cli.NewContext(nil, global, nil))
			err := validateProtectedSiblingCLI(c)
			if err == nil || !strings.Contains(err.Error(), "--"+test.name+" is incompatible") {
				t.Fatalf("unsupported mode reached artifact/resource preparation: %v", err)
			}
		})
	}
}

// protectedSiblingTestArgs supplies regular input-shape fixtures for protected
// preflight, including diode-only AHV tooling. No file is a bootable image and
// no native controller or VM is created.
func protectedSiblingTestArgs(t *testing.T, combined bool) []string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{
		"sibling_bus.ko", siblingNetModuleName(diodeRole), "diode_tcpbulk",
		"diode_vsock_test", iperfGuestName, "demo.sh", "covert_udp", "diode_tcpdump",
		"diode_tc", "diode_iptables", "ahv-guest-ctl", pageMetadataCollector,
		"diode_storvsp.ko", vmutils.DefaultGuestStateFile, siblingStorageRootVMGS,
		vmutils.DefaultDmVerityRootfsVhd,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("shape fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{
		"--" + protectedSharedMemoryArgName, "--" + securityHardwareFlag,
		"--" + siblingInteractiveArgName, "--" + siblingDiodeUplinkArgName,
		"--" + siblingBusGuestModuleArgName, filepath.Join(dir, "sibling_bus.ko"),
		"--" + bootFilesPathArgName, dir, "--" + rootFSTypeArgName, "none",
		"--" + sharedMemorySizeArgName, "2097152",
	}
	if combined {
		lun := uint8(0)
		plan := &siblingStoragePlan{Version: 1, Disks: []siblingStorageDisk{{
			ID: "workload-root", Role: "root", HostPath: filepath.Join(dir, vmutils.DefaultDmVerityRootfsVhd),
			Access: "read-only", ExportLUN: &lun,
		}}}
		path := filepath.Join(dir, "backends.json")
		if err := os.WriteFile(path, []byte(storagePlanJSON(t, plan)), 0600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--"+siblingStorageRootArgName, "--"+siblingGCSRelayArgName,
			"--"+siblingStorageBackendsArgName, path, "--"+sharedMemorySizeArgName,
			strconv.FormatUint(protectedCombinedBytes, 10))
	}
	return args
}

// TestProtectedSiblingProfilesPreflight admits both complete profiles without
// native authority. The combined workload selects relay-root VMGS while the
// diode/legacy roots remain direct; neither enables ordinary proof mappings.
func TestProtectedSiblingProfilesPreflight(t *testing.T) {
	oldGCS := useGCS
	// Restore the process-wide CLI fixture setting after this serial test.
	t.Cleanup(func() { useGCS = oldGCS })
	useGCS = true
	for _, combined := range []bool{false, true} {
		c := storageTestContext(t, protectedSiblingTestArgs(t, combined)...)
		if !combined {
			// The legacy route must not gain the combined provider/image
			// dependencies or a new geometry requirement.
			for _, name := range []string{"diode_storvsp.ko", siblingStorageRootVMGS} {
				if err := os.Remove(filepath.Join(c.String(bootFilesPathArgName), name)); err != nil {
					t.Fatal(err)
				}
			}
			if c.Uint64(sharedMemorySizeArgName) != 2<<20 {
				t.Fatal("legacy fixture lost its 2-MiB launcher geometry")
			}
		}
		profile, err := preflightProtectedSiblingProfile(c)
		want := protectedSiblingDirectRoot
		if combined {
			want = protectedSiblingMediatedRoot
		}
		if err != nil || profile != want || c.Bool(sharedMemoryTwoUVMArgName) {
			t.Fatalf("combined=%t: profile=%v err=%v (must not enable proof mode)", combined, profile, err)
		}
		if err := validateProtectedSiblingCLI(c); err != nil {
			t.Fatalf("supported profile did not reach protected owner admission: %v", err)
		}
		for i, id := range []string{"uvmboot-0", "uvmboot-1"} {
			options, err := createLCOWOptions(context.Background(), c, id)
			if err != nil {
				t.Fatal(err)
			}
			mediated := combined && i == 1
			image := vmutils.DefaultGuestStateFile
			if mediated {
				image = siblingStorageRootVMGS
			}
			if options.SiblingRoot != mediated || options.GuestStateFilePath != image ||
				options.BundleDirectory != "" || !options.DmVerityMode ||
				len(options.SharedMemoryRegions) != 0 ||
				strings.Contains(options.KernelBootOptions, "hcs_shmem_diag.role=") {
				t.Fatalf("combined=%t role=%s: incorrect root image, premature bundle or ordinary proof state", combined, id)
			}
		}
	}
}

// TestProtectedSiblingProfileSelections checks paired values, legacy geometry
// and combined-only size/route requirements so explicit false cannot opt in or
// silently downgrade a partial protected route.
func TestProtectedSiblingProfileSelections(t *testing.T) {
	oldGCS := useGCS
	// Restore the process-wide CLI fixture setting after this serial test.
	t.Cleanup(func() { useGCS = oldGCS })
	useGCS = true
	for _, test := range []struct {
		name     string
		combined bool
		args     []string
		fail     bool
	}{
		{"omitted", false, nil, false},
		{"false-pair", false, []string{"--" + siblingStorageRootArgName + "=false", "--" + siblingGCSRelayArgName + "=false"}, false},
		{"root-only", false, []string{"--" + siblingStorageRootArgName}, true},
		{"relay-only", false, []string{"--" + siblingGCSRelayArgName}, true},
		{"root-false", true, []string{"--" + siblingStorageRootArgName + "=false"}, true},
		{"relay-false", true, []string{"--" + siblingGCSRelayArgName + "=false"}, true},
		{"legacy-min", false, []string{"--" + sharedMemorySizeArgName, strconv.Itoa(protectedTransportMinBytes)}, false},
		{"legacy-max", false, []string{"--" + sharedMemorySizeArgName, strconv.Itoa(protectedTransportMaxBytes)}, false},
		{"legacy-unaligned", false, []string{"--" + sharedMemorySizeArgName, "2097153"}, true},
		{"legacy-small", false, []string{"--" + sharedMemorySizeArgName, "4096"}, true},
		{"legacy-large", false, []string{"--" + sharedMemorySizeArgName, "33558528"}, true},
		{"legacy-exports", false, []string{"--" + siblingStorageBackendsArgName, "backends.json"}, true},
		{"combined-small", true, []string{"--" + sharedMemorySizeArgName, "2097152"}, true},
		{"combined-large", true, []string{"--" + sharedMemorySizeArgName, "33558528"}, true},
		{"missing-plan", true, []string{"--" + siblingStorageBackendsArgName, ""}, true},
		{"proof", true, []string{"--" + sharedMemoryTwoUVMArgName}, true},
		{"proof-false", true, []string{"--" + sharedMemoryTwoUVMArgName + "=false"}, true},
		{"mapping", true, []string{"--" + sharedMemoryMappingOnlyArgName}, true},
		{"inventory", true, []string{"--" + sharedMemoryGuestInventoryArgName}, true},
		{"unikraft", true, []string{"--" + unikraftPackageArgName, "package"}, true},
		{"openshell", true, []string{"--" + siblingOpenShellBundleArgName, "bundle"}, true},
		{"benchmark", true, []string{"--" + networkBenchmarkScriptArgName, "benchmark"}, true},
		{"no-snp", true, []string{"--" + securityHardwareFlag + "=false"}, true},
		{"no-protected", true, []string{"--" + protectedSharedMemoryArgName + "=false"}, true},
		{"wrong-root-fs", true, []string{"--" + rootFSTypeArgName, "vhd"}, true},
		{"no-interactive", true, []string{"--" + siblingInteractiveArgName + "=false"}, true},
		{"no-uplink", true, []string{"--" + siblingDiodeUplinkArgName + "=false"}, true},
		{"no-verity", true, []string{"--" + noVerityBoot}, true},
	} {
		c := storageTestContext(t, append(protectedSiblingTestArgs(t, test.combined), test.args...)...)
		_, err := classifyProtectedSiblingProfile(c)
		if (err != nil) != test.fail {
			t.Fatalf("%s: error=%v, want failure=%t", test.name, err, test.fail)
		}
	}
}

// TestProtectedSiblingProfileWorkerConstraints rejects missing GCS and incorrect
// worker counts before any native work; both peers are required for root/relay.
func TestProtectedSiblingProfileWorkerConstraints(t *testing.T) {
	oldGCS := useGCS
	// Restore the process-wide CLI fixture setting after this serial test.
	t.Cleanup(func() { useGCS = oldGCS })
	useGCS = true
	for _, name := range []string{countArgName, parallelArgName} {
		c := storageTestContext(t, protectedSiblingTestArgs(t, true)...)
		if err := c.GlobalSet(name, "1"); err != nil {
			t.Fatal(err)
		}
		if _, err := classifyProtectedSiblingProfile(c); err == nil {
			t.Fatalf("accepted one-worker %s", name)
		}
	}
	useGCS = false
	if _, err := classifyProtectedSiblingProfile(storageTestContext(t, protectedSiblingTestArgs(t, true)...)); err == nil {
		t.Fatal("accepted protected root/relay without GCS")
	}
}

// TestProtectedSiblingProfileArtifacts keeps relay-root/provider and AHV inputs
// mandatory while treating files only as shape fixtures, not native evidence.
func TestProtectedSiblingProfileArtifacts(t *testing.T) {
	oldGCS := useGCS
	// Restore the process-wide CLI fixture setting after this serial test.
	t.Cleanup(func() { useGCS = oldGCS })
	useGCS = true
	for _, name := range []string{"diode_storvsp.ko", siblingStorageRootVMGS, vmutils.DefaultGuestStateFile,
		vmutils.DefaultDmVerityRootfsVhd, "ahv-guest-ctl"} {
		c := storageTestContext(t, protectedSiblingTestArgs(t, true)...)
		if err := os.Remove(filepath.Join(c.String(bootFilesPathArgName), name)); err != nil {
			t.Fatal(err)
		}
		if _, err := preflightProtectedSiblingProfile(c); err == nil {
			t.Fatalf("accepted missing required artifact %s", name)
		}
	}
}

// TestProtectedSiblingProfilePreservesPartitionMasks proves profile selection
// leaves omission, explicit zero and all uint64 bits untouched for later native
// experiments, rather than interpreting optional mask semantics.
func TestProtectedSiblingProfilePreservesPartitionMasks(t *testing.T) {
	oldGCS := useGCS
	// Restore the process-wide CLI fixture setting after this serial test.
	t.Cleanup(func() { useGCS = oldGCS })
	useGCS = true
	for _, combined := range []bool{false, true} {
		for _, value := range []string{"", "0", "18446744073709551615"} {
			args := protectedSiblingTestArgs(t, combined)
			if value != "" {
				args = append(args, "--"+diodePartitionSealMaskArgName, value,
					"--"+workloadPartitionSealMaskArgName, value)
			}
			c := storageTestContext(t, args...)
			if _, err := classifyProtectedSiblingProfile(c); err != nil {
				t.Fatal(err)
			}
			var want uint64
			if value != "" {
				var err error
				want, err = strconv.ParseUint(value, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{diodePartitionSealMaskArgName, workloadPartitionSealMaskArgName} {
				if c.IsSet(name) != (value != "") || c.Uint64(name) != want {
					t.Fatalf("profile changed optional %s=%q", name, value)
				}
			}
		}
	}
}

func TestSiblingInstanceCommandChecksActualTransportVersion(t *testing.T) {
	shell, err := exec.LookPath("wsl.exe")
	if err != nil {
		t.Skip("WSL shell is required to exercise the generated Linux startup command")
	}
	for _, test := range []struct {
		name     string
		instance string
		wantFail bool
	}{
		{"current", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", false},
		{"stale-v2", "bus_id=1 local_cid=3 peer_cid=4 version=2 ready=1", true},
		{"stale-v3", "bus_id=1 local_cid=3 peer_cid=4 version=3 ready=1", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := strings.Replace(siblingInstanceDiscoveryCommand(),
				"set -- /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance;",
				`fixture=$(mktemp); trap 'rm -f "$fixture"' EXIT; printf '%s\n' `+
					shellSingleQuote(test.instance)+` >"$fixture"; set -- "$fixture";`, 1)
			command += `echo "INSTANCE_ACCEPTED bus=$sb_bus local=$sb_local peer=$sb_peer"`
			output, err := exec.Command(shell, "--exec", "sh", "-c", command).CombinedOutput()
			if (err != nil) != test.wantFail {
				t.Fatalf("startup result=%v, want failure=%v:\n%s", err, test.wantFail, output)
			}
			if !test.wantFail && !strings.Contains(string(output),
				"INSTANCE_ACCEPTED bus=1 local=3 peer=4") {
				t.Fatalf("accepted instance lost its routing identity:\n%s", output)
			}
			if test.wantFail && (!strings.Contains(string(output), "protocol version mismatch expected=4") ||
				strings.Contains(string(output), "INSTANCE_ACCEPTED")) {
				t.Fatalf("incompatible transport was not explicitly rejected:\n%s", output)
			}
		})
	}
}

// TestProtectedSiblingDelayedInstanceDiscovery exercises the production shell
// guard when the native peer link appears only after its first failed poll.
// Re-expansion must admit one ready current link while preserving rejection of
// multiple links, unready instances, protocol mismatch and wrong local CID.
func TestProtectedSiblingDelayedInstanceDiscovery(t *testing.T) {
	shell, err := exec.LookPath("wsl.exe")
	if err != nil {
		t.Skip("WSL shell is required to exercise the generated Linux startup command")
	}
	for _, test := range []struct {
		name, instance, failure string
		multiple                bool
	}{
		{name: "delayed-current", instance: "bus_id=1 local_cid=4 peer_cid=3 version=4 ready=1"},
		{name: "delayed-multiple", instance: "bus_id=1 local_cid=4 peer_cid=3 version=4 ready=1",
			failure: "expected one configured link", multiple: true},
		{name: "delayed-unready", instance: "bus_id=1 local_cid=4 peer_cid=3 version=4 ready=0",
			failure: "common peer instance timed out"},
		{name: "delayed-old-version", instance: "bus_id=1 local_cid=4 peer_cid=3 version=3 ready=1",
			failure: "protocol version mismatch expected=4"},
		{name: "delayed-wrong-cid", instance: "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1",
			failure: "local CID mismatch"},
	} {
		// Each fixture publishes sysfs-shaped files only from the polling
		// sleep callback; no VM, transport or native receipt is simulated.
		t.Run(test.name, func(t *testing.T) {
			publish := `mkdir -p "$fixture/link-1"; printf '%s\n' ` +
				shellSingleQuote(test.instance) + ` >"$fixture/link-1/sibling_instance"; `
			if test.multiple {
				publish += `mkdir -p "$fixture/link-2"; cp "$fixture/link-1/sibling_instance" "$fixture/link-2/sibling_instance"; `
			}
			// The fixture sleep publishes once, after discovery has already
			// seen an unmatched glob, and makes timeout cases deterministic.
			setup := `set -eu; fixture=$(mktemp -d); trap 'rm -rf "$fixture"' EXIT; polls=0; ` +
				`sleep() { polls=$((polls+1)); if [ "$polls" -eq 1 ]; then ` + publish + `fi; }; `
			command := siblingInstanceDiscoveryCommand() + siblingVsockReadyCommand(diodeRole)
			command = strings.ReplaceAll(command, siblingFailureDiagnosticsCommand(), `echo fixture-diagnostics >&2; `)
			command = strings.ReplaceAll(command, "/sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance",
				`"$fixture"/*-*/sibling_instance`)
			command = strings.ReplaceAll(command, "/sys/bus/vmbus/drivers/hv_sock", `"$fixture"`)
			command = setup + command + `echo "INSTANCE_ACCEPTED polls=$polls bus=$sb_bus local=$sb_local peer=$sb_peer"`
			output, err := exec.Command(shell, "--exec", "sh", "-c", command).CombinedOutput()
			if test.failure == "" {
				if err != nil || !strings.Contains(string(output), "INSTANCE_ACCEPTED polls=1 bus=1 local=4 peer=3") {
					t.Fatalf("delayed link was not re-discovered: %v\n%s", err, output)
				}
			} else if err == nil || !strings.Contains(string(output), test.failure) ||
				strings.Contains(string(output), "INSTANCE_ACCEPTED") {
				t.Fatalf("delayed invalid link was not rejected with %q: %v\n%s", test.failure, err, output)
			}
		})
	}
}

func TestSharedMemorySectionNames(t *testing.T) {
	win32Name, hcsName, err := sharedMemorySectionNames("hcsshim-test", 3)
	if err != nil {
		t.Fatal(err)
	}
	if win32Name != "hcsshim-test" {
		t.Fatalf("Win32 section name = %q, want %q", win32Name, "hcsshim-test")
	}
	if hcsName != `\Sessions\3\BaseNamedObjects\hcsshim-test` {
		t.Fatalf(
			"HCS section name = %q, want %q",
			hcsName,
			`\Sessions\3\BaseNamedObjects\hcsshim-test`,
		)
	}
}

func TestSiblingRelayProofScopesDiagnosticCounters(t *testing.T) {
	shell, err := exec.LookPath("wsl.exe")
	if err != nil {
		t.Skip("WSL shell is required to exercise the generated Linux proof command")
	}
	for _, test := range []struct {
		name, initial string
		fail          bool
	}{
		{"disabled", "N", false},
		{"enabled", "Y", false},
		{"failure", "N", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := strings.ReplaceAll(siblingNetRelayCheck,
				"/sys/module/sibling_bus/parameters/stats_enabled", `"$fixture"`)
			proof = strings.ReplaceAll(proof, "/tmp/dn-ping", `"$fixture-ping"`)
			proof = strings.ReplaceAll(proof, "/tmp/dn-tcp", `"$fixture-tcp"`)
			snap := `snap() { [ "$(cat "$fixture")" = Y ] || exit 9; ` +
				`h=0 c=0 d=$((${d:-0}+600)) g=0 m=0 t=0 b=0 r=0; }; `
			if test.fail {
				snap = `snap() { exit 17; }; `
			}
			command := `fixture=$(mktemp); trap 'rm -f "$fixture" "$fixture-ping" "$fixture-tcp"' EXIT; ` +
				`printf %s ` + shellSingleQuote(test.initial) + ` >"$fixture"; ` +
				`ping() { :; }; dtb=true; ` + snap +
				`( ` + proof + `); rc=$?; echo "RESTORED=$(cat "$fixture")"; exit "$rc"`
			output, err := exec.Command(shell, "--exec", "sh", "-c", command).CombinedOutput()
			if (err != nil) != test.fail ||
				!strings.Contains(string(output), "RESTORED="+test.initial) {
				t.Fatalf("proof result=%v, expected failure=%v and restored=%s:\n%s",
					err, test.fail, test.initial, output)
			}
			if !test.fail && !strings.Contains(string(output), "diode_net: no-relay ok") {
				t.Fatalf("proof did not observe enabled counters:\n%s", output)
			}
		})
	}
}

func TestSharedMemorySectionNamesRejectsPath(t *testing.T) {
	_, _, err := sharedMemorySectionNames(`Global\hcsshim-test`, 3)
	if err == nil {
		t.Fatal("expected namespaced section name to be rejected")
	}
}

func TestShellSingleQuote(t *testing.T) {
	got := shellSingleQuote("/run/module's/hcs_shmem_diag.ko")
	want := `'/run/module'"'"'s/hcs_shmem_diag.ko'`
	if got != want {
		t.Fatalf("shellSingleQuote() = %q, want %q", got, want)
	}
}

func TestSiblingVsockReadyCommand(t *testing.T) {
	for _, test := range []struct {
		role  string
		ready string
	}{
		{diodeRole, "sibling_vmbus: stock hv_sock ready role=diode local_cid=4"},
		{workloadRole, "sibling_vmbus: stock hv_sock ready role=workload local_cid=3"},
	} {
		t.Run(test.role, func(t *testing.T) {
			command := siblingVsockReadyCommand(test.role)
			for _, expected := range []string{
				"/sys/bus/vmbus/drivers/hv_sock",
				"exit 1",
				"[ $i -le 30 ]",
				`echo "` + test.ready,
			} {
				if !strings.Contains(command, expected) {
					t.Fatalf("command %q does not contain %q", command, expected)
				}
			}
			if strings.Contains(command, "insmod") || strings.Contains(command, "diode_vsock") {
				t.Fatal("stock socket setup must not load the legacy transport")
			}
		})
	}
}

func TestSiblingGuestDiscoversInstanceOnce(t *testing.T) {
	for _, role := range []string{diodeRole, workloadRole} {
		command := siblingBusGuestModuleCommand("/run/sibling_bus.ko",
			"", role, siblingNetConfig{ifName: "dvsc0"}, nil)
		if strings.Count(command, "sb_instance=$1;") != 1 {
			t.Fatal("guest setup must discover its bus exactly once")
		}
		for _, expected := range []string{"/sibling_instance", `grep -q 'ready=1'`,
			"sibling_vmbus: protocol version mismatch"} {
			if !strings.Contains(command, expected) {
				t.Fatalf("guest setup missing %q", expected)
			}
		}
		if role == workloadRole && strings.Index(command, "sb_bus=${1#*=}") >
			strings.Index(command, "bus${sb_bus}-relid*") {
			t.Fatal("bus discovery must precede NIC selection")
		}
	}
}

func TestStockPeerNICIsSelectedByBusOwnership(t *testing.T) {
	command := siblingStockNICCommand("dvsc0")
	for _, expected := range []string{
		"bus${sb_bus}-relid*", "hv_netvsc",
		`[ "$sb_count" -eq 1 ]`, `ip link set "$sb_net" name 'dvsc0'`,
		"stock hv_netvsc registered", "peer NIC rename failed",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("stock NIC setup missing %q", expected)
		}
	}
	if siblingNetModuleName(workloadRole) != "" || siblingNetModuleName(diodeRole) != "diode_netvsp.ko" {
		t.Fatal("only the provider needs an out-of-tree network module")
	}
}

func TestSiblingGuestKernelLogAllowsNoMatchingMessages(t *testing.T) {
	for _, role := range []string{diodeRole, workloadRole} {
		command := siblingBusGuestModuleCommand("/run/sibling_bus.ko",
			"", role, siblingNetConfig{ifName: "dvsc0"}, nil)
		if !strings.HasSuffix(command,
			`dmesg | grep -E 'diode_net|hv_netvsc' || [ "$?" -eq 1 ]`) {
			t.Fatal("final diagnostic grep must accept no matches without suppressing grep errors")
		}
	}
}

func TestStockSocketProofUsesActualPeerAndVerifiedToolExit(t *testing.T) {
	for _, role := range []string{diodeRole, workloadRole} {
		command := siblingVsockProofCommand(role)
		for _, expected := range []string{
			`"$sb_local"`, `connect "$sb_peer"`, `wait "$sb_vsock_pid" ||`,
			"listening on vsock port", "[ $i -le 30 ]", "exit 1",
			"stock hv_sock payload role=" + siblingRoleName(role) + " ok",
		} {
			if !strings.Contains(command, expected) {
				t.Fatalf("stock socket proof missing %q", expected)
			}
		}
		if strings.Contains(command, "insmod") {
			t.Fatal("payload proof must use the built-in transport")
		}
	}
}

func TestSiblingFailuresIncludeDeviceStateAndUnfilteredKernelLog(t *testing.T) {
	for _, command := range []string{
		guestWaitFor("false", "test"),
		siblingVsockProofCommand(diodeRole),
		siblingVsockProofCommand(workloadRole),
	} {
		for _, expected := range []string{
			"sibling_vmbus: failure diagnostics",
			"/sys/class/net/*", "/sys/bus/vmbus/devices/bus*-relid*",
			`readlink "$p/driver"`, "in_read_index", "out_write_index",
			"sibling_instance", "sibling_stats", "dmesg >&2 || true",
		} {
			if !strings.Contains(command, expected) {
				t.Fatalf("failure diagnostics missing %q", expected)
			}
		}
		if strings.Contains(command, "dmesg | grep") {
			t.Fatal("failure diagnostics must not hide stock-driver probe errors")
		}
	}
}

func TestSiblingVsockToolStagedOnExecFilesystem(t *testing.T) {
	for _, expected := range []string{
		"mount -t tmpfs -o exec",
		"cp /run/diode-vsock-test/diode_vsock_test /run/dtb-exec/vsock-test",
		"chmod 755 /run/dtb-exec/vsock-test ||",
		"diode_vsock: tool staging failed",
	} {
		if !strings.Contains(siblingWorkloadStage, expected) {
			t.Fatalf("tool staging command does not contain %q", expected)
		}
	}
}

func TestBaselineNICDoesNotRequireSiblingVsock(t *testing.T) {
	command := baselineNICUp(&diodeUplink{
		address: "172.31.250.2/24",
		gateway: "172.31.250.1",
	})
	if strings.Contains(command, "diode-vsock") || strings.Contains(command, "vsock-test") {
		t.Fatal("baseline NIC setup must not require sibling vsock tools")
	}
}

func TestSharedMemoryGuestModuleCommandConvertsGPN(t *testing.T) {
	command, err := sharedMemoryGuestModuleCommand(
		"/run/hcs_shmem_diag.ko",
		hcsschema.SharedMemoryRegion{
			SectionName: "section",
			Length:      0x100000,
		},
		hcsschema.SharedMemoryRegionInfo{
			SectionName:          "section",
			GuestPhysicalAddress: 0x20000,
		},
		"a",
		siblingEventModuleArgs(hcsschema.SiblingCommunicationRouteInfo{
			TargetVP:             0,
			TargetSINT:           3,
			EventFlagNumber:      11,
			OutboundConnectionID: 0x100015,
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"gpa=0x20000000",
		"length=0x100000",
		"decrypted=1",
		"role='a' signal_conn=0x100015 rx_vp=0 rx_sint=3 rx_flag=11;",
	} {
		if !strings.Contains(command, expected) {
			t.Fatalf("command %q does not contain %q", command, expected)
		}
	}
}

func TestSharedMemoryGuestModuleCommandRejectsDifferentSection(t *testing.T) {
	_, err := sharedMemoryGuestModuleCommand(
		"/run/hcs_shmem_diag.ko",
		hcsschema.SharedMemoryRegion{
			SectionName: "expected",
			Length:      0x1000,
		},
		hcsschema.SharedMemoryRegionInfo{
			SectionName:          "other",
			GuestPhysicalAddress: 0x20000,
		},
		"single",
		"",
	)
	if err == nil {
		t.Fatal("expected mismatched section to fail")
	}
}

func TestSharedMemoryProofRole(t *testing.T) {
	for _, test := range []struct {
		id   string
		role string
	}{
		{id: "uvmboot-0", role: "a"},
		{id: "uvmboot-1", role: "b"},
	} {
		role, err := sharedMemoryProofRole(test.id)
		if err != nil {
			t.Fatalf("sharedMemoryProofRole(%q): %v", test.id, err)
		}
		if role != test.role {
			t.Fatalf(
				"sharedMemoryProofRole(%q) = %q, want %q",
				test.id,
				role,
				test.role,
			)
		}
	}
}

func TestSharedMemoryProofRoleRejectsUnexpectedID(t *testing.T) {
	if _, err := sharedMemoryProofRole("uvmboot-2"); err == nil {
		t.Fatal("expected unexpected UVM ID to fail")
	}
}
