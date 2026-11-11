//go:build windows

package main

import (
	"bytes"
	"errors"
	"flag"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func TestValidatedGuestNeverSuppressesFailure(t *testing.T) {
	failure := errors.New("guest process exited with exit code 1")
	for _, sharedMemory := range []bool{false, true} {
		for _, markerVerified := range []bool{false, true} {
			if err := lcowLifecycleResult(failure, sharedMemory, markerVerified, true); !errors.Is(err, failure) {
				t.Fatalf("lost validated guest error with sharedMemory=%v markerVerified=%v: %v",
					sharedMemory, markerVerified, err)
			}
		}
	}
	if err := lcowLifecycleResult(nil, true, true, true); err != nil {
		t.Fatal(err)
	}
	if err := lcowLifecycleResult(failure, true, true, false); err != nil {
		t.Fatalf("changed legacy verified-proof behavior: %v", err)
	}
	if err := lcowLifecycleResult(failure, true, false, false); !errors.Is(err, failure) {
		t.Fatalf("lost legacy unverified-proof error: %v", err)
	}
	if err := lcowLifecycleResult(failure, false, false, false); err != nil {
		t.Fatalf("changed legacy non-proof behavior: %v", err)
	}
}

func benchmarkTestContext(t *testing.T, args ...string) *cli.Context {
	t.Helper()
	global := flag.NewFlagSet("global", flag.ContinueOnError)
	for _, f := range []cli.Flag{
		cli.Uint64Flag{Name: cpusArgName, Value: 2},
		cli.IntFlag{Name: countArgName, Value: 1},
		cli.IntFlag{Name: parallelArgName, Value: 1},
	} {
		f.Apply(global)
	}
	parent := cli.NewContext(cli.NewApp(), global, nil)
	set := flag.NewFlagSet("lcow", flag.ContinueOnError)
	for _, f := range lcowCommand.Flags {
		f.Apply(set)
	}
	if err := set.Parse(args); err != nil {
		t.Fatal(err)
	}
	return cli.NewContext(cli.NewApp(), set, parent)
}

func TestNetworkBenchmarkCPUSamplingPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "benchmark.sh")
	for _, test := range []struct {
		script string
		want   bool
	}{
		{"session\n", true},
		{"session\ncpu_measurements=0\n", false},
		{"cpu_measurements=0\r\nsession\r\n", false},
		{"# cpu_measurements=0\n", true},
		{"cpu_measurements=0\ncpu_measurements=1\n", true},
	} {
		if err := os.WriteFile(path, []byte(test.script), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := networkBenchmarkCPUEnabled(benchmarkTestContext(t, "--network-benchmark-script", path))
		if err != nil || got != test.want {
			t.Fatalf("script %q: enabled=%v err=%v, want %v", test.script, got, err, test.want)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := networkBenchmarkCPUEnabled(benchmarkTestContext(t, "--network-benchmark-script", path)); err == nil {
		t.Fatal("missing policy script must not silently disable sampling")
	}
}

func TestNetworkBenchmarkValidationFailsClosed(t *testing.T) {
	script := filepath.Join(t.TempDir(), "bench.sh")
	if err := os.WriteFile(script, []byte("exit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldGCS, oldInteractive, oldDebug := useGCS, siblingInteractive, debug
	useGCS, siblingInteractive, debug = true, false, false
	t.Cleanup(func() { useGCS, siblingInteractive, debug = oldGCS, oldInteractive, oldDebug })
	groups := [][]uint32{{8, 24}}
	valid := []string{"--network-benchmark-script", script,
		"--network-benchmark-server", "192.0.2.10", "--security-hardware",
		"--baseline-nic-tcpbulk", "tool"}
	if err := validateNetworkBenchmark(benchmarkTestContext(t, valid...), groups); err != nil {
		t.Fatal(err)
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	localTested := false
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsGlobalUnicast() ||
			prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() ||
			netip.MustParsePrefix(diodeUplinkSubnet).Contains(prefix.Addr()) ||
			netip.MustParsePrefix("10.200.0.0/30").Contains(prefix.Addr()) {
			continue
		}
		t.Run("host-local-warns", func(t *testing.T) {
			var output bytes.Buffer
			logger := logrus.StandardLogger()
			oldOutput, oldLevel := logger.Out, logger.GetLevel()
			logger.SetOutput(&output)
			logger.SetLevel(logrus.WarnLevel)
			t.Cleanup(func() { logger.SetOutput(oldOutput); logger.SetLevel(oldLevel) })
			args := append(append([]string{}, valid...), "--network-benchmark-server", prefix.Addr().String())
			if err := validateNetworkBenchmark(benchmarkTestContext(t, args...), groups); err != nil {
				t.Fatalf("host-local server was rejected: %v", err)
			}
			if !strings.Contains(output.String(), "host-local path, not external LAN performance") ||
				!strings.Contains(output.String(), prefix.Addr().String()) {
				t.Fatalf("missing host-local warning: %s", output.String())
			}
		})
		localTested = true
		break
	}
	if !localTested {
		t.Log("No eligible assigned IPv4 address available for host-local validation")
	}
	for _, ip := range []string{"", "127.0.0.1", "::1", "224.0.0.1", "0.0.0.0",
		"169.254.1.2", "172.31.250.2", "10.200.0.1", "192.0.2.1; reboot"} {
		t.Run(ip, func(t *testing.T) {
			args := append(append([]string{}, valid...), "--network-benchmark-server", ip)
			if err := validateNetworkBenchmark(benchmarkTestContext(t, args...), groups); err == nil {
				t.Fatalf("accepted invalid server %q", ip)
			}
		})
	}
	for _, extra := range [][]string{
		{"--network-benchmark-port", "65535"}, {"--network-benchmark-timeout", "0s"},
		{"--sibling-openshell-bundle", "bundle.tar"}, {"--exec", "echo unsafe"},
	} {
		if err := validateNetworkBenchmark(benchmarkTestContext(t, append(append([]string{}, valid...), extra...)...), groups); err == nil {
			t.Fatalf("accepted incompatible flags %v", extra)
		}
	}
	if err := validateNetworkBenchmark(benchmarkTestContext(t, valid...), nil); err == nil {
		t.Fatal("accepted unpinned benchmark")
	}
	useGCS = false
	if err := validateNetworkBenchmark(benchmarkTestContext(t, valid...), groups); err == nil {
		t.Fatal("accepted benchmark without GCS")
	}
}

func TestNetworkBenchmarkSingleVPComparison(t *testing.T) {
	script := filepath.Join(t.TempDir(), "bench.sh")
	if err := os.WriteFile(script, []byte("exit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldGCS, oldInteractive, oldDebug := useGCS, siblingInteractive, debug
	useGCS, siblingInteractive, debug = true, false, false
	t.Cleanup(func() { useGCS, siblingInteractive, debug = oldGCS, oldInteractive, oldDebug })
	base := []string{"--network-benchmark-script", script,
		"--network-benchmark-server", "192.0.2.10", "--security-hardware",
		"--network-benchmark-single-vp"}
	for _, tc := range []struct {
		name      string
		flags     []string
		count     string
		wantError bool
	}{
		{"Unikraft pair", []string{"--unikraft-diode-package", "bundle", "--sibling-bus-guest-module", "bus.ko",
			"--shared-memory-two-uvm-proof", "--sibling-diode-uplink"}, "2", false},
		{"standalone reference", []string{"--baseline-nic-tcpbulk", "tool"}, "1", false},
		{"Linux comparison pair", []string{"--sibling-bus-guest-module", "bus.ko",
			"--shared-memory-two-uvm-proof", "--sibling-diode-uplink"}, "2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := benchmarkTestContext(t, append(append([]string{}, base...), tc.flags...)...)
			for key, value := range map[string]string{cpusArgName: "2", countArgName: tc.count, parallelArgName: tc.count} {
				if err := c.GlobalSet(key, value); err != nil {
					t.Fatal(err)
				}
			}
			groups := [][]uint32{{8, 24}}
			if tc.count == "2" {
				groups = append(groups, []uint32{9, 25})
			}
			if err := validateNetworkBenchmark(c, groups); (err != nil) != tc.wantError {
				t.Fatalf("validation=%v, wantError=%v", err, tc.wantError)
			}
			workloadID := "uvmboot-0"
			if tc.count == "2" {
				workloadID = "uvmboot-1"
				if got := benchmarkVMProcessors(c, "uvmboot-0"); got != 1 {
					t.Fatalf("SingleVP diode got %d VPs", got)
				}
			}
			if got := benchmarkVMProcessors(c, workloadID); got != 2 {
				t.Fatalf("workload got %d VPs; must always have two", got)
			}
			if command := networkBenchmarkClient(c, "workload"); !strings.Contains(command, "vcpus=2") {
				t.Fatalf("SingleVP changed workload preflight: %s", command)
			}
			if err := c.GlobalSet(cpusArgName, "1"); err != nil {
				t.Fatal(err)
			}
			if err := validateNetworkBenchmark(c, groups); err == nil {
				t.Fatal("accepted a one-VP workload")
			}
		})
	}
	c := benchmarkTestContext(t, "--network-benchmark-single-vp")
	if err := validateNetworkBenchmark(c, nil); err == nil {
		t.Fatal("accepted flag without benchmark")
	}
	for _, single := range []bool{false, true} {
		command := networkBenchmarkVPPreflight("workload", "192.0.2.10", false, "poll", single)
		want := "vcpus=2"
		if single {
			want = "vcpus=1"
		}
		if !strings.Contains(command, want) || !strings.Contains(command, "SEV-SNP") ||
			strings.Contains(command, "guest virtual SMT pair missing") == single {
			t.Fatalf("wrong VP/SNP/SMT requirements: %s", command)
		}
		args := []string{"--network-benchmark-script", script, "--network-benchmark-server", "192.0.2.10"}
		if single {
			args = append(args, "--network-benchmark-single-vp")
		}
		diode := networkBenchmarkSiblingCommand(benchmarkTestContext(t, args...), "/bus.ko", "/net.ko", diodeRole,
			siblingNetConfig{ifName: "dvsp0", address: "10.200.0.1/30"},
			&diodeUplink{address: "172.31.250.2/24", gateway: diodeUplinkGateway})
		if !strings.Contains(diode, want) || !strings.Contains(diode, "grep -qx 'receive_diagnostics=1'") ||
			strings.Count(diode, "net-diagnostics -interface") != 2 ||
			strings.Count(diode, "-provider-interface dvsp0") != 2 ||
			!strings.Contains(diode, "stats=/sys/module/diode_netvsp/parameters/stats_enabled") ||
			strings.Index(diode, `printf 'Y\n' >"$stats"`) < strings.Index(diode, "grep -qx 'receive_diagnostics=1'") ||
			!strings.Contains(diode, "NETBENCH_DIODE_DIAGNOSTICS_BEGIN") {
			t.Fatalf("Linux diode lost matched topology or buffered driver snapshots: %s", diode)
		}
	}
}

func TestNetworkBenchmarkHostGateway(t *testing.T) {
	for _, tc := range []struct {
		name      string
		server    string
		assigned  string
		wantLocal bool
		wantError bool
	}{
		{"host gateway", "172.31.250.1", "172.31.250.1/24", true, false},
		{"unassigned gateway", "172.31.250.1", "192.0.2.2/24", false, true},
		{"guest uplink", "172.31.250.2", "172.31.250.1/24", false, true},
		{"host-owned non-gateway", "172.31.250.2", "172.31.250.2/24", false, true},
		{"sibling gateway", "10.200.0.1", "10.200.0.1/30", false, true},
		{"sibling workload", "10.200.0.2", "172.31.250.1/24", false, true},
		{"uplink broadcast", "172.31.250.255", "172.31.250.1/24", false, true},
		{"external LAN", "192.0.2.10", "172.31.250.1/24", false, false},
		{"host LAN", "192.0.2.10", "192.0.2.10/24", true, false},
		{"loopback", "127.0.0.1", "127.0.0.1/8", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, address, err := net.ParseCIDR(tc.assigned)
			if err != nil {
				t.Fatal(err)
			}
			address.IP = net.ParseIP(strings.Split(tc.assigned, "/")[0])
			local, err := validateNetworkBenchmarkServer(tc.server, []net.Addr{address})
			if (err != nil) != tc.wantError || local != tc.wantLocal {
				t.Fatalf("local=%v error=%v; want local=%v error=%v", local, err, tc.wantLocal, tc.wantError)
			}
		})
	}
}

func TestNetworkBenchmarkCommandsEnforceModeAndDoNotStartLegacyTests(t *testing.T) {
	c := benchmarkTestContext(t, "--network-benchmark-script", `C:\scripts\experiment.sh`,
		"--network-benchmark-server", "192.0.2.10", "--network-benchmark-port", "5201")
	workload := networkBenchmarkSiblingCommand(c, "/bus.ko", "", workloadRole,
		siblingNetConfig{ifName: "dvsc0", address: "10.200.0.2/30", gateway: "10.200.0.1"}, nil)
	diode := networkBenchmarkSiblingCommand(c, "/bus.ko", "/netvsp.ko", diodeRole,
		siblingNetConfig{ifName: "dvsp0", address: "10.200.0.1/30"},
		&diodeUplink{address: "172.31.250.2/24", gateway: diodeUplinkGateway})
	baseline := networkBenchmarkClient(c, "baseline")
	for _, command := range []string{workload, diode, baseline} {
		for _, required := range []string{"SEV-SNP", "thread_siblings_list", "0-1", "idle=poll", "192.0.2.10", "ip addr show; ip route;"} {
			if !strings.Contains(command, required) {
				t.Fatalf("missing mandatory preflight %q in %s", required, command)
			}

		}
		for _, forbidden := range []string{"openshell", "iperf -s", "ipbench ", "ping -", "mon()", "insmod '/diode_vsock", "ip -details"} {
			if strings.Contains(command, forbidden) {
				t.Fatalf("benchmark starts unrelated traffic %q", forbidden)
			}
		}
	}
	if !strings.Contains(diode, "MASQUERADE") || !strings.Contains(diode, "channel closed") {
		t.Fatal("diode must NAT immediately and wait for workload closure")
	}
	if !strings.Contains(workload, "workload has an external NIC") ||
		!strings.Contains(workload, "dev dvsc0 ") || !strings.Contains(baseline, "hv_netvsc") ||
		!strings.Contains(workload, "/bin/sh /run/dtb-exec/network-benchmark.sh 192.0.2.10 5201") {
		t.Fatal("path verification or external script invocation missing")
	}
	if strings.Contains(workload, "insmod ''") || strings.Contains(workload, "netvsc.ko") ||
		!strings.Contains(workload, "bus${sb_bus}-relid*") {
		t.Fatal("stock peer NIC must be selected by its owning bus without loading a consumer module")
	}
	for _, command := range []string{workload, baseline} {
		stage := strings.Index(command, "cp /run/diode-controller/diode-controller /run/dtb-exec/diode-controller")
		run := strings.Index(command, "/bin/sh /run/dtb-exec/network-benchmark.sh")
		if stage < 0 || stage >= run {
			t.Fatal("diagnostic helper must be staged before the workload or baseline benchmark starts")
		}
	}
}

func TestNetworkBenchmarkNoSMTRecordsTopologyAndPreservesPreflight(t *testing.T) {
	for _, role := range []string{"diode", "workload"} {
		command := networkBenchmarkPreflight(role, "192.0.2.10", true, "poll")
		for _, required := range []string{"SEV-SNP", "expected exactly two online VPs",
			"thread_siblings_list", "guest_topology", "host_smt=disabled", "idle=poll",
			"iperf version 2.2.1", "ip route get 192.0.2.10"} {
			if !strings.Contains(command, required) {
				t.Fatalf("missing SMT-off preflight %q", required)
			}
		}
		if strings.Contains(command, "guest virtual SMT pair missing") || strings.Contains(command, "threads_per_core=2") {
			t.Fatal("SMT-off preflight still assumes guest SMT")
		}
	}
	c := benchmarkTestContext(t, "--network-benchmark-no-smt")
	if err := validateNetworkBenchmark(c, nil); err == nil {
		t.Fatal("SMT-off flag accepted outside a benchmark")
	}
}
