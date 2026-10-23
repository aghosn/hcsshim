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
}
