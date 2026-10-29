//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/internal/uvm"
)

const (
	networkBenchmarkScriptArgName  = "network-benchmark-script"
	networkBenchmarkServerArgName  = "network-benchmark-server"
	networkBenchmarkPortArgName    = "network-benchmark-port"
	networkBenchmarkTimeoutArgName = "network-benchmark-timeout"
	networkBenchmarkNoSMTArgName   = "network-benchmark-no-smt"
	networkBenchmarkIdleArgName    = "network-benchmark-idle"
)

func validateNetworkBenchmarkServer(server string, addresses []net.Addr) (bool, error) {
	ip, err := netip.ParseAddr(server)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip == netip.MustParseAddr("255.255.255.255") {
		return false, errors.New("network benchmark requires a non-loopback unicast server IPv4 address")
	}
	hostLocal := false
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil && prefix.Addr() == ip {
			hostLocal = true
			break
		}
	}
	for _, subnet := range []string{diodeUplinkSubnet, "10.200.0.0/30"} {
		if netip.MustParsePrefix(subnet).Contains(ip) && !(hostLocal && ip.String() == diodeUplinkGateway) {
			return false, fmt.Errorf("benchmark server must be external to the test networks or the host-owned diode-uplink gateway, not %s", subnet)
		}
	}
	return hostLocal, nil
}

func validateNetworkBenchmark(c *cli.Context, groups [][]uint32) error {
	if c.String(networkBenchmarkScriptArgName) == "" {
		if c.IsSet(networkBenchmarkServerArgName) || c.IsSet(networkBenchmarkPortArgName) ||
			c.IsSet(networkBenchmarkTimeoutArgName) || c.IsSet(networkBenchmarkNoSMTArgName) ||
			c.IsSet(networkBenchmarkIdleArgName) {
			return errors.New("network benchmark server, port and timeout require --network-benchmark-script")
		}
		return nil
	}
	if idle := c.String(networkBenchmarkIdleArgName); idle != "poll" && idle != "halt" {
		return errors.New("network benchmark idle policy must be poll or halt")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("enumerate host addresses: %w", err)
	}
	hostLocal, err := validateNetworkBenchmarkServer(c.String(networkBenchmarkServerArgName), addresses)
	if err != nil {
		return err
	}
	if hostLocal {
		logrus.WithField("server", c.String(networkBenchmarkServerArgName)).Warn("network benchmark server is this Windows host; results measure a host-local path, not external LAN performance")
	}
	if port := c.Int(networkBenchmarkPortArgName); port < 1024 || port > 65533 {
		return errors.New("network benchmark base port must be between 1024 and 65533 (uses port through port+2)")
	}
	if c.Duration(networkBenchmarkTimeoutArgName) <= 0 {
		return errors.New("network benchmark timeout must be positive")
	}
	if !useGCS || !c.Bool(securityHardwareFlag) || c.GlobalUint64(cpusArgName) != 2 ||
		c.GlobalInt(countArgName) != c.GlobalInt(parallelArgName) ||
		len(groups) != c.GlobalInt(countArgName) {
		return errors.New("network benchmark requires SNP, GCS, --cpus 2 and one explicit affinity pair per concurrently launched VM")
	}
	baseline := c.IsSet(baselineNICArgName) && c.GlobalInt(countArgName) == 1
	sibling := c.IsSet(siblingBusGuestModuleArgName) && c.Bool(sharedMemoryTwoUVMArgName) &&
		c.Bool(siblingDiodeUplinkArgName) && c.GlobalInt(countArgName) == 2
	if (!baseline && !sibling) || c.IsSet(baselinePairArgName) ||
		c.String(siblingOpenShellBundleArgName) != "" || siblingInteractive || debug ||
		c.IsSet(execCommandLineArgName) || c.IsSet(execFileArgName) {
		return errors.New("network benchmark supports only an untraced standalone baseline or sibling-IP diode pair; no OpenShell, interactive, debug, or custom exec")
	}
	if info, err := os.Stat(c.String(networkBenchmarkScriptArgName)); err != nil {
		return fmt.Errorf("inspect network benchmark script: %w", err)
	} else if !info.Mode().IsRegular() {
		return errors.New("network benchmark script must be a regular file")
	}
	return nil
}

func shareNetworkBenchmark(ctx context.Context, c *cli.Context, vm *uvm.UtilityVM) error {
	script := c.String(networkBenchmarkScriptArgName)
	if script == "" {
		return nil
	}
	if err := vm.Share(ctx, script, "/run/network-benchmark", true); err != nil {
		return fmt.Errorf("share network benchmark script: %w", err)
	}
	return nil
}

func networkBenchmarkPreflight(role, server string, noSMT bool, idlePolicy string) string {
	topologyCheck := `for c in 0 1; do s=$(cat /sys/devices/system/cpu/cpu$c/topology/thread_siblings_list); ` +
		`case "$s" in 0-1|0,1) :;; *) echo "network_benchmark: FAIL guest virtual SMT pair missing: cpu$c=$s" >&2; exit 1;; esac; done; `
	topologyEvidence := "threads_per_core=2"
	if noSMT {
		topologyCheck = `for c in 0 1; do s=$(cat /sys/devices/system/cpu/cpu$c/topology/thread_siblings_list); ` +
			`echo "network_benchmark: guest_topology cpu$c thread_siblings=$s"; done; `
		topologyEvidence = "host_smt=disabled guest_topology=recorded"
	}
	return `set -eu; ` +
		`dmesg | grep -F 'Memory Encryption Features active:' | grep -qw 'SEV-SNP' || ` +
		`{ echo 'network_benchmark: FAIL SNP boot evidence missing' >&2; exit 1; }; ` +
		`[ "$(cat /sys/devices/system/cpu/online)" = '0-1' ] || ` +
		`{ echo 'network_benchmark: FAIL expected exactly two online VPs' >&2; exit 1; }; ` +
		topologyCheck +
		`idle=$(awk '{for (i=1;i<=NF;i++) if ($i ~ /^idle=/) print $i}' /proc/cmdline); ` +
		`[ "$idle" = 'idle=` + idlePolicy + `' ] || ` +
		`{ echo "network_benchmark: FAIL expected idle=` + idlePolicy + `, got: $idle" >&2; exit 1; }; ` +
		`[ -x "$ipf" ] && "$ipf" --version 2>&1 | grep -F 'iperf version 2.2.1' || ` +
		`{ echo 'network_benchmark: FAIL matching iperf2 not staged' >&2; exit 1; }; ` +
		`echo 'network_benchmark: preflight role=` + role + ` idle=` + idlePolicy + ` snp=boot-evidence attestation=not-collected vcpus=2 ` + topologyEvidence + `'; ` +
		`uname -a; cat /proc/cmdline; cat /proc/cpuinfo; ip addr show; ip route; ` +
		`ip route get ` + server + `; `
}

func networkBenchmarkClient(c *cli.Context, role string) string {
	server := c.String(networkBenchmarkServerArgName)
	expected := "dvsc0"
	deviceCheck := `for n in /sys/class/net/*; do if [ -e "$n/device" ]; then ` +
		`d=$(readlink -f "$n/device"); case ${d##*/} in bus${sb_bus}-relid*) :;; ` +
		`*) echo 'network_benchmark: FAIL workload has an external NIC' >&2; exit 1;; esac; fi; done; `
	if role == "baseline" {
		expected = "$up"
		deviceCheck = `[ "$(basename "$(readlink /sys/class/net/$up/device/driver)")" = hv_netvsc ] || ` +
			`{ echo 'network_benchmark: FAIL baseline is not synthetic hv_netvsc' >&2; exit 1; }; `
	}
	script := "/run/network-benchmark/" + filepath.Base(c.String(networkBenchmarkScriptArgName))
	return networkBenchmarkPreflight(role, server, c.Bool(networkBenchmarkNoSMTArgName), c.String(networkBenchmarkIdleArgName)) + deviceCheck +
		`ip route get ` + server + ` | grep -q "dev ` + expected + ` " || ` +
		`{ echo 'network_benchmark: FAIL unexpected egress interface' >&2; exit 1; }; ` +
		`cp ` + shellSingleQuote(script) + ` /run/dtb-exec/network-benchmark.sh; ` +
		`/bin/sh /run/dtb-exec/network-benchmark.sh ` + server + ` ` +
		fmt.Sprint(c.Int(networkBenchmarkPortArgName)) + `; `
}

func networkBenchmarkSiblingCommand(c *cli.Context, module, netModule, role string,
	cfg siblingNetConfig, uplink *diodeUplink) string {
	command := "set -eu; insmod " + shellSingleQuote(module) + "; "
	if netModule != "" {
		command += "insmod " + shellSingleQuote(netModule) + "; "
	}
	if role == workloadRole {
		command += siblingInstanceCommand() + siblingStockNICCommand(cfg.ifName)
	}
	command += guestWaitFor("[ -e /sys/class/net/"+cfg.ifName+" ]", cfg.ifName) + cfg.command() +
		"set -eu; " + siblingTCPBulkStage + "set -eu; "
	if role == workloadRole {
		return command + guestWaitFor(`[ "$(cat /sys/class/net/dvsc0/carrier)" = 1 ]`, "stock packet filter") +
			networkBenchmarkClient(c, "workload")
	}
	return command + siblingDiodeUplinkCommand(uplink, guestWaitFor) +
		`echo 1 >/proc/sys/net/ipv4/ip_forward; ` +
		`"$ipt" iptables -w -t nat -A POSTROUTING -s 10.200.0.0/30 -o "$up" -j MASQUERADE; ` +
		networkBenchmarkPreflight("diode", c.String(networkBenchmarkServerArgName), c.Bool(networkBenchmarkNoSMTArgName), c.String(networkBenchmarkIdleArgName)) +
		`[ "$(basename "$(readlink /sys/class/net/$up/device/driver)")" = hv_netvsc ] || ` +
		`{ echo 'network_benchmark: FAIL diode uplink is not synthetic hv_netvsc' >&2; exit 1; }; ` +
		`echo 'network_benchmark: diode forwarding ready'; ` +
		`until dmesg | grep -qF 'dvsp0: channel closed'; do sleep 1; done; ` +
		`"$ipt" iptables -t nat -L POSTROUTING -v -n -x; `
}

// Buffer low-rate scheduled-CPU samples so stdout does not add VMBus traffic
// to the measured interval. HCS runtime is CPU time, not wall time or LP usage.
func sampleNetworkBenchmarkCPU(ctx context.Context, vm *uvm.UtilityVM) func() error {
	type sample struct {
		TimeUTC   time.Time `json:"time_utc"`
		RuntimeNS uint64    `json:"runtime_ns"`
	}
	var samples []sample
	var sampleErr error
	var stopOnce sync.Once
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			stats, err := vm.Stats(queryCtx)
			cancel()
			if err != nil {
				sampleErr = fmt.Errorf("sample benchmark CPU for %s: %w", vm.ID(), err)
				return
			}
			samples = append(samples, sample{time.Now().UTC(), stats.Processor.TotalRuntimeNS})
			select {
			case <-stop:
				return
			case <-ctx.Done():
				sampleErr = ctx.Err()
				return
			case <-ticker.C:
			}
		}
	}()
	return func() error {
		stopOnce.Do(func() {
			close(stop)
			wg.Wait()
			data, err := json.Marshal(struct {
				VM      string   `json:"vm"`
				Samples []sample `json:"samples"`
			}{vm.ID(), samples})
			if err != nil {
				sampleErr = errors.Join(sampleErr, err)
				return
			}
			fmt.Printf("network_benchmark_cpu: %s\n", data)
		})
		return sampleErr
	}
}
