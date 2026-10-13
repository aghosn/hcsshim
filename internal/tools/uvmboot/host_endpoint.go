//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// The host endpoint is the target of the throughput and latency comparison:
// an iperf 2 server on the host side of the diode-uplink NAT network.
const (
	hostEndpointPort = 5201
	hostEndpointRule = "uvmboot-host-endpoint"
)

// startHostEndpoint runs iperf.exe (next to uvmboot) on all host addresses
// (the guest reaches it as the NAT gateway) and opens the firewall for the
// NAT subnet only.
func startHostEndpoint() (func(), error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	server := exec.Command(filepath.Join(filepath.Dir(self), iperfHostName),
		"-s", "-p", fmt.Sprint(hostEndpointPort))
	if err := server.Start(); err != nil {
		return nil, fmt.Errorf("host endpoint: %w", err)
	}
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+hostEndpointRule).Run()
	if out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+hostEndpointRule, "dir=in", "action=allow", "protocol=TCP",
		fmt.Sprintf("localport=%d", hostEndpointPort),
		"remoteip="+diodeUplinkSubnet).CombinedOutput(); err != nil {
		fmt.Printf("host endpoint: firewall rule failed: %v: %s\n", err, out)
	}
	fmt.Printf("host endpoint: iperf server :%d gateway=%s\n", hostEndpointPort, diodeUplinkGateway)
	return func() {
		_ = server.Process.Kill()
		_ = server.Wait()
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+hostEndpointRule).Run()
	}, nil
}

// hostEndpointTests benchmarks the guest's path to the host endpoint. It
// needs iperfStage.
func hostEndpointTests() string {
	return ipbench("host", diodeUplinkGateway, hostEndpointPort)
}
