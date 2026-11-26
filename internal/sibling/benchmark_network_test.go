//go:build windows

package sibling

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBenchmarkNetworkMetadata(t *testing.T) {
	for _, provider := range []string{"linux", "unikraft"} {
		uplink := "172.31.250.42"
		if provider == "linux" {
			uplink += "/24"
		}
		metadata, err := newBenchmarkNetwork("10.200.0.2", uplink, provider, "workload-actual", "diode-actual")
		if err != nil {
			t.Fatal(err)
		}
		metadata.PublishedTCPPorts = []uint16{11211}
		directory := t.TempDir()
		if err := writeBenchmarkNetwork(directory, metadata); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "benchmark-network.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var actual benchmarkNetwork
		if err := json.Unmarshal(data, &actual); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, *metadata) || actual.Version != 1 || actual.DiodeUplinkIPv4 != "172.31.250.42" ||
			actual.DiodeGatewayIPv4 != UplinkGateway || actual.UplinkNetwork != UplinkNetworkName ||
			actual.WorkloadIPv4 != "10.200.0.2" || actual.WorkloadUVMID != "workload-actual" ||
			actual.DiodeUVMID != "diode-actual" || actual.DiodeProvider != provider {
			t.Fatalf("incorrect metadata: %s", data)
		}
		if err := writeBenchmarkNetwork(directory, metadata); !errors.Is(err, os.ErrExist) {
			t.Fatalf("must not overwrite existing metadata: %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != string(data) {
			t.Fatal("existing metadata changed", err)
		}
	}
}

func TestPublishedTCPPortsConfigAndLinuxDNAT(t *testing.T) {
	for _, ports := range [][]uint16{nil, {11211}, {11211, 11212}} {
		config := testConfig()
		config.PublishedTCPPorts = ports
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeConfig(strings.NewReader(string(data)))
		if err != nil || !reflect.DeepEqual(decoded.PublishedTCPPorts, ports) {
			t.Fatalf("publication config lost: %v, %v", decoded, err)
		}
		uplink := &Uplink{Address: "172.31.250.42/24", Gateway: UplinkGateway}
		command := diodeBootstrapCommand(uplink, false, ports...)
		if !strings.Contains(command, "-j MASQUERADE") {
			t.Fatal("publication removed existing outbound NAT")
		}
		if strings.Count(command, "-A PREROUTING") != len(ports) {
			t.Fatalf("publication not opt-in: %s", command)
		}
		if len(ports) != 0 && !strings.Contains(command, `-i "$up" -d '172.31.250.42' -p tcp --dport 11211 -j DNAT --to-destination 10.200.0.2:11211 || exit 1`) {
			t.Fatalf("DNAT not restricted to owned uplink and same workload port: %s", command)
		}
	}
	for _, ports := range [][]uint16{{0}, {11211, 11211}, make([]uint16, 17)} {
		config := testConfig()
		config.PublishedTCPPorts = ports
		data, _ := json.Marshal(config)
		if _, err := decodeConfig(strings.NewReader(string(data))); err == nil {
			t.Fatalf("accepted invalid publications: %v", ports)
		}
	}
	if _, err := decodeConfig(strings.NewReader(`{"version":1,"standalone":true,"published_tcp_ports":[11211]}`)); err == nil {
		t.Fatal("standalone baseline cannot publish a diode port")
	}
}

func TestBenchmarkNetworkInvalidInputsAndProgrammaticCaller(t *testing.T) {
	for _, test := range []struct{ workload, uplink, provider, workloadID, diodeID string }{
		{"invalid", "172.31.250.42", "linux", "w", "d"},
		{"10.200.0.2", "invalid", "linux", "w", "d"},
		{"10.200.0.2", "172.31.251.42", "linux", "w", "d"},
		{"10.200.0.2", UplinkGateway, "linux", "w", "d"},
		{"10.200.0.2", "172.31.250.42", "unknown", "w", "d"},
		{"10.200.0.2", "172.31.250.42", "linux", "", "d"},
		{"10.200.0.2", "172.31.250.42", "linux", "w", "w"},
	} {
		if _, err := newBenchmarkNetwork(test.workload, test.uplink, test.provider, test.workloadID, test.diodeID); err == nil {
			t.Fatalf("accepted invalid metadata: %+v", test)
		}
	}
	if err := writeBenchmarkNetwork("", nil); err != nil {
		t.Fatalf("programmatic caller without config directory: %v", err)
	}
	if err := writeBenchmarkNetwork(filepath.Join(t.TempDir(), "missing"), &benchmarkNetwork{}); err == nil {
		t.Fatal("lost metadata publication error")
	}
}
