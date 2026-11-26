//go:build windows

package sibling

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

type benchmarkNetwork struct {
	Version           int      `json:"version"`
	WorkloadIPv4      string   `json:"workload_ipv4"`
	DiodeUplinkIPv4   string   `json:"diode_uplink_ipv4"`
	DiodeGatewayIPv4  string   `json:"diode_gateway_ipv4"`
	DiodeProvider     string   `json:"diode_provider"`
	UplinkNetwork     string   `json:"uplink_network"`
	WorkloadUVMID     string   `json:"workload_uvm_id"`
	DiodeUVMID        string   `json:"diode_uvm_id"`
	PublishedTCPPorts []uint16 `json:"published_tcp_ports,omitempty"`
}

func newBenchmarkNetwork(workload, uplink, provider, workloadID, diodeID string) (*benchmarkNetwork, error) {
	if prefix, err := netip.ParsePrefix(uplink); err == nil {
		uplink = prefix.Addr().String()
	}
	peer, peerErr := netip.ParseAddr(workload)
	address, err := netip.ParseAddr(uplink)
	subnet := netip.MustParsePrefix(UplinkSubnet)
	if peerErr != nil || !peer.Is4() || peer.IsUnspecified() ||
		err != nil || !address.Is4() || !subnet.Contains(address) || uplink == UplinkGateway ||
		(provider != "linux" && provider != "unikraft") || workloadID == "" || diodeID == "" || workloadID == diodeID {
		return nil, errors.New("invalid owned benchmark network metadata")
	}
	return &benchmarkNetwork{
		Version: 1, WorkloadIPv4: peer.String(), DiodeUplinkIPv4: address.String(),
		DiodeGatewayIPv4: UplinkGateway, DiodeProvider: provider, UplinkNetwork: UplinkNetworkName,
		WorkloadUVMID: workloadID, DiodeUVMID: diodeID,
	}, nil
}

func writeBenchmarkNetwork(directory string, metadata *benchmarkNetwork) error {
	if directory == "" {
		return nil
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "benchmark-network.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create owned benchmark network metadata: %w", err)
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return errors.Join(fmt.Errorf("write owned benchmark network metadata: %w", err), os.Remove(path))
	}
	return nil
}
