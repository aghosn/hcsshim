//go:build windows

package guestresource

import (
	"encoding/json"
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
)

func TestLCOWNetworkAdapterPreservesInstalledGCSIPv4WireFormat(t *testing.T) {
	endpoint := &hcn.HostComputeEndpoint{
		MacAddress: "00-15-5D-76-F1-C2",
		IpConfigurations: []hcn.IpConfig{
			{IpAddress: "fd00::2", PrefixLength: 64},
			{IpAddress: "172.31.250.10", PrefixLength: 24},
		},
		Routes: []hcn.Route{
			{DestinationPrefix: "::/0", NextHop: "fd00::1"},
			{DestinationPrefix: "0.0.0.0/0", NextHop: "172.31.250.1"},
		},
	}
	adapter, err := BuildLCOWNetworkAdapter("namespace", "nic", endpoint, false)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(adapter)
	if err != nil {
		t.Fatal(err)
	}
	var installedGCS struct {
		IPAddress      string
		PrefixLength   uint8
		GatewayAddress string
	}
	if err := json.Unmarshal(wire, &installedGCS); err != nil {
		t.Fatal(err)
	}
	if installedGCS.IPAddress != "172.31.250.10" || installedGCS.PrefixLength != 24 ||
		installedGCS.GatewayAddress != "172.31.250.1" {
		t.Fatalf("installed GCS would fall back to DHCP: %s", wire)
	}
	var currentGCS LCOWNetworkAdapter
	if err := json.Unmarshal(wire, &currentGCS); err != nil {
		t.Fatal(err)
	}
	if len(currentGCS.IPConfigs) != 2 || len(currentGCS.Routes) != 2 ||
		currentGCS.IPConfigs[0].IPAddress != "fd00::2" || currentGCS.Routes[0].DestinationPrefix != "::/0" {
		t.Fatalf("current GCS lost dual-stack configuration: %s", wire)
	}
}
