//go:build windows

package main

import (
	"context"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

// The diode's uplink is a private HNS NAT network: the host NATs the diode to
// the outside, and the diode NATs the workload (10.200.0.0/30) onto it.
const (
	diodeUplinkNetworkName = "diode-uplink"
	diodeUplinkSubnet      = "172.31.250.0/24"
	diodeUplinkGateway     = "172.31.250.1"
)

type diodeUplink struct {
	address string // CIDR
	gateway string
}

func ensureDiodeUplinkNetwork() (*hcn.HostComputeNetwork, error) {
	network, err := hcn.GetNetworkByName(diodeUplinkNetworkName)
	if err == nil {
		return network, nil
	}
	if !hcn.IsNotFoundError(err) {
		return nil, fmt.Errorf("query HNS network %s: %w", diodeUplinkNetworkName, err)
	}
	network = &hcn.HostComputeNetwork{
		Type: hcn.NAT,
		Name: diodeUplinkNetworkName,
		Ipams: []hcn.Ipam{{
			Type: "Static",
			Subnets: []hcn.Subnet{{
				IpAddressPrefix: diodeUplinkSubnet,
				Routes: []hcn.Route{{
					NextHop:           diodeUplinkGateway,
					DestinationPrefix: "0.0.0.0/0",
				}},
			}},
		}},
		SchemaVersion: hcn.V2SchemaVersion(),
	}
	network, err = network.Create()
	if err != nil {
		return nil, fmt.Errorf("create HNS NAT network %s (%s): %w",
			diodeUplinkNetworkName, diodeUplinkSubnet, err)
	}
	return network, nil
}

// attachDiodeUplink hot-adds one NIC on the diode-uplink NAT network to vm.
// The guest leaves it unconfigured (no container namespace), so the returned
// address and gateway are applied by the guest command.
func attachDiodeUplink(ctx context.Context, vm *uvm.UtilityVM) (*diodeUplink, func(), error) {
	network, err := ensureDiodeUplinkNetwork()
	if err != nil {
		return nil, nil, err
	}

	name := vm.ID() + "-diode-uplink"
	if stale, err := hcn.GetEndpointByName(name); err == nil {
		_ = stale.Delete()
	}

	endpoint, err := network.CreateEndpoint(&hcn.HostComputeEndpoint{
		Name:          name,
		SchemaVersion: hcn.V2SchemaVersion(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create uplink endpoint: %w", err)
	}
	namespace, err := hcn.NewNamespace(hcn.NamespaceTypeGuest).Create()
	if err != nil {
		_ = endpoint.Delete()
		return nil, nil, fmt.Errorf("create uplink namespace: %w", err)
	}
	cleanup := func() {
		_ = hcn.RemoveNamespaceEndpoint(namespace.Id, endpoint.Id)
		_ = endpoint.Delete()
		_ = namespace.Delete()
	}

	if err := hcn.AddNamespaceEndpoint(namespace.Id, endpoint.Id); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("attach uplink endpoint to namespace: %w", err)
	}
	if endpoint, err = hcn.GetEndpointByID(endpoint.Id); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("query uplink endpoint: %w", err)
	}
	if len(endpoint.IpConfigurations) == 0 {
		cleanup()
		return nil, nil, fmt.Errorf("uplink endpoint %s has no IP address", endpoint.Id)
	}
	if err := vm.AddNetNS(ctx, namespace); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("add uplink namespace to UVM: %w", err)
	}
	if err := vm.AddEndpointsToNS(ctx, namespace.Id, []*hcn.HostComputeEndpoint{endpoint}); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("add uplink NIC to UVM: %w", err)
	}

	ip := endpoint.IpConfigurations[0]
	uplink := &diodeUplink{
		address: fmt.Sprintf("%s/%d", ip.IpAddress, ip.PrefixLength),
		gateway: diodeUplinkGateway,
	}
	for _, route := range endpoint.Routes {
		if route.DestinationPrefix == "0.0.0.0/0" && route.NextHop != "" {
			uplink.gateway = route.NextHop
		}
	}
	fmt.Printf("diode uplink: network=%s endpoint=%s mac=%s address=%s gateway=%s\n",
		network.Id, endpoint.Id, endpoint.MacAddress, uplink.address, uplink.gateway)
	return uplink, cleanup, nil
}

// hostDNSServers returns the IPv4 DNS servers of the host's up adapters.
// Public resolvers may be blocked on lab networks, so the workload uses these.
func hostDNSServers() ([]string, error) {
	size := uint32(16 << 10)
	var buf []byte
	for {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_SKIP_ANYCAST|
			windows.GAA_FLAG_SKIP_MULTICAST, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
	}
	seen := map[string]bool{}
	var servers []string
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for s := a.FirstDnsServerAddress; s != nil; s = s.Next {
			ip := s.Address.IP().To4()
			if ip == nil || ip.IsLoopback() || seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			servers = append(servers, ip.String())
		}
	}
	return servers, nil
}
