//go:build windows

package sibling

import (
	"context"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"golang.org/x/sys/windows"
)

const (
	UplinkNetworkName = "diode-uplink"
	UplinkSubnet      = "172.31.250.0/24"
	UplinkGateway     = "172.31.250.1"
)

type Uplink struct {
	Address    string
	Gateway    string
	NetworkID  string
	EndpointID string
	MAC        string
}

// EnsureUplinkNetwork shares the validated NAT network with pre-boot appliances.
func EnsureUplinkNetwork() (*hcn.HostComputeNetwork, error) {
	network, err := hcn.GetNetworkByName(UplinkNetworkName)
	if err == nil {
		if network.Type != hcn.NAT || len(network.Ipams) != 1 || len(network.Ipams[0].Subnets) != 1 ||
			network.Ipams[0].Subnets[0].IpAddressPrefix != UplinkSubnet {
			return nil, errors.New("existing diode-uplink network has an unexpected topology")
		}
		return network, nil
	}
	if !hcn.IsNotFoundError(err) {
		return nil, err
	}
	network = &hcn.HostComputeNetwork{
		Type: hcn.NAT, Name: UplinkNetworkName,
		Ipams: []hcn.Ipam{{Type: "Static", Subnets: []hcn.Subnet{{
			IpAddressPrefix: UplinkSubnet,
			Routes:          []hcn.Route{{NextHop: UplinkGateway, DestinationPrefix: "0.0.0.0/0"}},
		}}}},
		SchemaVersion: hcn.V2SchemaVersion(),
	}
	return network.Create()
}

// PrepareUnikraftUplink reserves the image's fixed address before VM creation.
func PrepareUnikraftUplink(name string, cfg *UnikraftNetwork) (_ *hcn.HostComputeEndpoint, _ func() error, resultErr error) {
	if cfg == nil {
		return nil, nil, errors.New("Unikraft uplink requires its launch configuration")
	}
	network, err := EnsureUplinkNetwork()
	if err != nil {
		return nil, nil, err
	}
	endpoint, err := network.CreateEndpoint(&hcn.HostComputeEndpoint{
		Name: name, SchemaVersion: hcn.V2SchemaVersion(),
		IpConfigurations: []hcn.IpConfig{{IpAddress: cfg.Uplink.String(), PrefixLength: 24}},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("allocate configured Unikraft uplink %s: %w", cfg.Uplink, err)
	}
	var namespace *hcn.HostComputeNamespace
	joined := false
	cleanup := func() error {
		var err error
		if joined {
			err = errors.Join(err, hcn.RemoveNamespaceEndpoint(namespace.Id, endpoint.Id))
		}
		err = errors.Join(err, endpoint.Delete())
		if namespace != nil {
			err = errors.Join(err, namespace.Delete())
		}
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, cleanup())
		}
	}()
	namespace, err = hcn.NewNamespace(hcn.NamespaceTypeGuest).Create()
	if err != nil {
		return nil, nil, err
	}
	if err := hcn.AddNamespaceEndpoint(namespace.Id, endpoint.Id); err != nil {
		return nil, nil, err
	}
	joined = true
	actual, err := hcn.GetEndpointByID(endpoint.Id)
	if err != nil {
		return nil, nil, err
	}
	if len(actual.IpConfigurations) != 1 || actual.IpConfigurations[0].IpAddress != cfg.Uplink.String() ||
		actual.IpConfigurations[0].PrefixLength != 24 || actual.MacAddress == "" {
		return nil, nil, errors.New("HNS did not assign the address embedded in the Unikraft image")
	}
	return actual, cleanup, nil
}

// AttachUplink is deliberately diode-only; callers must never pass the workload.
func AttachUplink(ctx context.Context, vm *uvm.UtilityVM) (*Uplink, func() error, error) {
	if vm.UsesSiblingNetworking() {
		return nil, nil, errors.New("cannot attach an uplink to a sibling workload")
	}
	network, err := EnsureUplinkNetwork()
	if err != nil {
		return nil, nil, err
	}
	endpoint, err := network.CreateEndpoint(&hcn.HostComputeEndpoint{
		Name: vm.ID() + "-diode-uplink", SchemaVersion: hcn.V2SchemaVersion(),
	})
	if err != nil {
		return nil, nil, err
	}
	namespace, err := hcn.NewNamespace(hcn.NamespaceTypeGuest).Create()
	if err != nil {
		_ = endpoint.Delete()
		return nil, nil, err
	}
	cleanup := func() error {
		removeErr := hcn.RemoveNamespaceEndpoint(namespace.Id, endpoint.Id)
		return errors.Join(removeErr, endpoint.Delete(), namespace.Delete())
	}
	fail := func(err error) (*Uplink, func() error, error) {
		return nil, nil, errors.Join(err, cleanup())
	}
	if err := hcn.AddNamespaceEndpoint(namespace.Id, endpoint.Id); err != nil {
		return fail(err)
	}
	updated, err := hcn.GetEndpointByID(endpoint.Id)
	if err != nil {
		return fail(err)
	}
	endpoint = updated
	if len(endpoint.IpConfigurations) != 1 {
		return fail(errors.New("diode uplink must have one IP address"))
	}
	if err := vm.AddNetNS(ctx, namespace); err != nil {
		return fail(err)
	}
	if err := vm.AddEndpointsToNS(ctx, namespace.Id, []*hcn.HostComputeEndpoint{endpoint}); err != nil {
		return fail(err)
	}
	ip := endpoint.IpConfigurations[0]
	if net.ParseIP(ip.IpAddress).To4() == nil || ip.PrefixLength > 32 {
		return fail(errors.New("invalid diode uplink IPv4 configuration"))
	}
	return &Uplink{
		Address: fmt.Sprintf("%s/%d", ip.IpAddress, ip.PrefixLength), Gateway: UplinkGateway,
		NetworkID: network.Id, EndpointID: endpoint.Id, MAC: endpoint.MacAddress,
	}, cleanup, nil
}

func HostDNSServers() ([]string, error) {
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
			return nil, err
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
			if ip != nil && !ip.IsLoopback() && !seen[ip.String()] {
				seen[ip.String()] = true
				servers = append(servers, ip.String())
			}
		}
	}
	return servers, nil
}
