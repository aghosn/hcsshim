//go:build windows

package main

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/hcsshim/internal/sibling"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

const (
	diodeUplinkNetworkName = sibling.UplinkNetworkName
	diodeUplinkSubnet      = sibling.UplinkSubnet
	diodeUplinkGateway     = sibling.UplinkGateway
)

type diodeUplink struct {
	address string
	gateway string
}

func attachDiodeUplink(ctx context.Context, vm *uvm.UtilityVM) (*diodeUplink, func(), error) {
	// Preserve the diagnostic launcher's stale-endpoint cleanup. The shim's
	// owned-pair path never deletes or imports a pre-existing endpoint.
	if stale, err := hcn.GetEndpointByName(vm.ID() + "-diode-uplink"); err == nil {
		_ = stale.Delete()
	}
	uplink, cleanup, err := sibling.AttachUplink(ctx, vm)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("diode uplink: network=%s endpoint=%s mac=%s address=%s gateway=%s\n",
		uplink.NetworkID, uplink.EndpointID, uplink.MAC, uplink.Address, uplink.Gateway)
	return &diodeUplink{address: uplink.Address, gateway: uplink.Gateway}, func() { _ = cleanup() }, nil
}

func hostDNSServers() ([]string, error) {
	return sibling.HostDNSServers()
}
