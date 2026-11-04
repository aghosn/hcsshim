//go:build windows

package uvm

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

// ConfigureSiblingNetworking installs a guest-only networking path. The ID is
// the discovered peer VMBus device name, understood by the existing GCS adapter
// resolver. No HCS NIC or HNS endpoint is attached to the workload.
func (uvm *UtilityVM) ConfigureSiblingNetworking(adapter guestresource.LCOWNetworkAdapter) error {
	if uvm.OS() != "linux" || !guestresource.IsSiblingVMBusDeviceID(adapter.ID) {
		return errors.New("sibling networking requires a Linux peer VMBus NIC identity")
	}
	if uvm.networkSetup != nil {
		return errors.New("network setup already configured")
	}
	uvm.networkSetup = &siblingNetworkSetup{
		adapter: adapter, add: uvm.AddNICInGuest, remove: uvm.RemoveNICInGuest,
	}
	return nil
}

// UsesSiblingNetworking indicates that replacing the network setup or attaching
// an RP NIC would bypass the diode.
func (uvm *UtilityVM) UsesSiblingNetworking() bool {
	_, ok := uvm.networkSetup.(*siblingNetworkSetup)
	return ok
}

type siblingNetworkSetup struct {
	adapter   guestresource.LCOWNetworkAdapter
	add       func(context.Context, *guestresource.LCOWNetworkAdapter) error
	remove    func(context.Context, *guestresource.LCOWNetworkAdapter) error
	mu        sync.Mutex
	namespace string
}

func (s *siblingNetworkSetup) ConfigureNetworking(ctx context.Context, id string, action NetworkConfigType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		return errors.New("sibling sandbox network namespace is empty")
	}
	adapter := s.adapter
	adapter.NamespaceID = id
	switch action {
	case NetworkRequestSetup:
		if s.namespace == id {
			return nil
		}
		if s.namespace != "" {
			return errors.New("sibling NIC already belongs to another sandbox")
		}
		if err := s.add(ctx, &adapter); err != nil {
			return fmt.Errorf("register sibling NIC with GCS (no HNS fallback): %w", err)
		}
		s.namespace = id
	case NetworkRequestTearDown:
		if s.namespace == "" {
			return nil
		}
		if s.namespace != id {
			return errors.New("sibling network namespace ownership mismatch")
		}
		if err := s.remove(ctx, &adapter); err != nil {
			return err
		}
		s.namespace = ""
	default:
		return fmt.Errorf("unknown sibling network action %d", action)
	}
	return nil
}
