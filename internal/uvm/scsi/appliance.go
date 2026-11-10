//go:build windows

package scsi

import (
	"context"
	"errors"
)

// ApplianceQuiescer confirms that neither an export nor root DMA still owns
// the backing. Absence of a guest filesystem does not make unplug a no-op.
type ApplianceQuiescer interface {
	Quiesce(context.Context, uint, uint) error
}

type applianceGuestBackend struct {
	control ApplianceQuiescer
}

func NewApplianceGuestBackend(control ApplianceQuiescer) (GuestBackend, error) {
	if control == nil {
		return nil, errors.New("appliance storage requires native quiescence control")
	}
	return &applianceGuestBackend{control: control}, nil
}

func (*applianceGuestBackend) mount(context.Context, uint, uint, string, *mountConfig) error {
	return errors.New("appliance has no guest filesystem mount service")
}

func (*applianceGuestBackend) unmount(context.Context, uint, uint, string, *mountConfig) error {
	return errors.New("appliance has no guest filesystem mount service")
}

func (b *applianceGuestBackend) unplug(ctx context.Context, controller, lun uint) error {
	return b.control.Quiesce(ctx, controller, lun)
}
