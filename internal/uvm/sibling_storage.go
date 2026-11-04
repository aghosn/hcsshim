//go:build windows

package uvm

import (
	"fmt"

	"github.com/Microsoft/hcsshim/internal/gcs"
	"github.com/Microsoft/hcsshim/internal/uvm/scsi"
)

// ConfigureSiblingStorage must run after pair bootstrap and before task creation.
func (uvm *UtilityVM) ConfigureSiblingStorage(backend scsi.HostBackend) error {
	if uvm.OS() != "linux" || uvm.gc == nil || uvm.SCSIManager == nil {
		return fmt.Errorf("sibling storage requires a started LCOW guest connection")
	}
	if uvm.siblingStorage {
		return fmt.Errorf("sibling storage is already configured")
	}
	caps := gcs.GetLCOWCapabilities(uvm.guestCaps)
	if caps == nil || !caps.SiblingSCSISupported {
		return fmt.Errorf("guest GCS does not support sibling SCSI mapping; use matching guest boot artifacts")
	}
	if err := uvm.SCSIManager.ConfigureSibling(backend, scsi.NewSiblingBridgeGuestBackend(uvm.gc)); err != nil {
		return err
	}
	uvm.siblingStorage = true
	return nil
}

func (uvm *UtilityVM) SiblingStorageEnabled() bool {
	return uvm.siblingStorage
}
