//go:build windows

package uvm

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/Microsoft/hcsshim/internal/diodecontrol"
	"github.com/Microsoft/hcsshim/internal/guestpath"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/uvm/scsi"
)

func applianceStorageSlots(opts *LCOWApplianceOptions) ([]scsi.Slot, error) {
	if opts == nil || len(opts.SCSI) != 1 {
		return nil, errors.New("native appliance storage requires one configured SCSI controller")
	}
	controller, ok := opts.SCSI[guestrequest.ScsiControllerGuids[0]]
	if !ok {
		return nil, errors.New("native appliance storage requires root SCSI controller 0")
	}
	root, ok := controller.Attachments["0"]
	if !ok || !root.ReadOnly {
		return nil, errors.New("native appliance storage requires a permanent read-only root LUN 0")
	}
	slots := make([]scsi.Slot, 0, len(controller.Attachments))
	for key, attachment := range controller.Attachments {
		lun, err := strconv.ParseUint(key, 10, 8)
		if err != nil || lun >= 64 || strconv.FormatUint(lun, 10) != key ||
			attachment.Type_ != "VirtualDisk" || attachment.Path == "" {
			return nil, fmt.Errorf("unsupported appliance boot attachment at LUN %q", key)
		}
		slots = append(slots, scsi.Slot{Controller: 0, LUN: uint(lun)})
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i].LUN < slots[j].LUN })
	return slots, nil
}

func newApplianceStorageManager(host scsi.HostBackend, control scsi.ApplianceQuiescer,
	opts *LCOWApplianceOptions) (*scsi.Manager, []scsi.Slot, error) {
	slots, err := applianceStorageSlots(opts)
	if err != nil {
		return nil, nil, err
	}
	guest, err := scsi.NewApplianceGuestBackend(control)
	if err != nil {
		return nil, nil, err
	}
	manager, err := scsi.NewManager(host, guest, 1, 64,
		guestpath.LCOWGlobalScsiMountPrefixFmt, slots)
	return manager, slots, err
}

func verifyApplianceExports(opts *LCOWApplianceOptions, exports []diodecontrol.Export) error {
	foundRoot := false
	for _, export := range exports {
		attachment, ok := opts.SCSI[guestrequest.ScsiControllerGuids[0]].Attachments[strconv.FormatUint(uint64(export.RootLUN), 10)]
		if !ok || export.Controller != 0 || export.Token != 0 ||
			export.Flags&diodecontrol.Boot == 0 || export.Flags&diodecontrol.Retiring != 0 ||
			(export.Flags&diodecontrol.ReadOnly != 0) != attachment.ReadOnly {
			return errors.New("native diode boot exports do not match attached boot disks")
		}
		if export.LUN == 0 {
			foundRoot = export.RootLUN == 0 && attachment.ReadOnly
		}
	}
	if !foundRoot {
		return errors.New("native diode has no active read-only boot root export")
	}
	return nil
}

func (uvm *UtilityVM) startApplianceStorage(ctx context.Context, opts *LCOWApplianceOptions) error {
	if !opts.NativeStorageControl {
		return nil
	}
	if uvm.applianceControlListener == nil {
		return errors.New("native diode storage requires its preboot listener")
	}
	conn, err := uvm.accept(ctx, uvm.applianceControlListener, true)
	uvm.applianceControlListener = nil
	if err != nil {
		return fmt.Errorf("accept native diode storage: %w", err)
	}
	control, err := diodecontrol.NewClient(ctx, conn)
	if err != nil {
		return fmt.Errorf("initialize native diode storage: %w", err)
	}
	exports, err := control.Query(ctx)
	if err == nil {
		err = verifyApplianceExports(opts, exports)
	}
	if err != nil {
		return errors.Join(err, control.Close())
	}
	manager, slots, err := newApplianceStorageManager(scsi.NewHCSHostBackend(uvm.hcsSystem), control, opts)
	if err != nil {
		return errors.Join(fmt.Errorf("create native diode attachment manager: %w", err), control.Close())
	}
	uvm.SCSIManager, uvm.reservedSCSISlots, uvm.applianceControl = manager, slots, control
	return nil
}

// NativeStorageControl exposes the existing sibling export-control seam.
// The caller must also watch Done and fail its owned pair on session loss.
func (uvm *UtilityVM) NativeStorageControl() (*diodecontrol.Client, error) {
	if uvm.applianceControl == nil {
		return nil, errors.New("native diode storage is not started")
	}
	return uvm.applianceControl, nil
}
