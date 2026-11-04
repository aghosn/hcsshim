//go:build linux

package scsi

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

const siblingStorageClass = "ba6163d9-04a1-4d29-b605-72e2ffb1dc7f"

// ResolveControllerNumber keeps sibling discovery separate from RP GUID lookup.
func ResolveControllerNumber(ctx context.Context, controller uint8, sibling bool) (uint8, error) {
	if sibling {
		if controller != 0 {
			return 0, fmt.Errorf("sibling storage only supports logical controller 0")
		}
		return siblingControllerNumber(os.DirFS("/"))
	}
	if int(controller) >= len(guestrequest.ScsiControllerGuids) {
		return 0, fmt.Errorf("RP SCSI controller %d is out of range", controller)
	}
	return ActualControllerNumber(ctx, controller)
}

func siblingControllerNumber(sys fs.FS) (uint8, error) {
	const root = "sys/bus/vmbus/devices"
	entries, err := fs.ReadDir(sys, root)
	if err != nil {
		return 0, fmt.Errorf("read sibling VMBus devices: %w", err)
	}
	var selected uint8
	found := false
	for _, entry := range entries {
		name := entry.Name()
		if !guestresource.IsSiblingVMBusDeviceID(name) {
			continue
		}
		device := path.Join(root, name)
		class, err := fs.ReadFile(sys, path.Join(device, "class_id"))
		if err != nil {
			return 0, fmt.Errorf("read sibling device %s class: %w", name, err)
		}
		if strings.Trim(strings.TrimSpace(string(class)), "{}") != siblingStorageClass {
			continue
		}
		children, err := fs.ReadDir(sys, device)
		if err != nil {
			return 0, fmt.Errorf("read sibling storage device %s: %w", name, err)
		}
		deviceFound := false
		for _, child := range children {
			if !strings.HasPrefix(child.Name(), "host") {
				continue
			}
			host, err := strconv.ParseUint(strings.TrimPrefix(child.Name(), "host"), 10, 8)
			if err != nil {
				return 0, fmt.Errorf("invalid sibling SCSI host %s: %w", child.Name(), err)
			}
			if found {
				return 0, fmt.Errorf("ambiguous sibling SCSI controller")
			}
			selected, found, deviceFound = uint8(host), true, true
		}
		if !deviceFound {
			return 0, fmt.Errorf("sibling storage device %s has no SCSI host", name)
		}
	}
	if !found {
		return 0, fmt.Errorf("sibling SCSI controller not found")
	}
	return selected, nil
}
