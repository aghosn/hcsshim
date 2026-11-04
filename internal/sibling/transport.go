//go:build windows

// Package sibling owns the resources and guest bootstrap of a workload/diode pair.
package sibling

import (
	"context"
	"fmt"
	"strings"
	"time"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

type Role string

const (
	Diode    Role = "a"
	Workload Role = "b"
)

func Quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func Endpoint(role Role, groupID string) (hcsschema.SiblingCommunicationEndpoint, error) {
	endpoint := hcsschema.SiblingCommunicationEndpoint{
		GroupID: groupID, TargetVP: 0, TargetSINT: 3,
	}
	switch role {
	case Diode:
		endpoint.Role = hcsschema.SiblingCommunicationEndpointRoleBackend
		endpoint.EventFlagNumber = 11
	case Workload:
		endpoint.Role = hcsschema.SiblingCommunicationEndpointRoleWorkload
		endpoint.EventFlagNumber = 12
	default:
		return endpoint, fmt.Errorf("invalid sibling role %q", role)
	}
	if groupID == "" {
		return endpoint, fmt.Errorf("sibling communication group is empty")
	}
	return endpoint, nil
}

func WaitForRoute(ctx context.Context, vm *uvm.UtilityVM, endpoint hcsschema.SiblingCommunicationEndpoint) (hcsschema.SiblingCommunicationRouteInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		routes, err := vm.SiblingCommunicationRoutes(ctx)
		if err != nil {
			return hcsschema.SiblingCommunicationRouteInfo{}, err
		}
		for _, route := range routes {
			if strings.EqualFold(route.GroupID, endpoint.GroupID) && route.OutboundConnectionID != 0 {
				return route, nil
			}
		}
		select {
		case <-ctx.Done():
			return hcsschema.SiblingCommunicationRouteInfo{}, fmt.Errorf("sibling route %s: %w", endpoint.GroupID, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func BusLoadCommand(modulePath string) string {
	return "if [ ! -d /sys/bus/vmbus/drivers/sibling_bus ]; then insmod " +
		Quote(modulePath) + " || exit 1; fi; "
}

// RPDeviceCommand selects a block device by the RP controller identity, not sdX
// enumeration order. The caller must bound the lifetime of the guest process.
func RPDeviceCommand(controller uint, lun uint) (string, error) {
	match, err := RPDeviceMatchCommand(controller, lun)
	if err != nil {
		return "", err
	}
	return "until " + match + "; do sleep 0.1; done; ", nil
}

func RPDeviceMatchCommand(controller uint, lun uint) (string, error) {
	if controller >= uint(len(guestrequest.ScsiControllerGuids)) || lun >= 64 {
		return "", fmt.Errorf("invalid diode SCSI address %d:%d", controller, lun)
	}
	return RPDeviceIdentityMatch(guestrequest.ScsiControllerGuids[controller], lun)
}

func RPDeviceIdentityMatch(controllerID string, lun uint) (string, error) {
	id := strings.ToLower(strings.Trim(controllerID, "{}"))
	if id == "" || strings.Trim(id, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" || lun >= 64 {
		return "", fmt.Errorf("invalid RP storage identity %q LUN %d", controllerID, lun)
	}
	match := fmt.Sprintf(`storage_dev=; storage_count=0; for p in /sys/class/block/*; do `+
		`d=$(readlink -f "$p/device" 2>/dev/null) || continue; `+
		`case "$d" in */%s/host*/target*/*:0:0:%d) `+
		`storage_dev=/dev/${p##*/}; storage_count=$((storage_count+1));; esac; done; `+
		`[ "$storage_count" -eq 1 ] && [ -b "$storage_dev" ]`, id, lun)
	return match, nil
}
