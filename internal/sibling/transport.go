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
	TransportVersion      = 4
	Diode            Role = "a"
	Workload         Role = "b"
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

// DiscoveryShell defines mode/owner discovery for generated guest commands.
// sibling_mode takes 1 to require an explicit mode, or 0 for legacy RP.
// sibling_owner retains sb_owner/sb_instance; 1 means not ready, 2 means
// invalid mode or link count. Callers own polling deadlines and identity checks.
const DiscoveryShell = `
# Select only the owner permitted by the kernel's measured mode.
sibling_mode() {
    sb_mode=N;
    if [ -e /sys/module/hv_vmbus/parameters/no_rp ] || [ -L /sys/module/hv_vmbus/parameters/no_rp ]; then
        [ -r /sys/module/hv_vmbus/parameters/no_rp ] &&
            sb_mode=$(cat /sys/module/hv_vmbus/parameters/no_rp) ||
            { echo 'sibling_vmbus: unreadable mode' >&2; return 2; };
        case "$sb_mode" in Y|N) :;; *) echo 'sibling_vmbus: invalid mode' >&2; return 2;; esac;
    elif [ "$1" = 1 ]; then
        echo 'sibling_vmbus: explicit mode required' >&2; return 2;
    fi;
};
# Re-expand the RP glob on every poll; identity and stats share this owner.
sibling_owner() {
    sb_owner=; sb_instance=;
    sibling_mode "$1" || return 2;
    case "$sb_mode" in
        Y) set -- /sys/devices/sibling_bus_acpi/sibling_instance;;
        N) set -- /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance;;
    esac;
    [ "$#" -eq 1 ] || { echo 'sibling_vmbus: expected one configured link' >&2; return 2; };
    sb_instance=$1; sb_owner=${sb_instance%/sibling_instance};
    [ -r "$sb_instance" ] && grep -q 'ready=1' "$sb_instance";
};
`

// OwnerReadyCommand polls through its caller, failing closed on mode/count
// errors rather than retrying a different owner.
func OwnerReadyCommand(requireMode bool) string {
	strict := "0"
	if requireMode {
		strict = "1"
	}
	return `sibling_owner ` + strict + ` || { [ "$?" -ne 2 ] || exit 1; false; }`
}

// BusLoadCommand preserves ordinary RP loading; no-RP requires a built-in owner.
func BusLoadCommand(modulePath string) string {
	return DiscoveryShell + `sibling_mode 0 || exit 1; if [ "$sb_mode" = Y ]; then ` +
		`[ -d /sys/devices/sibling_bus_acpi ] || { echo 'sibling_vmbus: built-in ACPI owner missing' >&2; exit 1; }; ` +
		`elif [ ! -d /sys/bus/vmbus/drivers/sibling_bus ]; then insmod ` +
		Quote(modulePath) + ` || exit 1; fi; `
}

func guestInstanceCommand(localCID, peerCID int) string {
	return `sb_wait=0; until set -- /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance; ` +
		`[ "$#" -eq 1 ] && [ -r "$1" ] && sb_instance=$(cat "$1") && ` +
		`case "$sb_instance" in *" ready=1") true;; *) false;; esac; do ` +
		`sb_wait=$((sb_wait+1)); if [ "$sb_wait" -ge 300 ]; then ` +
		`echo 'Timed out waiting for ready sibling bus' >&2; exit 1; fi; sleep 0.1; done; ` +
		`set -- $sb_instance; ` +
		fmt.Sprintf(`[ "$#" -eq 5 ] && [ "${2#*=}" = %d ] && [ "${3#*=}" = %d ] && [ "${4#*=}" = %d ] || `+
			`{ echo "Invalid sibling bus identity: $sb_instance" >&2; exit 1; }; `, localCID, peerCID, TransportVersion) +
		`sb_bus=${1#*=}; `
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
