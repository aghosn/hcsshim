package guestresource

import "regexp"

var siblingVMBusDeviceID = regexp.MustCompile(`^bus[1-9][0-9]*-relid[1-9][0-9]*-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IsSiblingVMBusDeviceID recognizes the full bus/relid/instance name emitted by
// vmbus_device_register, not the instance-only name used by the RP bus.
func IsSiblingVMBusDeviceID(id string) bool {
	return siblingVMBusDeviceID.MatchString(id)
}
