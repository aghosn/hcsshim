package guestresource

// The relayed workload has its own root-facing service and IO port namespace,
// independent of the diode's ordinary GCS connection.
const (
	GCSRelayControlPort uint32 = 0x50000000
	GCSRelayIOPortStart uint32 = 0x60000000
)
