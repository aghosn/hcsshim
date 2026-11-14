package guestresource

// LinuxLogVsockPort is GCS's inherited stdout/stderr log endpoint. The mediated
// workload uses this port on the diode; ordinary guests use it on the root.
const LinuxLogVsockPort = 109

// The relayed workload has its own root-facing service and IO port namespace,
// independent of the diode's ordinary GCS connection.
const (
	GCSRelayControlPort uint32 = 0x50000000
	// GCSRelayLogPort carries workload logs, separate from control, dynamic IO
	// and the diode's own port 109. The Linux protected profile excludes the
	// native appliance whose storage control otherwise uses this port.
	GCSRelayLogPort     uint32 = 0x50000001
	GCSRelayIOPortStart uint32 = 0x60000000
)
