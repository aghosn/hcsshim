package hcsschema

// Timesync retains the native producer and optionally redirects its transport.
// RelayId is a nonzero workload-owned GUID; omission preserves ordinary VMBus.
type Timesync struct {
	RelayId string `json:"RelayId,omitempty"`
}
