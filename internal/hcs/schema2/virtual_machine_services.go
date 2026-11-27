package hcsschema

// VirtualMachineServices mirrors the optional native HCS service configuration.
type VirtualMachineServices struct {
	Timesync *Timesync `json:"Timesync,omitempty"`
}
