//go:build linux

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// SNP boots use the command line embedded in the IGVM, not the host's normal
// LCOW ExecCommandLine. Select the peer before the first GCS connection.
func gcsPeerFromCommandLine(command string) (uint32, error) {
	const key = "gcs.vsock_peer_cid="
	peer := uint32(2)
	found := false
	for _, field := range strings.Fields(command) {
		if !strings.HasPrefix(field, key) {
			continue
		}
		if found {
			return 0, fmt.Errorf("duplicate %s", strings.TrimSuffix(key, "="))
		}
		found = true
		value, err := strconv.ParseUint(strings.TrimPrefix(field, key), 10, 32)
		if err != nil || (value != 2 && value != 4) {
			return 0, fmt.Errorf("%s requires root CID 2 or diode CID 4", strings.TrimSuffix(key, "="))
		}
		peer = uint32(value)
	}
	return peer, nil
}
