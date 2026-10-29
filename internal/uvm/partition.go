//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package uvm

import (
	"context"
	"fmt"
)

// SealPartition invokes native partition sealing for this VM through the
// payload-free VM-global control URI. It requires an available HCS system, not
// a prepared region or numeric partition ID. HCS retains the system handle
// through submission and operation wait; success acknowledges actual operation
// completion. Every call submits again, with no cached state. Failure, timeout,
// or cancellation does not establish that the partition remains unsealed.
func (uvm *UtilityVM) SealPartition(ctx context.Context) error {
	if uvm.hcsSystem == nil {
		return fmt.Errorf("utility VM has no HCS compute system")
	}

	return uvm.hcsSystem.SystemControl(ctx, "hcs:/VirtualMachine/SealPartition", "")
}
