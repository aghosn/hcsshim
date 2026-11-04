//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package uvm

import (
	"context"
	"encoding/json"
	"fmt"
)

// partitionSealPayload encodes the explicit unsigned bitmap for the existing HCS
// control URI. Zero and unknown bits are transmitted unchanged: only HV decides
// semantic validity. It returns JSON encoding errors without a partial payload.
func partitionSealPayload(sealFlags uint64) (string, error) {
	payload, err := json.Marshal(struct {
		SealFlags uint64
	}{SealFlags: sealFlags})
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

// SealPartition invokes native partition sealing for this VM through the
// VM-global control URI with an explicit uint64 SealFlags JSON field. Zero and
// future bits are forwarded without defaults or local semantic validation;
// runtime zero is rejected by HV, while newer HV may support future bits.
// It requires an available HCS system, not a prepared region or numeric
// partition ID. HCS retains the system handle through submission and operation
// wait; success acknowledges actual operation
// completion. Every call submits again, with no cached state. Failure, timeout,
// or cancellation does not establish that the partition remains unsealed.
func (uvm *UtilityVM) SealPartition(ctx context.Context, sealFlags uint64) error {
	if uvm.hcsSystem == nil {
		return fmt.Errorf("utility VM has no HCS compute system")
	}

	payload, err := partitionSealPayload(sealFlags)
	if err != nil {
		return err
	}
	return uvm.hcsSystem.SystemControl(ctx, "hcs:/VirtualMachine/SealPartition", payload)
}
