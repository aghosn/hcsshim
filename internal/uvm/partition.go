//go:build windows

// Copyright (c) Microsoft Corporation. All rights reserved.

package uvm

import (
	"context"
	"encoding/json"
	"fmt"
)

// PartitionSealError preserves whether native submission was attempted. Even
// after cancellation, a dispatched failure cannot establish that the VM remains
// unsealed. No native execution, rollback or retry is inferred from this value.
type PartitionSealError struct {
	Dispatched bool
	Err        error
}

// Error reports the original operation error and submission uncertainty without
// changing ownership or inspecting native state.
func (e *PartitionSealError) Error() string {
	return fmt.Sprintf("seal partition (dispatched=%t): %v", e.Dispatched, e.Err)
}

// Unwrap exposes the original lookup, cancellation or native failure for errors.Is.
func (e *PartitionSealError) Unwrap() error { return e.Err }

// partitionSealPayload encodes the exact unsigned bitmap as a JSON number.
// Zero and unknown bits are unchanged; only native/HV validation owns semantics.
// Encoding failure returns no usable payload and causes no native effects.
func partitionSealPayload(sealFlags uint64) (string, error) {
	payload, err := json.Marshal(struct {
		SealFlags uint64 `json:"SealFlags"`
	}{SealFlags: sealFlags})
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

// SealPartition submits one VM-global seal operation with the exact uint64 mask,
// including explicit zero/future bits, then waits for actual HCS completion.
// No partition ID, prepared region, retry, default mask or downgrade is used.
// HCS locks the system through native submission/wait/close. Errors are
// PartitionSealError values distinguishing preflight from submission attempts;
// dispatched failures/timeouts leave irreversible effects uncertain. Callers
// serialize selected seal operations, supply the operation deadline in ctx and
// keep the VM alive through return. No default budget overrides that deadline;
// native syscalls are never abandoned to satisfy a wall-clock limit.
func (uvm *UtilityVM) SealPartition(ctx context.Context, sealFlags uint64) error {
	if uvm.hcsSystem == nil {
		return &PartitionSealError{Err: fmt.Errorf("utility VM has no HCS compute system")}
	}
	payload, err := partitionSealPayload(sealFlags)
	if err != nil {
		return &PartitionSealError{Err: err}
	}
	dispatched, err := uvm.hcsSystem.SystemControlOutcome(ctx, "hcs:/VirtualMachine/SealPartition", payload)
	if err != nil {
		return &PartitionSealError{Dispatched: dispatched, Err: err}
	}
	return nil
}
