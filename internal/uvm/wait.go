//go:build windows

package uvm

import (
	"context"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/Microsoft/hcsshim/internal/logfields"
)

// Wait waits synchronously for a utility VM to terminate.
func (uvm *UtilityVM) Wait() error { return uvm.WaitCtx(context.Background()) }

// WaitCtx waits for native termination and any started output processing, or
// context cancellation. A created VM whose Start was never entered has no
// output borrower to join; waiting does not close its handles or boot files.
func (uvm *UtilityVM) WaitCtx(ctx context.Context) (err error) {
	err = uvm.hcsSystem.WaitCtx(ctx)

	return errors.Join(err, uvm.waitForOutput(ctx))
}

// waitForOutput joins only processing owned by an entered Start. Create may
// allocate the completion channel without starting a processor; leave that
// channel and all owners intact. Once Start is entered, timeout remains an
// error rather than evidence that its output borrower has drained.
func (uvm *UtilityVM) waitForOutput(ctx context.Context) error {
	if !uvm.startInvoked.Load() || uvm.outputProcessingDone == nil {
		return nil
	}
	logrus.WithField(logfields.UVMID, uvm.id).Debug("uvm exited, waiting for output processing to complete")
	select {
	case <-uvm.outputProcessingDone:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("failed to wait on uvm output processing: %w", ctx.Err())
	}
}
