//go:build windows

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Microsoft/hcsshim/internal/sibling"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

type siblingGCSRelay struct {
	diode chan *uvm.UtilityVM
}

func (relay *siblingGCSRelay) configure(ctx context.Context, vm *uvm.UtilityVM) error {
	if vm.ID() == "uvmboot-0" {
		relay.diode <- vm
		return nil
	}
	if vm.ID() != "uvmboot-1" {
		return fmt.Errorf("GCS relay requires exactly the diode and workload pair")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	select {
	case diode := <-relay.diode:
		return vm.ConfigureGCSRelay(diode)
	case <-ctx.Done():
		return fmt.Errorf("wait for diode GCS relay endpoint: %w", ctx.Err())
	}
}

func siblingGCSRelayCommand() string {
	return sibling.GCSRelayCommand()
}
