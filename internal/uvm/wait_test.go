//go:build windows

package uvm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// outputWaitTestContext exposes the production select's cancellation-channel
// subscription so a test can observe a pending join without timing sleeps.
type outputWaitTestContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

// Done records subscription without changing the wrapped cancellation lifetime.
func (ctx *outputWaitTestContext) Done() <-chan struct{} {
	// Multiple Done calls may observe the same pending output join.
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

// TestProtectedCleanupOutputBeforeStart checks Create-to-stop cleanup: an
// allocated completion channel with no entered Start must not consume the
// cleanup budget or be closed as fabricated output-drain evidence.
func TestProtectedCleanupOutputBeforeStart(t *testing.T) {
	output := make(chan struct{})
	vm := &UtilityVM{outputProcessingDone: output}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := vm.waitForOutput(ctx); err != nil {
		t.Fatalf("never-started output consumed cleanup budget: %v", err)
	}
	if vm.startInvoked.Load() || vm.outputProcessingDone != output {
		t.Fatal("waiting changed startup/output ownership")
	}
	select {
	case <-output:
		t.Fatal("waiting manufactured output completion")
	default:
	}
}

// TestProtectedCleanupStartedOutputJoin checks that the same production helper
// retains a started output borrower until its completion channel closes; the
// pre-Start exception must not weaken normal VM output drainage.
func TestProtectedCleanupStartedOutputJoin(t *testing.T) {
	output := make(chan struct{})
	vm := &UtilityVM{outputProcessingDone: output}
	vm.startInvoked.Store(true)
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx := &outputWaitTestContext{Context: parent, waiting: make(chan struct{})}
	result := make(chan error, 1)
	// Observe the real output join, without supplying an HCS system or receipt.
	go func() { result <- vm.waitForOutput(ctx) }()
	select {
	case <-ctx.waiting:
	case <-parent.Done():
		t.Fatal("started output join never subscribed")
	}
	select {
	case err := <-result:
		t.Fatalf("output borrower was not joined: %v", err)
	default:
	}
	close(output)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("completed output join failed: %v", err)
		}
	case <-parent.Done():
		t.Fatal("completed output borrower was not observed")
	}
}

// TestProtectedCleanupOutputTimeoutRetainsBorrower checks that an expired
// started-output join reports its deadline and preserves the channel/owner;
// only later observed processor completion can satisfy a subsequent join.
func TestProtectedCleanupOutputTimeoutRetainsBorrower(t *testing.T) {
	output := make(chan struct{})
	vm := &UtilityVM{outputProcessingDone: output}
	vm.startInvoked.Store(true)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := vm.waitForOutput(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unconfirmed output drain lost its deadline: %v", err)
	}
	if !vm.startInvoked.Load() || vm.outputProcessingDone != output {
		t.Fatal("timeout discarded output ownership")
	}
	select {
	case <-output:
		t.Fatal("timeout manufactured output completion")
	default:
	}
	close(output)
	if err := vm.waitForOutput(context.Background()); err != nil {
		t.Fatalf("later confirmed output completion was not joined: %v", err)
	}
}
