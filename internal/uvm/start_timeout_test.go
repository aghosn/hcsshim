//go:build windows

package uvm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Microsoft/hcsshim/internal/timeout"
)

// TestGCSBootstrapConnectionBudgets checks the production context boundary for
// default and early-attesting calls without native startup or minutes of wait.
// Per-call selection must not mutate the default used by unrelated UVMs.
func TestGCSBootstrapConnectionBudgets(t *testing.T) {
	original := timeout.GCSConnectionTimeout
	for _, budget := range []time.Duration{original, 7 * time.Minute} {
		before := time.Now()
		ctx, cancel := gcsBootstrapContext(context.Background(), budget)
		after := time.Now()
		deadline, ok := ctx.Deadline()
		cancel()
		if !ok || deadline.Before(before.Add(budget)) || deadline.After(after.Add(budget)) {
			t.Fatalf("connection deadline %v is not bounded by per-call %s", deadline, budget)
		}
	}
	if timeout.GCSConnectionTimeout != original {
		t.Fatal("per-call timeout changed the process default")
	}
}

// TestGCSBootstrapParentWins ensures a larger connection allowance cannot hide
// the caller's shorter deadline or cancellation, protecting shutdown ownership.
func TestGCSBootstrapParentWins(t *testing.T) {
	parent, cancelParent := context.WithTimeout(context.Background(), time.Minute)
	defer cancelParent()
	ctx, cancel := gcsBootstrapContext(parent, 7*time.Minute)
	defer cancel()
	want, _ := parent.Deadline()
	got, ok := ctx.Deadline()
	if !ok || !got.Equal(want) {
		t.Fatalf("connection context replaced parent deadline: %v != %v", got, want)
	}
	cancelParent()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("connection context lost parent cancellation")
	}
}

// TestGCSBootstrapRejectsInvalidTimeout checks validation before any VM state
// is touched. Zero/negative overrides must fail rather than mean an unbounded
// or immediately expired native startup; the public Start default is unchanged.
func TestGCSBootstrapRejectsInvalidTimeout(t *testing.T) {
	var vm *UtilityVM
	for _, budget := range []time.Duration{0, -time.Nanosecond} {
		if err := vm.StartWithGCSConnectionTimeout(context.Background(), budget); err == nil {
			t.Fatalf("accepted invalid per-call timeout %s", budget)
		}
	}
}
