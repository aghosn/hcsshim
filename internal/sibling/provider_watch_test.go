package sibling

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testProviderState struct {
	done chan struct{}
	err  error
}

func (s testProviderState) Done() <-chan struct{} { return s.done }
func (s testProviderState) Err() error            { return s.err }

func TestOwnedProviderLossCancelsStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lost := make(chan struct{})
	cancelOnProviderLoss(ctx, testProviderState{done: lost}, cancel)
	close(lost)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("lost native management did not cancel startup")
	}
}

func TestOwnedProviderWatchCoversControlConsoleExitAndCancellation(t *testing.T) {
	for _, source := range []string{"control", "console", "exit", "cancel"} {
		t.Run(source, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New(source + " failure")
			control := testProviderState{make(chan struct{}), cause}
			console := testProviderState{make(chan struct{}), cause}
			exit, returned := make(chan struct{}), make(chan struct{})
			result := make(chan error, 1)
			go func() {
				result <- waitOwnedProvider(ctx, control, console, func(ctx context.Context) error {
					defer close(returned)
					select {
					case <-exit:
						return cause
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			}()
			wantErr := cause
			switch source {
			case "control":
				close(control.done)
			case "console":
				close(console.done)
			case "exit":
				close(exit)
			case "cancel":
				cancel()
				wantErr = context.Canceled
			}
			select {
			case err := <-result:
				if !errors.Is(err, wantErr) {
					t.Fatalf("lost provider failure: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("provider failure did not wake its owner")
			}
			select {
			case <-returned:
			case <-time.After(time.Second):
				t.Fatal("provider wait remained blocked after watcher exit")
			}
		})
	}
}
