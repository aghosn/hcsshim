package sibling

import (
	"context"
	"errors"
)

type providerState interface {
	Done() <-chan struct{}
	Err() error
}

func cancelOnProviderLoss(ctx context.Context, state providerState, cancel context.CancelFunc) {
	go func() {
		select {
		case <-ctx.Done():
		case <-state.Done():
			cancel()
		}
	}()
}

func waitOwnedProvider(ctx context.Context, control, console providerState, wait func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	exited := make(chan error, 1)
	go func() { exited <- wait(ctx) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-control.Done():
		return errors.Join(errors.New("Unikraft management connection lost"), control.Err())
	case <-console.Done():
		return errors.Join(errors.New("Unikraft console ended"), console.Err())
	case err := <-exited:
		return errors.Join(errors.New("Unikraft provider exited"), err)
	}
}
