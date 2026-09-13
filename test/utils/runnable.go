package utils

import "context"

// Start runs runnable until the returned function stops it and returns what
// its Start returned.
func Start(runnable interface{ Start(context.Context) error }) func() error {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runnable.Start(ctx) }()
	return func() error {
		cancel()
		return <-done
	}
}
