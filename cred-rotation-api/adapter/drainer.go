package adapter

import "context"

// Drainer is an optional interface adapters may implement to signal that all
// background cleanup goroutines have finished. The server calls Drain during
// graceful shutdown so that best-effort old-credential deletions are not
// abandoned mid-flight when the process exits.
type Drainer interface {
	Drain(ctx context.Context) error
}
