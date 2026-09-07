package chaos_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/chaos"
)

// fastRotateHandler is a minimal generate handler with no artificial latency.
func fastRotateHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user_tokens/generate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": "bench-token-" + fmt.Sprint(time.Now().UnixNano()),
		})
	})
	mux.HandleFunc("/api/user_tokens/revoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// BenchmarkRotate measures single-goroutine rotation throughput.
func BenchmarkRotate(b *testing.B) {
	mp := chaos.NewMockProvider(fastRotateHandler())
	b.Cleanup(mp.Close)

	a, err := newSonarqubeAdapterFromURL(mp.URL)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := a.Rotate(ctx, adapter.RotateRequest{ProviderID: "bench-user"})
		cancel()
		if err != nil {
			b.Errorf("Rotate: %v", err)
		}
	}
}

// BenchmarkRotateParallel measures throughput under goroutine-per-request parallelism.
func BenchmarkRotateParallel(b *testing.B) {
	mp := chaos.NewMockProvider(fastRotateHandler())
	b.Cleanup(mp.Close)

	a, err := newSonarqubeAdapterFromURL(mp.URL)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := a.Rotate(ctx, adapter.RotateRequest{ProviderID: "bench-user"})
			cancel()
			if err != nil {
				b.Errorf("Rotate: %v", err)
			}
		}
	})
}

// BenchmarkRotateWithCleanup measures throughput when old-token cleanup is always triggered.
func BenchmarkRotateWithCleanup(b *testing.B) {
	mp := chaos.NewMockProvider(fastRotateHandler())
	b.Cleanup(mp.Close)

	a, err := newSonarqubeAdapterFromURL(mp.URL)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := a.Rotate(ctx, adapter.RotateRequest{
			ProviderID: "bench-user",
			Meta:       map[string]string{"old_token_name": "old-token"},
		})
		cancel()
		if err != nil {
			b.Errorf("Rotate: %v", err)
		}
	}

	drainCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = a.Drain(drainCtx)
}

// BenchmarkRotateWithLatency measures throughput with 5 ms artificial provider latency.
func BenchmarkRotateWithLatency(b *testing.B) {
	mp := chaos.NewMockProvider(fastRotateHandler())
	b.Cleanup(mp.Close)
	mp.SetLatency(5 * time.Millisecond)

	a, err := newSonarqubeAdapterFromURL(mp.URL)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := a.Rotate(ctx, adapter.RotateRequest{ProviderID: "bench-user"})
			cancel()
			if err != nil {
				b.Errorf("Rotate: %v", err)
			}
		}
	})
}
