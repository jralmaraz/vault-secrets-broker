// Package chaos provides a configurable mock provider server and supporting
// helpers for fault-injection testing and benchmarking of the adapter layer.
//
// MockProvider wraps an httptest.Server and exposes methods for injecting latency,
// error rates, and 429 responses at runtime, allowing tests to simulate realistic
// failure modes without network access or real provider accounts.
package chaos

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"
)

// MockProvider is a configurable httptest.Server that simulates a SaaS provider API.
// All injectable behaviour is safe for concurrent modification.
type MockProvider struct {
	*httptest.Server

	mu      sync.Mutex
	latency time.Duration // added to every response
	errRate float64       // 0.0–1.0: fraction of requests that return 500
	rate429 float64       // 0.0–1.0: fraction of requests that return 429
	blockCh chan struct{} // if non-nil, requests block until channel is closed

	// Counters for assertion in tests.
	TotalRequests    atomic.Int64
	Rejected429      atomic.Int64
	ServerErrors     atomic.Int64
	SuccessResponses atomic.Int64
}

// NewMockProvider starts a mock HTTPS test server and returns it.
// Callers must call Close() when done.
func NewMockProvider(handler http.Handler) *MockProvider {
	mp := &MockProvider{}
	if handler == nil {
		handler = mp.defaultHandler()
	}
	mp.Server = httptest.NewTLSServer(mp.wrap(handler))
	return mp
}

// SetLatency adds an artificial delay to every response.
func (mp *MockProvider) SetLatency(d time.Duration) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.latency = d
}

// SetErrRate sets the fraction of requests (0.0–1.0) that return HTTP 500.
func (mp *MockProvider) SetErrRate(r float64) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.errRate = r
}

// SetRate429 sets the fraction of requests (0.0–1.0) that return HTTP 429.
func (mp *MockProvider) SetRate429(r float64) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.rate429 = r
}

// Block makes all requests block indefinitely until Unblock is called.
// Useful to simulate provider timeouts without relying on wall-clock delays.
func (mp *MockProvider) Block() {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.blockCh = make(chan struct{})
}

// Unblock releases all requests that are currently blocked by Block.
func (mp *MockProvider) Unblock() {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	if mp.blockCh != nil {
		close(mp.blockCh)
		mp.blockCh = nil
	}
}

// Reset clears all injected faults and unblocks any waiting requests.
func (mp *MockProvider) Reset() {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.latency = 0
	mp.errRate = 0
	mp.rate429 = 0
	if mp.blockCh != nil {
		close(mp.blockCh)
		mp.blockCh = nil
	}
}

// wrap layers fault injection in front of the real handler.
func (mp *MockProvider) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mp.TotalRequests.Add(1)

		mp.mu.Lock()
		lat := mp.latency
		errRate := mp.errRate
		rate429 := mp.rate429
		blockCh := mp.blockCh
		mp.mu.Unlock()

		// Block until Unblock() is called (simulates provider hang / network partition).
		if blockCh != nil {
			select {
			case <-blockCh:
			case <-r.Context().Done():
				w.WriteHeader(http.StatusGatewayTimeout)
				return
			}
		}

		if lat > 0 {
			time.Sleep(lat)
		}

		roll := rand.Float64() //nolint:gosec // #nosec G404 -- fault-injection mock intentionally uses weak RNG
		if roll < rate429 {
			mp.Rejected429.Add(1)
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if roll < rate429+errRate {
			mp.ServerErrors.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		mp.SuccessResponses.Add(1)
		next.ServeHTTP(w, r)
	})
}

// defaultHandler responds with a minimal JSON body on all routes.
// Tests that need specific route logic should pass their own handler to NewMockProvider.
func (mp *MockProvider) defaultHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":    "mock-cred-id",
				"token": "mock-token-value",
				"key":   "mock-key-value",
			})
		}
	})
}
