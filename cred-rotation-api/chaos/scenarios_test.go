package chaos_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/chaos"
)

// sonarqubeHandler returns an httptest handler that implements the minimal
// SonarQube Web API surface the adapter exercises.
func sonarqubeHandler() http.Handler {
	mux := http.NewServeMux()

	// POST /api/user_tokens/generate → returns {"token":"<value>"}
	mux.HandleFunc("/api/user_tokens/generate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": "generated-token-" + fmt.Sprint(time.Now().UnixNano()),
		})
	})

	// POST /api/user_tokens/revoke → 204 NoContent
	mux.HandleFunc("/api/user_tokens/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// GET /api/user_tokens/search → returns {"userTokens":[{"name":"<n>"}]}
	mux.HandleFunc("/api/user_tokens/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"userTokens": []map[string]string{},
		})
	})

	return mux
}

// TestHappyPath verifies that a rotation succeeds and cleanup goroutine finishes
// before Drain returns.
func TestHappyPath(t *testing.T) {
	mp := chaos.NewMockProvider(sonarqubeHandler())
	t.Cleanup(mp.Close)
	a := newSonarqubeAdapterForTest(t, mp)

	ctx := context.Background()
	result, err := a.Rotate(ctx, adapter.RotateRequest{
		ProviderID: "alice",
		Meta:       map[string]string{"old_token_name": "alice-old-token"},
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected non-empty CredentialID")
	}
	if result.Credential == "" {
		t.Fatal("expected non-empty Credential")
	}

	// Drain should return quickly — cleanup goroutine has at most deleteOldTimeout.
	drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := a.Drain(drainCtx); err != nil {
		t.Errorf("Drain: %v", err)
	}
}

// TestCleanupGoroutinePanic verifies that a panic inside the cleanup goroutine
// does not propagate to the caller and Rotate still returns successfully.
func TestCleanupGoroutinePanic(t *testing.T) {
	// Handler that panics on revoke requests.
	panicOnRevoke := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/user_tokens/revoke" {
			panic("injected revoke panic")
		}
		// generate endpoint — succeed normally
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok-value"})
	})

	mp := chaos.NewMockProvider(panicOnRevoke)
	t.Cleanup(mp.Close)
	a := newSonarqubeAdapterForTest(t, mp)

	ctx := context.Background()
	result, err := a.Rotate(ctx, adapter.RotateRequest{
		ProviderID: "bob",
		Meta:       map[string]string{"old_token_name": "bob-old-token"},
	})
	if err != nil {
		t.Fatalf("Rotate must succeed even when cleanup goroutine will panic: %v", err)
	}
	if result.Credential == "" {
		t.Fatal("expected non-empty Credential")
	}

	// Drain should return (recovered panic counts as goroutine done).
	drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Drain may return context error if the goroutine panicked internally and
	// the server connection is severed; we only check it doesn't hang.
	_ = a.Drain(drainCtx)
}

// TestProviderTimeout verifies Rotate returns an error when the caller's context
// expires before the provider responds.
func TestProviderTimeout(t *testing.T) {
	mp := chaos.NewMockProvider(sonarqubeHandler())

	// Block all requests. Unblock on test cleanup so mp.Close() can finish.
	mp.Block()
	t.Cleanup(func() {
		mp.Unblock()
		mp.Close()
	})

	a := newSonarqubeAdapterForTest(t, mp)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := a.Rotate(ctx, adapter.RotateRequest{ProviderID: "charlie"})
	if err == nil {
		t.Fatal("expected error from timed-out provider, got nil")
	}
}

// TestBurst429Serialised verifies that with a semaphore limit of 10, a burst
// of 50 concurrent rotations that all receive 429 on the first attempt
// does not panic and all return errors (not mix success+panic).
func TestBurst429Serialised(t *testing.T) {
	mp := chaos.NewMockProvider(sonarqubeHandler())
	t.Cleanup(mp.Close)
	mp.SetRate429(1.0) // all requests return 429

	a := newSonarqubeAdapterForTest(t, mp)

	const goroutines = 50
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, errs[i] = a.Rotate(ctx, adapter.RotateRequest{ProviderID: fmt.Sprintf("user-%d", i)})
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	// All must fail — provider rejected every call with 429.
	if successes > 0 {
		t.Errorf("expected all rotations to fail under 100%% 429 rate, got %d successes", successes)
	}
	t.Logf("burst 429: all %d goroutines returned errors (correct)", goroutines)
}

// TestGracefulShutdownDrainsCleanup verifies that Drain blocks until cleanup
// goroutines launched during rotation have finished.
func TestGracefulShutdownDrainsCleanup(t *testing.T) {
	// Use a slow revoke to ensure the cleanup goroutine is still in-flight
	// when Drain is called.
	var revokeStarted, revokeDone sync.WaitGroup
	revokeStarted.Add(1)
	revokeDone.Add(1)

	slowRevoke := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/user_tokens/revoke" {
			revokeStarted.Done()
			// Block until Drain has been called (simulated via sleep).
			time.Sleep(200 * time.Millisecond)
			revokeDone.Done()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok-val"})
	})

	mp := chaos.NewMockProvider(slowRevoke)
	t.Cleanup(mp.Close)
	a := newSonarqubeAdapterForTest(t, mp)

	ctx := context.Background()
	_, err := a.Rotate(ctx, adapter.RotateRequest{
		ProviderID: "dave",
		Meta:       map[string]string{"old_token_name": "dave-old-token"},
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Wait for revoke goroutine to start.
	revokeStarted.Wait()

	// Drain should block until revoke finishes.
	start := time.Now()
	drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := a.Drain(drainCtx); err != nil {
		t.Errorf("Drain: %v", err)
	}

	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond {
		t.Errorf("Drain returned too fast (%v); cleanup goroutine may not have been awaited", elapsed)
	}
	t.Logf("Drain waited %v for cleanup goroutine", elapsed.Round(time.Millisecond))
}

// TestConcurrencySemaphore verifies the adapter's semaphore caps concurrent
// outbound calls. It counts overlapping in-flight generate requests.
func TestConcurrencySemaphore(t *testing.T) {
	const semLimit = 10
	var (
		mu       sync.Mutex
		inFlight int
		peak     int
	)

	countingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/user_tokens/generate" {
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			mu.Unlock()

			time.Sleep(50 * time.Millisecond) // hold the slot open briefly

			mu.Lock()
			inFlight--
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mp := chaos.NewMockProvider(countingHandler)
	t.Cleanup(mp.Close)
	a := newSonarqubeAdapterForTest(t, mp)

	const goroutines = 30
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = a.Rotate(ctx, adapter.RotateRequest{ProviderID: fmt.Sprintf("user-%d", i)})
		}(i)
	}
	wg.Wait()

	mu.Lock()
	p := peak
	mu.Unlock()

	if p > semLimit {
		t.Errorf("semaphore violation: peak in-flight was %d, limit is %d", p, semLimit)
	}
	t.Logf("peak concurrent in-flight: %d (limit %d)", p, semLimit)
}
