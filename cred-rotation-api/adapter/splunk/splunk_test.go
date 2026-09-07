package splunk_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/splunk"
)

const (
	fakeToken     = "aabbccdd-1111-2222-3333-ffffffffffff"
	fakeAuthToken = "admin-management-token"
)

// splunkEntry mirrors the Splunk REST response shape for test servers.
type splunkEntry struct {
	Name    string        `json:"name"`
	Content splunkContent `json:"content"`
}

type splunkContent struct {
	Disabled   bool   `json:"disabled"`
	Index      string `json:"index"`
	Sourcetype string `json:"sourcetype"`
	Token      string `json:"token,omitempty"`
}

func splunkResp(entries ...splunkEntry) []byte {
	b, _ := json.Marshal(map[string]interface{}{"entry": entries})
	return b
}

// newTestServer returns an httptest.Server with configurable per-path behaviour.
// handlers maps "METHOD /path" to a handler func.
func newTestServer(t *testing.T, handlers map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for pattern, h := range handlers {
		// httptest uses exact path matching; register both with and without trailing slash.
		mux.HandleFunc(pattern, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newAdapter(t *testing.T, srv *httptest.Server) *splunk.Adapter {
	t.Helper()
	a, err := splunk.New(splunk.Config{
		BaseURL:   srv.URL,
		AuthToken: fakeAuthToken,
	}, splunk.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("splunk.New: %v", err)
	}
	return a
}

// ── Name ─────────────────────────────────────────────────────────────────────

func TestAdapter_Name(t *testing.T) {
	a, err := splunk.New(splunk.Config{BaseURL: "https://splunk:8089", AuthToken: "tok"})
	if err != nil {
		t.Fatalf("splunk.New: %v", err)
	}
	if got := a.Name(); got != "splunk" {
		t.Errorf("Name() = %q, want %q", got, "splunk")
	}
}

// ── New — validation ─────────────────────────────────────────────────────────

func TestNew_MissingBaseURL(t *testing.T) {
	_, err := splunk.New(splunk.Config{AuthToken: "tok"})
	if err == nil {
		t.Fatal("expected error for missing BaseURL")
	}
}

func TestNew_MissingAuthToken(t *testing.T) {
	_, err := splunk.New(splunk.Config{BaseURL: "https://splunk:8089"})
	if err == nil {
		t.Fatal("expected error for missing AuthToken")
	}
}

func TestNew_BadCACert(t *testing.T) {
	_, err := splunk.New(splunk.Config{
		BaseURL:   "https://splunk:8089",
		AuthToken: "tok",
		CACert:    "not-valid-pem",
	})
	if err == nil {
		t.Fatal("expected error for invalid CACert")
	}
}

// ── Rotate ───────────────────────────────────────────────────────────────────

func TestRotate_Success(t *testing.T) {
	createCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			// Verify Authorization header — never log it.
			if r.Header.Get("Authorization") != "Bearer "+fakeAuthToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			createCalled = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(splunkResp(splunkEntry{
				Name:    "prod-app-20260905T120000Z",
				Content: splunkContent{Token: fakeToken, Index: "main"},
			}))
		},
	})

	a := newAdapter(t, srv)
	result, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "prod-app"})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !createCalled {
		t.Error("create endpoint was not called")
	}
	if result.Credential == "" {
		t.Error("expected non-empty Credential")
	}
	if result.Credential == fakeAuthToken {
		t.Error("Credential must not equal the management token")
	}
	if !strings.HasPrefix(result.CredentialID, "prod-app-") {
		t.Errorf("CredentialID %q should be prefixed with provider ID", result.CredentialID)
	}
	if result.ProviderID != "prod-app" {
		t.Errorf("ProviderID = %q, want %q", result.ProviderID, "prod-app")
	}
}

func TestRotate_DeletesOldToken(t *testing.T) {
	deleteCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(splunkResp(splunkEntry{
					Name:    "app-20260905T120000Z",
					Content: splunkContent{Token: fakeToken},
				}))
			}
		},
		"/services/data/inputs/http/old-token-name": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				deleteCalled = true
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(splunkResp())
			}
		},
	})

	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "app",
		Meta:       map[string]string{"old_token_name": "old-token-name"},
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	_ = a.Drain(context.Background())
	if !deleteCalled {
		t.Error("expected DELETE call for old token name, got none")
	}
}

func TestRotate_NameContainsTimestampAndRandomSuffix(t *testing.T) {
	var capturedName string
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				_ = r.ParseForm()
				capturedName = r.FormValue("name")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(splunkResp(splunkEntry{
					Name:    capturedName,
					Content: splunkContent{Token: fakeToken},
				}))
			}
		},
	})

	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "svc"})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if !strings.HasPrefix(capturedName, "svc-") {
		t.Errorf("token name %q should start with provider ID prefix", capturedName)
	}
	// Format: svc-<timestamp>-<4hexchars>
	parts := strings.Split(capturedName, "-")
	if len(parts) < 3 {
		t.Errorf("token name %q should have at least 3 dash-separated parts", capturedName)
	}
	lastPart := parts[len(parts)-1]
	if len(lastPart) != 4 {
		t.Errorf("random suffix %q should be 4 hex characters, got len=%d", lastPart, len(lastPart))
	}
}

// TestRotate_LogInjection_TokenNameSanitized verifies that a newline-embedded
// old_token_name does not produce multi-line log output (CWE-117 guard).
// A catch-all handler returns 500 for any DELETE so the Warn path is reached.
func TestRotate_LogInjection_TokenNameSanitized(t *testing.T) {
	injectedName := "legit-token\nfake-log-entry: injected"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(splunkResp(splunkEntry{
				Name:    "app-new",
				Content: splunkContent{Token: fakeToken},
			}))
			return
		}
		if r.Method == http.MethodDelete {
			// Force a 500 so the adapter logs the old_token_name via Warn.
			http.Error(w, `{"messages":[{"type":"ERROR","text":"forced"}]}`,
				http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	a, err := splunk.New(splunk.Config{
		BaseURL:   srv.URL,
		AuthToken: fakeAuthToken,
	}, splunk.WithBaseURL(srv.URL), splunk.WithLogger(logger))
	if err != nil {
		t.Fatalf("splunk.New: %v", err)
	}

	_, err = a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "app",
		Meta:       map[string]string{"old_token_name": injectedName},
	})
	if err != nil {
		t.Fatalf("Rotate should succeed, got: %v", err)
	}
	_ = a.Drain(context.Background())

	logged := logBuf.String()
	// The injected suffix must NOT appear as a standalone log line.
	injectedSuffix := strings.Split(injectedName, "\n")[1]
	if strings.Contains(logged, "\n"+injectedSuffix) {
		t.Errorf("log injection not sanitized — newline present in output: %q", logged)
	}
	// The safe prefix before the newline must still appear.
	if !strings.Contains(logged, "legit-token") {
		t.Errorf("expected safe prefix in log, got: %q", logged)
	}
}

func TestRotate_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"messages":[{"type":"ERROR","text":"internal error"}]}`, http.StatusInternalServerError)
		},
	})
	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "app"})
	if err == nil {
		t.Fatal("expected error from Splunk 500, got nil")
	}
}

func TestRotate_MissingTokenInResponse(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			// token field absent
			_, _ = w.Write(splunkResp(splunkEntry{Name: "app-ts", Content: splunkContent{Index: "main"}}))
		},
	})
	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "app"})
	if err == nil {
		t.Fatal("expected error when token value is missing from response")
	}
}

// ── Revoke ───────────────────────────────────────────────────────────────────

func TestRevoke_Success(t *testing.T) {
	deleteCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http/my-hec-token": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				deleteCalled = true
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(splunkResp())
			}
		},
	})

	a := newAdapter(t, srv)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{
		ProviderID:   "app",
		CredentialID: "my-hec-token",
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !deleteCalled {
		t.Error("expected DELETE call, got none")
	}
}

func TestRevoke_EmptyCredentialID_FailsClosed(t *testing.T) {
	a, _ := splunk.New(splunk.Config{BaseURL: "https://splunk:8089", AuthToken: "tok"})
	err := a.Revoke(context.Background(), adapter.RevokeRequest{ProviderID: "app", CredentialID: ""})
	if err == nil {
		t.Fatal("expected error for empty credential_id, got nil")
	}
	if !strings.Contains(err.Error(), "credential_id is required") {
		t.Errorf("error %q should mention credential_id requirement", err.Error())
	}
}

func TestRevoke_AlreadyDeleted_IsIdempotent(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http/gone-token": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		},
	})
	a := newAdapter(t, srv)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{
		ProviderID:   "app",
		CredentialID: "gone-token",
	})
	if err != nil {
		t.Fatalf("Revoke of already-deleted token should be idempotent, got: %v", err)
	}
}

// ── Status ───────────────────────────────────────────────────────────────────

func TestStatus_Active(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http/my-token": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(splunkResp(splunkEntry{
				Name:    "my-token",
				Content: splunkContent{Disabled: false, Index: "main"},
			}))
		},
	})
	a := newAdapter(t, srv)
	status, err := a.Status(context.Background(), "my-token")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Active {
		t.Error("expected Active=true for enabled token")
	}
}

func TestStatus_Disabled(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http/my-token": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(splunkResp(splunkEntry{
				Name:    "my-token",
				Content: splunkContent{Disabled: true},
			}))
		},
	})
	a := newAdapter(t, srv)
	status, err := a.Status(context.Background(), "my-token")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Active {
		t.Error("expected Active=false for disabled token")
	}
}

func TestStatus_NotFound(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http/missing-token": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		},
	})
	a := newAdapter(t, srv)
	status, err := a.Status(context.Background(), "missing-token")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Active {
		t.Error("expected Active=false for non-existent token")
	}
}

func TestStatus_EmptyCredentialID(t *testing.T) {
	a, _ := splunk.New(splunk.Config{BaseURL: "https://splunk:8089", AuthToken: "tok"})
	_, err := a.Status(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty credential_id")
	}
}

// ── Authorization header guard ────────────────────────────────────────────────

func TestRotate_SendsAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http": func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(splunkResp(splunkEntry{
				Name:    "app-ts",
				Content: splunkContent{Token: fakeToken},
			}))
		},
	})
	a := newAdapter(t, srv)
	_, _ = a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "app"})

	wantPrefix := "Bearer "
	if !strings.HasPrefix(gotAuth, wantPrefix) {
		t.Errorf("Authorization header %q should start with %q", gotAuth, wantPrefix)
	}
	// The value after "Bearer " must equal fakeAuthToken (management token, not HEC token).
	got := strings.TrimPrefix(gotAuth, wantPrefix)
	if got != fakeAuthToken {
		t.Errorf("auth token = %q, want %q", got, fakeAuthToken)
	}
}

// TestRotate_DeleteOldToken_LogsFailure verifies that when best-effort deletion
// of the old token fails, the error is logged via the adapter's logger rather
// than being silently dropped. This tests the new observable behaviour added
// alongside the context-detachment fix.
func TestRotate_DeleteOldToken_LogsFailure(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/services/data/inputs/http": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(splunkResp(splunkEntry{
				Name:    "app-new",
				Content: splunkContent{Token: fakeToken},
			}))
		},
		"/services/data/inputs/http/old-token": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				// Simulate Splunk returning an error on delete.
				http.Error(w, `{"messages":[{"type":"ERROR","text":"internal error"}]}`,
					http.StatusInternalServerError)
			}
		},
	})

	// Capture log output via a pipe-backed slog handler.
	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	a, err := splunk.New(splunk.Config{
		BaseURL:   srv.URL,
		AuthToken: fakeAuthToken,
	}, splunk.WithBaseURL(srv.URL), splunk.WithLogger(logger))
	if err != nil {
		t.Fatalf("splunk.New: %v", err)
	}

	// Rotate must succeed even though old-token delete fails.
	_, err = a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "app",
		Meta:       map[string]string{"old_token_name": "old-token"},
	})
	if err != nil {
		t.Fatalf("Rotate should succeed despite delete failure, got: %v", err)
	}
	_ = a.Drain(context.Background())

	// The failure must appear in the log.
	logged := logBuf.String()
	if !strings.Contains(logged, "best-effort delete of old token failed") {
		t.Errorf("expected warning in log, got: %q", logged)
	}
	if !strings.Contains(logged, "old-token") {
		t.Errorf("expected old token name in log, got: %q", logged)
	}
}
