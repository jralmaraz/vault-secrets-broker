package pagerduty_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/pagerduty"
)

const (
	fakeAPIKey = "pagerduty-api-key-aaaa-bbbb-cccc"
	fakeEmail  = "sre@example.com"
	fakeKeyID  = "PABC123"
	fakeKeyVal = "u+Qh7FkFGE4O3nU5tGv2" // never log this in tests either
)

// pdCreateResponse builds a minimal PagerDuty create-key response.
func pdCreateResponse(name, key string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"api_key": map[string]interface{}{
			"id":   fakeKeyID,
			"name": name,
			"key":  key,
			"type": "read_write_api_key",
		},
	})
	return b
}

// pdListResponse builds a minimal PagerDuty list-keys response.
func pdListResponse(ids ...string) []byte {
	keys := make([]map[string]string, len(ids))
	for i, id := range ids {
		keys[i] = map[string]string{"id": id, "name": "key-" + id, "type": "read_write_api_key"}
	}
	b, _ := json.Marshal(map[string]interface{}{"api_keys": keys, "more": false})
	return b
}

func newTestServer(t *testing.T, handlers map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for pattern, h := range handlers {
		mux.HandleFunc(pattern, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newAdapter(t *testing.T, srv *httptest.Server, opts ...pagerduty.Option) *pagerduty.Adapter {
	t.Helper()
	opts = append([]pagerduty.Option{pagerduty.WithBaseURL(srv.URL)}, opts...)
	a, err := pagerduty.New(pagerduty.Config{
		APIKey: fakeAPIKey,
		Email:  fakeEmail,
	}, opts...)
	if err != nil {
		t.Fatalf("pagerduty.New: %v", err)
	}
	return a
}

// ── Name ─────────────────────────────────────────────────────────────────────

func TestAdapter_Name(t *testing.T) {
	a, err := pagerduty.New(pagerduty.Config{APIKey: "x", Email: "a@b.com"})
	if err != nil {
		t.Fatalf("pagerduty.New: %v", err)
	}
	if got := a.Name(); got != "pagerduty" {
		t.Errorf("Name() = %q, want %q", got, "pagerduty")
	}
}

// ── New — validation ──────────────────────────────────────────────────────────

func TestNew_MissingAPIKey(t *testing.T) {
	_, err := pagerduty.New(pagerduty.Config{Email: fakeEmail})
	if err == nil {
		t.Fatal("expected error for missing APIKey")
	}
}

func TestNew_MissingEmail(t *testing.T) {
	_, err := pagerduty.New(pagerduty.Config{APIKey: fakeAPIKey})
	if err == nil {
		t.Fatal("expected error for missing Email")
	}
}

// ── Rotate ───────────────────────────────────────────────────────────────────

func TestRotate_Success(t *testing.T) {
	createCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get("Authorization") == "" || r.Header.Get("From") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			createCalled = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(pdCreateResponse("infra-auto-ts", fakeKeyVal))
		},
	})

	a := newAdapter(t, srv)
	result, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "infra-auto"})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !createCalled {
		t.Error("create endpoint was not called")
	}
	if result.Credential == "" {
		t.Error("expected non-empty Credential")
	}
	if result.Credential == fakeAPIKey {
		t.Error("Credential must not equal the admin key")
	}
	if result.CredentialID != fakeKeyID {
		t.Errorf("CredentialID = %q, want %q", result.CredentialID, fakeKeyID)
	}
	if result.ProviderID != "infra-auto" {
		t.Errorf("ProviderID = %q, want %q", result.ProviderID, "infra-auto")
	}
	if result.RotatedAt.IsZero() {
		t.Error("RotatedAt must not be zero")
	}
}

func TestRotate_NameContainsProviderIDAndSuffix(t *testing.T) {
	var capturedName string
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				var body struct {
					APIKey struct {
						Name string `json:"name"`
					} `json:"api_key"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				capturedName = body.APIKey.Name
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(pdCreateResponse(capturedName, fakeKeyVal))
			}
		},
	})

	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "monitoring"})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !strings.HasPrefix(capturedName, "monitoring-") {
		t.Errorf("key name %q should start with provider ID prefix", capturedName)
	}
	parts := strings.Split(capturedName, "-")
	if len(parts) < 3 {
		t.Errorf("key name %q should have at least 3 dash-separated parts", capturedName)
	}
	last := parts[len(parts)-1]
	if len(last) != 4 {
		t.Errorf("random suffix %q should be 4 hex characters", last)
	}
}

func TestRotate_DeletesOldKey(t *testing.T) {
	deleteCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(pdCreateResponse("ts", fakeKeyVal))
			}
		},
		"/api_keys/OLD123": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				deleteCalled = true
				w.WriteHeader(http.StatusNoContent)
			}
		},
	})

	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "infra-auto",
		Meta:       map[string]string{"old_key_id": "OLD123"},
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !deleteCalled {
		t.Error("expected DELETE call for old key id, got none")
	}
}

func TestRotate_OldKeyDeleteFailure_LogsAndSucceeds(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(pdCreateResponse("ts", fakeKeyVal))
			}
		},
		"/api_keys/BAD-OLD": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":{"message":"Internal error"}}`, http.StatusInternalServerError)
		},
	})

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	a := newAdapter(t, srv, pagerduty.WithLogger(logger))
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "infra-auto",
		Meta:       map[string]string{"old_key_id": "BAD-OLD"},
	})
	if err != nil {
		t.Fatalf("Rotate should succeed despite delete failure: %v", err)
	}
	if !strings.Contains(logBuf.String(), "best-effort delete of old key failed") {
		t.Errorf("expected warning in log, got: %q", logBuf.String())
	}
}

func TestRotate_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":{"message":"Forbidden"}}`, http.StatusForbidden)
		},
	})
	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "svc"})
	if err == nil {
		t.Fatal("expected error from PagerDuty 403, got nil")
	}
}

func TestRotate_MissingKeyValueInResponse(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			b, _ := json.Marshal(map[string]interface{}{
				"api_key": map[string]interface{}{
					"id":   fakeKeyID,
					"name": "ts",
					// key intentionally absent
				},
			})
			_, _ = w.Write(b)
		},
	})
	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "svc"})
	if err == nil {
		t.Fatal("expected error when key value is missing from response")
	}
}

func TestRotate_LogInjection_OldKeyIDSanitized(t *testing.T) {
	injected := "legit-prefix\nfake-log-entry: injected"
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(pdCreateResponse("ts", fakeKeyVal))
			}
		},
		// No delete handler — will fail, triggering the Warn log path.
	})

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	a := newAdapter(t, srv, pagerduty.WithLogger(logger))
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "svc",
		Meta:       map[string]string{"old_key_id": injected},
	})
	if err != nil {
		t.Fatalf("Rotate should succeed: %v", err)
	}
	logged := logBuf.String()
	if strings.Contains(logged, "\n"+strings.Split(injected, "\n")[1]) {
		t.Errorf("log injection not sanitized: %q", logged)
	}
	if !strings.Contains(logged, "legit-prefix") {
		t.Errorf("safe prefix should appear in log: %q", logged)
	}
}

// ── Revoke ───────────────────────────────────────────────────────────────────

func TestRevoke_Success(t *testing.T) {
	deleteCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys/" + fakeKeyID: func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				deleteCalled = true
				w.WriteHeader(http.StatusNoContent)
			}
		},
	})

	a := newAdapter(t, srv)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{
		ProviderID:   "svc",
		CredentialID: fakeKeyID,
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !deleteCalled {
		t.Error("expected DELETE call, got none")
	}
}

func TestRevoke_EmptyCredentialID_FailsClosed(t *testing.T) {
	a, _ := pagerduty.New(pagerduty.Config{APIKey: fakeAPIKey, Email: fakeEmail})
	err := a.Revoke(context.Background(), adapter.RevokeRequest{ProviderID: "svc", CredentialID: ""})
	if err == nil {
		t.Fatal("expected error for empty credential_id")
	}
	if !strings.Contains(err.Error(), "credential_id is required") {
		t.Errorf("error should mention credential_id requirement, got: %v", err)
	}
}

func TestRevoke_AlreadyDeleted_IsIdempotent(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys/GONE": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		},
	})
	a := newAdapter(t, srv)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{
		ProviderID:   "svc",
		CredentialID: "GONE",
	})
	if err != nil {
		t.Fatalf("Revoke of already-deleted key should be idempotent, got: %v", err)
	}
}

func TestRevoke_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys/ERR123": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":{"message":"Internal error"}}`, http.StatusInternalServerError)
		},
	})
	a := newAdapter(t, srv)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{
		ProviderID:   "svc",
		CredentialID: "ERR123",
	})
	if err == nil {
		t.Fatal("expected error from PagerDuty 500, got nil")
	}
}

// ── Status ───────────────────────────────────────────────────────────────────

func TestStatus_Active(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(pdListResponse(fakeKeyID, "OTHER1"))
			}
		},
	})
	a := newAdapter(t, srv)
	status, err := a.Status(context.Background(), fakeKeyID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Active {
		t.Error("expected Active=true for existing key")
	}
	if status.CheckedAt.IsZero() {
		t.Error("CheckedAt must not be zero")
	}
}

func TestStatus_NotFound_Inactive(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(pdListResponse("OTHER1", "OTHER2"))
			}
		},
	})
	a := newAdapter(t, srv)
	status, err := a.Status(context.Background(), "MISSING123")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Active {
		t.Error("expected Active=false for non-existent key")
	}
}

func TestStatus_EmptyCredentialID(t *testing.T) {
	a, _ := pagerduty.New(pagerduty.Config{APIKey: fakeAPIKey, Email: fakeEmail})
	_, err := a.Status(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty credential_id")
	}
}

func TestStatus_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":{"message":"Forbidden"}}`, http.StatusForbidden)
		},
	})
	a := newAdapter(t, srv)
	_, err := a.Status(context.Background(), fakeKeyID)
	if err == nil {
		t.Fatal("expected error from PagerDuty 403, got nil")
	}
}

// ── Auth header guard ─────────────────────────────────────────────────────────

func TestRotate_SendsAuthAndFromHeaders(t *testing.T) {
	var gotAuth, gotFrom string
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				gotAuth = r.Header.Get("Authorization")
				gotFrom = r.Header.Get("From")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(pdCreateResponse("ts", fakeKeyVal))
			}
		},
	})

	a := newAdapter(t, srv)
	_, _ = a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "svc"})

	if gotAuth != "Token token="+fakeAPIKey {
		t.Errorf("Authorization = %q, want Token token=...", gotAuth)
	}
	if gotFrom != fakeEmail {
		t.Errorf("From = %q, want %q", gotFrom, fakeEmail)
	}
}
