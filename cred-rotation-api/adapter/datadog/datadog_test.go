package datadog_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/datadog"
)

const (
	fakeAPIKey = "api-key-aaaa-bbbb-cccc-ddddeeeeeeee"
	fakeAppKey = "app-key-aaaa-bbbb-cccc-ddddeeeeeeee"
	fakeKeyID  = "00000000-0000-0000-0000-aabbccddeeff"
	fakeKeyVal = "secretkeyvalue1234567890abcdef"
)

// ddCreateResponse builds a minimal Datadog create response.
func ddCreateResponse(id, name, keyVal string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"data": map[string]interface{}{
			"id":   id,
			"type": "api_keys",
			"attributes": map[string]interface{}{
				"name":  name,
				"key":   keyVal,
				"last4": keyVal[len(keyVal)-4:],
			},
		},
	})
	return b
}

// ddGetResponse builds a minimal Datadog get response (no key value).
func ddGetResponse(id, name string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"data": map[string]interface{}{
			"id":   id,
			"type": "api_keys",
			"attributes": map[string]interface{}{
				"name":  name,
				"last4": "eeff",
			},
		},
	})
	return b
}

// newTestServer builds an httptest.Server from a "METHOD /path" → handler map.
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

// newAdapter creates a minimal Datadog adapter pointing at the given test server.
func newAdapter(t *testing.T, srv *httptest.Server, opts ...datadog.Option) *datadog.Adapter {
	t.Helper()
	opts = append([]datadog.Option{datadog.WithBaseURL(srv.URL)}, opts...)
	a, err := datadog.New(datadog.Config{
		AdminAPIKey: fakeAPIKey,
		AdminAppKey: fakeAppKey,
	}, opts...)
	if err != nil {
		t.Fatalf("datadog.New: %v", err)
	}
	return a
}

// ── Name ─────────────────────────────────────────────────────────────────────

func TestAdapter_Name(t *testing.T) {
	a, err := datadog.New(datadog.Config{AdminAPIKey: "x", AdminAppKey: "y"})
	if err != nil {
		t.Fatalf("datadog.New: %v", err)
	}
	if got := a.Name(); got != "datadog" {
		t.Errorf("Name() = %q, want %q", got, "datadog")
	}
}

// ── New — validation ─────────────────────────────────────────────────────────

func TestNew_MissingAdminAPIKey(t *testing.T) {
	_, err := datadog.New(datadog.Config{AdminAppKey: "y"})
	if err == nil {
		t.Fatal("expected error for missing AdminAPIKey")
	}
}

func TestNew_MissingAdminAppKey(t *testing.T) {
	_, err := datadog.New(datadog.Config{AdminAPIKey: "x"})
	if err == nil {
		t.Fatal("expected error for missing AdminAppKey")
	}
}

func TestNew_InvalidKeyType(t *testing.T) {
	_, err := datadog.New(datadog.Config{AdminAPIKey: "x", AdminAppKey: "y", KeyType: "bad_type"})
	if err == nil {
		t.Fatal("expected error for invalid KeyType")
	}
}

func TestNew_DefaultsToAPIKey(t *testing.T) {
	a, err := datadog.New(datadog.Config{AdminAPIKey: "x", AdminAppKey: "y"})
	if err != nil {
		t.Fatalf("datadog.New: %v", err)
	}
	// Internally it should use /api/v2/api_keys; we test indirectly through Rotate.
	_ = a
}

// ── Rotate ───────────────────────────────────────────────────────────────────

func TestRotate_Success(t *testing.T) {
	createCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			// Auth headers must be present.
			if r.Header.Get("DD-API-KEY") == "" || r.Header.Get("DD-APPLICATION-KEY") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			createCalled = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(ddCreateResponse(fakeKeyID, "prod-app-ts", fakeKeyVal))
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
	if result.Credential == fakeAPIKey || result.Credential == fakeAppKey {
		t.Error("Credential must not equal the management keys")
	}
	if result.CredentialID == "" {
		t.Error("expected non-empty CredentialID")
	}
	if result.ProviderID != "prod-app" {
		t.Errorf("ProviderID = %q, want %q", result.ProviderID, "prod-app")
	}
	if result.RotatedAt.IsZero() {
		t.Error("RotatedAt must not be zero")
	}
}

func TestRotate_NameContainsTimestampAndRandomSuffix(t *testing.T) {
	var capturedName string
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			var body struct {
				Data struct {
					Attributes struct {
						Name string `json:"name"`
					} `json:"attributes"`
				} `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			capturedName = body.Data.Attributes.Name
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(ddCreateResponse(fakeKeyID, capturedName, fakeKeyVal))
		},
	})

	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "svc"})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if !strings.HasPrefix(capturedName, "svc-") {
		t.Errorf("key name %q should start with provider ID prefix", capturedName)
	}
	// Format: svc-<timestamp>-<4hexchars>
	parts := strings.Split(capturedName, "-")
	if len(parts) < 3 {
		t.Errorf("key name %q should have at least 3 dash-separated parts", capturedName)
	}
	// Last part should be 4 hex characters (2 random bytes).
	lastPart := parts[len(parts)-1]
	if len(lastPart) != 4 {
		t.Errorf("random suffix %q should be 4 hex characters, got len=%d", lastPart, len(lastPart))
	}
}

func TestRotate_DeletesOldKey(t *testing.T) {
	deleteCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(ddCreateResponse(fakeKeyID, "svc-ts", fakeKeyVal))
			}
		},
		"/api/v2/api_keys/old-key-id-0000": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				deleteCalled = true
				w.WriteHeader(http.StatusNoContent)
			}
		},
	})

	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "svc",
		Meta:       map[string]string{"old_key_id": "old-key-id-0000"},
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
		"/api/v2/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(ddCreateResponse(fakeKeyID, "svc-ts", fakeKeyVal))
			}
		},
		"/api/v2/api_keys/old-key-id-fail": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				http.Error(w, `{"errors":["Internal Server Error"]}`, http.StatusInternalServerError)
			}
		},
	})

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	a := newAdapter(t, srv, datadog.WithLogger(logger))
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "svc",
		Meta:       map[string]string{"old_key_id": "old-key-id-fail"},
	})
	if err != nil {
		t.Fatalf("Rotate should succeed despite delete failure, got: %v", err)
	}

	logged := logBuf.String()
	if !strings.Contains(logged, "best-effort delete of old key failed") {
		t.Errorf("expected warning in log, got: %q", logged)
	}
	if !strings.Contains(logged, "old-key-id-fail") {
		t.Errorf("expected old key id in log, got: %q", logged)
	}
}

func TestRotate_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/api_keys": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"errors":["Forbidden"]}`, http.StatusForbidden)
		},
	})
	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "svc"})
	if err == nil {
		t.Fatal("expected error from Datadog 403, got nil")
	}
}

func TestRotate_MissingKeyValueInResponse(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/api_keys": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			// key value intentionally absent
			b, _ := json.Marshal(map[string]interface{}{
				"data": map[string]interface{}{
					"id":   fakeKeyID,
					"type": "api_keys",
					"attributes": map[string]interface{}{
						"name":  "svc-ts",
						"last4": "eeee",
					},
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

func TestRotate_AppKey_UsesCorrectEndpoint(t *testing.T) {
	createCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/application_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				createCalled = true
				b, _ := json.Marshal(map[string]interface{}{
					"data": map[string]interface{}{
						"id":   fakeKeyID,
						"type": "application_keys",
						"attributes": map[string]interface{}{
							"name":  "svc-ts",
							"key":   fakeKeyVal,
							"last4": "eeff",
						},
					},
				})
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(b)
			}
		},
	})

	a, err := datadog.New(datadog.Config{
		AdminAPIKey: fakeAPIKey,
		AdminAppKey: fakeAppKey,
		KeyType:     datadog.KeyTypeApp,
	}, datadog.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("datadog.New: %v", err)
	}
	_, err = a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "svc"})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !createCalled {
		t.Error("application_keys endpoint was not called")
	}
}

// ── Revoke ───────────────────────────────────────────────────────────────────

func TestRevoke_Success(t *testing.T) {
	deleteCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/api_keys/" + fakeKeyID: func(w http.ResponseWriter, r *http.Request) {
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
	a, _ := datadog.New(datadog.Config{AdminAPIKey: "x", AdminAppKey: "y"})
	err := a.Revoke(context.Background(), adapter.RevokeRequest{ProviderID: "svc", CredentialID: ""})
	if err == nil {
		t.Fatal("expected error for empty credential_id, got nil")
	}
	if !strings.Contains(err.Error(), "credential_id is required") {
		t.Errorf("error %q should mention credential_id requirement", err.Error())
	}
}

func TestRevoke_AlreadyDeleted_IsIdempotent(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/api_keys/gone-key-id": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		},
	})
	a := newAdapter(t, srv)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{
		ProviderID:   "svc",
		CredentialID: "gone-key-id",
	})
	if err != nil {
		t.Fatalf("Revoke of already-deleted key should be idempotent, got: %v", err)
	}
}

func TestRevoke_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/api_keys/some-key-id": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"errors":["Internal error"]}`, http.StatusInternalServerError)
		},
	})
	a := newAdapter(t, srv)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{
		ProviderID:   "svc",
		CredentialID: "some-key-id",
	})
	if err == nil {
		t.Fatal("expected error from Datadog 500, got nil")
	}
}

// ── Status ───────────────────────────────────────────────────────────────────

func TestStatus_Active(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/api_keys/" + fakeKeyID: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(ddGetResponse(fakeKeyID, "svc-ts"))
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
		"/api/v2/api_keys/missing-key": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		},
	})
	a := newAdapter(t, srv)
	status, err := a.Status(context.Background(), "missing-key")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Active {
		t.Error("expected Active=false for non-existent key")
	}
}

func TestStatus_EmptyCredentialID(t *testing.T) {
	a, _ := datadog.New(datadog.Config{AdminAPIKey: "x", AdminAppKey: "y"})
	_, err := a.Status(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty credential_id")
	}
}

func TestStatus_UnexpectedStatus_ReturnsError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/api_keys/some-key": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"errors":["Forbidden"]}`, http.StatusForbidden)
		},
	})
	a := newAdapter(t, srv)
	_, err := a.Status(context.Background(), "some-key")
	if err == nil {
		t.Fatal("expected error for unexpected status, got nil")
	}
}

// ── Auth header guard ─────────────────────────────────────────────────────────

func TestRotate_SendsAuthHeaders(t *testing.T) {
	var gotAPIKey, gotAppKey string
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/v2/api_keys": func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				gotAPIKey = r.Header.Get("DD-API-KEY")
				gotAppKey = r.Header.Get("DD-APPLICATION-KEY")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(ddCreateResponse(fakeKeyID, "svc-ts", fakeKeyVal))
			}
		},
	})

	a := newAdapter(t, srv)
	_, _ = a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "svc"})

	if gotAPIKey != fakeAPIKey {
		t.Errorf("DD-API-KEY = %q, want %q", gotAPIKey, fakeAPIKey)
	}
	if gotAppKey != fakeAppKey {
		t.Errorf("DD-APPLICATION-KEY = %q, want %q", gotAppKey, fakeAppKey)
	}
}
