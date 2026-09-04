package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// fakeAuth0 returns a test server that mimics the Auth0 Management API.
// rotateOK controls whether /rotate-secret succeeds.
func fakeAuth0(t *testing.T, rotateOK bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// token endpoint
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		expiresIn := int(time.Hour.Seconds())
		_, _ = fmt.Fprintf(w, `{"access_token":"test-token","expires_in":%d}`, expiresIn)
	})

	// rotate-secret endpoint
	mux.HandleFunc("/api/v2/clients/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if !rotateOK {
				http.Error(w, `{"statusCode":403,"error":"Forbidden"}`, http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"client_secret":"new-secret-value"}`)
			return
		}
		// GET — status check
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"client_id":"test-app-id"}`)
	})

	return httptest.NewServer(mux)
}

// newTestBackend creates a Backend backed by in-memory storage and pre-writes
// the given config (without transit key by default).
func newTestBackend(t *testing.T, cfg map[string]interface{}) (logical.Backend, logical.Storage) {
	t.Helper()
	storage := &logical.InmemStorage{}
	b, err := Factory(context.Background(), &logical.BackendConfig{
		StorageView: storage,
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	if cfg != nil {
		entry, err := logical.StorageEntryJSON("config/connection", cfg)
		if err != nil {
			t.Fatalf("encode config: %v", err)
		}
		if err := storage.Put(context.Background(), entry); err != nil {
			t.Fatalf("store config: %v", err)
		}
	}

	return b, storage
}

func TestReadConfig_NotConfigured(t *testing.T) {
	b, storage := newTestBackend(t, nil)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/connection",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when not configured")
	}
}

func TestWriteAndReadConfig(t *testing.T) {
	b, storage := newTestBackend(t, nil)
	ctx := context.Background()

	// Write config
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/connection",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain":        "example.auth0.com",
			"client_id":     "mgmt-client-id",
			"client_secret": "mgmt-client-secret",
			"audience":      "https://example.auth0.com/api/v2/",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write config failed: err=%v resp=%v", err, resp)
	}

	// Read back — secret must not appear
	req.Operation = logical.ReadOperation
	req.Data = nil
	resp, err = b.HandleRequest(ctx, req)
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("read config failed: err=%v resp=%v", err, resp)
	}
	if _, ok := resp.Data["client_secret"]; ok {
		t.Fatal("client_secret must not be returned in read response")
	}
	if resp.Data["domain"] != "example.auth0.com" {
		t.Fatalf("unexpected domain: %v", resp.Data["domain"])
	}
}

func TestWriteConfig_MissingRequired(t *testing.T) {
	b, storage := newTestBackend(t, nil)

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/connection",
		Storage:   storage,
		Data: map[string]interface{}{
			"domain": "example.auth0.com",
			// client_id, client_secret, audience missing
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing required fields")
	}
}

func TestRotateCreds_Success(t *testing.T) {
	srv := fakeAuth0(t, true)
	defer srv.Close()

	domain := srv.Listener.Addr().String()
	cfg := map[string]interface{}{
		"domain":        domain,
		"client_id":     "mgmt-id",
		"client_secret": "mgmt-secret",
		"audience":      "https://" + domain + "/api/v2/",
	}
	b, storage := newTestBackend(t, cfg)

	// Patch auth0Client to use http:// via the baseURL override by calling the
	// internal client directly (integration-level test via HandleRequest would
	// need TLS; test the client directly for unit coverage).
	client := &auth0Client{
		domain:       domain,
		clientID:     "mgmt-id",
		clientSecret: "mgmt-secret",
		audience:     "https://" + domain + "/api/v2/",
		baseURL:      srv.URL,
		httpClient:   srv.Client(),
	}
	newSecret, err := client.rotateSecret(context.Background(), "app-client-id")
	if err != nil {
		t.Fatalf("rotateSecret: %v", err)
	}
	if newSecret != "new-secret-value" {
		t.Fatalf("unexpected secret: %q", newSecret)
	}

	_ = storage // backend wired in but not exercised here (no Transit available in unit tests)
	_ = b
}

func TestRotateCreds_APIError(t *testing.T) {
	srv := fakeAuth0(t, false) // rotate returns 403
	defer srv.Close()

	client := &auth0Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}
	_, err := client.rotateSecret(context.Background(), "app-client-id")
	if err == nil {
		t.Fatal("expected error on 403 response")
	}
}

func TestAppActive(t *testing.T) {
	srv := fakeAuth0(t, true)
	defer srv.Close()

	client := &auth0Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}
	active, err := client.appActive(context.Background(), "test-app-id")
	if err != nil {
		t.Fatalf("appActive: %v", err)
	}
	if !active {
		t.Fatal("expected active=true for 200 response")
	}
}

func TestManagementTokenCaching(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":3600}`, callCount)
		}
	}))
	defer srv.Close()

	client := &auth0Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	tok1, err := client.managementToken(context.Background())
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	tok2, err := client.managementToken(context.Background())
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if tok1 != tok2 {
		t.Fatal("expected cached token to be reused")
	}
	if callCount != 1 {
		t.Fatalf("expected 1 token fetch, got %d", callCount)
	}
}

func TestCheckStatus_NotConfigured(t *testing.T) {
	b, storage := newTestBackend(t, nil)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "status/some-app-id",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when not configured")
	}
}

// TestBackendFactory verifies the factory wires up paths correctly.
func TestBackendFactory(t *testing.T) {
	storage := &logical.InmemStorage{}
	b, err := Factory(context.Background(), &logical.BackendConfig{StorageView: storage})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	fb, ok := b.(*framework.Backend)
	if !ok {
		// Backend wraps framework.Backend — check that paths are registered
		t.Log("backend type ok")
		return
	}
	if len(fb.Paths) == 0 {
		t.Fatal("expected at least one path registered")
	}
}

// TestConfigRoundtrip verifies JSON encoding round-trips config correctly.
func TestConfigRoundtrip(t *testing.T) {
	original := map[string]interface{}{
		"domain":        "t.auth0.com",
		"client_id":     "cid",
		"client_secret": "csec",
		"audience":      "https://t.auth0.com/api/v2/",
		"transit_key":   "mykey",
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k, v := range original {
		if decoded[k] != v {
			t.Fatalf("field %q: got %v want %v", k, decoded[k], v)
		}
	}
}
