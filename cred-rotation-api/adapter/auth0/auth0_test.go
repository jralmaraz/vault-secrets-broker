package auth0_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/auth0"
)

// newTestServer sets up an httptest server that stubs the Auth0 Management API.
// tokenResp is returned for /oauth/token; rotateResp for the rotate-secret path.
func newTestServer(t *testing.T, tokenResp, rotateResp interface{}) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenResp); err != nil {
			t.Errorf("encode token response: %v", err)
		}
	})

	mux.HandleFunc("/api/v2/clients/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(rotateResp); err != nil {
				t.Errorf("encode rotate response: %v", err)
			}
			return
		}
		// GET /api/v2/clients/{id} — status check
		w.WriteHeader(http.StatusOK)
	})

	return httptest.NewServer(mux)
}

func newAdapter(t *testing.T, srv *httptest.Server) *auth0.Adapter {
	t.Helper()
	a, err := auth0.New(auth0.Config{
		Domain:       "test.auth0.example",
		ClientID:     "mgmt-client-id",
		ClientSecret: "mgmt-client-secret",
		Audience:     "https://test.auth0.example/api/v2/",
	}, auth0.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("auth0.New: %v", err)
	}
	return a
}

func TestRotate_Success(t *testing.T) {
	tokenResp := map[string]interface{}{
		"access_token": "mgmt-access-token",
		"expires_in":   86400,
		"token_type":   "Bearer",
	}
	rotateResp := map[string]string{
		"client_id":     "app-client-id",
		"client_secret": "new-secret-value",
	}

	srv := newTestServer(t, tokenResp, rotateResp)
	defer srv.Close()

	a := newAdapter(t, srv)
	res, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "app-client-id"})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if res.Credential != "new-secret-value" {
		t.Errorf("credential: got %q, want %q", res.Credential, "new-secret-value")
	}
	if res.ProviderID != "app-client-id" {
		t.Errorf("provider_id: got %q, want %q", res.ProviderID, "app-client-id")
	}
	if res.RotatedAt.IsZero() {
		t.Error("RotatedAt should not be zero")
	}
}

func TestRotate_EmptySecret(t *testing.T) {
	tokenResp := map[string]interface{}{"access_token": "tok", "expires_in": 3600}
	rotateResp := map[string]string{"client_id": "id"} // missing client_secret

	srv := newTestServer(t, tokenResp, rotateResp)
	defer srv.Close()

	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "id"})
	if err == nil {
		t.Fatal("expected error on empty client_secret, got nil")
	}
}

func TestManagementToken_Cached(t *testing.T) {
	tokenCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		tokenCalls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "cached-token",
			"expires_in":   86400,
		})
	})
	mux.HandleFunc("/api/v2/clients/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"client_secret": "s"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	a := newAdapter(t, srv)
	for i := range 3 {
		_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "id"})
		if err != nil {
			t.Fatalf("Rotate iteration %d: %v", i, err)
		}
	}

	if tokenCalls != 1 {
		t.Errorf("token fetched %d times, expected 1 (should be cached)", tokenCalls)
	}
}

func TestRotate_TokenEndpointError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "id"})
	if err == nil {
		t.Fatal("expected error on token endpoint failure, got nil")
	}
}

func TestRevoke_NotSupported(t *testing.T) {
	srv := newTestServer(t,
		map[string]interface{}{"access_token": "tok", "expires_in": 3600},
		map[string]string{},
	)
	defer srv.Close()

	a := newAdapter(t, srv)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{ProviderID: "id"})
	if err == nil {
		t.Fatal("expected error from Revoke (not supported), got nil")
	}
}

func TestStatus_Active(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v2/clients/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	a := newAdapter(t, srv)
	status, err := a.Status(context.Background(), "app-client-id")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Active {
		t.Error("expected Active=true for 200 response")
	}
	if status.CheckedAt.IsZero() || status.CheckedAt.After(time.Now().Add(time.Second)) {
		t.Error("CheckedAt should be recent UTC time")
	}
}

func TestNew_MissingFields(t *testing.T) {
	_, err := auth0.New(auth0.Config{Domain: "d"}) // missing ClientID, ClientSecret, Audience
	if err == nil {
		t.Fatal("expected error on missing config fields, got nil")
	}
}
