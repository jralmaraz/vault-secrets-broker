package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vclient "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/vault"
)

// vaultAuthResponse returns a minimal Vault secret JSON with a client_token.
func vaultAuthResponse(token string) []byte {
	resp := map[string]interface{}{
		"auth": map[string]interface{}{
			"client_token":   token,
			"policies":       []string{"default"},
			"lease_duration": 3600,
			"renewable":      true,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

func TestNew_JWTAuth_Success(t *testing.T) {
	const wantToken = "s.jwtissued"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/v1/auth/jwt/login" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(vaultAuthResponse(wantToken))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := vclient.Config{
		Address:      srv.URL,
		JWTMountPath: "auth/jwt/login",
		JWTRole:      "ci-role",
		JWTToken:     "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig",
	}
	c, err := vclient.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNew_JWTAuth_EmptyMount(t *testing.T) {
	const wantToken = "s.defaultmount"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/v1/auth/jwt/login" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(vaultAuthResponse(wantToken))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := vclient.Config{
		Address:      srv.URL,
		JWTMountPath: "auth/jwt/login", // NewFromEnv default
		JWTToken:     "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig",
	}
	c, err := vclient.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNew_JWTAuth_VaultError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	}))
	defer srv.Close()

	cfg := vclient.Config{
		Address:      srv.URL,
		JWTMountPath: "auth/jwt/login",
		JWTToken:     "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig",
	}
	_, err := vclient.New(cfg)
	if err == nil {
		t.Fatal("expected error from Vault JWT auth, got nil")
	}
}

func TestNew_SPIFFE_AudienceRequired(t *testing.T) {
	cfg := vclient.Config{
		Address:      "http://127.0.0.1:8200",
		SPIFFESocket: "unix:///run/spire/agent.sock",
		// SPIFFEAudience intentionally empty
	}
	_, err := vclient.New(cfg)
	if err == nil {
		t.Fatal("expected error when SPIFFEAudience is empty, got nil")
	}
	want := "SPIFFE: audience is required"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error message %q does not contain %q", err.Error(), want)
	}
}

func TestNew_Priority_TokenBeatsJWT(t *testing.T) {
	// The mock server must NOT receive any JWT login call.
	jwtCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/jwt/login" {
			jwtCalled = true
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := vclient.Config{
		Address:      srv.URL,
		Token:        "dev-root-token",
		JWTMountPath: "auth/jwt/login",
		JWTToken:     "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig",
	}
	c, err := vclient.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if jwtCalled {
		t.Error("JWT auth endpoint was called despite VAULT_TOKEN being set")
	}
}
