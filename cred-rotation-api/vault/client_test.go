//go:build integration

// Integration tests require a live Vault dev server.
// Run with: make test-integration (which sets VAULT_ADDR and VAULT_TOKEN via .vault-env).
//
// Auth method tests (TestNew_AppRole_Integration, TestNew_JWT_Integration) configure
// their own mounts on the dev server using the root VAULT_TOKEN, then authenticate
// using each method to verify the full path through vault.New().
package vault_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	vclient "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/vault"
)

// rootClient returns a Vault API client authenticated as root (VAULT_TOKEN).
// Used by tests to configure mounts before testing non-root auth methods.
func rootClient(t *testing.T) *vaultapi.Client {
	t.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = envOr("VAULT_ADDR", "http://127.0.0.1:8200")
	vc, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("vaultapi.NewClient: %v", err)
	}
	vc.SetToken(os.Getenv("VAULT_TOKEN"))
	return vc
}

func newClient(t *testing.T) *vclient.Client {
	t.Helper()
	cfg := vclient.NewFromEnv()
	c, err := vclient.New(cfg)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return c
}

// ── Existing Transit / KV / PKI tests ────────────────────────────────────────

func TestTransitRoundTrip(t *testing.T) {
	skipIfNoVault(t)
	c := newClient(t)
	ctx := context.Background()

	const plaintext = "super-secret-credential-value"
	ct, err := c.TransitEncrypt(ctx, "cred-rotation-key", plaintext)
	if err != nil {
		t.Fatalf("TransitEncrypt: %v", err)
	}
	if ct == "" {
		t.Fatal("empty ciphertext")
	}

	recovered, err := c.TransitDecrypt(ctx, "cred-rotation-key", ct)
	if err != nil {
		t.Fatalf("TransitDecrypt: %v", err)
	}
	if recovered != plaintext {
		t.Errorf("round-trip mismatch: got %q, want %q", recovered, plaintext)
	}
}

func TestKVGet(t *testing.T) {
	skipIfNoVault(t)
	c := newClient(t)
	ctx := context.Background()

	data, err := c.KVGet(ctx, "secret/data/cred-rotation-api/adapters/auth0")
	if err != nil {
		t.Fatalf("KVGet: %v", err)
	}
	if _, ok := data["domain"]; !ok {
		t.Errorf("expected 'domain' field in KV data, got keys: %v", keysOf(data))
	}
}

func TestIssuePKICert(t *testing.T) {
	skipIfNoVault(t)
	c := newClient(t)
	ctx := context.Background()

	cert, err := c.IssuePKICert(ctx, "internal-mtls-server", "cred-rotation-api.internal", nil)
	if err != nil {
		t.Fatalf("IssuePKICert: %v", err)
	}
	if cert.Certificate == "" || cert.PrivateKey == "" {
		t.Error("expected non-empty Certificate and PrivateKey")
	}
}

// ── AppRole auth integration test ────────────────────────────────────────────

// TestNew_AppRole_Integration enables AppRole on the canonical mount (idempotent
// on a dev server), creates a scoped role, and calls vault.New() with AppRole
// credentials — verifying the full auth path through vclient.New.
func TestNew_AppRole_Integration(t *testing.T) {
	skipIfNoVault(t)

	rc := rootClient(t)

	// Enable AppRole (idempotent — dev server may already have it enabled).
	_ = rc.Sys().EnableAuthWithOptions("approle", &vaultapi.EnableAuthOptions{Type: "approle"})

	rolePath := "auth/approle/role/integ-vault-client"
	if _, err := rc.Logical().Write(rolePath, map[string]interface{}{
		"token_policies": "default",
		"secret_id_ttl":  "5m",
		"token_ttl":      "1m",
		"token_max_ttl":  "5m",
		"bind_secret_id": true,
	}); err != nil {
		t.Fatalf("create approle role: %v", err)
	}
	t.Cleanup(func() { _, _ = rc.Logical().Delete(rolePath) })

	roleIDSecret, err := rc.Logical().Read(rolePath + "/role-id")
	if err != nil || roleIDSecret == nil {
		t.Fatalf("read role-id: %v", err)
	}
	roleID, _ := roleIDSecret.Data["role_id"].(string)

	secretIDSecret, err := rc.Logical().Write(rolePath+"/secret-id", nil)
	if err != nil || secretIDSecret == nil {
		t.Fatalf("generate secret-id: %v", err)
	}
	secretID, _ := secretIDSecret.Data["secret_id"].(string)

	cfg := vclient.Config{
		Address:  envOr("VAULT_ADDR", "http://127.0.0.1:8200"),
		RoleID:   roleID,
		SecretID: secretID,
	}
	c, err := vclient.New(cfg)
	if err != nil {
		t.Fatalf("vault.New with AppRole: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client from AppRole auth")
	}
	t.Log("AppRole auth: OK")
}

// ── JWT/OIDC auth integration tests ──────────────────────────────────────────

// TestNew_JWT_Integration stands up a self-contained JWKS endpoint, configures
// Vault JWT auth against it, generates a signed ES256 token, and calls
// vault.New() with VAULT_JWT_TOKEN — no external OIDC provider required.
func TestNew_JWT_Integration(t *testing.T) {
	skipIfNoVault(t)

	rc := rootClient(t)
	privKey, kid := generateECKey(t)

	jwksSrv := newJWKSServer(t, &privKey.PublicKey, kid)

	mount := "jwt-integ-" + randSuffix(t)
	if err := rc.Sys().EnableAuthWithOptions(mount, &vaultapi.EnableAuthOptions{Type: "jwt"}); err != nil {
		t.Fatalf("enable jwt mount %q: %v", mount, err)
	}
	t.Cleanup(func() { _ = rc.Sys().DisableAuth(mount) })

	jwksURL := jwksSrv.URL + "/.well-known/jwks.json"
	if _, err := rc.Logical().Write(fmt.Sprintf("auth/%s/config", mount), map[string]interface{}{
		"jwks_url":           jwksURL,
		"jwt_supported_algs": []string{"ES256"},
	}); err != nil {
		t.Fatalf("configure jwt mount: %v", err)
	}

	const roleName = "integ-role"
	if _, err := rc.Logical().Write(fmt.Sprintf("auth/%s/role/%s", mount, roleName), map[string]interface{}{
		"role_type":       "jwt",
		"bound_audiences": []string{"vault-integ-test"},
		"user_claim":      "sub",
		"token_policies":  []string{"default"},
		"token_ttl":       "1m",
		"token_max_ttl":   "5m",
	}); err != nil {
		t.Fatalf("create jwt role: %v", err)
	}

	now := time.Now()
	token := mintES256JWT(t, privKey, kid, map[string]interface{}{
		"iss": jwksSrv.URL,
		"sub": "test-workload",
		"aud": []string{"vault-integ-test"},
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})

	cfg := vclient.Config{
		Address:      envOr("VAULT_ADDR", "http://127.0.0.1:8200"),
		JWTMountPath: fmt.Sprintf("auth/%s/login", mount),
		JWTRole:      roleName,
		JWTToken:     token,
	}
	c, err := vclient.New(cfg)
	if err != nil {
		t.Fatalf("vault.New with JWT: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil client from JWT auth")
	}
	t.Log("JWT/OIDC auth: OK")
}

// TestNew_JWT_ExpiredToken verifies Vault rejects an already-expired JWT.
func TestNew_JWT_ExpiredToken(t *testing.T) {
	skipIfNoVault(t)

	rc := rootClient(t)
	privKey, kid := generateECKey(t)
	jwksSrv := newJWKSServer(t, &privKey.PublicKey, kid)

	mount := "jwt-exp-" + randSuffix(t)
	if err := rc.Sys().EnableAuthWithOptions(mount, &vaultapi.EnableAuthOptions{Type: "jwt"}); err != nil {
		t.Fatalf("enable jwt mount: %v", err)
	}
	t.Cleanup(func() { _ = rc.Sys().DisableAuth(mount) })

	if _, err := rc.Logical().Write(fmt.Sprintf("auth/%s/config", mount), map[string]interface{}{
		"jwks_url":           jwksSrv.URL + "/.well-known/jwks.json",
		"jwt_supported_algs": []string{"ES256"},
	}); err != nil {
		t.Fatalf("configure jwt mount: %v", err)
	}
	if _, err := rc.Logical().Write(fmt.Sprintf("auth/%s/role/integ-role", mount), map[string]interface{}{
		"role_type":       "jwt",
		"bound_audiences": []string{"vault-integ-test"},
		"user_claim":      "sub",
		"token_policies":  []string{"default"},
		"token_ttl":       "1m",
	}); err != nil {
		t.Fatalf("create jwt role: %v", err)
	}

	// Token expired 10 minutes ago.
	past := time.Now().Add(-10 * time.Minute)
	expiredToken := mintES256JWT(t, privKey, kid, map[string]interface{}{
		"iss": jwksSrv.URL,
		"sub": "test-workload",
		"aud": []string{"vault-integ-test"},
		"iat": past.Unix(),
		"exp": past.Add(time.Minute).Unix(),
	})

	cfg := vclient.Config{
		Address:      envOr("VAULT_ADDR", "http://127.0.0.1:8200"),
		JWTMountPath: fmt.Sprintf("auth/%s/login", mount),
		JWTRole:      "integ-role",
		JWTToken:     expiredToken,
	}
	_, err := vclient.New(cfg)
	if err == nil {
		t.Fatal("expected error for expired JWT, got nil")
	}
	t.Logf("expired JWT correctly rejected: %v", err)
}

// TestNew_JWT_WrongAudience verifies Vault rejects a JWT with a non-matching audience.
func TestNew_JWT_WrongAudience(t *testing.T) {
	skipIfNoVault(t)

	rc := rootClient(t)
	privKey, kid := generateECKey(t)
	jwksSrv := newJWKSServer(t, &privKey.PublicKey, kid)

	mount := "jwt-aud-" + randSuffix(t)
	if err := rc.Sys().EnableAuthWithOptions(mount, &vaultapi.EnableAuthOptions{Type: "jwt"}); err != nil {
		t.Fatalf("enable jwt mount: %v", err)
	}
	t.Cleanup(func() { _ = rc.Sys().DisableAuth(mount) })

	if _, err := rc.Logical().Write(fmt.Sprintf("auth/%s/config", mount), map[string]interface{}{
		"jwks_url":           jwksSrv.URL + "/.well-known/jwks.json",
		"jwt_supported_algs": []string{"ES256"},
	}); err != nil {
		t.Fatalf("configure jwt mount: %v", err)
	}
	if _, err := rc.Logical().Write(fmt.Sprintf("auth/%s/role/integ-role", mount), map[string]interface{}{
		"role_type":       "jwt",
		"bound_audiences": []string{"vault-integ-test"},
		"user_claim":      "sub",
		"token_policies":  []string{"default"},
		"token_ttl":       "1m",
	}); err != nil {
		t.Fatalf("create jwt role: %v", err)
	}

	now := time.Now()
	wrongAudToken := mintES256JWT(t, privKey, kid, map[string]interface{}{
		"iss": jwksSrv.URL,
		"sub": "test-workload",
		"aud": []string{"wrong-audience"},
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	})

	cfg := vclient.Config{
		Address:      envOr("VAULT_ADDR", "http://127.0.0.1:8200"),
		JWTMountPath: fmt.Sprintf("auth/%s/login", mount),
		JWTRole:      "integ-role",
		JWTToken:     wrongAudToken,
	}
	_, err := vclient.New(cfg)
	if err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}
	t.Logf("wrong-audience JWT correctly rejected: %v", err)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func skipIfNoVault(t *testing.T) {
	t.Helper()
	if os.Getenv("VAULT_ADDR") == "" {
		t.Skip("VAULT_ADDR not set — skipping integration test")
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func keysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return fmt.Sprintf("%x", b)
}

func generateECKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	kid := fmt.Sprintf("integ-key-%x", b)
	return privKey, kid
}

// newJWKSServer stands up an httptest.Server that serves the public key as a JWKS.
func newJWKSServer(t *testing.T, pub *ecdsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC",
				"crv": "P-256",
				"kid": kid,
				"x":   base64.RawURLEncoding.EncodeToString(padTo32(pub.X)),
				"y":   base64.RawURLEncoding.EncodeToString(padTo32(pub.Y)),
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// mintES256JWT creates a minimal ES256 JWT signed with privKey.
// No external JWT library required — crypto/ecdsa + crypto/sha256 suffice.
func mintES256JWT(t *testing.T, privKey *ecdsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()

	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatalf("marshal jwt header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal jwt payload: %v", err)
	}

	sigInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(sigInput))

	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}

	// IEEE P1363: r || s, each padded to 32 bytes for P-256.
	sig := append(padTo32(r), padTo32(s)...)
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// padTo32 left-pads n.Bytes() to exactly 32 bytes (required for P-256 coordinates).
func padTo32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
