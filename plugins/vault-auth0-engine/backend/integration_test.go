//go:build integration

// Integration tests for vault-auth0-engine.
// They call the real Auth0 Management API and (for transit tests) a live Vault instance.
//
// Required environment (load from .env before running):
//
//	AUTH0_DOMAIN              — tenant domain, e.g. example.au.auth0.com
//	AUTH0_MGMT_CLIENT_ID      — secrets-broker M2M app client_id
//	AUTH0_MGMT_CLIENT_SECRET  — secrets-broker M2M app client_secret  (NEVER commit)
//	AUTH0_MGMT_AUDIENCE       — Management API audience (default: https://<domain>/api/v2/)
//	AUTH0_TEST_APP_CLIENT_ID  — app-alpha client_id whose secret will be rotated
//
// Optional (Transit sub-test only):
//
//	VAULT_ADDR   — default http://127.0.0.1:8200
//	VAULT_TOKEN  — root/dev token; must have transit/encrypt+decrypt on auth0-engine-key
//
// WARNING: Rotating app-alpha's client_secret is destructive — the old secret is
// immediately invalidated by Auth0. Run against a dedicated test application only.
//
// Run with:
//
//	source .env && go test -tags=integration -v ./backend/ -run TestIntegration
package backend

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/logical"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// integrationEnv loads required env vars and skips the test if the secret is absent.
type integrationEnv struct {
	domain          string
	mgmtClientID    string
	mgmtClientSecret string
	audience        string
	appClientID     string
}

func loadIntegrationEnv(t *testing.T) integrationEnv {
	t.Helper()

	secret := os.Getenv("AUTH0_MGMT_CLIENT_SECRET")
	if secret == "" {
		t.Skip("AUTH0_MGMT_CLIENT_SECRET not set — skipping integration tests (source .env first)")
	}

	domain := os.Getenv("AUTH0_DOMAIN")
	if domain == "" {
		t.Fatal("AUTH0_DOMAIN is required when AUTH0_MGMT_CLIENT_SECRET is set")
	}

	audience := os.Getenv("AUTH0_MGMT_AUDIENCE")
	if audience == "" {
		audience = "https://" + domain + "/api/v2/"
	}

	mgmtClientID := os.Getenv("AUTH0_MGMT_CLIENT_ID")
	if mgmtClientID == "" {
		t.Fatal("AUTH0_MGMT_CLIENT_ID is required")
	}

	appClientID := os.Getenv("AUTH0_TEST_APP_CLIENT_ID")
	if appClientID == "" {
		t.Fatal("AUTH0_TEST_APP_CLIENT_ID is required (the app whose secret will be rotated)")
	}

	return integrationEnv{
		domain:           domain,
		mgmtClientID:     mgmtClientID,
		mgmtClientSecret: secret,
		audience:         audience,
		appClientID:      appClientID,
	}
}

// newIntegrationBackend creates a backend wired with real Auth0 credentials.
func newIntegrationBackend(t *testing.T, env integrationEnv, transitKey string) (logical.Backend, logical.Storage) {
	t.Helper()
	storage := &logical.InmemStorage{}
	b, err := Factory(context.Background(), &logical.BackendConfig{StorageView: storage})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	cfg := map[string]interface{}{
		"domain":        env.domain,
		"client_id":     env.mgmtClientID,
		"client_secret": env.mgmtClientSecret,
		"audience":      env.audience,
		"transit_key":   transitKey,
	}
	entry, err := logical.StorageEntryJSON("config/connection", cfg)
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}
	if err := storage.Put(context.Background(), entry); err != nil {
		t.Fatalf("store config: %v", err)
	}
	return b, storage
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestIntegration_Status verifies the M2M token flow and that app-alpha is reachable.
// This is read-only — nothing is modified.
func TestIntegration_Status(t *testing.T) {
	env := loadIntegrationEnv(t)
	b, storage := newIntegrationBackend(t, env, "")

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "status/" + env.appClientID,
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}

	active, _ := resp.Data["active"].(bool)
	if !active {
		t.Fatalf("expected app %s to be active; got data=%v", env.appClientID, resp.Data)
	}
	t.Logf("app-alpha status: active=%v checked_at=%v", resp.Data["active"], resp.Data["checked_at"])
}

// TestIntegration_Rotate rotates app-alpha's client_secret without Transit encryption.
// The test verifies:
//  1. Rotation succeeds and returns a non-empty credential.
//  2. A second rotation also succeeds — proving Auth0 accepted and stored the first one.
//  3. The two returned secrets differ (each rotation produces a new secret).
//
// NOTE: both rotations invalidate the previous secret. Run against a test-only app.
func TestIntegration_Rotate(t *testing.T) {
	env := loadIntegrationEnv(t)
	b, storage := newIntegrationBackend(t, env, "") // no transit_key

	rotate := func(label string) string {
		t.Helper()
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + env.appClientID,
			Storage:   storage,
		}
		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("%s HandleRequest: %v", label, err)
		}
		if resp == nil || resp.IsError() {
			t.Fatalf("%s unexpected error response: %v", label, resp)
		}

		secret, _ := resp.Data["credential"].(string)
		if secret == "" {
			t.Fatalf("%s: empty credential in response data=%v", label, resp.Data)
		}
		if len(secret) < 32 {
			t.Fatalf("%s: credential suspiciously short (%d chars)", label, len(secret))
		}

		ts, _ := resp.Data["rotated_at"].(string)
		t.Logf("%s: rotated_at=%s credential_len=%d", label, ts, len(secret))
		return secret
	}

	secret1 := rotate("rotation-1")
	// Brief pause so Auth0 propagation is complete before the second call.
	time.Sleep(500 * time.Millisecond)
	secret2 := rotate("rotation-2")

	if secret1 == secret2 {
		t.Fatal("rotation-1 and rotation-2 returned identical secrets — rotation may not have taken effect")
	}
	t.Log("secrets differ between rotations: PASS")
}

// TestIntegration_RotateWithTransit rotates app-alpha with transit_key set.
// The returned value is a vault:v1:... ciphertext; the test decrypts it using the
// Vault API and verifies the plaintext is a plausible Auth0 client_secret.
//
// Requires VAULT_ADDR and VAULT_TOKEN in the environment, plus the auth0-engine-key
// transit key to exist (make setup && make setup-phase4 creates it).
func TestIntegration_RotateWithTransit(t *testing.T) {
	env := loadIntegrationEnv(t)

	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		t.Skip("VAULT_TOKEN not set — skipping transit sub-test (run: make setup && make setup-phase4)")
	}
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8200"
	}

	const transitKeyName = "auth0-engine-key"

	// Ensure the transit key exists.
	ensureTransitKey(t, vaultAddr, vaultToken, transitKeyName)

	b, storage := newIntegrationBackend(t, env, transitKeyName)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + env.appClientID,
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}

	// With transit_key set, the response must have credential_ciphertext, NOT credential.
	if _, hasPlaintext := resp.Data["credential"]; hasPlaintext {
		t.Fatal("plaintext credential must NOT be present when transit_key is configured")
	}
	ciphertext, _ := resp.Data["credential_ciphertext"].(string)
	if ciphertext == "" {
		t.Fatalf("credential_ciphertext missing from response: %v", resp.Data)
	}
	if !strings.HasPrefix(ciphertext, "vault:v") {
		t.Fatalf("expected vault:v... ciphertext, got: %s", ciphertext[:min(40, len(ciphertext))])
	}
	returnedKey, _ := resp.Data["transit_key"].(string)
	if returnedKey != transitKeyName {
		t.Fatalf("transit_key in response %q != configured %q", returnedKey, transitKeyName)
	}
	t.Logf("ciphertext prefix: %s...", ciphertext[:min(20, len(ciphertext))])

	// Decrypt and verify the plaintext is a plausible Auth0 client_secret.
	plaintext := transitDecryptDirect(t, vaultAddr, vaultToken, transitKeyName, ciphertext)
	if len(plaintext) < 32 {
		t.Fatalf("decrypted credential suspiciously short (%d chars)", len(plaintext))
	}
	t.Logf("Transit decrypt: PASS — plaintext len=%d", len(plaintext))
}

// TestIntegration_ReadConfig_HidesSecret verifies that a vault read on config/connection
// never leaks the management client_secret.
func TestIntegration_ReadConfig_HidesSecret(t *testing.T) {
	env := loadIntegrationEnv(t)
	b, storage := newIntegrationBackend(t, env, "")

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/connection",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error: %v", resp)
	}
	if _, ok := resp.Data["client_secret"]; ok {
		t.Fatal("SECURITY: client_secret must never appear in config read response")
	}
	// Also check the secret value isn't accidentally stored in some other field.
	for k, v := range resp.Data {
		if s, ok := v.(string); ok && s == env.mgmtClientSecret {
			t.Fatalf("SECURITY: mgmt client_secret leaked in field %q", k)
		}
	}
	t.Logf("config read response fields: %v", keySet(resp.Data))
}

// TestIntegration_RotateRoot rotates the M2M app's OWN client_secret (the secrets-broker
// management application), mirroring the Vault database root-rotation pattern.
//
// After this call:
//   - The original client_secret is permanently invalidated by Auth0.
//   - Only Vault's seal-wrapped config storage holds the new secret.
//   - The test verifies the updated stored secret can obtain a fresh Management API token,
//     proving Auth0 accepted the rotation.
//
// NOTE: This modifies the M2M app's secret. Ensure AUTH0_MGMT_CLIENT_ID is a
// dedicated secrets-broker M2M app, not shared with other systems.
func TestIntegration_RotateRoot(t *testing.T) {
	env := loadIntegrationEnv(t)
	b, storage := newIntegrationBackend(t, env, "")

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("rotate-root HandleRequest: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}

	// Response must not include the new secret.
	if _, ok := resp.Data["client_secret"]; ok {
		t.Fatal("SECURITY: new client_secret must never appear in rotate-root response")
	}
	t.Logf("rotate-root response: %v", resp.Data)

	// Verify the new secret works: read updated config from storage, build a new
	// auth0Client, and fetch a management token successfully.
	updatedCfg, err := getConfig(context.Background(), storage)
	if err != nil || updatedCfg == nil {
		t.Fatalf("read updated config: %v", err)
	}

	newSecret, _ := updatedCfg["client_secret"].(string)
	if newSecret == "" {
		t.Fatal("stored client_secret is empty after rotate-root")
	}
	if newSecret == env.mgmtClientSecret {
		t.Fatal("stored secret unchanged after rotate-root — rotation may have failed silently")
	}

	// The new secret must be able to obtain a Management API token.
	client := newAuth0Client(env.domain, env.mgmtClientID, newSecret, env.audience)
	tok, err := client.managementToken(context.Background())
	if err != nil {
		t.Fatalf("management token with new secret: %v — rotation stored an invalid secret", err)
	}
	if tok == "" {
		t.Fatal("management token empty after rotate-root")
	}
	t.Logf("rotate-root: PASS — new secret authenticates successfully (token len=%d)", len(tok))
}

// TestIntegration_ManagementTokenCache verifies the token is cached across calls.
func TestIntegration_ManagementTokenCache(t *testing.T) {
	env := loadIntegrationEnv(t)

	client := newAuth0Client(env.domain, env.mgmtClientID, env.mgmtClientSecret, env.audience)

	ctx := context.Background()
	tok1, err := client.managementToken(ctx)
	if err != nil {
		t.Fatalf("first token fetch: %v", err)
	}
	tok2, err := client.managementToken(ctx)
	if err != nil {
		t.Fatalf("second token fetch: %v", err)
	}
	if tok1 != tok2 {
		t.Fatal("expected cached token to be reused on second call")
	}
	t.Logf("token caching: PASS (token len=%d)", len(tok1))
}

// ── internal helpers ──────────────────────────────────────────────────────────

// ensureTransitKey creates the Transit key if it does not exist yet.
func ensureTransitKey(t *testing.T, addr, token, keyName string) {
	t.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	vc, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	vc.SetToken(token)

	// POST is idempotent when the key already exists (returns 204).
	_, err = vc.Logical().Write(fmt.Sprintf("transit/keys/%s", keyName),
		map[string]interface{}{"type": "aes256-gcm96"})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("ensure transit key %q: %v", keyName, err)
	}
}

// transitDecryptDirect decrypts a vault:v1:... ciphertext directly via the Vault API.
func transitDecryptDirect(t *testing.T, addr, token, keyName, ciphertext string) string {
	t.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	vc, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	vc.SetToken(token)

	secret, err := vc.Logical().Write(fmt.Sprintf("transit/decrypt/%s", keyName),
		map[string]interface{}{"ciphertext": ciphertext})
	if err != nil {
		t.Fatalf("transit/decrypt: %v", err)
	}
	if secret == nil {
		t.Fatal("transit/decrypt: nil response")
	}

	encoded, _ := secret.Data["plaintext"].(string)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode plaintext: %v", err)
	}
	return string(raw)
}

// keySet returns the keys of a map for logging (no values, to avoid leaking secrets).
func keySet(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// verifyAuth0Reachable is a lightweight sanity check: GET /api/v2/ with no auth
// should return 401, not a connection error.
func verifyAuth0Reachable(t *testing.T, domain string) {
	t.Helper()
	url := "https://" + domain + "/api/v2/"
	resp, err := http.Get(url) //nolint:noctx // one-shot probe, no ctx needed
	if err != nil {
		t.Fatalf("Auth0 not reachable at %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Logf("unexpected status from /api/v2/ probe: %d (expected 401)", resp.StatusCode)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
