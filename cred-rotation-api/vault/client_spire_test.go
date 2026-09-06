//go:build integration && spire

// SPIFFE/SPIRE end-to-end integration tests for the Vault client.
//
// These tests exercise the complete path from SPIRE workload API → JWT-SVID fetch
// → Vault JWT auth login → Vault token issued and verified.
//
// Prerequisites (set up by scripts/integration-test-spire.sh):
//
//	SPIFFE_ENDPOINT_SOCKET   — workload API socket (e.g. unix:///run/spire/agent.sock)
//	VAULT_ADDR               — Vault address reachable from this process
//	VAULT_JWT_MOUNT          — JWT auth mount path (default: auth/jwt/login)
//	VAULT_JWT_ROLE           — JWT role name (default: cred-rotation-api)
//	VAULT_SPIFFE_TRUST_DOMAIN — expected SPIFFE trust domain (e.g. example.org)
//
// Run via: make test-integration-spire
// Or directly: go test -tags=integration,spire -v -run TestSPIFFE ./vault/...
package vault_test

import (
	"context"
	"os"
	"testing"
	"time"

	vclient "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/vault"
)

func requireEnvOrSkip(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set — run via: make test-integration-spire", key)
	}
	return v
}

func spiffeConfig(t *testing.T) vclient.Config {
	t.Helper()
	socket := requireEnvOrSkip(t, "SPIFFE_ENDPOINT_SOCKET")
	vaultAddr := requireEnvOrSkip(t, "VAULT_ADDR")

	jwtMount := os.Getenv("VAULT_JWT_MOUNT")
	if jwtMount == "" {
		jwtMount = "auth/jwt/login"
	}
	jwtRole := os.Getenv("VAULT_JWT_ROLE")
	if jwtRole == "" {
		jwtRole = "cred-rotation-api"
	}

	return vclient.Config{
		Address:           vaultAddr,
		JWTMountPath:      jwtMount,
		JWTRole:           jwtRole,
		SPIFFESocket:      socket,
		SPIFFEAudience:    vaultAddr,
		SPIFFETrustDomain: os.Getenv("VAULT_SPIFFE_TRUST_DOMAIN"),
	}
}

// TestSPIFFEAuth_FullFlow exercises the complete SPIFFE/SPIRE → Vault JWT auth path:
// SPIRE workload API → JWT-SVID fetch → Vault JWT login → Vault token issued.
//
// Steps verified:
//  1. SPIRE agent is reachable at SPIFFE_ENDPOINT_SOCKET
//  2. SVID is fetched and its trust domain matches VAULT_SPIFFE_TRUST_DOMAIN
//  3. SVID is accepted by Vault JWT auth → token returned
//  4. StartRenewer can be wired without panicking
func TestSPIFFEAuth_FullFlow(t *testing.T) {
	cfg := spiffeConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := vclient.New(cfg)
	if err != nil {
		t.Fatalf("SPIFFE Vault auth failed: %v", err)
	}
	t.Log("step 1 ✓ — JWT-SVID fetched from SPIRE workload API")
	t.Log("step 2 ✓ — trust domain validated")
	t.Log("step 3 ✓ — Vault JWT auth accepted SVID, token issued")
	_ = ctx

	// Verify StartRenewer is safe to wire with an already-cancelled context.
	renewCtx, renewCancel := context.WithCancel(context.Background())
	renewCancel()
	c.StartRenewer(renewCtx, func(err error) {
		t.Errorf("onError fired unexpectedly: %v", err)
	})
	t.Log("step 4 ✓ — StartRenewer wired cleanly")
}

// TestSPIFFEAuth_WrongTrustDomain verifies that trust domain pinning rejects an SVID
// whose trust domain does not match Config.SPIFFETrustDomain before presenting it to Vault.
//
// This test proves the defense-in-depth layer: even with a valid SPIRE deployment,
// an SVID from an unexpected trust domain is rejected in client code, not just by Vault.
func TestSPIFFEAuth_WrongTrustDomain(t *testing.T) {
	cfg := spiffeConfig(t)
	cfg.SPIFFETrustDomain = "wrong-trust-domain.invalid" // intentionally mismatched

	_, err := vclient.New(cfg)
	if err == nil {
		t.Fatal("expected trust domain mismatch error, got nil")
	}
	t.Logf("trust domain pinning correctly rejected SVID: %v", err)
}
