//go:build integration

// Integration tests require a live Vault dev server.
// Run with: make test-integration (which sets VAULT_ADDR and VAULT_TOKEN via .vault-env).
package vault_test

import (
	"context"
	"os"
	"testing"

	vclient "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/vault"
)

func newClient(t *testing.T) *vclient.Client {
	t.Helper()
	cfg := vclient.NewFromEnv()
	c, err := vclient.New(cfg)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return c
}

func TestTransitRoundTrip(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" {
		t.Skip("VAULT_ADDR not set — skipping integration test")
	}
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
	if os.Getenv("VAULT_ADDR") == "" {
		t.Skip("VAULT_ADDR not set — skipping integration test")
	}
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
	if os.Getenv("VAULT_ADDR") == "" {
		t.Skip("VAULT_ADDR not set — skipping integration test")
	}
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

func keysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
