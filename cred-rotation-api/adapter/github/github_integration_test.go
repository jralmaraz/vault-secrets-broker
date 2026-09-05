//go:build integration

// Integration tests for the GitHub fine-grained PAT adapter.
//
// Requirements:
//   - GITHUB_ADMIN_PAT: a fine-grained PAT (or classic PAT) with
//     the personal_access_tokens:write permission (or admin:personal_access_tokens).
//   - GITHUB_BASE_URL (optional): override for GitHub Enterprise Server.
//
// Each test creates real fine-grained PATs on GitHub and cleans them up via t.Cleanup.
// Tests are skipped unless GITHUB_ADMIN_PAT is set.
//
// Run locally: GITHUB_ADMIN_PAT=<pat> go test -tags=integration -v ./adapter/github/...
package github_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	githubadapter "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/github"
)

func skipIfNoGitHubPAT(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ADMIN_PAT") == "" {
		t.Skip("GITHUB_ADMIN_PAT not set — skipping GitHub integration tests")
	}
}

func newIntegrationAdapter(t *testing.T) *githubadapter.Adapter {
	t.Helper()
	cfg := githubadapter.Config{
		AdminPAT: os.Getenv("GITHUB_ADMIN_PAT"),
		BaseURL:  os.Getenv("GITHUB_BASE_URL"), // empty → defaults to api.github.com
	}
	a, err := githubadapter.New(cfg)
	if err != nil {
		t.Fatalf("githubadapter.New: %v", err)
	}
	return a
}

// TestGitHub_RotateRevoke_Integration exercises the full lifecycle:
// create → status (active) → rotate-with-old-delete → status (gone) → revoke new.
func TestGitHub_RotateRevoke_Integration(t *testing.T) {
	skipIfNoGitHubPAT(t)
	a := newIntegrationAdapter(t)
	ctx := context.Background()
	providerID := "vsb-integ-test"

	// Step 1 — create a new fine-grained PAT.
	t.Logf("Step 1: creating initial PAT for provider %q", providerID)
	result1, err := a.Rotate(ctx, adapter.RotateRequest{
		ProviderID: providerID,
		Meta: map[string]string{
			"expires_days": "1",
			// No permissions → read-only public repos (safest for CI)
		},
	})
	if err != nil {
		t.Fatalf("Rotate (initial): %v", err)
	}
	if result1.Credential == "" || !strings.HasPrefix(result1.Credential, "github_pat_") {
		t.Fatalf("unexpected token value %q — expected github_pat_ prefix", result1.Credential)
	}
	t.Logf("Step 1: token ID=%s created (last 4: ...%s)",
		result1.CredentialID, result1.Credential[len(result1.Credential)-4:])

	// Register cleanup: delete the first token if the test fails before step 4.
	id1 := result1.CredentialID
	t.Cleanup(func() {
		_ = a.Revoke(ctx, adapter.RevokeRequest{ProviderID: providerID, CredentialID: id1})
	})

	// Step 2 — Status should report active.
	t.Logf("Step 2: checking status of token %s", id1)
	cs1, err := a.Status(ctx, id1)
	if err != nil {
		t.Fatalf("Status (initial): %v", err)
	}
	if !cs1.Active {
		t.Fatalf("expected newly created token to be active, got active=%v", cs1.Active)
	}
	t.Logf("Step 2: token %s active=%v checked_at=%s", id1, cs1.Active, cs1.CheckedAt.Format(time.RFC3339))

	// Step 3 — Rotate again, passing old_token_id so the first token gets deleted.
	t.Logf("Step 3: rotating (creating token2, deleting token1 %s)", id1)
	result2, err := a.Rotate(ctx, adapter.RotateRequest{
		ProviderID: providerID,
		Meta: map[string]string{
			"expires_days": "1",
			"old_token_id": id1,
		},
	})
	if err != nil {
		t.Fatalf("Rotate (second): %v", err)
	}
	id2 := result2.CredentialID
	t.Logf("Step 3: token2 ID=%s created", id2)

	// Register cleanup for id2.
	t.Cleanup(func() {
		_ = a.Revoke(ctx, adapter.RevokeRequest{ProviderID: providerID, CredentialID: id2})
	})

	// Step 4 — The old token should now be gone.
	t.Logf("Step 4: checking that old token %s is gone", id1)
	cs1After, err := a.Status(ctx, id1)
	if err != nil {
		t.Fatalf("Status (old token after rotation): %v", err)
	}
	if cs1After.Active {
		t.Errorf("old token %s should be inactive after rotation, got active=true", id1)
	}
	t.Logf("Step 4: old token %s active=%v (expected false)", id1, cs1After.Active)

	// Step 5 — New token should be active.
	t.Logf("Step 5: checking status of new token %s", id2)
	cs2, err := a.Status(ctx, id2)
	if err != nil {
		t.Fatalf("Status (new token): %v", err)
	}
	if !cs2.Active {
		t.Errorf("new token %s should be active, got active=false", id2)
	}
	t.Logf("Step 5: token %s active=%v", id2, cs2.Active)

	// Step 6 — Revoke the new token explicitly.
	t.Logf("Step 6: revoking new token %s", id2)
	if err := a.Revoke(ctx, adapter.RevokeRequest{ProviderID: providerID, CredentialID: id2}); err != nil {
		t.Fatalf("Revoke (new token): %v", err)
	}
	cs2After, err := a.Status(ctx, id2)
	if err != nil {
		t.Fatalf("Status (after revoke): %v", err)
	}
	if cs2After.Active {
		t.Errorf("revoked token %s should be inactive, got active=true", id2)
	}
	t.Logf("Step 6: token %s active=%v after revoke (expected false)", id2, cs2After.Active)
}

func TestGitHub_Revoke_EmptyCredentialID_Integration(t *testing.T) {
	skipIfNoGitHubPAT(t)
	a := newIntegrationAdapter(t)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{CredentialID: ""})
	if err == nil {
		t.Fatal("expected error for empty credential_id")
	}
}
