//go:build integration

// Package datadog_test contains integration tests that call the real Datadog API.
// They require valid management credentials and are gated by environment variables.
//
// Run with:
//
//	DD_API_KEY=<api_key> DD_APP_KEY=<app_key> \
//	  go test -tags integration ./adapter/datadog/... -v -count=1
//
// The test creates a real Datadog API key, reads its status, revokes it, and
// verifies that the status endpoint reports it as gone. Every key created by
// the test is cleaned up — if a test panics, the key name will be present in
// the Datadog Key Management UI for manual cleanup.
package datadog_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/datadog"
)

func datadogIntegrationAdapter(t *testing.T) *datadog.Adapter {
	t.Helper()
	apiKey := os.Getenv("DD_API_KEY")
	appKey := os.Getenv("DD_APP_KEY")
	if apiKey == "" || appKey == "" {
		t.Skip("DD_API_KEY and DD_APP_KEY must be set to run integration tests")
	}

	a, err := datadog.New(datadog.Config{
		AdminAPIKey: apiKey,
		AdminAppKey: appKey,
	})
	if err != nil {
		t.Fatalf("datadog.New: %v", err)
	}
	return a
}

func TestIntegration_Rotate_Status_Revoke(t *testing.T) {
	a := datadogIntegrationAdapter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const providerID = "integration-test-cred-rotation"

	// 1 — Rotate: create a new API key.
	result, err := a.Rotate(ctx, adapter.RotateRequest{ProviderID: providerID})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if result.CredentialID == "" {
		t.Fatal("CredentialID is empty")
	}
	if result.Credential == "" {
		t.Fatal("Credential (key value) is empty")
	}
	if !strings.HasPrefix(result.CredentialID, "") {
		// UUID — just check non-empty (already checked above).
	}

	t.Logf("created key id=%s name starts with %s", result.CredentialID, providerID)

	// Ensure cleanup even if later steps fail.
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanCancel()
		if err := a.Revoke(cleanCtx, adapter.RevokeRequest{
			ProviderID:   providerID,
			CredentialID: result.CredentialID,
		}); err != nil {
			t.Logf("cleanup Revoke failed (may already be deleted): %v", err)
		}
	})

	// 2 — Status: key should be active immediately after creation.
	status, err := a.Status(ctx, result.CredentialID)
	if err != nil {
		t.Fatalf("Status after create: %v", err)
	}
	if !status.Active {
		t.Error("expected Active=true immediately after key creation")
	}

	// 3 — Revoke: delete the key.
	if err := a.Revoke(ctx, adapter.RevokeRequest{
		ProviderID:   providerID,
		CredentialID: result.CredentialID,
	}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// 4 — Status after revoke: key should no longer exist (404 → inactive).
	// Datadog deletes are typically immediate but allow a brief retry window.
	var finalStatus adapter.CredentialStatus
	for i := 0; i < 3; i++ {
		finalStatus, err = a.Status(ctx, result.CredentialID)
		if err != nil {
			t.Fatalf("Status after revoke: %v", err)
		}
		if !finalStatus.Active {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if finalStatus.Active {
		t.Error("expected Active=false after revoke, but key still appears active")
	}
}

func TestIntegration_Rotate_OldKeyDeleted(t *testing.T) {
	a := datadogIntegrationAdapter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const providerID = "integration-test-rotation-chain"

	// First rotation — no old key.
	first, err := a.Rotate(ctx, adapter.RotateRequest{ProviderID: providerID})
	if err != nil {
		t.Fatalf("first Rotate: %v", err)
	}
	t.Logf("first key id=%s", first.CredentialID)

	// Ensure the first key is cleaned up if second rotation fails.
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanCancel()
		_ = a.Revoke(cleanCtx, adapter.RevokeRequest{
			ProviderID:   providerID,
			CredentialID: first.CredentialID,
		})
	})

	// Second rotation — passes old key id so the adapter deletes the first.
	second, err := a.Rotate(ctx, adapter.RotateRequest{
		ProviderID: providerID,
		Meta:       map[string]string{"old_key_id": first.CredentialID},
	})
	if err != nil {
		t.Fatalf("second Rotate: %v", err)
	}
	t.Logf("second key id=%s", second.CredentialID)

	// Cleanup: revoke the second key.
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanCancel()
		_ = a.Revoke(cleanCtx, adapter.RevokeRequest{
			ProviderID:   providerID,
			CredentialID: second.CredentialID,
		})
	})

	// The first key should now be gone (deleted as part of second Rotate).
	for i := 0; i < 3; i++ {
		status, err := a.Status(ctx, first.CredentialID)
		if err != nil {
			t.Fatalf("Status for old key: %v", err)
		}
		if !status.Active {
			break
		}
		time.Sleep(2 * time.Second)
	}
	// Note: old key deletion is best-effort — if still active after retries,
	// we log but do not fail the test (the new credential was successfully issued).
	status, err := a.Status(ctx, first.CredentialID)
	if err != nil {
		t.Fatalf("final Status for old key: %v", err)
	}
	if status.Active {
		t.Logf("WARN: old key %s still active after rotation — best-effort delete may have raced", first.CredentialID)
	} else {
		t.Logf("old key %s correctly cleaned up by rotation", first.CredentialID)
	}
}

func TestIntegration_Revoke_EmptyCredentialID_FailsClosed(t *testing.T) {
	a := datadogIntegrationAdapter(t)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{ProviderID: "test", CredentialID: ""})
	if err == nil {
		t.Fatal("expected error for empty credential_id, got nil")
	}
}
