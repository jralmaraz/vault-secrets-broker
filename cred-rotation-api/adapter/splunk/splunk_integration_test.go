//go:build integration

// Splunk integration tests require a running Splunk instance.
//
// Local:
//
//	docker run -d -p 8089:8089 -p 8088:8088 \
//	  -e SPLUNK_START_ARGS=--accept-license \
//	  -e SPLUNK_PASSWORD=changeme \
//	  splunk/splunk:latest
//	SPLUNK_BASE_URL=https://localhost:8089 SPLUNK_AUTH_TOKEN=admin:changeme \
//	  go test -tags=integration -v -run TestSplunk ./adapter/splunk/...
//
// CI: uses the splunk/splunk Docker service defined in integration.yml.
// SPLUNK_AUTH_TOKEN may be "user:password" (Basic) or a Splunk management token (Bearer).
// Set SPLUNK_INSECURE=true to skip TLS verification against the Docker self-signed cert.
package splunk_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/splunk"
)

// splunkIntegClient builds an Adapter for integration tests, authenticating
// via a temporary session token exchanged from SPLUNK_AUTH_TOKEN (user:pass or bearer).
func splunkIntegClient(t *testing.T) *splunk.Adapter {
	t.Helper()
	baseURL := os.Getenv("SPLUNK_BASE_URL")
	if baseURL == "" {
		t.Skip("SPLUNK_BASE_URL not set — skipping Splunk integration test")
	}
	rawCred := os.Getenv("SPLUNK_AUTH_TOKEN")
	if rawCred == "" {
		t.Skip("SPLUNK_AUTH_TOKEN not set — skipping Splunk integration test")
	}

	// Exchange user:pass for a session token so we don't store the password in the adapter.
	authToken, err := splunkSessionToken(baseURL, rawCred)
	if err != nil {
		t.Fatalf("obtain Splunk session token: %v", err)
	}

	a, err := splunk.New(splunk.Config{
		BaseURL:           baseURL,
		AuthToken:         authToken,
		DefaultIndex:      "main",
		DefaultSourcetype: "_json",
	}, splunk.WithBaseURL(baseURL))
	if err != nil {
		t.Fatalf("splunk.New: %v", err)
	}
	return a
}

// splunkSessionToken exchanges "user:pass" for a Splunk session token via /services/auth/login.
// If rawCred doesn't contain ":", it's assumed to be a bearer token already.
func splunkSessionToken(baseURL, rawCred string) (string, error) {
	if !strings.Contains(rawCred, ":") {
		return rawCred, nil // already a bearer token
	}
	parts := strings.SplitN(rawCred, ":", 2)

	insecure := os.Getenv("SPLUNK_INSECURE") == "true"
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: insecure, //nolint:gosec // only for local Docker integration tests, never production
			},
		},
	}

	form := fmt.Sprintf("username=%s&password=%s&output_mode=json",
		parts[0], parts[1])
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost,
		baseURL+"/services/auth/login",
		strings.NewReader(form),
	)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Basic auth as fallback for session endpoint.
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(rawCred)))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth/login: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth/login: status %d", resp.StatusCode)
	}

	// Return Basic auth header value for simplicity — Splunk accepts it on all management endpoints.
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(rawCred)), nil
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestSplunk_RotateRevoke_Integration(t *testing.T) {
	a := splunkIntegClient(t)
	ctx := context.Background()

	providerID := fmt.Sprintf("integ-test-%d", time.Now().UnixMilli())
	t.Logf("=== Splunk HEC token lifecycle test: providerID=%s ===", providerID)

	// Step 1: Rotate creates a new token.
	t0 := time.Now()
	result, err := a.Rotate(ctx, adapter.RotateRequest{ProviderID: providerID})
	if err != nil {
		t.Fatalf("Step 1 — Rotate: %v", err)
	}
	if result.Credential == "" {
		t.Fatal("Step 1 — Rotate returned empty Credential")
	}
	if result.CredentialID == "" {
		t.Fatal("Step 1 — Rotate returned empty CredentialID")
	}
	t.Logf("Step 1 PASS — Rotate: created token name=%q credential_len=%d rotated_at=%s elapsed=%s",
		result.CredentialID, len(result.Credential), result.RotatedAt.Format(time.RFC3339), time.Since(t0).Round(time.Millisecond))

	// Step 2: Status shows the new token is active.
	t1 := time.Now()
	st1, err := a.Status(ctx, result.CredentialID)
	if err != nil {
		t.Fatalf("Step 2 — Status after rotate: %v", err)
	}
	if !st1.Active {
		t.Error("Step 2 FAIL — expected Active=true for newly created token")
	}
	t.Logf("Step 2 PASS — Status: token=%q active=%v elapsed=%s",
		result.CredentialID, st1.Active, time.Since(t1).Round(time.Millisecond))

	// Step 3: Second Rotate with old_token_name deletes the first.
	t2 := time.Now()
	result2, err := a.Rotate(ctx, adapter.RotateRequest{
		ProviderID: providerID,
		Meta:       map[string]string{"old_token_name": result.CredentialID},
	})
	if err != nil {
		t.Fatalf("Step 3 — second Rotate: %v", err)
	}
	t.Logf("Step 3 PASS — Rotate (with old deletion): new=%q old=%q elapsed=%s",
		result2.CredentialID, result.CredentialID, time.Since(t2).Round(time.Millisecond))

	// Step 4: Old token is gone (deleted during rotation).
	t3 := time.Now()
	oldSt, err := a.Status(ctx, result.CredentialID)
	if err != nil {
		t.Fatalf("Step 4 — Status of old token: %v", err)
	}
	if oldSt.Active {
		t.Errorf("Step 4 FAIL — old token %q should be inactive after rotation deleted it", result.CredentialID)
	}
	t.Logf("Step 4 PASS — old token inactive: name=%q active=%v elapsed=%s",
		result.CredentialID, oldSt.Active, time.Since(t3).Round(time.Millisecond))

	// Step 5: Revoke the second token.
	t4 := time.Now()
	if err := a.Revoke(ctx, adapter.RevokeRequest{
		ProviderID:   providerID,
		CredentialID: result2.CredentialID,
	}); err != nil {
		t.Fatalf("Step 5 — Revoke: %v", err)
	}
	t.Logf("Step 5 PASS — Revoke: token=%q elapsed=%s",
		result2.CredentialID, time.Since(t4).Round(time.Millisecond))

	// Step 6: Revoked token is gone.
	t5 := time.Now()
	finalSt, err := a.Status(ctx, result2.CredentialID)
	if err != nil {
		t.Fatalf("Step 6 — Status after revoke: %v", err)
	}
	if finalSt.Active {
		t.Errorf("Step 6 FAIL — revoked token %q should be inactive", result2.CredentialID)
	}
	t.Logf("Step 6 PASS — revoked token inactive: name=%q active=%v elapsed=%s",
		result2.CredentialID, finalSt.Active, time.Since(t5).Round(time.Millisecond))

	t.Logf("=== lifecycle test complete: all 6 steps passed, total=%s ===", time.Since(t0).Round(time.Millisecond))
}

func TestSplunk_Revoke_EmptyCredentialID_Integration(t *testing.T) {
	a := splunkIntegClient(t)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{ProviderID: "app", CredentialID: ""})
	if err == nil {
		t.Fatal("expected error for empty credential_id")
	}
}
