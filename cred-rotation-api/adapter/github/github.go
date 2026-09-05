// Package github implements the adapter.Adapter interface for GitHub fine-grained
// personal access token (PAT) rotation via the GitHub REST API.
//
// Rotation path:
//  1. POST /user/personal_access_tokens  → creates a new token (value only returned here)
//  2. DELETE /user/personal_access_tokens/{old_id}  → best-effort revoke of the old token
//
// Authentication uses an admin PAT with the personal_access_tokens:write permission,
// stored encrypted in Vault Transit and decrypted at startup.
//
// TLS minimum is TLS 1.3 — api.github.com always supports it and enables the
// X25519MLKEM768 hybrid post-quantum key exchange when offered by the client.
package github

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
)

const (
	adapterName    = "github"
	defaultBaseURL = "https://api.github.com"
	httpTimeout    = 30 * time.Second
	bodyLimit      = 1 << 20 // 1 MiB
	defaultExpiry  = 90      // days
	apiVersion     = "2022-11-28"
)

// Config carries the parameters needed to construct a GitHub adapter.
type Config struct {
	// BaseURL overrides https://api.github.com (useful for GHES deployments).
	BaseURL string
	// AdminPAT is the plaintext personal access token with
	// personal_access_tokens:write permission — decrypted from Vault Transit at startup.
	AdminPAT string
}

// Option is a functional option for the adapter.
type Option func(*Adapter)

// WithBaseURL overrides the default api.github.com base URL (for unit tests or GHES).
func WithBaseURL(u string) Option {
	return func(a *Adapter) { a.baseURL = strings.TrimRight(u, "/") }
}

// Adapter rotates GitHub fine-grained personal access tokens.
type Adapter struct {
	baseURL  string
	adminPAT string
	client   *http.Client
}

// New constructs a GitHub adapter enforcing TLS 1.3 minimum.
func New(cfg Config, opts ...Option) (*Adapter, error) {
	if cfg.AdminPAT == "" {
		return nil, errors.New("github: AdminPAT is required")
	}
	base := cfg.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	a := &Adapter{
		baseURL:  strings.TrimRight(base, "/"),
		adminPAT: cfg.AdminPAT,
		client: &http.Client{
			Timeout: httpTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
				},
			},
		},
	}
	for _, o := range opts {
		o(a)
	}
	return a, nil
}

// Name returns the adapter's canonical identifier.
func (a *Adapter) Name() string { return adapterName }

// Rotate creates a new fine-grained PAT and best-effort deletes the old one.
//
//   - req.ProviderID: logical name prefix (e.g. "ci-deployer"); a millisecond timestamp is appended.
//   - req.Meta["old_token_id"]: numeric ID of the token to delete after creation (optional).
//   - req.Meta["expires_days"]: days until expiry (1–366, default 90).
//   - req.Meta["permissions"]: JSON object of GitHub permission scopes, e.g. {"contents":"read"}.
//   - req.Meta["repositories"]: comma-separated list of repository names to scope the token.
func (a *Adapter) Rotate(ctx context.Context, req adapter.RotateRequest) (adapter.Result, error) {
	expireDays := defaultExpiry
	if v, ok := req.Meta["expires_days"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 366 {
			expireDays = n
		}
	}

	body := map[string]any{
		"name":       fmt.Sprintf("%s-%d", req.ProviderID, time.Now().UnixMilli()),
		"expires_at": time.Now().UTC().AddDate(0, 0, expireDays).Format(time.RFC3339),
	}

	if v, ok := req.Meta["permissions"]; ok && v != "" {
		var perms map[string]string
		if err := json.Unmarshal([]byte(v), &perms); err == nil {
			body["permissions"] = perms
		}
	}

	if v, ok := req.Meta["repositories"]; ok && v != "" {
		var repos []string
		for _, r := range strings.Split(v, ",") {
			if s := strings.TrimSpace(r); s != "" {
				repos = append(repos, s)
			}
		}
		if len(repos) > 0 {
			body["repositories"] = repos
		}
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("github rotate: marshal request: %w", err)
	}

	status, respBody, err := a.do(ctx, http.MethodPost, "/user/personal_access_tokens", bodyBytes)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("github rotate: %w", err)
	}
	if status != http.StatusCreated {
		return adapter.Result{}, fmt.Errorf("github rotate: unexpected status %d: %s", status, respBody)
	}

	var created struct {
		ID    int64  `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &created); err != nil {
		return adapter.Result{}, fmt.Errorf("github rotate: parse response: %w", err)
	}
	if created.Token == "" {
		return adapter.Result{}, errors.New("github rotate: empty token in response")
	}

	result := adapter.Result{
		ProviderID:   req.ProviderID,
		CredentialID: strconv.FormatInt(created.ID, 10),
		Credential:   created.Token,
		RotatedAt:    time.Now().UTC(),
	}

	// Best-effort: delete the old token. A failure here does not fail the rotation
	// since the new credential is already issued and returned.
	if oldID, ok := req.Meta["old_token_id"]; ok && oldID != "" {
		_ = a.Revoke(ctx, adapter.RevokeRequest{
			ProviderID:   req.ProviderID,
			CredentialID: oldID,
		})
	}

	return result, nil
}

// Revoke deletes the fine-grained PAT identified by req.CredentialID (numeric token ID).
// Returns nil if the token is already gone (404 is idempotent).
// Fails closed if CredentialID is empty.
func (a *Adapter) Revoke(ctx context.Context, req adapter.RevokeRequest) error {
	if req.CredentialID == "" {
		return errors.New("github revoke: credential_id is required")
	}
	status, body, err := a.do(ctx, http.MethodDelete,
		"/user/personal_access_tokens/"+req.CredentialID, nil)
	if err != nil {
		return fmt.Errorf("github revoke: %w", err)
	}
	if status == http.StatusNotFound {
		return nil // already gone — idempotent
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("github revoke: unexpected status %d: %s", status, body)
	}
	return nil
}

// Status reports whether the fine-grained PAT still exists and has not expired.
// credentialID is the numeric token ID returned by Rotate.
func (a *Adapter) Status(ctx context.Context, credentialID string) (adapter.CredentialStatus, error) {
	if credentialID == "" {
		return adapter.CredentialStatus{}, errors.New("github status: credential_id is required")
	}
	status, body, err := a.do(ctx, http.MethodGet,
		"/user/personal_access_tokens/"+credentialID, nil)
	if err != nil {
		return adapter.CredentialStatus{}, fmt.Errorf("github status: %w", err)
	}
	if status == http.StatusNotFound {
		return adapter.CredentialStatus{
			CredentialID: credentialID,
			Active:       false,
			CheckedAt:    time.Now().UTC(),
		}, nil
	}
	if status != http.StatusOK {
		return adapter.CredentialStatus{}, fmt.Errorf("github status: unexpected status %d: %s", status, body)
	}

	var info struct {
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return adapter.CredentialStatus{}, fmt.Errorf("github status: parse response: %w", err)
	}

	active := true
	if info.ExpiresAt != "" {
		if exp, err := time.Parse(time.RFC3339, info.ExpiresAt); err == nil {
			active = time.Now().UTC().Before(exp)
		}
	}

	return adapter.CredentialStatus{
		CredentialID: credentialID,
		Active:       active,
		CheckedAt:    time.Now().UTC(),
	}, nil
}

// do executes an authenticated GitHub API request and returns the HTTP status code
// and response body. The body is fully consumed and the response closed inside this
// function — no *http.Response escapes, which avoids the bodyclose lint warning.
func (a *Adapter) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, bodyReader)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.adminPAT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	return resp.StatusCode, respBody, nil
}
