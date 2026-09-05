// Package auth0 implements the adapter.Adapter interface for Auth0 Management API credential rotation.
//
// Rotation path: POST /api/v2/clients/{client_id}/rotate-secret
// This is atomic — Auth0 invalidates the old secret immediately.
// Management tokens are cached and refreshed 5 minutes before expiry to avoid
// unnecessary round-trips to the Auth0 /oauth/token endpoint.
package auth0

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
)

const (
	name              = "auth0"
	tokenRefreshBuf   = 5 * time.Minute
	httpClientTimeout = 15 * time.Second
)

// Adapter rotates Auth0 application client_secrets via the Management API.
type Adapter struct {
	domain   string
	clientID string
	// clientSecret is the Management API client_secret (plaintext, decrypted from Vault Transit at startup).
	clientSecret string
	audience     string
	baseURL      string // overridable for tests

	httpClient *http.Client

	// management token cache
	mu          sync.RWMutex
	mgmtToken   string
	tokenExpiry time.Time
}

// Config carries the parameters needed to construct the Auth0 adapter.
type Config struct {
	Domain       string
	ClientID     string
	ClientSecret string // plaintext — decrypted by vault.Client before passing here
	Audience     string
}

// Option is a functional option for the adapter (used in tests).
type Option func(*Adapter)

// WithBaseURL overrides the default https://{domain} base URL (for unit tests).
func WithBaseURL(u string) Option {
	return func(a *Adapter) { a.baseURL = u }
}

// New constructs an Auth0 adapter enforcing TLS 1.3 minimum.
func New(cfg Config, opts ...Option) (*Adapter, error) {
	if cfg.Domain == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.Audience == "" {
		return nil, errors.New("auth0: all Config fields are required")
	}
	a := &Adapter{
		domain:       cfg.Domain,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		audience:     cfg.Audience,
		baseURL:      "https://" + cfg.Domain,
		httpClient: &http.Client{
			Timeout: httpClientTimeout,
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

// Name returns the adapter's registered name.
func (a *Adapter) Name() string { return name }

// Rotate calls POST /api/v2/clients/{providerID}/rotate-secret.
// providerID is the Auth0 application client_id whose secret is being rotated.
func (a *Adapter) Rotate(ctx context.Context, req adapter.RotateRequest) (adapter.Result, error) {
	token, err := a.managementToken(ctx)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("auth0 rotate: get management token: %w", err)
	}

	url := fmt.Sprintf("%s/api/v2/clients/%s/rotate-secret", a.baseURL, req.ProviderID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("auth0 rotate: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("auth0 rotate: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return adapter.Result{}, fmt.Errorf("auth0 rotate: unexpected status %d: %s", resp.StatusCode, body)
	}

	var out struct {
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return adapter.Result{}, fmt.Errorf("auth0 rotate: parse response: %w", err)
	}
	if out.ClientSecret == "" {
		return adapter.Result{}, errors.New("auth0 rotate: empty client_secret in response")
	}

	return adapter.Result{
		ProviderID:   req.ProviderID,
		CredentialID: req.ProviderID, // Auth0 keeps the same client_id; the secret is the credential
		Credential:   out.ClientSecret,
		RotatedAt:    time.Now().UTC(),
	}, nil
}

// Revoke is not supported by Auth0 for client_secrets — rotation is the only lifecycle operation.
// Callers should use Rotate to invalidate and replace in one step.
func (a *Adapter) Revoke(_ context.Context, _ adapter.RevokeRequest) error {
	return errors.New("auth0: explicit revocation is not supported; use Rotate to replace the secret")
}

// Status checks whether the application exists and is enabled in Auth0.
func (a *Adapter) Status(ctx context.Context, credentialID string) (adapter.CredentialStatus, error) {
	token, err := a.managementToken(ctx)
	if err != nil {
		return adapter.CredentialStatus{}, fmt.Errorf("auth0 status: get management token: %w", err)
	}

	url := fmt.Sprintf("%s/api/v2/clients/%s?fields=client_id,name&include_fields=true", a.baseURL, credentialID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return adapter.CredentialStatus{}, fmt.Errorf("auth0 status: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return adapter.CredentialStatus{}, fmt.Errorf("auth0 status: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	active := resp.StatusCode == http.StatusOK
	return adapter.CredentialStatus{
		ProviderID:   credentialID,
		CredentialID: credentialID,
		Active:       active,
		CheckedAt:    time.Now().UTC(),
	}, nil
}

// managementToken returns a cached Management API token, refreshing it when within
// tokenRefreshBuf of expiry. Thread-safe.
func (a *Adapter) managementToken(ctx context.Context) (string, error) {
	// Fast path: return cached token if still valid.
	a.mu.RLock()
	if a.mgmtToken != "" && time.Until(a.tokenExpiry) > tokenRefreshBuf {
		tok := a.mgmtToken
		a.mu.RUnlock()
		return tok, nil
	}
	a.mu.RUnlock()

	// Slow path: fetch a new token under write lock.
	a.mu.Lock()
	defer a.mu.Unlock()

	// Double-check after acquiring write lock.
	if a.mgmtToken != "" && time.Until(a.tokenExpiry) > tokenRefreshBuf {
		return a.mgmtToken, nil
	}

	body := fmt.Sprintf(
		`{"client_id":%q,"client_secret":%q,"audience":%q,"grant_type":"client_credentials"}`,
		a.clientID, a.clientSecret, a.audience,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.baseURL+"/oauth/token", strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, respBody)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &tok); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("empty access_token in response")
	}

	a.mgmtToken = tok.AccessToken
	a.tokenExpiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return a.mgmtToken, nil
}
