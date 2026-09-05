// Package splunk implements the adapter.Adapter interface for Splunk HEC token rotation.
//
// Splunk HTTP Event Collector (HEC) tokens are the primary credential used by agents
// and applications to push events to Splunk. Tokens are named entities managed via
// the Splunk REST management API (default port :8089).
//
// Rotation strategy:
//   - Rotate creates a new HEC token named "<providerID>-<UTC timestamp>" and
//     optionally deletes the old token if Meta["old_token_name"] is set.
//   - Revoke deletes the named token. Fails closed if credential_id is empty.
//   - Status reports whether the named token exists and is enabled.
//
// Auth: Splunk management token ("Authorization: Bearer <token>"), stored
// Transit-encrypted in Vault KV at secret/cred-rotation-api/adapters/splunk.
//
// TLS: the http.Client enforces TLS verification by default. Provide CACert (PEM)
// in Config for deployments that use a private CA. Never set InsecureSkipVerify in prod.
package splunk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
)

const (
	adapterName   = "splunk"
	httpTimeout   = 15 * time.Second
	bodyLimit     = 1 << 20 // 1 MiB
	tokenTimeFmt  = "20060102T150405Z"
)

// Adapter rotates Splunk HEC tokens via the Splunk REST management API.
type Adapter struct {
	baseURL    string // e.g. "https://splunk.example.com:8089"
	authToken  string // Splunk management token
	httpClient *http.Client

	// Defaults applied when creating new HEC tokens.
	defaultIndex      string
	defaultSourcetype string
}

// Config carries parameters needed to construct the Splunk adapter.
// AuthToken is the Splunk management token (plaintext, decrypted from Vault Transit at startup).
// CACert is an optional PEM-encoded CA certificate for TLS verification; uses the system pool if empty.
type Config struct {
	BaseURL           string // https://splunk.example.com:8089
	AuthToken         string // plaintext — decrypted by vault.Client before passing here
	CACert            string // PEM-encoded CA cert (optional)
	DefaultIndex      string // Splunk index for new tokens (optional, e.g. "main")
	DefaultSourcetype string // sourcetype for new tokens (optional, e.g. "_json")
}

// Option is a functional option for the adapter (used in tests).
type Option func(*Adapter)

// WithBaseURL overrides the default BaseURL (for unit tests using httptest).
func WithBaseURL(u string) Option {
	return func(a *Adapter) { a.baseURL = u }
}

// New constructs a Splunk adapter from Config.
func New(cfg Config, opts ...Option) (*Adapter, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("splunk: BaseURL is required")
	}
	if cfg.AuthToken == "" {
		return nil, errors.New("splunk: AuthToken is required")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, errors.New("splunk: CACert contains no valid PEM blocks")
		}
		tlsCfg.RootCAs = pool
	}

	a := &Adapter{
		baseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		authToken: cfg.AuthToken,
		httpClient: &http.Client{
			Timeout:   httpTimeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
		defaultIndex:      cfg.DefaultIndex,
		defaultSourcetype: cfg.DefaultSourcetype,
	}
	for _, o := range opts {
		o(a)
	}
	return a, nil
}

// Name returns the adapter's registered name.
func (a *Adapter) Name() string { return adapterName }

// Rotate creates a new HEC token named "<providerID>-<UTC timestamp>".
// If req.Meta["old_token_name"] is set, the named old token is deleted after
// the new one is successfully created — fail-open on deletion (logs are lost if
// Splunk rejects the delete, but the new credential is already live).
//
// The new token value is only returned once by Splunk; it is Transit-encrypted
// by the server layer before being sent to callers.
func (a *Adapter) Rotate(ctx context.Context, req adapter.RotateRequest) (adapter.Result, error) {
	newName := req.ProviderID + "-" + time.Now().UTC().Format(tokenTimeFmt)

	tokenValue, err := a.createToken(ctx, newName, req.Meta)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("splunk rotate: %w", err)
	}

	// Best-effort deletion of the old token. The new credential is already live
	// so we do NOT fail the rotation if this step errors — callers should use
	// Revoke explicitly if they need a hard guarantee.
	if old, ok := req.Meta["old_token_name"]; ok && old != "" {
		_ = a.deleteToken(ctx, old)
	}

	return adapter.Result{
		ProviderID:   req.ProviderID,
		CredentialID: newName,
		Credential:   tokenValue,
		RotatedAt:    time.Now().UTC(),
	}, nil
}

// Revoke deletes the named HEC token. Fails closed if credential_id is empty.
func (a *Adapter) Revoke(ctx context.Context, req adapter.RevokeRequest) error {
	if req.CredentialID == "" {
		return errors.New("splunk revoke: credential_id is required — refusing to skip revocation")
	}
	if err := a.deleteToken(ctx, req.CredentialID); err != nil {
		return fmt.Errorf("splunk revoke: %w", err)
	}
	return nil
}

// Status reports whether the named HEC token exists and is enabled.
func (a *Adapter) Status(ctx context.Context, credentialID string) (adapter.CredentialStatus, error) {
	if credentialID == "" {
		return adapter.CredentialStatus{}, errors.New("splunk status: credential_id is required")
	}

	endpoint := fmt.Sprintf("%s/services/data/inputs/http/%s?output_mode=json",
		a.baseURL, url.PathEscape(credentialID))
	status, body, err := a.do(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return adapter.CredentialStatus{}, fmt.Errorf("splunk status: %w", err)
	}

	if status == http.StatusNotFound {
		return adapter.CredentialStatus{
			ProviderID:   credentialID,
			CredentialID: credentialID,
			Active:       false,
			CheckedAt:    time.Now().UTC(),
		}, nil
	}
	if status != http.StatusOK {
		return adapter.CredentialStatus{}, fmt.Errorf("splunk status: unexpected status %d: %s", status, body)
	}

	var result splunkResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return adapter.CredentialStatus{}, fmt.Errorf("splunk status: parse response: %w", err)
	}
	active := len(result.Entry) > 0 && !result.Entry[0].Content.Disabled

	return adapter.CredentialStatus{
		ProviderID:   credentialID,
		CredentialID: credentialID,
		Active:       active,
		CheckedAt:    time.Now().UTC(),
	}, nil
}

// ── internal ──────────────────────────────────────────────────────────────────

func (a *Adapter) createToken(ctx context.Context, name string, meta map[string]string) (string, error) {
	form := url.Values{"name": {name}}
	if a.defaultIndex != "" {
		form.Set("index", a.defaultIndex)
	}
	if a.defaultSourcetype != "" {
		form.Set("sourcetype", a.defaultSourcetype)
	}
	// Allow callers to override via Meta.
	if idx, ok := meta["index"]; ok && idx != "" {
		form.Set("index", idx)
	}
	if st, ok := meta["sourcetype"]; ok && st != "" {
		form.Set("sourcetype", st)
	}

	endpoint := a.baseURL + "/services/data/inputs/http?output_mode=json"
	status, body, err := a.do(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token %q: %w", name, err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("create token %q: unexpected status %d: %s", name, status, body)
	}

	var result splunkResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("create token %q: parse response: %w", name, err)
	}
	if len(result.Entry) == 0 || result.Entry[0].Content.Token == "" {
		return "", fmt.Errorf("create token %q: token value missing in response", name)
	}
	return result.Entry[0].Content.Token, nil
}

func (a *Adapter) deleteToken(ctx context.Context, name string) error {
	endpoint := fmt.Sprintf("%s/services/data/inputs/http/%s?output_mode=json",
		a.baseURL, url.PathEscape(name))
	status, body, err := a.do(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("delete token %q: %w", name, err)
	}
	// 200 OK or 204 No Content are both success; 404 means already gone (idempotent).
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("delete token %q: unexpected status %d: %s", name, status, body)
	}
	return nil
}

// do executes an authenticated HTTP request and returns (statusCode, body, error).
// The response body is fully consumed and closed inside do; callers never hold
// an open body reference and bodyclose linters are satisfied at the source.
// Callers must not log body when it may contain credential material.
func (a *Adapter) do(ctx context.Context, method, endpoint string, reqBody io.Reader) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.authToken)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	return resp.StatusCode, body, nil
}

// splunkResponse is the JSON envelope returned by all Splunk REST management endpoints.
type splunkResponse struct {
	Entry []splunkEntry `json:"entry"`
}

type splunkEntry struct {
	Name    string        `json:"name"`
	Content splunkContent `json:"content"`
}

type splunkContent struct {
	Disabled  bool   `json:"disabled"`
	Index     string `json:"index"`
	Sourcetype string `json:"sourcetype"`
	Token     string `json:"token"` // only present in create/get responses
}
