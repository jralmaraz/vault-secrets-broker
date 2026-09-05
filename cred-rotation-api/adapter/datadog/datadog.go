// Package datadog implements the adapter.Adapter interface for Datadog key rotation.
//
// Datadog supports two credential types:
//   - API keys  (DD-API-KEY)  — used by agents and forwarders to send data
//   - App keys  (DD-APPLICATION-KEY) — used by integrations and automation to call the API
//
// Both types are managed via the Datadog Key Management v2 API.
// The key value is returned only once, on the 201 Create response.
// All subsequent GET responses return only the last four characters (last4).
//
// Rotation strategy:
//   - Rotate creates a new key with a timestamped name, returns its id (UUID) as
//     CredentialID and the secret value as Credential. Best-effort deletes the old
//     key by id if Meta["old_key_id"] is set.
//   - Revoke deletes the key by id. Fails closed if credential_id is empty.
//   - Status checks whether the key id exists (200 OK → active, 404 → inactive).
//
// Auth: two management credentials are required at construction time —
//   - AdminAPIKey: a DD-API-KEY with api_keys_write / org_app_keys_write
//   - AdminAppKey: a DD-APPLICATION-KEY with the same permissions
//
// Both are stored Transit-encrypted in Vault KV and decrypted at startup.
//
// TLS: enforces TLS 1.3 minimum on all outbound requests.
// BaseURL is configurable for Datadog's regional sites (US1, EU, AP1, …).
package datadog

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
)

const (
	adapterName      = "datadog"
	defaultBaseURL   = "https://api.datadoghq.com"
	httpTimeout      = 20 * time.Second
	bodyLimit        = 1 << 20 // 1 MiB
	tokenTimeFmt     = "20060102T150405.000Z"
	deleteOldTimeout = 10 * time.Second

	KeyTypeAPI = "api_key"
	KeyTypeApp = "app_key"
)

// Adapter rotates Datadog API keys or Application keys via the v2 Key Management API.
type Adapter struct {
	baseURL     string
	adminAPIKey string // DD-API-KEY for management requests
	adminAppKey string // DD-APPLICATION-KEY for management requests
	keyType     string // KeyTypeAPI or KeyTypeApp
	httpClient  *http.Client
	logger      *slog.Logger
}

// Config carries parameters needed to construct the Datadog adapter.
type Config struct {
	// AdminAPIKey is a Datadog API key with write permissions (Transit-decrypted at startup).
	AdminAPIKey string
	// AdminAppKey is a Datadog Application key with write permissions (Transit-decrypted at startup).
	AdminAppKey string
	// BaseURL is the Datadog API base URL. Defaults to https://api.datadoghq.com.
	// Set to the regional URL for non-US1 Datadog sites (EU, AP1, Gov, etc.).
	BaseURL string
	// KeyType is the credential type to manage: KeyTypeAPI or KeyTypeApp.
	// Defaults to KeyTypeAPI.
	KeyType string
}

// Option is a functional option for the adapter.
type Option func(*Adapter)

// WithBaseURL overrides the BaseURL (for unit tests using httptest).
func WithBaseURL(u string) Option {
	return func(a *Adapter) { a.baseURL = strings.TrimRight(u, "/") }
}

// WithLogger sets the logger for best-effort operation warnings.
// Defaults to a discarding no-op logger if not set.
func WithLogger(l *slog.Logger) Option {
	return func(a *Adapter) { a.logger = l }
}

// New constructs a Datadog adapter from Config.
func New(cfg Config, opts ...Option) (*Adapter, error) {
	if cfg.AdminAPIKey == "" {
		return nil, errors.New("datadog: AdminAPIKey is required")
	}
	if cfg.AdminAppKey == "" {
		return nil, errors.New("datadog: AdminAppKey is required")
	}

	keyType := cfg.KeyType
	if keyType == "" {
		keyType = KeyTypeAPI
	}
	if keyType != KeyTypeAPI && keyType != KeyTypeApp {
		return nil, fmt.Errorf("datadog: KeyType must be %q or %q, got %q", KeyTypeAPI, KeyTypeApp, keyType)
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	a := &Adapter{
		baseURL:     strings.TrimRight(baseURL, "/"),
		adminAPIKey: cfg.AdminAPIKey,
		adminAppKey: cfg.AdminAppKey,
		keyType:     keyType,
		httpClient: &http.Client{
			Timeout: httpTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
			},
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, o := range opts {
		o(a)
	}
	return a, nil
}

// Name returns the adapter's registered name.
func (a *Adapter) Name() string { return adapterName }

// Rotate creates a new Datadog key named "<providerID>-<timestamp>-<rand>".
// If req.Meta["old_key_id"] is set, the old key is deleted best-effort in a
// detached context so caller deadline expiry cannot silently skip cleanup.
func (a *Adapter) Rotate(ctx context.Context, req adapter.RotateRequest) (adapter.Result, error) {
	suffix, err := randomHex(2) // 4 hex chars — addresses issue #31
	if err != nil {
		return adapter.Result{}, fmt.Errorf("datadog rotate: generate name suffix: %w", err)
	}
	newName := req.ProviderID + "-" + time.Now().UTC().Format(tokenTimeFmt) + "-" + suffix

	keyID, keyValue, err := a.createKey(ctx, newName, req.Meta)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("datadog rotate: %w", err)
	}

	// Best-effort delete of old key — detached from caller context (issue #30 pattern).
	if oldID, ok := req.Meta["old_key_id"]; ok && oldID != "" {
		deleteCtx, cancel := context.WithTimeout(context.Background(), deleteOldTimeout)
		defer cancel()
		if err := a.deleteKey(deleteCtx, oldID); err != nil {
			a.logger.Warn("datadog: best-effort delete of old key failed",
				"old_key_id", oldID,
				"provider_id", req.ProviderID,
				"err", err,
			)
		}
	}

	return adapter.Result{
		ProviderID:   req.ProviderID,
		CredentialID: keyID,
		Credential:   keyValue,
		RotatedAt:    time.Now().UTC(),
	}, nil
}

// Revoke deletes the Datadog key with the given id. Fails closed if empty.
func (a *Adapter) Revoke(ctx context.Context, req adapter.RevokeRequest) error {
	if req.CredentialID == "" {
		return errors.New("datadog revoke: credential_id is required — refusing to skip revocation")
	}
	if err := a.deleteKey(ctx, req.CredentialID); err != nil {
		return fmt.Errorf("datadog revoke: %w", err)
	}
	return nil
}

// Status reports whether the Datadog key with the given id exists and is usable.
func (a *Adapter) Status(ctx context.Context, credentialID string) (adapter.CredentialStatus, error) {
	if credentialID == "" {
		return adapter.CredentialStatus{}, errors.New("datadog status: credential_id is required")
	}

	endpoint := a.baseURL + a.keyPath(credentialID)
	status, _, err := a.do(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return adapter.CredentialStatus{}, fmt.Errorf("datadog status: %w", err)
	}

	active := status == http.StatusOK
	if status != http.StatusOK && status != http.StatusNotFound {
		return adapter.CredentialStatus{}, fmt.Errorf("datadog status: unexpected status %d", status)
	}

	return adapter.CredentialStatus{
		ProviderID:   credentialID,
		CredentialID: credentialID,
		Active:       active,
		CheckedAt:    time.Now().UTC(),
	}, nil
}

// ── internal ──────────────────────────────────────────────────────────────────

func (a *Adapter) createKey(ctx context.Context, name string, meta map[string]string) (id, value string, err error) {
	body, err := a.buildCreateBody(name, meta)
	if err != nil {
		return "", "", fmt.Errorf("build request body: %w", err)
	}

	endpoint := a.baseURL + a.collectionPath()
	status, respBody, err := a.do(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("create key %q: %w", name, err)
	}
	if status != http.StatusCreated {
		return "", "", fmt.Errorf("create key %q: unexpected status %d: %s", name, status, respBody)
	}

	var result ddResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", "", fmt.Errorf("create key %q: parse response: %w", name, err)
	}
	if result.Data.ID == "" {
		return "", "", fmt.Errorf("create key %q: id missing in response", name)
	}
	if result.Data.Attributes.Key == "" {
		return "", "", fmt.Errorf("create key %q: key value missing in response", name)
	}
	return result.Data.ID, result.Data.Attributes.Key, nil
}

func (a *Adapter) deleteKey(ctx context.Context, id string) error {
	endpoint := a.baseURL + a.keyPath(id)
	status, body, err := a.do(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("delete key %q: %w", id, err)
	}
	// 204 No Content is success; 404 means already gone (idempotent).
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("delete key %q: unexpected status %d: %s", id, status, body)
	}
	return nil
}

// buildCreateBody returns the JSON request body for a key creation.
// App keys additionally accept a "scopes" meta field (comma-separated).
func (a *Adapter) buildCreateBody(name string, meta map[string]string) ([]byte, error) {
	attrs := map[string]interface{}{"name": name}
	if a.keyType == KeyTypeApp {
		scopes := []string{}
		if s, ok := meta["scopes"]; ok && s != "" {
			for _, sc := range strings.Split(s, ",") {
				if sc = strings.TrimSpace(sc); sc != "" {
					scopes = append(scopes, sc)
				}
			}
		}
		attrs["scopes"] = scopes
	}

	ddType := "api_keys"
	if a.keyType == KeyTypeApp {
		ddType = "application_keys"
	}

	return json.Marshal(map[string]interface{}{
		"data": map[string]interface{}{
			"type":       ddType,
			"attributes": attrs,
		},
	})
}

// collectionPath returns the v2 collection endpoint for the configured key type.
func (a *Adapter) collectionPath() string {
	if a.keyType == KeyTypeApp {
		return "/api/v2/application_keys"
	}
	return "/api/v2/api_keys"
}

// keyPath returns the v2 resource path for a specific key id.
func (a *Adapter) keyPath(id string) string {
	if a.keyType == KeyTypeApp {
		return "/api/v2/application_keys/" + id
	}
	return "/api/v2/api_keys/" + id
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
	req.Header.Set("DD-API-KEY", a.adminAPIKey)
	req.Header.Set("DD-APPLICATION-KEY", a.adminAppKey)
	req.Header.Set("Accept", "application/json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	return resp.StatusCode, body, nil
}

// randomHex returns n random bytes encoded as a 2n-character hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ── response types ────────────────────────────────────────────────────────────

type ddResponse struct {
	Data ddData `json:"data"`
}

type ddData struct {
	ID         string       `json:"id"`
	Type       string       `json:"type"`
	Attributes ddAttributes `json:"attributes"`
}

type ddAttributes struct {
	Name  string `json:"name"`
	Key   string `json:"key"`   // present only in 201 Create response; never log
	Last4 string `json:"last4"` // safe to log
}
