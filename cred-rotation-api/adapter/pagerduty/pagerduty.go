// Package pagerduty implements the adapter.Adapter interface for PagerDuty API key rotation.
//
// PagerDuty API keys are org-scoped read/write credentials used by on-call automation,
// incident response tooling, and monitoring integrations. The adapter performs
// self-referential rotation: the existing key creates the new key, then the old key
// is deleted. Vault stores the active key ID alongside the encrypted key value so the
// next rotation can reference the old key for cleanup.
//
// Auth: Authorization: Token token=<api_key> + From: <email> (required by PagerDuty).
// CredentialID: the PagerDuty API key ID returned on creation.
//
// TLS: enforces TLS 1.3 minimum on all outbound requests.
package pagerduty

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
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
)

const (
	adapterName      = "pagerduty"
	defaultBaseURL   = "https://api.pagerduty.com"
	httpTimeout      = 20 * time.Second
	bodyLimit        = 1 << 20 // 1 MiB
	tokenTimeFmt     = "20060102T150405Z"
	deleteOldTimeout = 10 * time.Second
	pdAccept         = "application/vnd.pagerduty+json;version=2"
	defaultSemLimit  = 10
)

// Adapter rotates PagerDuty API keys via the PagerDuty REST API v2.
type Adapter struct {
	baseURL    string
	apiKey     string
	email      string
	httpClient *http.Client
	logger     *slog.Logger

	sem       *semaphore.Weighted
	cleanupWg sync.WaitGroup
}

// Config carries parameters needed to construct the PagerDuty adapter.
type Config struct {
	// APIKey is the PagerDuty API key used to create and delete keys (Transit-decrypted at startup).
	APIKey string
	// Email is the value sent in the required PagerDuty From header.
	Email string
	// BaseURL is the PagerDuty API base URL. Defaults to https://api.pagerduty.com.
	BaseURL string
}

// Option is a functional option for the adapter.
type Option func(*Adapter)

// WithBaseURL overrides BaseURL (for unit tests using httptest).
func WithBaseURL(u string) Option {
	return func(a *Adapter) { a.baseURL = strings.TrimRight(u, "/") }
}

// WithLogger sets the logger for best-effort operation warnings.
func WithLogger(l *slog.Logger) Option {
	return func(a *Adapter) { a.logger = l }
}

// New constructs a PagerDuty adapter from Config.
func New(cfg Config, opts ...Option) (*Adapter, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("pagerduty: APIKey is required")
	}
	if cfg.Email == "" {
		return nil, errors.New("pagerduty: Email is required (PagerDuty From header)")
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	a := &Adapter{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  cfg.APIKey,
		email:   cfg.Email,
		httpClient: &http.Client{
			Timeout: httpTimeout,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13},
				MaxConnsPerHost:     defaultSemLimit,
				MaxIdleConnsPerHost: defaultSemLimit,
				MaxIdleConns:        defaultSemLimit * 2,
			},
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		sem:    semaphore.NewWeighted(defaultSemLimit),
	}
	for _, o := range opts {
		o(a)
	}
	return a, nil
}

// Name returns the adapter's registered name.
func (a *Adapter) Name() string { return adapterName }

// Rotate creates a new PagerDuty API key named "<providerID>-<timestamp>-<rand>".
// If req.Meta["old_key_id"] is set, the old key is deleted best-effort in a
// detached context so caller deadline expiry cannot silently skip cleanup.
func (a *Adapter) Rotate(ctx context.Context, req adapter.RotateRequest) (adapter.Result, error) {
	if err := a.sem.Acquire(ctx, 1); err != nil {
		return adapter.Result{}, fmt.Errorf("pagerduty rotate: acquire slot: %w", err)
	}
	defer a.sem.Release(1)

	suffix, err := randomHex(2)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("pagerduty rotate: generate name suffix: %w", err)
	}
	name := req.ProviderID + "-" + time.Now().UTC().Format(tokenTimeFmt) + "-" + suffix

	keyID, keyValue, err := a.createKey(ctx, name)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("pagerduty rotate: %w", err)
	}

	if oldID, ok := req.Meta["old_key_id"]; ok && oldID != "" {
		providerID := req.ProviderID
		a.cleanupWg.Add(1)
		go func() { // #nosec G118 //nolint:gosec -- independent context: cleanup must not cancel when caller request expires
			defer a.cleanupWg.Done()
			defer func() {
				if r := recover(); r != nil {
					a.logger.Error("pagerduty: cleanup goroutine panic", "panic", fmt.Sprint(r))
				}
			}()
			deleteCtx, cancel := context.WithTimeout(context.Background(), deleteOldTimeout)
			defer cancel()
			if err := a.deleteKey(deleteCtx, oldID); err != nil {
				a.logger.Warn("pagerduty: best-effort delete of old key failed",
					"old_key_id", sanitizeForLog(oldID),
					"provider_id", sanitizeForLog(providerID),
					"err", sanitizeForLog(err.Error()),
				)
			}
		}()
	}

	return adapter.Result{
		ProviderID:   req.ProviderID,
		CredentialID: keyID,
		Credential:   keyValue,
		RotatedAt:    time.Now().UTC(),
	}, nil
}

// Drain waits for all in-flight cleanup goroutines to finish or ctx to expire.
func (a *Adapter) Drain(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		a.cleanupWg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Revoke deletes the PagerDuty API key with the given ID. Fails closed if empty.
func (a *Adapter) Revoke(ctx context.Context, req adapter.RevokeRequest) error {
	if req.CredentialID == "" {
		return errors.New("pagerduty revoke: credential_id is required — refusing to skip revocation")
	}
	if err := a.deleteKey(ctx, req.CredentialID); err != nil {
		return fmt.Errorf("pagerduty revoke: %w", err)
	}
	return nil
}

// Status reports whether the PagerDuty API key with the given ID is active.
// Lists keys (up to 100) and checks for presence of the ID.
func (a *Adapter) Status(ctx context.Context, credentialID string) (adapter.CredentialStatus, error) {
	if credentialID == "" {
		return adapter.CredentialStatus{}, errors.New("pagerduty status: credential_id is required")
	}
	active, err := a.keyExists(ctx, credentialID)
	if err != nil {
		return adapter.CredentialStatus{}, fmt.Errorf("pagerduty status: %w", err)
	}
	return adapter.CredentialStatus{
		ProviderID:   credentialID,
		CredentialID: credentialID,
		Active:       active,
		CheckedAt:    time.Now().UTC(),
	}, nil
}

// ── internal ──────────────────────────────────────────────────────────────────

func (a *Adapter) createKey(ctx context.Context, name string) (id, value string, err error) {
	body, err := json.Marshal(map[string]interface{}{
		"api_key": map[string]interface{}{
			"name": name,
			"type": "read_write_api_key",
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("build request body: %w", err)
	}

	status, respBody, err := a.do(ctx, http.MethodPost, a.baseURL+"/api_keys", bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("create key %q: %w", name, err)
	}
	if status != http.StatusCreated {
		return "", "", fmt.Errorf("create key %q: unexpected status %d: %s", name, status, respBody)
	}

	var resp pdKeyResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", "", fmt.Errorf("create key %q: parse response: %w", name, err)
	}
	if resp.APIKey.ID == "" {
		return "", "", fmt.Errorf("create key %q: id missing in response", name)
	}
	if resp.APIKey.Key == "" {
		return "", "", fmt.Errorf("create key %q: key value missing in response", name)
	}
	return resp.APIKey.ID, resp.APIKey.Key, nil
}

func (a *Adapter) deleteKey(ctx context.Context, id string) error {
	status, body, err := a.do(ctx, http.MethodDelete, a.baseURL+"/api_keys/"+id, nil)
	if err != nil {
		return fmt.Errorf("delete key %q: %w", id, err)
	}
	// 204 is success; 404 means already gone (idempotent).
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("delete key %q: unexpected status %d: %s", id, status, body)
	}
	return nil
}

func (a *Adapter) keyExists(ctx context.Context, id string) (bool, error) {
	status, body, err := a.do(ctx, http.MethodGet, a.baseURL+"/api_keys?limit=100", nil)
	if err != nil {
		return false, fmt.Errorf("list keys: %w", err)
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("list keys: unexpected status %d: %s", status, body)
	}

	var resp pdKeysListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, fmt.Errorf("list keys: parse response: %w", err)
	}
	for _, k := range resp.APIKeys {
		if k.ID == id {
			return true, nil
		}
	}
	return false, nil
}

// do executes an authenticated HTTP request and returns (statusCode, body, error).
// The response body is fully consumed and closed; callers never hold an open body reference.
// Callers must not log body — it may contain error messages that echo user-supplied values.
func (a *Adapter) do(ctx context.Context, method, endpoint string, reqBody io.Reader) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Token token="+a.apiKey)
	req.Header.Set("Accept", pdAccept)
	req.Header.Set("From", a.email)
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

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sanitizeForLog(s string) string {
	const maxRunes = 256
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		n++
		if n >= maxRunes {
			b.WriteString("…")
			break
		}
	}
	return b.String()
}

// ── response types ────────────────────────────────────────────────────────────

type pdKeyResponse struct {
	APIKey pdKey `json:"api_key"`
}

type pdKeysListResponse struct {
	APIKeys []pdKey `json:"api_keys"`
	More    bool    `json:"more"`
}

type pdKey struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"` // only present in create response; never log
}
