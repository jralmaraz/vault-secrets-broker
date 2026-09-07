// Package sonarqube implements the adapter.Adapter interface for SonarQube user token rotation.
//
// SonarQube user tokens are identified by name, not an opaque ID. The rotation strategy:
//  1. Generate a new token named "<login>-<timestamp>-<rand>"
//  2. Return the plaintext value (only returned once by the generate endpoint)
//  3. Revoke the old token name best-effort if Meta["old_token_name"] is set
//
// CredentialID convention: "<login>:<tokenname>" — composite so that Revoke and Status
// can resolve both fields from a single string without a separate parameter.
//
// Auth: Bearer token (Authorization: Bearer <token>), supported from SonarQube 10.0+.
// The pre-10 Basic-auth-with-token scheme is intentionally not used.
//
// TLS: enforces TLS 1.3 minimum on all outbound requests.
package sonarqube

import (
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
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
)

const (
	adapterName      = "sonarqube"
	httpTimeout      = 20 * time.Second
	bodyLimit        = 1 << 20 // 1 MiB
	tokenTimeFmt     = "20060102T150405Z"
	deleteOldTimeout = 10 * time.Second
	defaultSemLimit  = 10
)

// Adapter rotates SonarQube user tokens via the SonarQube Web API.
type Adapter struct {
	baseURL    string
	adminToken string
	httpClient *http.Client
	logger     *slog.Logger

	sem       *semaphore.Weighted // caps concurrent outbound calls to SonarQube
	cleanupWg sync.WaitGroup      // tracks in-flight best-effort cleanup goroutines
}

// Config carries parameters needed to construct the SonarQube adapter.
type Config struct {
	// BaseURL is the SonarQube instance URL (e.g. https://sonarqube.example.com). Required.
	BaseURL string
	// AdminToken is an admin user token with permission to manage other users' tokens.
	// Stored Transit-encrypted in Vault KV and decrypted at startup.
	AdminToken string
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

// WithTestTransport replaces the HTTP transport. Use only in tests to accept
// self-signed httptest.TLSServer certificates.
func WithTestTransport(t http.RoundTripper) Option {
	return func(a *Adapter) {
		a.httpClient = &http.Client{
			Timeout:   a.httpClient.Timeout,
			Transport: t,
		}
	}
}

// New constructs a SonarQube adapter from Config.
func New(cfg Config, opts ...Option) (*Adapter, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("sonarqube: BaseURL is required")
	}
	if cfg.AdminToken == "" {
		return nil, errors.New("sonarqube: AdminToken is required")
	}
	a := &Adapter{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		adminToken: cfg.AdminToken,
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

// Rotate generates a new SonarQube user token for req.ProviderID (the SonarQube login).
// Token name format: "<login>-<timestamp>-<rand>".
// The returned Result.CredentialID is "<login>:<tokenname>" so callers can pass it
// back unchanged to Revoke and Status.
// If req.Meta["old_token_name"] is set, the old token is revoked best-effort after
// the new one is created, using a detached context so caller cancellation cannot skip cleanup.
func (a *Adapter) Rotate(ctx context.Context, req adapter.RotateRequest) (adapter.Result, error) {
	if req.ProviderID == "" {
		return adapter.Result{}, errors.New("sonarqube rotate: provider_id (login) is required")
	}

	if err := a.sem.Acquire(ctx, 1); err != nil {
		return adapter.Result{}, fmt.Errorf("sonarqube rotate: acquire slot: %w", err)
	}
	defer a.sem.Release(1)

	suffix, err := randomHex(2)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("sonarqube rotate: generate name suffix: %w", err)
	}
	tokenName := req.ProviderID + "-" + time.Now().UTC().Format(tokenTimeFmt) + "-" + suffix

	tokenType := "USER_TOKEN"
	if t, ok := req.Meta["token_type"]; ok && t != "" {
		tokenType = t
	}

	tokenValue, err := a.generateToken(ctx, req.ProviderID, tokenName, tokenType)
	if err != nil {
		return adapter.Result{}, fmt.Errorf("sonarqube rotate: %w", err)
	}

	if oldName, ok := req.Meta["old_token_name"]; ok && oldName != "" {
		login := req.ProviderID
		a.cleanupWg.Add(1)
		go func() { //nolint:gosec // G118: intentional — independent context so cleanup isn't cancelled when the caller's request context expires // #nosec G118
			defer a.cleanupWg.Done()
			defer func() {
				if r := recover(); r != nil {
					a.logger.Error("sonarqube: cleanup goroutine panic", "panic", fmt.Sprint(r))
				}
			}()
			deleteCtx, cancel := context.WithTimeout(context.Background(), deleteOldTimeout)
			defer cancel()
			if err := a.revokeToken(deleteCtx, login, oldName); err != nil {
				a.logger.Warn("sonarqube: best-effort revoke of old token failed",
					"login", sanitizeForLog(login),
					"old_token_name", sanitizeForLog(oldName),
					"err", sanitizeForLog(err.Error()),
				)
			}
		}()
	}

	return adapter.Result{
		ProviderID:   req.ProviderID,
		CredentialID: req.ProviderID + ":" + tokenName,
		Credential:   tokenValue,
		RotatedAt:    time.Now().UTC(),
	}, nil
}

// Drain waits for all in-flight cleanup goroutines to finish or ctx to expire.
// Called during graceful shutdown to avoid abandoning old-credential deletions.
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

// Revoke revokes the SonarQube token identified by req.CredentialID.
// req.CredentialID must be "<login>:<tokenname>" as returned by Rotate.
// Fails closed if CredentialID is empty.
func (a *Adapter) Revoke(ctx context.Context, req adapter.RevokeRequest) error {
	if req.CredentialID == "" {
		return errors.New("sonarqube revoke: credential_id is required — refusing to skip revocation")
	}
	login, tokenName, err := parseCredentialID(req.CredentialID)
	if err != nil {
		return fmt.Errorf("sonarqube revoke: %w", err)
	}
	if err := a.revokeToken(ctx, login, tokenName); err != nil {
		return fmt.Errorf("sonarqube revoke: %w", err)
	}
	return nil
}

// Status reports whether the token identified by credentialID ("<login>:<tokenname>") still exists.
func (a *Adapter) Status(ctx context.Context, credentialID string) (adapter.CredentialStatus, error) {
	if credentialID == "" {
		return adapter.CredentialStatus{}, errors.New("sonarqube status: credential_id is required")
	}
	login, tokenName, err := parseCredentialID(credentialID)
	if err != nil {
		return adapter.CredentialStatus{}, fmt.Errorf("sonarqube status: %w", err)
	}
	active, err := a.tokenExists(ctx, login, tokenName)
	if err != nil {
		return adapter.CredentialStatus{}, fmt.Errorf("sonarqube status: %w", err)
	}
	return adapter.CredentialStatus{
		ProviderID:   login,
		CredentialID: credentialID,
		Active:       active,
		CheckedAt:    time.Now().UTC(),
	}, nil
}

// ── internal ──────────────────────────────────────────────────────────────────

func (a *Adapter) generateToken(ctx context.Context, login, name, tokenType string) (string, error) {
	form := url.Values{}
	form.Set("login", login)
	form.Set("name", name)
	form.Set("type", tokenType)

	status, body, err := a.do(ctx, http.MethodPost,
		a.baseURL+"/api/user_tokens/generate",
		strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded")
	if err != nil {
		return "", fmt.Errorf("generate token %q: %w", name, err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("generate token %q: unexpected status %d: %s", name, status, body)
	}

	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("generate token %q: parse response: %w", name, err)
	}
	if resp.Token == "" {
		return "", fmt.Errorf("generate token %q: token value missing in response", name)
	}
	return resp.Token, nil
}

func (a *Adapter) revokeToken(ctx context.Context, login, name string) error {
	form := url.Values{}
	form.Set("login", login)
	form.Set("name", name)

	status, body, err := a.do(ctx, http.MethodPost,
		a.baseURL+"/api/user_tokens/revoke",
		strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded")
	if err != nil {
		return fmt.Errorf("revoke token %q: %w", name, err)
	}
	// 204 is success; 404 means already gone (idempotent).
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("revoke token %q: unexpected status %d: %s", name, status, body)
	}
	return nil
}

func (a *Adapter) tokenExists(ctx context.Context, login, tokenName string) (bool, error) {
	endpoint := a.baseURL + "/api/user_tokens/search?login=" + url.QueryEscape(login)
	status, body, err := a.do(ctx, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return false, fmt.Errorf("search tokens for %q: %w", login, err)
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("search tokens for %q: unexpected status %d: %s", login, status, body)
	}

	var resp struct {
		UserTokens []struct {
			Name string `json:"name"`
		} `json:"userTokens"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, fmt.Errorf("search tokens: parse response: %w", err)
	}
	for _, t := range resp.UserTokens {
		if t.Name == tokenName {
			return true, nil
		}
	}
	return false, nil
}

// do executes an authenticated HTTP request and returns (statusCode, body, error).
// The response body is fully consumed and closed; callers never hold an open body reference.
// Callers must not log body — it may contain error messages that echo user-supplied values.
func (a *Adapter) do(ctx context.Context, method, endpoint string, reqBody io.Reader, contentType string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	// SonarQube 10+ Bearer token auth — semantically correct for API tokens
	// and avoids the Basic auth scheme (which SonarQube < 10 required).
	req.Header.Set("Authorization", "Bearer "+a.adminToken)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	return resp.StatusCode, body, nil
}

// parseCredentialID splits "<login>:<tokenname>" into its components.
func parseCredentialID(id string) (login, tokenName string, err error) {
	idx := strings.IndexByte(id, ':')
	if idx < 1 || idx == len(id)-1 {
		return "", "", fmt.Errorf("invalid credential_id %q: expected \"<login>:<tokenname>\"", sanitizeForLog(id))
	}
	return id[:idx], id[idx+1:], nil
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
