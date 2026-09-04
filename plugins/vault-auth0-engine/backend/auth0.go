// Package backend provides an Auth0 Management API client used internally by the
// vault-auth0-engine plugin. It is not intended for use outside this package.
package backend

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
)

const (
	tokenRefreshBuf   = 5 * time.Minute
	httpClientTimeout = 15 * time.Second
)

// auth0Client holds cached Management API token state and is safe for concurrent use.
type auth0Client struct {
	domain       string
	clientID     string
	clientSecret string
	audience     string
	baseURL      string

	httpClient *http.Client

	mu          sync.RWMutex
	mgmtToken   string
	tokenExpiry time.Time
}

func newAuth0Client(domain, clientID, clientSecret, audience string) *auth0Client {
	return &auth0Client{
		domain:       domain,
		clientID:     clientID,
		clientSecret: clientSecret,
		audience:     audience,
		baseURL:      "https://" + domain,
		httpClient: &http.Client{
			Timeout: httpClientTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
			},
		},
	}
}

// rotateSecret calls POST /api/v2/clients/{clientID}/rotate-secret and returns
// the new client_secret. Auth0 invalidates the previous secret atomically.
func (c *auth0Client) rotateSecret(ctx context.Context, clientID string) (string, error) {
	token, err := c.managementToken(ctx)
	if err != nil {
		return "", fmt.Errorf("auth0: get management token: %w", err)
	}

	url := fmt.Sprintf("%s/api/v2/clients/%s/rotate-secret", c.baseURL, clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("auth0: build rotate request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth0: rotate http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth0: rotate status %d: %s", resp.StatusCode, body)
	}

	var out struct {
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("auth0: parse rotate response: %w", err)
	}
	if out.ClientSecret == "" {
		return "", errors.New("auth0: empty client_secret in rotate response")
	}
	return out.ClientSecret, nil
}

// appActive returns true when GET /api/v2/clients/{clientID} responds 200.
func (c *auth0Client) appActive(ctx context.Context, clientID string) (bool, error) {
	token, err := c.managementToken(ctx)
	if err != nil {
		return false, fmt.Errorf("auth0: get management token: %w", err)
	}

	url := fmt.Sprintf("%s/api/v2/clients/%s?fields=client_id&include_fields=true", c.baseURL, clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("auth0: build status request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("auth0: status http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}

// managementToken returns a cached M2M token, fetching a fresh one when within
// tokenRefreshBuf of expiry. Safe for concurrent use.
func (c *auth0Client) managementToken(ctx context.Context) (string, error) {
	c.mu.RLock()
	if c.mgmtToken != "" && time.Until(c.tokenExpiry) > tokenRefreshBuf {
		tok := c.mgmtToken
		c.mu.RUnlock()
		return tok, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check under write lock.
	if c.mgmtToken != "" && time.Until(c.tokenExpiry) > tokenRefreshBuf {
		return c.mgmtToken, nil
	}

	body := fmt.Sprintf(
		`{"client_id":%q,"client_secret":%q,"audience":%q,"grant_type":"client_credentials"}`,
		c.clientID, c.clientSecret, c.audience,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/oauth/token", strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, raw)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("empty access_token in token response")
	}

	c.mgmtToken = tok.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return c.mgmtToken, nil
}
