package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// ── Config path ───────────────────────────────────────────────────────────────

func (b *Backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config/connection",
		Fields: map[string]*framework.FieldSchema{
			"api_url": {
				Type:        framework.TypeString,
				Description: "Base URL of cred-rotation-api, e.g. https://cred-rotation-api.internal:8443",
				Required:    true,
			},
			"transit_key": {
				Type:        framework.TypeString,
				Description: "Name of the Vault Transit key used to decrypt credential values returned by cred-rotation-api.",
				Default:     "cred-rotation-key",
			},
			"tls_ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM-encoded CA certificate to verify cred-rotation-api's server certificate.",
			},
			"tls_client_cert": {
				Type:        framework.TypeString,
				Description: "PEM-encoded mTLS client certificate (signed by the internal Vault CA).",
			},
			"tls_client_key": {
				Type:        framework.TypeString,
				Description: "PEM-encoded private key for the mTLS client certificate.",
			},
		},
		ExistenceCheck: b.configExists,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.writeConfig},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.writeConfig},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.readConfig},
		},
		HelpSynopsis:    "Configure or read cred-rotation-api connection parameters.",
		HelpDescription: "Stores the API URL, Transit key name, and mTLS certificate material used to connect to cred-rotation-api.",
	}
}

func (b *Backend) configExists(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, "config/connection")
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *Backend) writeConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	apiURL, ok, err := d.GetOkErr("api_url")
	if err != nil {
		return logical.ErrorResponse("api_url: %v", err), nil
	}
	apiURLStr, _ := apiURL.(string)
	if !ok || apiURLStr == "" {
		return logical.ErrorResponse("api_url is required"), nil
	}

	transitKey, _ := d.Get("transit_key").(string)
	tlsCACert, _ := d.Get("tls_ca_cert").(string)
	tlsClientCert, _ := d.Get("tls_client_cert").(string)
	tlsClientKey, _ := d.Get("tls_client_key").(string)

	entry := map[string]interface{}{
		"api_url":         apiURLStr,
		"transit_key":     transitKey,
		"tls_ca_cert":     tlsCACert,
		"tls_client_cert": tlsClientCert,
		"tls_client_key":  tlsClientKey,
	}

	storageEntry, err := logical.StorageEntryJSON("config/connection", entry)
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	if err := req.Storage.Put(ctx, storageEntry); err != nil {
		return nil, fmt.Errorf("store config: %w", err)
	}
	return nil, nil
}

func (b *Backend) readConfig(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("config not found — write config/connection first"), nil
	}
	// Never return TLS private key material through the read path.
	return &logical.Response{Data: map[string]interface{}{
		"api_url":     cfg["api_url"],
		"transit_key": cfg["transit_key"],
	}}, nil
}

// ── Credentials path ──────────────────────────────────────────────────────────

func (b *Backend) pathCredentials() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("provider") + "/" + framework.GenericNameRegex("provider_id"),
		Fields: map[string]*framework.FieldSchema{
			"provider": {
				Type:        framework.TypeString,
				Description: "The adapter name (e.g. auth0, datadog, cloudflare).",
			},
			"provider_id": {
				Type:        framework.TypeString,
				Description: "The provider-specific entity identifier to rotate (e.g. Auth0 client_id).",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:                    b.rotateCreds,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis:    "Rotate credentials for a SaaS provider entity.",
		HelpDescription: "Calls cred-rotation-api to rotate the credential for the given provider and entity, then Transit-decrypts the result before returning it to the caller.",
	}
}

// rotateCreds is the main credential rotation handler.
// Flow: call cred-rotation-api → receive Transit ciphertext → Transit decrypt → return plaintext.
func (b *Backend) rotateCreds(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("plugin not configured — write config/connection first"), nil
	}

	provider, _ := d.Get("provider").(string)
	providerID, _ := d.Get("provider_id").(string)

	// Build the mTLS client for cred-rotation-api.
	httpClient, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("build http client: %w", err)
	}

	// Call cred-rotation-api.
	rawAPIURL, _ := cfg["api_url"].(string)
	apiURL := strings.TrimRight(rawAPIURL, "/")
	rotateResp, err := callRotateAPI(ctx, httpClient, apiURL, provider, providerID)
	if err != nil {
		return logical.ErrorResponse("rotation API call failed: %v", err), nil
	}

	// Transit-decrypt the returned ciphertext.
	// The plugin's Vault token (VAULT_TOKEN env var, set by Vault on plugin launch)
	// has the vault-plugin-policy which allows transit/decrypt/cred-rotation-key.
	transitKey, _ := cfg["transit_key"].(string)
	if transitKey == "" {
		transitKey = "cred-rotation-key"
	}
	plaintext, err := transitDecrypt(ctx, transitKey, rotateResp.EncryptedValue)
	if err != nil {
		return nil, fmt.Errorf("transit decrypt: %w", err)
	}

	return &logical.Response{Data: map[string]interface{}{
		"credential":  plaintext,
		"provider":    provider,
		"provider_id": providerID,
		"rotated_at":  rotateResp.RotatedAt.UTC().Format(time.RFC3339),
	}}, nil
}

// ── Transit decrypt ───────────────────────────────────────────────────────────

// transitDecrypt decrypts a vault:v1:... ciphertext using the Vault Transit API.
// The plugin is launched by Vault with VAULT_ADDR and VAULT_TOKEN already set;
// the token carries vault-plugin-policy (transit/decrypt only).
func transitDecrypt(ctx context.Context, keyName, ciphertext string) (string, error) {
	vc, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return "", fmt.Errorf("new vault client: %w", err)
	}

	secret, err := vc.Logical().WriteWithContext(ctx,
		"transit/decrypt/"+keyName,
		map[string]interface{}{"ciphertext": ciphertext},
	)
	if err != nil {
		return "", fmt.Errorf("vault transit/decrypt: %w", err)
	}
	if secret == nil {
		return "", fmt.Errorf("transit/decrypt: empty response")
	}

	encoded, ok := secret.Data["plaintext"].(string)
	if !ok || encoded == "" {
		return "", fmt.Errorf("transit/decrypt: missing plaintext in response")
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("transit/decrypt: base64 decode: %w", err)
	}
	return string(raw), nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

type rotateAPIResponse struct {
	ProviderID     string    `json:"provider_id"`
	EncryptedValue string    `json:"encrypted_value"`
	RotatedAt      time.Time `json:"rotated_at"`
}

func callRotateAPI(ctx context.Context, client *http.Client, apiURL, provider, providerID string) (*rotateAPIResponse, error) {
	body := fmt.Sprintf(`{"provider":%q,"provider_id":%q}`, provider, providerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/v1/credentials/rotate", strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API status %d: %s", resp.StatusCode, raw)
	}

	var out rotateAPIResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if out.EncryptedValue == "" {
		return nil, fmt.Errorf("empty encrypted_value in response")
	}
	return &out, nil
}

func getConfig(ctx context.Context, storage logical.Storage) (map[string]interface{}, error) {
	entry, err := storage.Get(ctx, "config/connection")
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if entry == nil {
		return nil, nil
	}
	var cfg map[string]interface{}
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return cfg, nil
}

func buildHTTPClient(cfg map[string]interface{}) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}

	if ca, _ := cfg["tls_ca_cert"].(string); ca != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(ca)) {
			return nil, fmt.Errorf("build http client: invalid CA cert PEM")
		}
		tlsConfig.RootCAs = pool
	}

	clientCert, _ := cfg["tls_client_cert"].(string)
	clientKey, _ := cfg["tls_client_key"].(string)
	if clientCert != "" && clientKey != "" {
		cert, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err != nil {
			return nil, fmt.Errorf("build http client: parse client cert/key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   30 * time.Second,
	}, nil
}
