// Package vault wraps the Vault API client for the operations cred-rotation-api needs:
// JWT/OIDC + SPIFFE workload identity auth, Transit encrypt/decrypt, KV v2 reads, and PKI certificate issuance.
package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Client wraps the Vault API client and exposes only the operations used by cred-rotation-api.
type Client struct {
	vc *vaultapi.Client
}

// Config holds the parameters needed to authenticate and connect to Vault.
type Config struct {
	// Address is the Vault server URL (e.g. "http://127.0.0.1:8200").
	Address string

	// Token is used directly (dev mode / root token). Highest priority.
	Token string

	// JWT/OIDC auth — present a JWT to Vault's auth/jwt method.
	// JWTMountPath: Vault auth mount, e.g. "auth/jwt/login" (default).
	// JWTRole: the Vault JWT role name.
	// JWTToken: raw JWT string (e.g. from env VAULT_JWT_TOKEN). Used if SPIFFE is not available.
	JWTMountPath string
	JWTRole      string
	JWTToken     string

	// SPIFFE workload identity.
	// If SPIFFESocket is set, a JWT-SVID is fetched from the SPIRE workload API
	// and presented to Vault JWT auth. Takes priority over JWTToken.
	// Format: "unix:///run/spire/agent.sock" or "tcp://spire-agent:8081".
	// If empty, falls back to VAULT_JWT_TOKEN, then AppRole.
	SPIFFESocket   string
	SPIFFEAudience string // Vault audience claim for the JWT-SVID (required when SPIFFESocket is set)

	// AppRole credentials. Local-dev fallback when no other auth method is configured.
	RoleID   string
	SecretID string

	// CACertPath is the path to the PEM-encoded CA cert for mTLS verification.
	// Optional; leave empty in dev mode.
	CACertPath string
}

// NewFromEnv builds a Config from the standard environment variables.
func NewFromEnv() Config {
	return Config{
		Address:        envOr("VAULT_ADDR", "http://127.0.0.1:8200"),
		Token:          os.Getenv("VAULT_TOKEN"),
		JWTMountPath:   envOr("VAULT_JWT_MOUNT", "auth/jwt/login"),
		JWTRole:        os.Getenv("VAULT_JWT_ROLE"),
		JWTToken:       os.Getenv("VAULT_JWT_TOKEN"),
		SPIFFESocket:   os.Getenv("SPIFFE_ENDPOINT_SOCKET"),
		SPIFFEAudience: os.Getenv("VAULT_SPIFFE_AUDIENCE"),
		RoleID:         os.Getenv("VAULT_APPROLE_ROLE_ID"),
		SecretID:       os.Getenv("VAULT_APPROLE_SECRET_ID"),
		CACertPath:     os.Getenv("VAULT_CACERT"),
	}
}

// New authenticates to Vault and returns a ready Client.
func New(cfg Config) (*Client, error) {
	vcfg := vaultapi.DefaultConfig()
	vcfg.Address = cfg.Address

	if cfg.CACertPath != "" {
		if err := vcfg.ConfigureTLS(&vaultapi.TLSConfig{CACert: cfg.CACertPath}); err != nil {
			return nil, fmt.Errorf("vault: configure TLS: %w", err)
		}
	}

	vc, err := vaultapi.NewClient(vcfg)
	if err != nil {
		return nil, fmt.Errorf("vault: new client: %w", err)
	}

	switch {
	case cfg.Token != "":
		vc.SetToken(cfg.Token)

	case cfg.SPIFFESocket != "":
		jwt, err := fetchSPIFFEJWT(context.Background(), cfg.SPIFFESocket, cfg.SPIFFEAudience)
		if err != nil {
			return nil, fmt.Errorf("vault: SPIFFE JWT-SVID: %w", err)
		}
		if err := loginJWT(vc, cfg.JWTMountPath, cfg.JWTRole, jwt); err != nil {
			return nil, err
		}

	case cfg.JWTToken != "":
		if err := loginJWT(vc, cfg.JWTMountPath, cfg.JWTRole, cfg.JWTToken); err != nil {
			return nil, err
		}

	case cfg.RoleID != "" && cfg.SecretID != "":
		secret, err := vc.Logical().Write("auth/approle/login", map[string]interface{}{
			"role_id":   cfg.RoleID,
			"secret_id": cfg.SecretID,
		})
		if err != nil {
			return nil, fmt.Errorf("vault: AppRole login: %w", err)
		}
		if secret == nil || secret.Auth == nil {
			return nil, errors.New("vault: AppRole login returned empty auth")
		}
		vc.SetToken(secret.Auth.ClientToken)

	default:
		return nil, errors.New("vault: must supply VAULT_TOKEN, SPIFFE_ENDPOINT_SOCKET, VAULT_JWT_TOKEN, or VAULT_APPROLE_ROLE_ID+VAULT_APPROLE_SECRET_ID")
	}

	return &Client{vc: vc}, nil
}

// loginJWT authenticates to Vault via the JWT auth method and sets the client token.
func loginJWT(vc *vaultapi.Client, mountPath, role, jwt string) error {
	params := map[string]interface{}{"jwt": jwt}
	if role != "" {
		params["role"] = role
	}
	secret, err := vc.Logical().Write(mountPath, params)
	if err != nil {
		return fmt.Errorf("vault: JWT auth login: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return errors.New("vault: JWT auth returned empty auth")
	}
	vc.SetToken(secret.Auth.ClientToken)
	return nil
}

// fetchSPIFFEJWT retrieves a JWT-SVID from the SPIFFE workload API.
// The returned string is the raw JWT (three base64url-encoded parts separated by dots).
func fetchSPIFFEJWT(ctx context.Context, socketAddr, audience string) (string, error) {
	if audience == "" {
		return "", errors.New("SPIFFE: audience is required for JWT-SVID fetch (set VAULT_SPIFFE_AUDIENCE)")
	}
	source, err := workloadapi.NewJWTSource(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketAddr)),
	)
	if err != nil {
		return "", fmt.Errorf("SPIFFE: connect to workload API at %s: %w", socketAddr, err)
	}
	defer func() { _ = source.Close() }()

	svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
	if err != nil {
		return "", fmt.Errorf("SPIFFE: fetch JWT-SVID (audience=%s): %w", audience, err)
	}
	return svid.Marshal(), nil
}

// TransitEncrypt encrypts plaintext (raw bytes) using the named Transit key.
// Returns the vault:v1:... ciphertext string.
func (c *Client) TransitEncrypt(ctx context.Context, keyName, plaintext string) (string, error) {
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	secret, err := c.vc.Logical().WriteWithContext(ctx,
		"transit/encrypt/"+keyName,
		map[string]interface{}{"plaintext": encoded},
	)
	if err != nil {
		return "", fmt.Errorf("vault transit encrypt: %w", err)
	}
	ct, ok := secret.Data["ciphertext"].(string)
	if !ok || ct == "" {
		return "", errors.New("vault transit encrypt: missing ciphertext in response")
	}
	return ct, nil
}

// TransitDecrypt decrypts a vault:v1:... ciphertext and returns the plaintext string.
func (c *Client) TransitDecrypt(ctx context.Context, keyName, ciphertext string) (string, error) {
	secret, err := c.vc.Logical().WriteWithContext(ctx,
		"transit/decrypt/"+keyName,
		map[string]interface{}{"ciphertext": ciphertext},
	)
	if err != nil {
		return "", fmt.Errorf("vault transit decrypt: %w", err)
	}
	encoded, ok := secret.Data["plaintext"].(string)
	if !ok || encoded == "" {
		return "", errors.New("vault transit decrypt: missing plaintext in response")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("vault transit decrypt: base64 decode: %w", err)
	}
	return string(raw), nil
}

// KVGet reads a key-value v2 secret at the given path and returns the data map.
func (c *Client) KVGet(ctx context.Context, path string) (map[string]interface{}, error) {
	secret, err := c.vc.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vault kv get %s: %w", path, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("vault kv get %s: not found", path)
	}
	// KV v2 wraps data under secret.Data["data"].
	if data, ok := secret.Data["data"].(map[string]interface{}); ok {
		return data, nil
	}
	return secret.Data, nil
}

// IssuedCert holds the TLS certificate and private key returned by Vault PKI.
type IssuedCert struct {
	Certificate string // PEM
	PrivateKey  string // PEM
	CAChain     string // PEM (CA cert for building the pool)
}

// IssuePKICert issues a certificate from the named PKI role.
// commonName should be set to the service's DNS name or identity.
func (c *Client) IssuePKICert(ctx context.Context, role, commonName string, altNames []string) (*IssuedCert, error) {
	params := map[string]interface{}{
		"common_name": commonName,
		"ttl":         "24h",
	}
	if len(altNames) > 0 {
		params["alt_names"] = altNames
	}
	secret, err := c.vc.Logical().WriteWithContext(ctx, "pki/issue/"+role, params)
	if err != nil {
		return nil, fmt.Errorf("vault pki issue %s: %w", role, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("vault pki issue %s: empty response", role)
	}

	cert, _ := secret.Data["certificate"].(string)
	key, _ := secret.Data["private_key"].(string)

	// ca_chain is []interface{}; join into PEM bundle.
	chain := ""
	if raw, ok := secret.Data["ca_chain"].([]interface{}); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok {
				chain += s + "\n"
			}
		}
	}
	if ca, ok := secret.Data["issuing_ca"].(string); ok && chain == "" {
		chain = ca
	}

	if cert == "" || key == "" {
		return nil, fmt.Errorf("vault pki issue %s: missing certificate or private_key in response", role)
	}
	return &IssuedCert{Certificate: cert, PrivateKey: key, CAChain: chain}, nil
}

// LoadCACertPool builds a *x509.CertPool from the PKI CA certificate stored at caPath.
func LoadCACertPool(caPath string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(filepath.Clean(caPath))
	if err != nil {
		return nil, fmt.Errorf("load CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("load CA cert: no valid PEM blocks found")
	}
	return pool, nil
}

// TLSConfigFromIssuedCert builds a *tls.Config suitable for an mTLS server
// from an IssuedCert and the CA pool. TLS 1.3 minimum; client auth required.
func TLSConfigFromIssuedCert(cert *IssuedCert, caPool *x509.CertPool) (*tls.Config, error) {
	tlsCert, err := tls.X509KeyPair([]byte(cert.Certificate), []byte(cert.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parse server cert/key: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// KVGetString is a convenience helper that reads a single string field from a KV v2 path.
func (c *Client) KVGetString(ctx context.Context, path, field string) (string, error) {
	data, err := c.KVGet(ctx, path)
	if err != nil {
		return "", err
	}
	v, ok := data[field]
	if !ok {
		return "", fmt.Errorf("vault kv get %s: field %q not found", path, field)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("vault kv get %s: field %q is not a string", path, field)
	}
	return s, nil
}

// StringField extracts a string from a JSON-unmarshaled map[string]interface{} safely.
func StringField(data map[string]interface{}, key string) (string, error) {
	v, ok := data[key]
	if !ok {
		return "", fmt.Errorf("field %q not present", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("field %q is not a string (got %T)", key, v)
	}
	return s, nil
}

// MustStringField is like StringField but returns "" on missing rather than an error.
// Use only for optional fields.
func MustStringField(data map[string]interface{}, key string) string {
	s, _ := StringField(data, key)
	return s
}

// jsonString serialises v for logging/debugging without panicking.
func jsonString(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<marshal error: %v>", err)
	}
	return string(b)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Ensure jsonString is used (avoids "declared but not used" if optimised away).
var _ = jsonString
