// cred-rotation-api is the credential rotation abstraction layer.
// It authenticates to Vault via AppRole (or token in dev mode), reads adapter
// configuration from KV v2, decrypts secrets with Vault Transit, and serves an
// mTLS HTTP API that Vault secrets engine plugins call to rotate SaaS credentials.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	auth0adapter "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/auth0"
	githubadapter "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/github"
	splunkadapter "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/splunk"
	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/server"
	vclient "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/vault"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("startup failed", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ── Vault authentication ──────────────────────────────────────────────────
	cfg := vclient.NewFromEnv()
	vc, err := vclient.New(cfg)
	if err != nil {
		return fmt.Errorf("vault client: %w", err)
	}
	logger.Info("authenticated to Vault", "addr", cfg.Address)

	transitKeyName := envOr("VAULT_TRANSIT_KEY", "cred-rotation-key")

	// ── Load adapter configs from KV v2, decrypt secrets with Transit ─────────
	auth0Cfg, err := loadAuth0Config(ctx, vc, transitKeyName)
	if err != nil {
		return fmt.Errorf("load auth0 config: %w", err)
	}
	auth0Adapter, err := auth0adapter.New(auth0Cfg)
	if err != nil {
		return fmt.Errorf("build auth0 adapter: %w", err)
	}

	splunkCfg, err := loadSplunkConfig(ctx, vc, transitKeyName)
	if err != nil {
		return fmt.Errorf("load splunk config: %w", err)
	}
	splunkAdapter, err := splunkadapter.New(splunkCfg)
	if err != nil {
		return fmt.Errorf("build splunk adapter: %w", err)
	}

	githubCfg, err := loadGitHubConfig(ctx, vc, transitKeyName)
	if err != nil {
		return fmt.Errorf("load github config: %w", err)
	}
	githubAdapter, err := githubadapter.New(githubCfg)
	if err != nil {
		return fmt.Errorf("build github adapter: %w", err)
	}

	reg := adapter.NewRegistry()
	reg.Register(auth0Adapter)
	reg.Register(splunkAdapter)
	reg.Register(githubAdapter)
	logger.Info("adapters registered", "providers", reg.Names())

	// ── mTLS TLS config ───────────────────────────────────────────────────────
	tlsConfig, err := buildTLSConfig(ctx, vc, logger)
	if err != nil {
		return fmt.Errorf("build TLS config: %w", err)
	}

	// ── HTTP server ───────────────────────────────────────────────────────────
	addr := envOr("LISTEN_ADDR", ":8443")
	srv, err := server.New(server.Config{
		Addr:           addr,
		TLSConfig:      tlsConfig,
		Registry:       reg,
		VaultClient:    vc,
		TransitKeyName: transitKeyName,
		Logger:         logger,
	})
	if err != nil {
		return fmt.Errorf("build server: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServeTLS()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		return srv.Shutdown(context.Background())
	case err := <-errCh:
		return fmt.Errorf("server: %w", err)
	}
}

// loadAuth0Config reads Auth0 adapter configuration from Vault KV v2 and
// decrypts the management client_secret using Transit before returning.
func loadAuth0Config(ctx context.Context, vc *vclient.Client, transitKey string) (auth0adapter.Config, error) {
	const kvPath = "secret/data/cred-rotation-api/adapters/auth0"

	data, err := vc.KVGet(ctx, kvPath)
	if err != nil {
		return auth0adapter.Config{}, fmt.Errorf("kv read %s: %w", kvPath, err)
	}

	domain, err := vclient.StringField(data, "domain")
	if err != nil {
		return auth0adapter.Config{}, err
	}
	clientID, err := vclient.StringField(data, "mgmt_client_id")
	if err != nil {
		return auth0adapter.Config{}, err
	}
	audience, err := vclient.StringField(data, "mgmt_audience")
	if err != nil {
		return auth0adapter.Config{}, err
	}
	encryptedSecret, err := vclient.StringField(data, "mgmt_client_secret_encrypted")
	if err != nil {
		return auth0adapter.Config{}, err
	}

	// Decrypt the client_secret with Transit. It is stored as vault:v1:... ciphertext.
	plainSecret, err := vc.TransitDecrypt(ctx, transitKey, encryptedSecret)
	if err != nil {
		return auth0adapter.Config{}, fmt.Errorf("transit decrypt client_secret: %w", err)
	}

	return auth0adapter.Config{
		Domain:       domain,
		ClientID:     clientID,
		ClientSecret: plainSecret,
		Audience:     audience,
	}, nil
}

// loadSplunkConfig reads Splunk adapter configuration from Vault KV v2 and
// decrypts the management token using Transit before returning.
func loadSplunkConfig(ctx context.Context, vc *vclient.Client, transitKey string) (splunkadapter.Config, error) {
	const kvPath = "secret/data/cred-rotation-api/adapters/splunk"

	data, err := vc.KVGet(ctx, kvPath)
	if err != nil {
		return splunkadapter.Config{}, fmt.Errorf("kv read %s: %w", kvPath, err)
	}

	baseURL, err := vclient.StringField(data, "base_url")
	if err != nil {
		return splunkadapter.Config{}, err
	}
	encryptedToken, err := vclient.StringField(data, "auth_token_encrypted")
	if err != nil {
		return splunkadapter.Config{}, err
	}

	plainToken, err := vc.TransitDecrypt(ctx, transitKey, encryptedToken)
	if err != nil {
		return splunkadapter.Config{}, fmt.Errorf("transit decrypt auth_token: %w", err)
	}

	// Optional fields — absent means Splunk default.
	cfg := splunkadapter.Config{
		BaseURL:   baseURL,
		AuthToken: plainToken,
	}
	if idx, _ := vclient.StringField(data, "default_index"); idx != "" {
		cfg.DefaultIndex = idx
	}
	if st, _ := vclient.StringField(data, "default_sourcetype"); st != "" {
		cfg.DefaultSourcetype = st
	}
	if caCert, _ := vclient.StringField(data, "ca_cert"); caCert != "" {
		cfg.CACert = caCert
	}
	return cfg, nil
}

// loadGitHubConfig reads GitHub adapter configuration from Vault KV v2 and
// decrypts the admin PAT using Transit before returning.
func loadGitHubConfig(ctx context.Context, vc *vclient.Client, transitKey string) (githubadapter.Config, error) {
	const kvPath = "secret/data/cred-rotation-api/adapters/github"

	data, err := vc.KVGet(ctx, kvPath)
	if err != nil {
		return githubadapter.Config{}, fmt.Errorf("kv read %s: %w", kvPath, err)
	}

	encryptedPAT, err := vclient.StringField(data, "admin_pat_encrypted")
	if err != nil {
		return githubadapter.Config{}, err
	}

	plainPAT, err := vc.TransitDecrypt(ctx, transitKey, encryptedPAT)
	if err != nil {
		return githubadapter.Config{}, fmt.Errorf("transit decrypt admin_pat: %w", err)
	}

	cfg := githubadapter.Config{AdminPAT: plainPAT}
	// base_url is optional — absent means api.github.com (production).
	if baseURL, _ := vclient.StringField(data, "base_url"); baseURL != "" {
		cfg.BaseURL = baseURL
	}
	return cfg, nil
}

// buildTLSConfig issues a server certificate from Vault PKI and assembles the mTLS config.
// In dev mode (VAULT_SKIP_PKI=true), it falls back to a plain HTTP server config.
func buildTLSConfig(ctx context.Context, vc *vclient.Client, logger *slog.Logger) (*tls.Config, error) { //nolint:unparam
	if os.Getenv("VAULT_SKIP_PKI") == "true" {
		// Dev-only: no mTLS. The server will call ListenAndServeTLS with an empty cert,
		// which will fail — set LISTEN_ADDR=:8080 and use ListenAndServe directly.
		// For now, return nil to surface the config path clearly.
		logger.Warn("VAULT_SKIP_PKI=true: mTLS disabled — for development only")
		return nil, fmt.Errorf("VAULT_SKIP_PKI set but full TLS bypass not implemented; remove the flag and run phase2-setup.sh")
	}

	caPath := envOr("VAULT_CACERT", "vault/certs/internal-ca.crt")
	caPool, err := vclient.LoadCACertPool(caPath)
	if err != nil {
		return nil, fmt.Errorf("load CA cert pool from %s: %w", caPath, err)
	}

	commonName := envOr("TLS_COMMON_NAME", "cred-rotation-api.internal")
	cert, err := vc.IssuePKICert(ctx, "internal-mtls-server", commonName, nil)
	if err != nil {
		return nil, fmt.Errorf("issue PKI server cert: %w", err)
	}
	logger.Info("PKI server certificate issued", "common_name", commonName)

	tlsCfg, err := vclient.TLSConfigFromIssuedCert(cert, caPool)
	if err != nil {
		return nil, fmt.Errorf("build TLS config from issued cert: %w", err)
	}
	return tlsCfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
