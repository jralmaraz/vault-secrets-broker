package backend

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// ── config/connection ─────────────────────────────────────────────────────────

func (b *Backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config/connection",
		Fields: map[string]*framework.FieldSchema{
			"domain": {
				Type:        framework.TypeString,
				Description: "Auth0 tenant domain, e.g. your-tenant.auth0.com",
				Required:    true,
			},
			"client_id": {
				Type:        framework.TypeString,
				Description: "client_id of the Auth0 Machine-to-Machine app with Management API access.",
				Required:    true,
			},
			"client_secret": {
				Type:        framework.TypeString,
				Description: "client_secret of the Auth0 M2M Management API application. Stored seal-wrapped.",
				Required:    true,
			},
			"audience": {
				Type:        framework.TypeString,
				Description: "Auth0 Management API audience, e.g. https://your-tenant.auth0.com/api/v2/",
				Required:    true,
			},
			"transit_key": {
				Type: framework.TypeString,
				Description: "Name of a Vault Transit key used to encrypt the rotated credential before " +
					"returning it. If empty the plaintext credential is returned (still protected by Vault TLS).",
				Default: "",
			},
		},
		ExistenceCheck: b.configExists,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.writeConfig},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.writeConfig},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.readConfig},
		},
		HelpSynopsis:    "Configure or read Auth0 Management API connection parameters.",
		HelpDescription: "Stores the Auth0 tenant domain, M2M client credentials, and optional Transit key name. The client_secret is stored under Vault's seal-wrapped storage path.",
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
	domain, _, err := d.GetOkErr("domain")
	if err != nil {
		return logical.ErrorResponse("domain: %v", err), nil
	}
	domainStr, _ := domain.(string)
	if domainStr == "" {
		return logical.ErrorResponse("domain is required"), nil
	}

	clientID, _, err := d.GetOkErr("client_id")
	if err != nil {
		return logical.ErrorResponse("client_id: %v", err), nil
	}
	clientIDStr, _ := clientID.(string)
	if clientIDStr == "" {
		return logical.ErrorResponse("client_id is required"), nil
	}

	clientSecret, _, err := d.GetOkErr("client_secret")
	if err != nil {
		return logical.ErrorResponse("client_secret: %v", err), nil
	}
	clientSecretStr, _ := clientSecret.(string)
	if clientSecretStr == "" {
		return logical.ErrorResponse("client_secret is required"), nil
	}

	audience, _, err := d.GetOkErr("audience")
	if err != nil {
		return logical.ErrorResponse("audience: %v", err), nil
	}
	audienceStr, _ := audience.(string)
	if audienceStr == "" {
		return logical.ErrorResponse("audience is required"), nil
	}

	transitKey, _ := d.Get("transit_key").(string)

	entry := map[string]interface{}{
		"domain":        domainStr,
		"client_id":     clientIDStr,
		"client_secret": clientSecretStr,
		"audience":      audienceStr,
		"transit_key":   transitKey,
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
		return logical.ErrorResponse("not configured — write config/connection first"), nil
	}
	// Never return client_secret through the read path.
	return &logical.Response{Data: map[string]interface{}{
		"domain":      cfg["domain"],
		"client_id":   cfg["client_id"],
		"audience":    cfg["audience"],
		"transit_key": cfg["transit_key"],
	}}, nil
}

// ── config/rotate-root ────────────────────────────────────────────────────────

// pathRotateRoot adds config/rotate-root, mirroring the Vault database
// "rotate-root" pattern: the plugin uses its current Management API credentials
// to rotate its OWN client_secret, then stores the new one.  After this call,
// only Vault knows the secret — the operator-typed value is gone.
func (b *Backend) pathRotateRoot() *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.rotateRoot,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis: "Rotate the Management API client_secret that Vault uses to authenticate with Auth0.",
		HelpDescription: `Calls the Auth0 Management API to rotate the M2M application's own client_secret,
then stores the new secret in Vault's seal-wrapped config storage.

After this call the original secret is permanently invalidated — only Vault knows
the current secret.  Call this path periodically to limit secret exposure windows.

No parameters are required.  The current credentials in config/connection are used.`,
	}
}

func (b *Backend) rotateRoot(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("not configured — write config/connection first"), nil
	}

	domain, _ := cfg["domain"].(string)
	clientID, _ := cfg["client_id"].(string)
	clientSecret, _ := cfg["client_secret"].(string)
	audience, _ := cfg["audience"].(string)

	// The plugin rotates its OWN client_secret (clientID = the M2M app itself).
	client := newAuth0Client(domain, clientID, clientSecret, audience)
	newSecret, err := client.rotateSecret(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("rotate-root: Auth0 rotation failed: %w", err)
	}

	// Store the new secret — the old one is already invalidated by Auth0.
	cfg["client_secret"] = newSecret
	storageEntry, err := logical.StorageEntryJSON("config/connection", cfg)
	if err != nil {
		return nil, fmt.Errorf("rotate-root: encode updated config: %w", err)
	}
	if err := req.Storage.Put(ctx, storageEntry); err != nil {
		return nil, fmt.Errorf("rotate-root: store updated config: %w", err)
	}

	// Return only metadata — never the new secret itself.
	return &logical.Response{Data: map[string]interface{}{
		"rotated_at": time.Now().UTC().Format(time.RFC3339),
		"client_id":  clientID,
		"message":    "Management API client_secret rotated and stored. The previous secret is permanently invalidated.",
	}}, nil
}

// ── creds/<application_client_id> ────────────────────────────────────────────

func (b *Backend) pathCreds() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameWithAtRegex("application_client_id"),
		Fields: map[string]*framework.FieldSchema{
			"application_client_id": {
				Type:        framework.TypeString,
				Description: "The Auth0 application client_id whose client_secret will be rotated.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:                    b.rotateCreds,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis:    "Rotate an Auth0 application's client_secret.",
		HelpDescription: "Calls the Auth0 Management API to atomically rotate the client_secret for the given application. Returns the new credential, optionally Transit-encrypted.",
	}
}

func (b *Backend) rotateCreds(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("not configured — write config/connection first"), nil
	}

	appClientID, _ := d.Get("application_client_id").(string)
	if appClientID == "" {
		return logical.ErrorResponse("application_client_id is required"), nil
	}

	domain, _ := cfg["domain"].(string)
	clientID, _ := cfg["client_id"].(string)
	clientSecret, _ := cfg["client_secret"].(string)
	audience, _ := cfg["audience"].(string)
	transitKey, _ := cfg["transit_key"].(string)

	client := newAuth0Client(domain, clientID, clientSecret, audience)
	newSecret, err := client.rotateSecret(ctx, appClientID)
	if err != nil {
		return logical.ErrorResponse("rotation failed: %v", err), nil
	}

	data := map[string]interface{}{
		"application_client_id": appClientID,
		"rotated_at":            time.Now().UTC().Format(time.RFC3339),
	}

	if transitKey != "" {
		// Transit-encrypt before returning so the credential never appears in
		// plaintext in Vault audit logs or intermediate storage.
		ciphertext, encErr := transitEncrypt(ctx, transitKey, newSecret)
		if encErr != nil {
			return nil, fmt.Errorf("transit encrypt: %w", encErr)
		}
		data["credential_ciphertext"] = ciphertext
		data["transit_key"] = transitKey
	} else {
		data["credential"] = newSecret
	}

	internal := map[string]interface{}{
		"application_client_id": appClientID,
	}
	return b.Secret(SecretTypeAuth0Creds).Response(data, internal), nil
}

func (b *Backend) renewCreds(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return framework.LeaseExtend(0, 0, b.System())(ctx, req, d)
}

func (b *Backend) revokeCreds(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	appClientID, ok := req.Secret.InternalData["application_client_id"].(string)
	if !ok || appClientID == "" {
		return nil, errors.New("revoke: missing application_client_id in internal data — refusing to skip revocation")
	}
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New("revoke: plugin not configured")
	}
	domain, _ := cfg["domain"].(string)
	clientID, _ := cfg["client_id"].(string)
	clientSecret, _ := cfg["client_secret"].(string)
	audience, _ := cfg["audience"].(string)

	client := newAuth0Client(domain, clientID, clientSecret, audience)
	// Rotate to invalidate the issued credential. The new value is discarded.
	if _, err := client.rotateSecret(ctx, appClientID); err != nil {
		return nil, fmt.Errorf("revoke: Auth0 rotation to invalidate credential failed: %w", err)
	}
	return nil, nil
}

// ── status/<application_client_id> ───────────────────────────────────────────

func (b *Backend) pathStatus() *framework.Path {
	return &framework.Path{
		Pattern: "status/" + framework.GenericNameWithAtRegex("application_client_id"),
		Fields: map[string]*framework.FieldSchema{
			"application_client_id": {
				Type:        framework.TypeString,
				Description: "The Auth0 application client_id to check.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.checkStatus},
		},
		HelpSynopsis:    "Check whether an Auth0 application is reachable.",
		HelpDescription: "Uses the Management API to verify the application exists. Returns active=true when the Auth0 API responds 200.",
	}
}

func (b *Backend) checkStatus(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("not configured — write config/connection first"), nil
	}

	appClientID, _ := d.Get("application_client_id").(string)
	if appClientID == "" {
		return logical.ErrorResponse("application_client_id is required"), nil
	}

	domain, _ := cfg["domain"].(string)
	clientID, _ := cfg["client_id"].(string)
	clientSecret, _ := cfg["client_secret"].(string)
	audience, _ := cfg["audience"].(string)

	client := newAuth0Client(domain, clientID, clientSecret, audience)
	active, err := client.appActive(ctx, appClientID)
	if err != nil {
		return logical.ErrorResponse("status check failed: %v", err), nil
	}

	return &logical.Response{Data: map[string]interface{}{
		"application_client_id": appClientID,
		"active":                active,
		"checked_at":            time.Now().UTC().Format(time.RFC3339),
	}}, nil
}

// ── Transit encryption ────────────────────────────────────────────────────────

// transitEncrypt encrypts plaintext using the Vault Transit API.
// The plugin is launched by Vault with VAULT_ADDR and VAULT_TOKEN already set.
func transitEncrypt(ctx context.Context, keyName, plaintext string) (string, error) {
	vc, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return "", fmt.Errorf("new vault client: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	secret, err := vc.Logical().WriteWithContext(ctx,
		"transit/encrypt/"+keyName,
		map[string]interface{}{"plaintext": encoded},
	)
	if err != nil {
		return "", fmt.Errorf("vault transit/encrypt: %w", err)
	}
	if secret == nil {
		return "", fmt.Errorf("transit/encrypt: empty response")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok || ciphertext == "" {
		return "", fmt.Errorf("transit/encrypt: missing ciphertext in response")
	}
	return ciphertext, nil
}

// ── Storage helpers ───────────────────────────────────────────────────────────

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
