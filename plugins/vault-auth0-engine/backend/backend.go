// Package backend implements the vault-auth0-engine Vault secrets engine plugin.
// It talks directly to the Auth0 Management API to rotate application client_secrets,
// storing Management API credentials in Vault's seal-wrapped storage for defense-in-depth.
//
// Paths:
//
//	config/connection                           — store Auth0 Management API credentials
//	creds/<application_client_id>               — rotate and return a new client_secret
//	status/<application_client_id>              — check whether the application is active
package backend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const pluginVersion = "v0.1.0"

// Backend is the secrets engine implementation.
type Backend struct {
	*framework.Backend
}

// Factory is the factory function passed to plugin.Serve.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &Backend{}
	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,
		Paths:       b.paths(),
		PathsSpecial: &logical.Paths{
			// Seal-wrap the config path so Management API credentials get an extra
			// encryption layer (barrier encryption + seal encryption) at rest.
			SealWrapStorage: []string{"config/"},
		},
		RunningVersion: pluginVersion,
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, fmt.Errorf("vault-auth0-engine setup: %w", err)
	}
	return b, nil
}

func (b *Backend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
		b.pathRotateRoot(),
		b.pathCreds(),
		b.pathStatus(),
	}
}

const backendHelp = `
The vault-auth0-engine secrets engine rotates Auth0 application client_secrets
directly via the Auth0 Management API, without any intermediate service.

Configure Management API credentials once:

  vault write <mount>/config/connection \
    domain="your-tenant.auth0.com" \
    client_id="<management-app-client-id>" \
    client_secret="<management-app-client-secret>" \
    audience="https://your-tenant.auth0.com/api/v2/" \
    transit_key="auth0-engine-key"

After initial setup, rotate the M2M app's own secret so only Vault knows it
(mirrors Vault's database root-rotation pattern — run once after setup, then periodically):

  vault write <mount>/config/rotate-root

Rotate an application's client_secret:

  vault read <mount>/creds/<application-client-id>

Check whether an application exists and is reachable:

  vault read <mount>/status/<application-client-id>
`
