// Package backend implements the vault-rest-engine Vault secrets engine plugin.
// It exposes two path families:
//
//	config/            — store cred-rotation-api URL and mTLS certificate material
//	creds/<provider>/<provider_id> — trigger credential rotation and return the decrypted value
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
			// Creds paths are unauthenticated at the SDK level; Vault policies gate access.
			SealWrapStorage: []string{"config/"},
		},
		RunningVersion: pluginVersion,
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, fmt.Errorf("vault-rest-engine setup: %w", err)
	}
	return b, nil
}

func (b *Backend) paths() []*framework.Path {
	return []*framework.Path{
		b.pathConfig(),
		b.pathCredentials(),
	}
}

const backendHelp = `
The vault-rest-engine secrets engine calls cred-rotation-api to rotate
credentials for any SaaS provider that implements the rotation adapter interface.

Configure the API endpoint once:
  vault write <mount>/config/connection \
    api_url="https://cred-rotation-api.internal:8443" \
    transit_key="cred-rotation-key" \
    tls_ca_cert=@vault/certs/internal-ca.crt \
    tls_client_cert=@/path/to/client.crt \
    tls_client_key=@/path/to/client.key

Then rotate credentials:
  vault read <mount>/creds/auth0/<client-id>
`
