// vault-auth0-engine is a native Vault secrets engine plugin that rotates Auth0
// application client_secrets directly via the Auth0 Management API.
//
// Unlike vault-rest-engine (which proxies through cred-rotation-api), this plugin
// embeds the Auth0 rotation logic and stores Management API credentials in
// Vault's seal-wrapped storage — no intermediate service required.
//
// Registration (after building the binary into vault/plugins/):
//
//	PLUGIN_SHA=$(sha256sum vault/plugins/vault-auth0-engine | cut -d' ' -f1)
//	vault plugin register -sha256=$PLUGIN_SHA secret vault-auth0-engine
//	vault secrets enable -path=auth0 vault-auth0-engine
package main

import (
	"os"

	"github.com/hashicorp/vault/sdk/plugin"

	"github.com/jralmaraz/vault-secrets-broker/plugins/vault-auth0-engine/backend"
)

func main() {
	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
	}); err != nil {
		os.Exit(1)
	}
}
