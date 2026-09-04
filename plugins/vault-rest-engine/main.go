// vault-rest-engine is a Vault secrets engine plugin that delegates credential
// rotation to cred-rotation-api. It is provider-agnostic: a single binary can
// rotate credentials for any SaaS provider that implements the adapter interface.
//
// Registration (after building the binary into vault/plugins/):
//
//	PLUGIN_SHA=$(sha256sum vault/plugins/vault-rest-engine | cut -d' ' -f1)
//	vault plugin register -sha256=$PLUGIN_SHA secret vault-rest-engine
//	vault secrets enable -path=rotation vault-rest-engine
package main

import (
	"os"

	"github.com/hashicorp/vault/sdk/plugin"

	"github.com/jralmaraz/vault-secrets-broker/plugins/vault-rest-engine/backend"
)

func main() {
	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
	}); err != nil {
		os.Exit(1)
	}
}
