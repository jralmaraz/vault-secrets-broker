# Policy for cred-rotation-api: Transit encrypt/decrypt + KV adapter config reads.

# Encrypt credential values before returning them to the Vault plugin.
path "transit/encrypt/cred-rotation-key" {
  capabilities = ["update"]
}

# Decrypt adapter config (Auth0 mgmt secret, Splunk token, etc.) at startup.
path "transit/decrypt/cred-rotation-key" {
  capabilities = ["update"]
}

# Generate data encryption keys for envelope encryption of credential values.
path "transit/datakey/plaintext/cred-rotation-key" {
  capabilities = ["update"]
}

# Read adapter configuration from KV v2.
path "secret/data/cred-rotation-api/*" {
  capabilities = ["read"]
}

path "secret/metadata/cred-rotation-api/*" {
  capabilities = ["read", "list"]
}
