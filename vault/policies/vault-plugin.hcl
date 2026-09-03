# Policy for Vault secrets engine plugins: Transit decrypt only.
# Plugins receive Transit-encrypted credential values from cred-rotation-api
# and decrypt them before returning to the consumer.

path "transit/decrypt/cred-rotation-key" {
  capabilities = ["update"]
}
