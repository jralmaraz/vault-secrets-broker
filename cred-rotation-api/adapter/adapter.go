// Package adapter defines the interface all credential-provider adapters must implement,
// plus the request/response types shared between the HTTP server and adapter implementations.
package adapter

import (
	"context"
	"time"
)

// Adapter is the single interface every SaaS provider adapter must implement.
// The server calls Rotate; it never touches provider credentials directly.
type Adapter interface {
	// Rotate generates a new credential for providerID, invalidates the old one,
	// and returns the plaintext value. The server layer is responsible for
	// Transit-encrypting the returned credential before sending it to callers.
	Rotate(ctx context.Context, req RotateRequest) (Result, error)

	// Revoke explicitly invalidates the credential identified by credentialID.
	// Not all providers support revocation; implementations may return ErrNotSupported.
	Revoke(ctx context.Context, req RevokeRequest) error

	// Status reports whether the credential identified by credentialID is still active.
	Status(ctx context.Context, credentialID string) (CredentialStatus, error)

	// Name returns the canonical adapter identifier used in routing (e.g. "auth0").
	Name() string
}

// RotateRequest carries the parameters needed to rotate one credential.
type RotateRequest struct {
	// ProviderID is the adapter-specific entity to rotate (e.g. Auth0 client_id,
	// Datadog API key ID, Cloudflare API token ID).
	ProviderID string `json:"provider_id"`

	// Meta holds optional adapter-specific key-value hints.
	Meta map[string]string `json:"meta,omitempty"`
}

// RotateResponse is what the HTTP handler returns to the Vault plugin.
// The plaintext credential is never included; only the Transit ciphertext.
type RotateResponse struct {
	// ProviderID echoes the request field.
	ProviderID string `json:"provider_id"`

	// EncryptedValue is the Transit ciphertext of the new credential
	// (format: "vault:v1:<base64-ciphertext>").
	EncryptedValue string `json:"encrypted_value"`

	// RotatedAt is the UTC time the rotation occurred.
	RotatedAt time.Time `json:"rotated_at"`
}

// RevokeRequest identifies a credential to be explicitly revoked.
type RevokeRequest struct {
	// ProviderID is the same entity identifier used in RotateRequest.
	ProviderID string `json:"provider_id"`

	// CredentialID is the provider-specific identifier of the credential to revoke
	// (e.g. Auth0 returns a new client_id on rotation — pass the old one here).
	CredentialID string `json:"credential_id"`
}

// CredentialStatus is returned by the Status endpoint.
type CredentialStatus struct {
	ProviderID   string    `json:"provider_id"`
	CredentialID string    `json:"credential_id"`
	Active       bool      `json:"active"`
	CheckedAt    time.Time `json:"checked_at"`
}

// Result is the adapter's internal return value from Rotate.
// It carries the plaintext credential and is consumed exclusively by the handler;
// it is NEVER serialised or sent over the network.
type Result struct {
	// ProviderID echoes the request.
	ProviderID string

	// CredentialID is the provider-assigned identifier of the new credential.
	CredentialID string

	// Credential is the plaintext secret value (client_secret, API key, token…).
	// The handler Transit-encrypts this and discards it before responding.
	Credential string

	// RotatedAt is the UTC timestamp of the rotation.
	RotatedAt time.Time
}
