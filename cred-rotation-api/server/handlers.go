package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	vclient "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/vault"
)

const handlerTimeout = 25 * time.Second

// Handlers holds the shared dependencies for all HTTP handlers.
type Handlers struct {
	registry       *adapter.Registry
	vaultClient    *vclient.Client
	transitKeyName string
	logger         *slog.Logger
}

// rotateRequest is the JSON body expected by the /v1/credentials/rotate endpoint.
type rotateRequest struct {
	Provider   string            `json:"provider"`
	ProviderID string            `json:"provider_id"`
	Meta       map[string]string `json:"meta,omitempty"`
}

// Rotate handles POST /v1/credentials/rotate.
// It routes to the appropriate adapter, encrypts the returned plaintext credential
// with Vault Transit, and returns the ciphertext to the caller.
// The plaintext credential is never stored or logged.
func (h *Handlers) Rotate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()

	var req rotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Provider == "" || req.ProviderID == "" {
		h.jsonError(w, http.StatusBadRequest, "provider and provider_id are required")
		return
	}

	a, err := h.registry.Get(req.Provider)
	if err != nil {
		h.jsonError(w, http.StatusNotFound, err.Error())
		return
	}

	result, err := a.Rotate(ctx, adapter.RotateRequest{
		ProviderID: req.ProviderID,
		Meta:       req.Meta,
	})
	if err != nil {
		h.logger.Error("adapter rotate failed", "provider", fmt.Sprintf("%.64q", req.Provider), "err", fmt.Sprintf("%.256q", err.Error()))
		h.jsonError(w, http.StatusBadGateway, "rotation failed: "+err.Error())
		return
	}

	// Transit-encrypt the plaintext credential. result.Credential is discarded after this.
	ciphertext, err := h.vaultClient.TransitEncrypt(ctx, h.transitKeyName, result.Credential)
	if err != nil {
		h.logger.Error("transit encrypt failed", "provider", fmt.Sprintf("%.64q", req.Provider), "err", fmt.Sprintf("%.256q", err.Error()))
		h.jsonError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	h.jsonOK(w, adapter.RotateResponse{
		ProviderID:     result.ProviderID,
		EncryptedValue: ciphertext,
		RotatedAt:      result.RotatedAt,
	})
}

// revokeRequest is the JSON body expected by /v1/credentials/revoke.
type revokeRequest struct {
	Provider     string `json:"provider"`
	ProviderID   string `json:"provider_id"`
	CredentialID string `json:"credential_id"`
}

// Revoke handles POST /v1/credentials/revoke.
func (h *Handlers) Revoke(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()

	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Provider == "" || req.ProviderID == "" {
		h.jsonError(w, http.StatusBadRequest, "provider and provider_id are required")
		return
	}

	a, err := h.registry.Get(req.Provider)
	if err != nil {
		h.jsonError(w, http.StatusNotFound, err.Error())
		return
	}

	if err := a.Revoke(ctx, adapter.RevokeRequest{
		ProviderID:   req.ProviderID,
		CredentialID: req.CredentialID,
	}); err != nil {
		h.logger.Error("adapter revoke failed", "provider", fmt.Sprintf("%.64q", req.Provider), "err", fmt.Sprintf("%.256q", err.Error()))
		h.jsonError(w, http.StatusBadGateway, "revocation failed: "+err.Error())
		return
	}

	h.jsonOK(w, map[string]string{"status": "revoked"})
}

// Status handles GET /v1/credentials/status?provider=auth0&credential_id=xxx
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()

	provider := r.URL.Query().Get("provider")
	credentialID := r.URL.Query().Get("credential_id")
	if provider == "" || credentialID == "" {
		h.jsonError(w, http.StatusBadRequest, "provider and credential_id query params are required")
		return
	}

	a, err := h.registry.Get(provider)
	if err != nil {
		h.jsonError(w, http.StatusNotFound, err.Error())
		return
	}

	status, err := a.Status(ctx, credentialID)
	if err != nil {
		h.logger.Error("adapter status failed", "provider", fmt.Sprintf("%.64q", provider), "err", fmt.Sprintf("%.256q", err.Error()))
		h.jsonError(w, http.StatusBadGateway, "status check failed: "+err.Error())
		return
	}

	h.jsonOK(w, status)
}

// Health handles GET /healthz — returns 200 OK if the server is running.
func (h *Handlers) Health(w http.ResponseWriter, _ *http.Request) {
	h.jsonOK(w, map[string]string{"status": "ok", "time": time.Now().UTC().Format(time.RFC3339)})
}

func (h *Handlers) jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger.Error("encode response", "err", err)
	}
}

func (h *Handlers) jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
