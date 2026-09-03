package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
)

// stubAdapter is a test double for the Adapter interface.
type stubAdapter struct {
	name       string
	rotateErr  error
	revokeErr  error
	statusResp adapter.CredentialStatus
	statusErr  error
	rotateRes  adapter.Result
}

func (s *stubAdapter) Name() string { return s.name }

func (s *stubAdapter) Rotate(_ context.Context, req adapter.RotateRequest) (adapter.Result, error) {
	if s.rotateErr != nil {
		return adapter.Result{}, s.rotateErr
	}
	return s.rotateRes, nil
}

func (s *stubAdapter) Revoke(_ context.Context, _ adapter.RevokeRequest) error {
	return s.revokeErr
}

func (s *stubAdapter) Status(_ context.Context, _ string) (adapter.CredentialStatus, error) {
	return s.statusResp, s.statusErr
}

// stubTransit stands in for Vault Transit encrypt. We pass the encrypted value
// directly rather than calling a real Vault instance.
type stubTransit struct {
	encrypted string
	err       error
}

// testRouter mirrors the server handler routing but uses a stubbed Transit.
type testRouter struct {
	registry *adapter.Registry
	transit  *stubTransit
}

func buildTestMux(reg *adapter.Registry, transit *stubTransit) http.Handler {
	return &testRouter{registry: reg, transit: transit}
}

func (tr *testRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/credentials/rotate":
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		tr.handleRotate(w, r)
	case "/v1/credentials/revoke":
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		tr.handleRevoke(w, r)
	case "/v1/credentials/status":
		tr.handleStatus(w, r)
	case "/healthz":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		http.NotFound(w, r)
	}
}

func (tr *testRouter) handleRotate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider   string `json:"provider"`
		ProviderID string `json:"provider_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	a, err := tr.registry.Get(req.Provider)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	res, err := a.Rotate(r.Context(), adapter.RotateRequest{ProviderID: req.ProviderID})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if tr.transit.err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encryption failed"})
		return
	}
	writeJSON(w, http.StatusOK, adapter.RotateResponse{
		ProviderID:     res.ProviderID,
		EncryptedValue: tr.transit.encrypted,
		RotatedAt:      res.RotatedAt,
	})
}

func (tr *testRouter) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider   string `json:"provider"`
		ProviderID string `json:"provider_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	a, err := tr.registry.Get(req.Provider)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if err := a.Revoke(r.Context(), adapter.RevokeRequest{ProviderID: req.ProviderID}); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (tr *testRouter) handleStatus(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	credentialID := r.URL.Query().Get("credential_id")
	if provider == "" || credentialID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing params"})
		return
	}
	a, err := tr.registry.Get(provider)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	status, err := a.Status(r.Context(), credentialID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func makeRegistry(a adapter.Adapter) *adapter.Registry {
	reg := adapter.NewRegistry()
	reg.Register(a)
	return reg
}

func TestRotateHandler_Success(t *testing.T) {
	stub := &stubAdapter{
		name: "testprovider",
		rotateRes: adapter.Result{
			ProviderID: "client-id-1",
			Credential: "plaintext-secret",
			RotatedAt:  time.Now().UTC(),
		},
	}
	transit := &stubTransit{encrypted: "vault:v1:encryptedvalue=="}

	mux := buildTestMux(makeRegistry(stub), transit)
	body, _ := json.Marshal(map[string]string{"provider": "testprovider", "provider_id": "client-id-1"})
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/rotate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200. body: %s", rec.Code, rec.Body)
	}
	var resp adapter.RotateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.EncryptedValue != "vault:v1:encryptedvalue==" {
		t.Errorf("encrypted_value: got %q, want %q", resp.EncryptedValue, "vault:v1:encryptedvalue==")
	}
	if resp.ProviderID != "client-id-1" {
		t.Errorf("provider_id: got %q, want %q", resp.ProviderID, "client-id-1")
	}
}

func TestRotateHandler_UnknownProvider(t *testing.T) {
	mux := buildTestMux(adapter.NewRegistry(), &stubTransit{encrypted: "x"})
	body, _ := json.Marshal(map[string]string{"provider": "nonexistent", "provider_id": "id"})
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/rotate", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", rec.Code)
	}
}

func TestRevokeHandler_NotSupported(t *testing.T) {
	stub := &stubAdapter{
		name:      "testprovider",
		revokeErr: errors.New("not supported"),
	}
	mux := buildTestMux(makeRegistry(stub), &stubTransit{encrypted: "x"})
	body, _ := json.Marshal(map[string]string{"provider": "testprovider", "provider_id": "id"})
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/revoke", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status: got %d, want 502", rec.Code)
	}
}

func TestStatusHandler(t *testing.T) {
	stub := &stubAdapter{
		name: "testprovider",
		statusResp: adapter.CredentialStatus{
			ProviderID:   "client-id-1",
			CredentialID: "client-id-1",
			Active:       true,
			CheckedAt:    time.Now().UTC(),
		},
	}
	mux := buildTestMux(makeRegistry(stub), &stubTransit{encrypted: "x"})
	req := httptest.NewRequest(http.MethodGet, "/v1/credentials/status?provider=testprovider&credential_id=client-id-1", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200. body: %s", rec.Code, rec.Body)
	}
}

func TestHealthHandler(t *testing.T) {
	mux := buildTestMux(adapter.NewRegistry(), &stubTransit{encrypted: "x"})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
}
