package sonarqube_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/sonarqube"
)

const (
	fakeAdminToken = "squ_admintoken1234567890abcdef"
	fakeTokenValue = "squ_newtoken1234567890abcdef"
	fakeLogin      = "ci-pipeline"
)

// sqGenerateResponse builds a minimal SonarQube generate response.
func sqGenerateResponse(name string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"login": fakeLogin,
		"name":  name,
		"token": fakeTokenValue,
	})
	return b
}

// sqSearchResponse builds a minimal SonarQube search response.
func sqSearchResponse(tokens ...string) []byte {
	items := make([]map[string]string, len(tokens))
	for i, name := range tokens {
		items[i] = map[string]string{"name": name, "type": "USER_TOKEN"}
	}
	b, _ := json.Marshal(map[string]interface{}{"userTokens": items})
	return b
}

func newTestServer(t *testing.T, handlers map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for pattern, h := range handlers {
		mux.HandleFunc(pattern, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newAdapter(t *testing.T, srv *httptest.Server, opts ...sonarqube.Option) *sonarqube.Adapter {
	t.Helper()
	opts = append([]sonarqube.Option{sonarqube.WithBaseURL(srv.URL)}, opts...)
	a, err := sonarqube.New(sonarqube.Config{
		BaseURL:    srv.URL,
		AdminToken: fakeAdminToken,
	}, opts...)
	if err != nil {
		t.Fatalf("sonarqube.New: %v", err)
	}
	return a
}

// ── Name ─────────────────────────────────────────────────────────────────────

func TestAdapter_Name(t *testing.T) {
	a, err := sonarqube.New(sonarqube.Config{BaseURL: "https://sq.example.com", AdminToken: "x"})
	if err != nil {
		t.Fatalf("sonarqube.New: %v", err)
	}
	if got := a.Name(); got != "sonarqube" {
		t.Errorf("Name() = %q, want %q", got, "sonarqube")
	}
}

// ── New — validation ──────────────────────────────────────────────────────────

func TestNew_MissingBaseURL(t *testing.T) {
	_, err := sonarqube.New(sonarqube.Config{AdminToken: "x"})
	if err == nil {
		t.Fatal("expected error for missing BaseURL")
	}
}

func TestNew_MissingAdminToken(t *testing.T) {
	_, err := sonarqube.New(sonarqube.Config{BaseURL: "https://sq.example.com"})
	if err == nil {
		t.Fatal("expected error for missing AdminToken")
	}
}

// ── Rotate ───────────────────────────────────────────────────────────────────

func TestRotate_Success(t *testing.T) {
	generateCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/generate": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			generateCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sqGenerateResponse("ci-pipeline-ts-ab"))
		},
	})

	a := newAdapter(t, srv)
	result, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: fakeLogin})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !generateCalled {
		t.Error("generate endpoint was not called")
	}
	if result.Credential == "" {
		t.Error("expected non-empty Credential")
	}
	if result.Credential == fakeAdminToken {
		t.Error("Credential must not equal the admin token")
	}
	if result.CredentialID == "" {
		t.Error("expected non-empty CredentialID")
	}
	if !strings.HasPrefix(result.CredentialID, fakeLogin+":") {
		t.Errorf("CredentialID %q should start with %q", result.CredentialID, fakeLogin+":")
	}
	if result.ProviderID != fakeLogin {
		t.Errorf("ProviderID = %q, want %q", result.ProviderID, fakeLogin)
	}
	if result.RotatedAt.IsZero() {
		t.Error("RotatedAt must not be zero")
	}
}

func TestRotate_CredentialIDContainsLoginAndTokenName(t *testing.T) {
	var capturedName string
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/generate": func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			capturedName = r.FormValue("name")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sqGenerateResponse(capturedName))
		},
	})

	a := newAdapter(t, srv)
	result, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: fakeLogin})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	want := fakeLogin + ":" + capturedName
	if result.CredentialID != want {
		t.Errorf("CredentialID = %q, want %q", result.CredentialID, want)
	}
}

func TestRotate_TokenNameContainsTimestampAndSuffix(t *testing.T) {
	var capturedName string
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/generate": func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			capturedName = r.FormValue("name")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sqGenerateResponse(capturedName))
		},
	})

	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: fakeLogin})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !strings.HasPrefix(capturedName, fakeLogin+"-") {
		t.Errorf("token name %q should start with login prefix", capturedName)
	}
	parts := strings.Split(capturedName, "-")
	if len(parts) < 3 {
		t.Errorf("token name %q should have at least 3 dash-separated parts", capturedName)
	}
	// Last part should be 4 hex characters (2 random bytes).
	last := parts[len(parts)-1]
	if len(last) != 4 {
		t.Errorf("random suffix %q should be 4 hex characters", last)
	}
}

func TestRotate_RevokesOldToken(t *testing.T) {
	revokeCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/generate": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sqGenerateResponse("new-token"))
		},
		"/api/user_tokens/revoke": func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			if r.FormValue("name") == "old-token-name" {
				revokeCalled = true
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})

	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: fakeLogin,
		Meta:       map[string]string{"old_token_name": "old-token-name"},
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// Cleanup is async; wait for it before asserting.
	_ = a.Drain(context.Background())
	if !revokeCalled {
		t.Error("expected revoke call for old token, got none")
	}
}

func TestRotate_OldTokenRevokeFailure_LogsAndSucceeds(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/generate": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sqGenerateResponse("new-token"))
		},
		"/api/user_tokens/revoke": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"errors":[{"msg":"Internal error"}]}`, http.StatusInternalServerError)
		},
	})

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	a := newAdapter(t, srv, sonarqube.WithLogger(logger))
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: fakeLogin,
		Meta:       map[string]string{"old_token_name": "old-token-fail"},
	})
	if err != nil {
		t.Fatalf("Rotate should succeed despite revoke failure: %v", err)
	}
	_ = a.Drain(context.Background())
	if !strings.Contains(logBuf.String(), "best-effort revoke of old token failed") {
		t.Errorf("expected warning in log, got: %q", logBuf.String())
	}
}

func TestRotate_MissingProviderID_ReturnsError(t *testing.T) {
	a, _ := sonarqube.New(sonarqube.Config{BaseURL: "https://sq.example.com", AdminToken: "x"})
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{})
	if err == nil {
		t.Fatal("expected error for missing provider_id")
	}
}

func TestRotate_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/generate": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"errors":[{"msg":"Insufficient privileges"}]}`, http.StatusForbidden)
		},
	})
	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: fakeLogin})
	if err == nil {
		t.Fatal("expected error from SonarQube 403, got nil")
	}
}

func TestRotate_MissingTokenValueInResponse(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/generate": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			// token field intentionally absent
			b, _ := json.Marshal(map[string]string{"login": fakeLogin, "name": "ts"})
			_, _ = w.Write(b)
		},
	})
	a := newAdapter(t, srv)
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: fakeLogin})
	if err == nil {
		t.Fatal("expected error when token value is missing from response")
	}
}

func TestRotate_LogInjection_OldTokenNameSanitized(t *testing.T) {
	injected := "legit\nfake-log-entry: injected"
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/generate": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sqGenerateResponse("ts"))
		},
		// 500 forces the Warn log path so we can verify the token name is sanitized.
		// (404 would be treated as idempotent success and produce no warning.)
		"/api/user_tokens/revoke": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"errors":[{"msg":"Server error"}]}`, http.StatusInternalServerError)
		},
	})

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	a := newAdapter(t, srv, sonarqube.WithLogger(logger))
	_, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: fakeLogin,
		Meta:       map[string]string{"old_token_name": injected},
	})
	if err != nil {
		t.Fatalf("Rotate should succeed: %v", err)
	}
	_ = a.Drain(context.Background())
	logged := logBuf.String()
	if strings.Contains(logged, "\n"+strings.Split(injected, "\n")[1]) {
		t.Errorf("log injection not sanitized: %q", logged)
	}
	if !strings.Contains(logged, "legit") {
		t.Errorf("safe prefix should appear in log: %q", logged)
	}
}

// ── Revoke ───────────────────────────────────────────────────────────────────

func TestRevoke_Success(t *testing.T) {
	revokeCalled := false
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/revoke": func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			if r.FormValue("login") == fakeLogin && r.FormValue("name") == "ci-pipeline-ts-ab" {
				revokeCalled = true
			}
			w.WriteHeader(http.StatusNoContent)
		},
	})

	a := newAdapter(t, srv)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{
		ProviderID:   fakeLogin,
		CredentialID: fakeLogin + ":ci-pipeline-ts-ab",
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !revokeCalled {
		t.Error("expected revoke call, got none")
	}
}

func TestRevoke_EmptyCredentialID_FailsClosed(t *testing.T) {
	a, _ := sonarqube.New(sonarqube.Config{BaseURL: "https://sq.example.com", AdminToken: "x"})
	err := a.Revoke(context.Background(), adapter.RevokeRequest{ProviderID: fakeLogin, CredentialID: ""})
	if err == nil {
		t.Fatal("expected error for empty credential_id")
	}
	if !strings.Contains(err.Error(), "credential_id is required") {
		t.Errorf("error should mention credential_id requirement, got: %v", err)
	}
}

func TestRevoke_InvalidCredentialID_ReturnsError(t *testing.T) {
	a, _ := sonarqube.New(sonarqube.Config{BaseURL: "https://sq.example.com", AdminToken: "x"})
	err := a.Revoke(context.Background(), adapter.RevokeRequest{ProviderID: fakeLogin, CredentialID: "notacompositeid"})
	if err == nil {
		t.Fatal("expected error for invalid credential_id format")
	}
}

func TestRevoke_AlreadyDeleted_IsIdempotent(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/revoke": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		},
	})
	a := newAdapter(t, srv)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{
		ProviderID:   fakeLogin,
		CredentialID: fakeLogin + ":old-token",
	})
	if err != nil {
		t.Fatalf("Revoke of already-deleted token should be idempotent, got: %v", err)
	}
}

func TestRevoke_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/revoke": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"errors":[{"msg":"Server error"}]}`, http.StatusInternalServerError)
		},
	})
	a := newAdapter(t, srv)
	err := a.Revoke(context.Background(), adapter.RevokeRequest{
		ProviderID:   fakeLogin,
		CredentialID: fakeLogin + ":some-token",
	})
	if err == nil {
		t.Fatal("expected error from SonarQube 500, got nil")
	}
}

// ── Status ───────────────────────────────────────────────────────────────────

func TestStatus_Active(t *testing.T) {
	tokenName := "ci-pipeline-ts-ab"
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/search": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sqSearchResponse(tokenName, "other-token"))
		},
	})
	a := newAdapter(t, srv)
	status, err := a.Status(context.Background(), fakeLogin+":"+tokenName)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Active {
		t.Error("expected Active=true for existing token")
	}
	if status.CheckedAt.IsZero() {
		t.Error("CheckedAt must not be zero")
	}
}

func TestStatus_NotFound_Inactive(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/search": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sqSearchResponse("some-other-token"))
		},
	})
	a := newAdapter(t, srv)
	status, err := a.Status(context.Background(), fakeLogin+":gone-token")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Active {
		t.Error("expected Active=false for missing token")
	}
}

func TestStatus_EmptyCredentialID(t *testing.T) {
	a, _ := sonarqube.New(sonarqube.Config{BaseURL: "https://sq.example.com", AdminToken: "x"})
	_, err := a.Status(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty credential_id")
	}
}

func TestStatus_InvalidCredentialID(t *testing.T) {
	a, _ := sonarqube.New(sonarqube.Config{BaseURL: "https://sq.example.com", AdminToken: "x"})
	_, err := a.Status(context.Background(), "nocolon")
	if err == nil {
		t.Fatal("expected error for invalid credential_id format")
	}
}

func TestStatus_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/search": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"errors":[{"msg":"Forbidden"}]}`, http.StatusForbidden)
		},
	})
	a := newAdapter(t, srv)
	_, err := a.Status(context.Background(), fakeLogin+":some-token")
	if err == nil {
		t.Fatal("expected error from SonarQube 403, got nil")
	}
}

// ── Auth header guard ─────────────────────────────────────────────────────────

func TestRotate_SendsBearerAuthHeader(t *testing.T) {
	var gotAuth string
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"/api/user_tokens/generate": func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sqGenerateResponse("ts"))
		},
	})

	a := newAdapter(t, srv)
	_, _ = a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: fakeLogin})

	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Errorf("Authorization header = %q, want Bearer scheme", gotAuth)
	}
}
