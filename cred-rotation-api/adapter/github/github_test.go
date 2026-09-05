package github_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	githubadapter "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/github"
)

// newTestServer returns an httptest.Server that routes by method+path prefix.
// The caller registers handlers in a map keyed on "<METHOD> <path-prefix>".
func newTestServer(t *testing.T, handlers map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	// Route by "METHOD /path" key; fall back to a 404 handler.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		for k, h := range handlers {
			if strings.HasPrefix(key, k) {
				h(w, r)
				return
			}
		}
		http.NotFound(w, r)
	})
	return srv
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ── Constructor ──────────────────────────────────────────────────────────────

func TestNew_MissingAdminPAT(t *testing.T) {
	_, err := githubadapter.New(githubadapter.Config{})
	if err == nil {
		t.Fatal("expected error for missing AdminPAT")
	}
}

func TestNew_DefaultBaseURL(t *testing.T) {
	a, err := githubadapter.New(githubadapter.Config{AdminPAT: "pat"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.Name() != "github" {
		t.Errorf("Name() = %q, want %q", a.Name(), "github")
	}
}

// ── Rotate ───────────────────────────────────────────────────────────────────

func TestRotate_Success(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"POST /user/personal_access_tokens": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusCreated, map[string]any{
				"id":    int64(99001),
				"token": "github_pat_AABBCCDD",
			})
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "admin-token"},
		githubadapter.WithBaseURL(srv.URL))

	result, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "ci-deployer",
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if result.Credential != "github_pat_AABBCCDD" {
		t.Errorf("Credential = %q, want %q", result.Credential, "github_pat_AABBCCDD")
	}
	if result.CredentialID != "99001" {
		t.Errorf("CredentialID = %q, want %q", result.CredentialID, "99001")
	}
	if result.ProviderID != "ci-deployer" {
		t.Errorf("ProviderID = %q, want %q", result.ProviderID, "ci-deployer")
	}
}

func TestRotate_WithPermissionsAndRepositories(t *testing.T) {
	var gotBody map[string]any
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"POST /user/personal_access_tokens": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			writeJSON(w, http.StatusCreated, map[string]any{
				"id":    int64(99002),
				"token": "github_pat_XYZ",
			})
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	_, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "scanner",
		Meta: map[string]string{
			"permissions":  `{"contents":"read","metadata":"read"}`,
			"repositories": "my-repo, other-repo",
			"expires_days": "30",
		},
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	perms, _ := gotBody["permissions"].(map[string]any)
	if perms["contents"] != "read" {
		t.Errorf("permissions.contents = %v, want read", perms["contents"])
	}
	repos, _ := gotBody["repositories"].([]any)
	if len(repos) != 2 {
		t.Errorf("repositories length = %d, want 2", len(repos))
	}
}

func TestRotate_WithCustomExpiry(t *testing.T) {
	var gotBody map[string]any
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"POST /user/personal_access_tokens": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			writeJSON(w, http.StatusCreated, map[string]any{"id": int64(1), "token": "tok"})
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	_, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "scanner",
		Meta:       map[string]string{"expires_days": "14"},
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	expiresAt, _ := gotBody["expires_at"].(string)
	exp, _ := time.Parse(time.RFC3339, expiresAt)
	want := time.Now().UTC().AddDate(0, 0, 14)
	diff := exp.Sub(want).Abs()
	if diff > 2*time.Second {
		t.Errorf("expires_at off by %v, expected ~14 days from now", diff)
	}
}

func TestRotate_BestEffortDeleteOldToken(t *testing.T) {
	var deleteCalled bool
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"POST /user/personal_access_tokens": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusCreated, map[string]any{"id": int64(200), "token": "new-tok"})
		},
		"DELETE /user/personal_access_tokens/": func(w http.ResponseWriter, r *http.Request) {
			deleteCalled = true
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	result, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "my-svc",
		Meta:       map[string]string{"old_token_id": "100"},
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if result.Credential != "new-tok" {
		t.Errorf("Credential = %q", result.Credential)
	}
	if !deleteCalled {
		t.Error("expected DELETE to be called for old_token_id")
	}
}

func TestRotate_BestEffortDeleteFailure_RotateStillSucceeds(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"POST /user/personal_access_tokens": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusCreated, map[string]any{"id": int64(300), "token": "new"})
		},
		"DELETE /user/personal_access_tokens/": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	result, err := a.Rotate(context.Background(), adapter.RotateRequest{
		ProviderID: "svc",
		Meta:       map[string]string{"old_token_id": "999"},
	})
	if err != nil {
		t.Fatalf("Rotate must succeed even when old-token delete fails: %v", err)
	}
	if result.Credential != "new" {
		t.Errorf("Credential = %q, want new", result.Credential)
	}
}

func TestRotate_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"POST /user/personal_access_tokens": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"message": "Validation Failed"})
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "x"})
	if err == nil {
		t.Fatal("expected error on 422 response")
	}
}

func TestRotate_EmptyTokenInResponse(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"POST /user/personal_access_tokens": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusCreated, map[string]any{"id": int64(1), "token": ""})
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	_, err := a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "x"})
	if err == nil {
		t.Fatal("expected error for empty token in response")
	}
}

// ── Revoke ───────────────────────────────────────────────────────────────────

func TestRevoke_Success(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"DELETE /user/personal_access_tokens/": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	if err := a.Revoke(context.Background(), adapter.RevokeRequest{CredentialID: "42"}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

func TestRevoke_NotFound_Idempotent(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"DELETE /user/personal_access_tokens/": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "Not Found"})
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	if err := a.Revoke(context.Background(), adapter.RevokeRequest{CredentialID: "99"}); err != nil {
		t.Fatalf("Revoke on 404 should be idempotent, got: %v", err)
	}
}

func TestRevoke_EmptyCredentialID(t *testing.T) {
	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"})
	err := a.Revoke(context.Background(), adapter.RevokeRequest{CredentialID: ""})
	if err == nil {
		t.Fatal("expected error for empty CredentialID")
	}
}

func TestRevoke_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"DELETE /user/personal_access_tokens/": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	err := a.Revoke(context.Background(), adapter.RevokeRequest{CredentialID: "1"})
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
}

// ── Status ───────────────────────────────────────────────────────────────────

func TestStatus_Active(t *testing.T) {
	future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"GET /user/personal_access_tokens/": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"id": 1, "expires_at": future})
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	cs, err := a.Status(context.Background(), "1")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !cs.Active {
		t.Error("expected Active=true for future expiry")
	}
}

func TestStatus_Expired(t *testing.T) {
	past := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"GET /user/personal_access_tokens/": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"id": 1, "expires_at": past})
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	cs, err := a.Status(context.Background(), "1")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if cs.Active {
		t.Error("expected Active=false for past expiry")
	}
}

func TestStatus_NotFound(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"GET /user/personal_access_tokens/": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusNotFound, map[string]any{"message": "Not Found"})
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	cs, err := a.Status(context.Background(), "404")
	if err != nil {
		t.Fatalf("Status on 404 should return active=false, not error: %v", err)
	}
	if cs.Active {
		t.Error("expected Active=false for 404 response")
	}
}

func TestStatus_EmptyCredentialID(t *testing.T) {
	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"})
	_, err := a.Status(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty credential_id")
	}
}

func TestStatus_APIError(t *testing.T) {
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"GET /user/personal_access_tokens/": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))

	_, err := a.Status(context.Background(), "1")
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
}

// ── Auth headers ─────────────────────────────────────────────────────────────

func TestRotate_AuthHeaderPresent(t *testing.T) {
	var gotAuth string
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"POST /user/personal_access_tokens": func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			writeJSON(w, http.StatusCreated, map[string]any{"id": int64(1), "token": "tok"})
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "my-secret-pat"},
		githubadapter.WithBaseURL(srv.URL))
	_, _ = a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "x"})

	if gotAuth != "Bearer my-secret-pat" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer my-secret-pat")
	}
}

func TestRotate_GitHubAPIVersionHeader(t *testing.T) {
	var gotVersion string
	srv := newTestServer(t, map[string]http.HandlerFunc{
		"POST /user/personal_access_tokens": func(w http.ResponseWriter, r *http.Request) {
			gotVersion = r.Header.Get("X-GitHub-Api-Version")
			writeJSON(w, http.StatusCreated, map[string]any{"id": int64(1), "token": "tok"})
		},
	})
	defer srv.Close()

	a, _ := githubadapter.New(githubadapter.Config{AdminPAT: "pat"},
		githubadapter.WithBaseURL(srv.URL))
	_, _ = a.Rotate(context.Background(), adapter.RotateRequest{ProviderID: "x"})

	if gotVersion != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version = %q, want 2022-11-28", gotVersion)
	}
}
