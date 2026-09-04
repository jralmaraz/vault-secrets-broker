package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func makePeerCert(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func requestWithCert(method, path string, cert *x509.Certificate) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	return r
}

// ── clientCertIdentity ────────────────────────────────────────────────────────

func TestClientCertIdentity_NoTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	cn, serial := clientCertIdentity(r)
	if cn != "none" || serial != "none" {
		t.Errorf("got (%q, %q), want (\"none\", \"none\")", cn, serial)
	}
}

func TestClientCertIdentity_WithCert(t *testing.T) {
	cert := makePeerCert(t, "ci-pipeline", 255)
	r := requestWithCert(http.MethodPost, "/v1/credentials/rotate", cert)
	cn, serial := clientCertIdentity(r)
	if cn != "ci-pipeline" {
		t.Errorf("cn: got %q, want %q", cn, "ci-pipeline")
	}
	if serial != "ff" { // 255 in hex
		t.Errorf("serial: got %q, want %q", serial, "ff")
	}
}

// ── certAuthz ─────────────────────────────────────────────────────────────────

var nopLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestCertAuthz_EmptyAllowlist_PassesThrough(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := certAuthz(nil, nopLogger, next)

	r := httptest.NewRequest(http.MethodPost, "/v1/credentials/rotate", nil)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !called {
		t.Error("expected next handler to be called with empty allowlist")
	}
}

func TestCertAuthz_PathNotInAllowlist_PassesThrough(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	allowlist := map[string][]string{
		"POST /v1/credentials/rotate": {"operator"},
	}
	h := certAuthz(allowlist, nopLogger, next)

	r := requestWithCert(http.MethodGet, "/healthz", makePeerCert(t, "anyone", 1))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !called {
		t.Error("expected next handler to be called for path not in allowlist")
	}
}

func TestCertAuthz_AllowedCN_PassesThrough(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	allowlist := map[string][]string{
		"POST /v1/credentials/rotate": {"ci-pipeline", "operator"},
	}
	h := certAuthz(allowlist, nopLogger, next)

	r := requestWithCert(http.MethodPost, "/v1/credentials/rotate", makePeerCert(t, "ci-pipeline", 1))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !called {
		t.Error("expected next handler to be called for allowed CN")
	}
}

func TestCertAuthz_DeniedCN_Returns403(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for denied CN")
	})
	allowlist := map[string][]string{
		"POST /v1/credentials/rotate": {"operator"},
	}
	h := certAuthz(allowlist, nopLogger, next)

	r := requestWithCert(http.MethodPost, "/v1/credentials/rotate", makePeerCert(t, "ci-pipeline", 1))
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", rw.Code)
	}
}

func TestCertAuthz_NoCert_Denied(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called when no cert matches")
	})
	allowlist := map[string][]string{
		"POST /v1/credentials/rotate": {"operator"},
	}
	h := certAuthz(allowlist, nopLogger, next)

	r := httptest.NewRequest(http.MethodPost, "/v1/credentials/rotate", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", rw.Code)
	}
}
