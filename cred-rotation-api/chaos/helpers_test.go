package chaos_test

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter/sonarqube"
	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/chaos"
)

// insecureTransport allows loopback-only test servers with self-signed certs.
// Never use outside test code.
var insecureTransport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // #nosec G402 -- loopback httptest certs only, never production
}

// newSonarqubeAdapterFromURL builds a sonarqube adapter pointed at url,
// using InsecureSkipVerify so httptest.TLSServer certs are accepted.
func newSonarqubeAdapterFromURL(url string) (*sonarqube.Adapter, error) {
	return sonarqube.New(
		sonarqube.Config{BaseURL: url, AdminToken: "test-admin-token"},
		sonarqube.WithBaseURL(url),
		sonarqube.WithTestTransport(insecureTransport),
	)
}

// newSonarqubeAdapterForTest is a *testing.T-aware wrapper.
func newSonarqubeAdapterForTest(t *testing.T, mp *chaos.MockProvider) *sonarqube.Adapter {
	t.Helper()
	a, err := newSonarqubeAdapterFromURL(mp.URL)
	if err != nil {
		t.Fatalf("sonarqube.New: %v", err)
	}
	return a
}
