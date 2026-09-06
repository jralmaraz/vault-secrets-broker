// Internal tests for validateSPIFFESocket. Running in package vault (not vault_test)
// so we can reach the unexported function directly without risking connection attempts.
package vault

import (
	"strings"
	"testing"
)

func TestValidateSPIFFESocket_ValidSchemes(t *testing.T) {
	cases := []string{
		"unix:///run/spire/agent.sock",
		"unix:///var/lib/spire/agent.sock",
		"tcp://127.0.0.1:8081",
		"tcp://spire-agent.internal:8081",
	}
	for _, addr := range cases {
		if err := validateSPIFFESocket(addr); err != nil {
			t.Errorf("addr %q should be valid, got: %v", addr, err)
		}
	}
}

func TestValidateSPIFFESocket_InvalidScheme(t *testing.T) {
	cases := []string{
		"http://spire:8081",
		"https://spire:8081",
		"ftp://host:22",
		"/run/spire/agent.sock",
		"spire:///run/agent.sock",
		"",
	}
	for _, addr := range cases {
		if err := validateSPIFFESocket(addr); err == nil {
			t.Errorf("addr %q should be rejected, got nil", addr)
		} else if !strings.Contains(err.Error(), "unix:// or tcp://") {
			t.Errorf("addr %q: error %q does not mention scheme requirement", addr, err.Error())
		}
	}
}

func TestValidateSPIFFESocket_PathTraversal(t *testing.T) {
	cases := []string{
		"unix:///var/run/../../etc/passwd",
		"unix:///a/../b/agent.sock",
		"unix:///../root/.ssh/agent.sock",
	}
	for _, addr := range cases {
		err := validateSPIFFESocket(addr)
		if err == nil {
			t.Errorf("addr %q should be rejected for path traversal, got nil", addr)
			continue
		}
		if !strings.Contains(err.Error(), "traversal") {
			t.Errorf("addr %q: error %q does not mention traversal", addr, err.Error())
		}
	}
}

func TestValidateSPIFFESocket_TooLong(t *testing.T) {
	long := "unix:///" + strings.Repeat("x", 600)
	err := validateSPIFFESocket(long)
	if err == nil {
		t.Fatal("expected error for over-long socket addr, got nil")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("error %q does not mention length limit", err.Error())
	}
}
