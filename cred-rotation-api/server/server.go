// Package server provides the mTLS HTTP server for cred-rotation-api.
// All connections require a valid client certificate signed by the internal CA;
// TLS 1.3 is the minimum version.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	vclient "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/vault"
)

const (
	readTimeout     = 10 * time.Second
	writeTimeout    = 30 * time.Second
	idleTimeout     = 60 * time.Second
	shutdownTimeout = 15 * time.Second
)

// Server is the cred-rotation-api mTLS HTTP server.
type Server struct {
	http      *http.Server
	logger    *slog.Logger
	tlsConfig *tls.Config
}

// Config groups the dependencies needed by the server at construction time.
type Config struct {
	// Addr is the listen address, e.g. ":8443".
	Addr string

	// TLSConfig is a fully-built *tls.Config (server cert + CA pool + RequireAndVerifyClientCert).
	TLSConfig *tls.Config

	// Registry is the adapter registry routing requests to provider adapters.
	Registry *adapter.Registry

	// VaultClient is used by handlers to Transit-encrypt plaintext credentials.
	VaultClient *vclient.Client

	// TransitKeyName is the Vault Transit key used to encrypt credential values.
	TransitKeyName string

	// Logger is the structured logger. If nil, a default logger is created.
	Logger *slog.Logger
}

// New constructs a Server from Config. Call ListenAndServeTLS to start it.
func New(cfg Config) (*Server, error) {
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("server: TLSConfig is required")
	}
	if cfg.Registry == nil {
		return nil, fmt.Errorf("server: Registry is required")
	}
	if cfg.VaultClient == nil {
		return nil, fmt.Errorf("server: VaultClient is required")
	}
	if cfg.TransitKeyName == "" {
		return nil, fmt.Errorf("server: TransitKeyName is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	h := &Handlers{
		registry:       cfg.Registry,
		vaultClient:    cfg.VaultClient,
		transitKeyName: cfg.TransitKeyName,
		logger:         logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/credentials/rotate", h.Rotate)
	mux.HandleFunc("POST /v1/credentials/revoke", h.Revoke)
	mux.HandleFunc("GET /v1/credentials/status", h.Status)
	mux.HandleFunc("GET /healthz", h.Health)

	httpSrv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      requestLogger(logger, mux),
		TLSConfig:    cfg.TLSConfig,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	return &Server{
		http:      httpSrv,
		logger:    logger,
		tlsConfig: cfg.TLSConfig,
	}, nil
}

// ListenAndServeTLS starts the mTLS server. It blocks until the server is stopped.
// TLS certificates are already embedded in the server's TLSConfig, so the cert/key
// path arguments are intentionally empty strings (required by net/http API).
func (s *Server) ListenAndServeTLS() error {
	ln, err := tls.Listen("tcp", s.http.Addr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("server listen: %w", err)
	}
	s.logger.Info("cred-rotation-api listening",
		"addr", listenerAddr(ln),
		"tls_min_version", "TLS 1.3",
		"client_auth", "RequireAndVerifyClientCert",
	)
	return s.http.Serve(ln)
}

// Shutdown gracefully drains in-flight requests within a deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()
	return s.http.Shutdown(ctx)
}

// requestLogger is a minimal middleware that logs method, path, and status code.
func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		logger.Info("request",
			"method", r.Method,
			"path", sanitizeLog(r.URL.Path),
			"status", rw.statusCode,
			"remote", sanitizeLog(r.RemoteAddr),
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// sanitizeLog strips control characters from a string before including it in a
// log entry to prevent log-injection attacks.
func sanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '_'
		}
		return r
	}, s)
}

func listenerAddr(ln net.Listener) string {
	if ln == nil {
		return "unknown"
	}
	return ln.Addr().String()
}
