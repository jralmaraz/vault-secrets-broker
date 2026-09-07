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
	"sync/atomic"
	"time"

	"github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/adapter"
	vclient "github.com/jralmaraz/vault-secrets-broker/cred-rotation-api/vault"
)

const (
	readTimeout           = 10 * time.Second
	writeTimeout          = 30 * time.Second
	idleTimeout           = 60 * time.Second
	shutdownTimeout       = 15 * time.Second
	defaultMaxConcurrency = 100
)

// Server is the cred-rotation-api mTLS HTTP server.
type Server struct {
	http      *http.Server
	logger    *slog.Logger
	tlsConfig *tls.Config
	registry  *adapter.Registry
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

	// CertAllowlist restricts which client cert CNs may call each endpoint.
	// Key format: "METHOD /path" (e.g. "POST /v1/credentials/rotate").
	// Value: slice of allowed client cert Common Names.
	// If a path has no entry, any verified cert CN is accepted for that path.
	// If the map is nil or empty, all endpoints accept any verified cert.
	CertAllowlist map[string][]string

	// MaxConcurrentRequests is the server-wide in-flight request cap. Requests
	// beyond this limit receive 503 immediately. Defaults to 100 if zero.
	MaxConcurrentRequests int
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

	maxConcurrent := cfg.MaxConcurrentRequests
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrency
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

	handler := requestLogger(logger,
		concurrencyLimiter(int64(maxConcurrent), logger,
			certAuthz(cfg.CertAllowlist, logger, mux)))

	httpSrv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      handler,
		TLSConfig:    cfg.TLSConfig,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	return &Server{
		http:      httpSrv,
		logger:    logger,
		tlsConfig: cfg.TLSConfig,
		registry:  cfg.Registry,
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

// Shutdown gracefully drains in-flight HTTP requests and adapter cleanup goroutines.
func (s *Server) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()

	if err := s.http.Shutdown(ctx); err != nil {
		return err
	}

	// Wait for any background cleanup goroutines that adapters launched during rotation.
	for _, name := range s.registry.Names() {
		a, err := s.registry.Get(name)
		if err != nil {
			continue
		}
		if d, ok := a.(adapter.Drainer); ok {
			if err := d.Drain(ctx); err != nil {
				s.logger.Warn("adapter drain timed out", "adapter", name, "err", err)
			}
		}
	}
	return nil
}

// concurrencyLimiter rejects requests with 503 when the server-wide in-flight
// count exceeds limit. This prevents unbounded goroutine growth under load spikes.
func concurrencyLimiter(limit int64, logger *slog.Logger, next http.Handler) http.Handler {
	var inFlight atomic.Int64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := inFlight.Add(1); n > limit {
			inFlight.Add(-1)
			logger.Warn("request rejected: concurrency limit reached",
				"limit", limit,
				"path", fmt.Sprintf("%q", r.URL.Path),
			)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"server overloaded, retry after 1s"}`))
			return
		}
		defer inFlight.Add(-1)
		next.ServeHTTP(w, r)
	})
}

// requestLogger logs method, path, status, remote address, and client cert identity
// on every request. Client cert CN and serial are required for the audit trail.
func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		cn, serial := clientCertIdentity(r)
		logger.Info("request",
			"method", r.Method,
			"path", fmt.Sprintf("%q", r.URL.Path),
			"status", rw.statusCode,
			"remote", fmt.Sprintf("%q", r.RemoteAddr),
			"cert_cn", fmt.Sprintf("%q", cn),
			"cert_serial", serial,
		)
	})
}

// certAuthz enforces per-endpoint client cert CN authorization.
// Paths absent from the allowlist accept any verified cert CN.
func certAuthz(allowlist map[string][]string, logger *slog.Logger, next http.Handler) http.Handler {
	if len(allowlist) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		allowed, ok := allowlist[key]
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		cn, _ := clientCertIdentity(r)
		for _, a := range allowed {
			if a == cn {
				next.ServeHTTP(w, r)
				return
			}
		}
		logger.Warn("cert authz denied", "path", fmt.Sprintf("%q", r.URL.Path), "cert_cn", fmt.Sprintf("%q", cn))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	})
}

// clientCertIdentity returns the Common Name and hex-encoded serial number of the
// first peer certificate from the TLS handshake. Returns "none" for both if there
// is no TLS connection or no peer certificate (unauthenticated connections are
// rejected upstream by RequireAndVerifyClientCert).
func clientCertIdentity(r *http.Request) (cn, serial string) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "none", "none"
	}
	cert := r.TLS.PeerCertificates[0]
	return cert.Subject.CommonName, cert.SerialNumber.Text(16)
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func listenerAddr(ln net.Listener) string {
	if ln == nil {
		return "unknown"
	}
	return ln.Addr().String()
}
