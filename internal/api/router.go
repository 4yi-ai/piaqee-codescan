// Package api holds the HTTP handlers and routing for codescan.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/4yi-ai/codescan/internal/scan"
	"github.com/4yi-ai/codescan/internal/source"
	"github.com/4yi-ai/codescan/internal/store"
)

const extraAllowedHostsSetting = "extra_allowed_hosts"

// apiKeyHeader is the header PIAQEE's server-to-server client sends. On 4YI the
// key value is injected via Secrets (never committed / never in 4yi-app.json env).
const apiKeyHeader = "X-API-Key"

// Server bundles the dependencies the HTTP handlers need.
type Server struct {
	store  *store.Store
	mgr    *scan.Manager
	guards source.Guards
	web    fs.FS // embedded web assets (templates/*, static/*)
	pages  *pages
	apiKey string // required key for /api/*; empty = enforcement disabled (dev/test only)
}

// NewServer builds a Server. webFS is the embedded web/ directory. The API key is
// read from CODESCAN_API_KEY: when set, every /api/* request must carry it in the
// X-API-Key header; when empty (local dev / tests) enforcement is disabled.
func NewServer(st *store.Store, mgr *scan.Manager, guards source.Guards, webFS fs.FS) *Server {
	key := os.Getenv("CODESCAN_API_KEY")
	if key == "" {
		log.Printf("[api] WARNING: CODESCAN_API_KEY is not set — /api/* is UNAUTHENTICATED. " +
			"This is only safe for local dev; on 4YI (route=public) the key MUST be injected via Secrets.")
	}
	return &Server{store: st, mgr: mgr, guards: guards, web: webFS, pages: parsePages(webFS), apiKey: key}
}

// Routes returns the HTTP handler with all routes registered.
//
// Engine mode (plan §3③): the cross-tenant list route (GET /api/scans) and the
// human-facing UI (GET /{$}, /scans/{id}, /static/) are intentionally NOT
// registered — PIAQEE renders findings in its own UI and tenant isolation lives
// on the PIAQEE side. They are kept commented as a one-line restore path for the
// optional reverse-proxy-UI enhancement (plan §1), which additionally requires a
// PIAQEE-signed-JWT middleware and a jobs.tenant column before re-enabling.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Async scan API (see plan §5).
	mux.HandleFunc("POST /api/scans", s.handleCreateScan)
	// mux.HandleFunc("GET /api/scans", s.handleListScans) // [engine-mode §3③] cross-tenant list — never expose
	mux.HandleFunc("PUT /api/settings/allowed-hosts", s.handleUpdateAllowedHosts)
	mux.HandleFunc("GET /api/scans/{id}", s.handleGetScan)
	mux.HandleFunc("GET /api/scans/{id}/findings", s.handleListFindings)
	mux.HandleFunc("GET /api/scans/{id}/export", s.handleExport)
	mux.HandleFunc("POST /api/scans/{id}/cancel", s.handleCancelScan)
	mux.HandleFunc("DELETE /api/scans/{id}", s.handleDeleteScan)

	// Server-rendered pages — disabled in engine mode (§3③).
	// mux.HandleFunc("GET /{$}", s.handleIndex)
	// mux.HandleFunc("GET /scans/{id}", s.handleScanPage)
	// mux.Handle("GET /static/", http.FileServerFS(s.web))

	return s.withAPIKey(mux)
}

// withAPIKey enforces the X-API-Key header on every request except the platform
// health probe. /healthz must stay unauthenticated and cheap: the 4YI gateway
// probes it without the key, and a failing probe causes cold-start 502s
// (deployment guide §6). When s.apiKey is empty, enforcement is skipped.
func (s *Server) withAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || s.apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}
		got := r.Header.Get(apiKeyHeader)
		// constant-time compare to avoid leaking the key via timing.
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.apiKey)) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleHealthz is deliberately cheap: no DB access, no migration, no scan
// work — it only proves the process can accept requests. The platform gateway
// probes this; a slow or failing healthz means cold-start 502s (deployment
// guide §6).
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// writeJSON encodes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr sends a JSON error body.
func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) extraAllowedHosts(ctx context.Context) ([]string, error) {
	raw, err := s.store.GetSetting(ctx, extraAllowedHostsSetting)
	if err != nil {
		return nil, err
	}
	return source.ParseAllowedHostsCSV(raw)
}

func (s *Server) currentAllowedHosts(ctx context.Context) ([]string, error) {
	extra, err := s.extraAllowedHosts(ctx)
	if err != nil {
		return nil, err
	}
	return source.MergeAllowedHosts(s.guards.AllowedHosts, extra), nil
}

func (s *Server) currentGuards(ctx context.Context) (source.Guards, error) {
	hosts, err := s.currentAllowedHosts(ctx)
	if err != nil {
		return source.Guards{}, err
	}
	return source.Guards{
		MaxBytes:     s.guards.MaxBytes,
		AllowedHosts: hosts,
	}, nil
}

func joinHosts(hosts []string) string {
	return strings.Join(hosts, ", ")
}
