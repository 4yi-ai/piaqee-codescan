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

// legacyAPIKeyHeader is the header older PIAQEE clients send. Still accepted for a
// transition window; the canonical scheme is now Authorization: Bearer <key>.
const legacyAPIKeyHeader = "X-API-Key"

// Server bundles the dependencies the HTTP handlers need.
type Server struct {
	store        *store.Store
	mgr          *scan.Manager
	guards       source.Guards
	web          fs.FS // embedded web assets (templates/*, static/*)
	pages        *pages
	apiKey       string // required key for /api/*; empty = behavior depends on authRequired
	authRequired bool   // when true, empty apiKey fails closed (all /api/* → 503)
}

// NewServer builds a Server. webFS is the embedded web/ directory.
//
// Auth (aligned with the 4YI platform recommendation): every /api/* request must
// carry the key as "Authorization: Bearer <CODESCAN_API_KEY>". The same header
// also clears the 4YI gateway's bearer-passthrough, so one header does both. The
// legacy "X-API-Key" header is still accepted during the transition.
//
// CODESCAN_API_KEY holds the expected key. Empty-key behavior is governed by
// CODESCAN_AUTH_REQUIRED:
//   - unset/false: empty key → enforcement disabled. This is the fallback that
//     keeps the engine usable before 4YI secret storage is wired up (local dev,
//     or the current install where the platform secret has no value yet).
//   - true: empty key → fail closed (every /api/* returns 503). Turn on once the
//     secret value is configured on 4YI, so the engine never serves
//     unauthenticated when it's meant to be protected.
func NewServer(st *store.Store, mgr *scan.Manager, guards source.Guards, webFS fs.FS) *Server {
	key := os.Getenv("CODESCAN_API_KEY")
	authRequired := os.Getenv("CODESCAN_AUTH_REQUIRED") == "true"
	if key == "" && !authRequired {
		log.Printf("[api] WARNING: CODESCAN_API_KEY is not set and CODESCAN_AUTH_REQUIRED is off — " +
			"/api/* is UNAUTHENTICATED. Safe only for local dev or a not-yet-secured 4YI install; " +
			"set the secret and CODESCAN_AUTH_REQUIRED=true to enforce.")
	}
	if key == "" && authRequired {
		log.Printf("[api] CODESCAN_AUTH_REQUIRED=true but CODESCAN_API_KEY is empty — " +
			"failing closed: every /api/* request returns 503 until the key is injected.")
	}
	return &Server{store: st, mgr: mgr, guards: guards, web: webFS, pages: parsePages(webFS), apiKey: key, authRequired: authRequired}
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

// withAPIKey enforces the API key on every request except the platform health
// probe. /healthz must stay unauthenticated and cheap: the 4YI gateway probes it
// without the key, and a failing probe causes cold-start 502s (deployment guide §6).
//
// The canonical credential is "Authorization: Bearer <key>" (also what clears the
// 4YI gateway bearer-passthrough); the legacy "X-API-Key" header is still accepted.
// Empty-key behavior: authRequired=false → skip enforcement (usable fallback);
// authRequired=true → fail closed with 503 (key was meant to be injected but isn't).
func (s *Server) withAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if s.apiKey == "" {
			if s.authRequired {
				writeErr(w, http.StatusServiceUnavailable, "auth required but no API key configured")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		got := ""
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			got = strings.TrimPrefix(auth, "Bearer ")
		}
		if got == "" {
			got = r.Header.Get(legacyAPIKeyHeader)
		}
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
