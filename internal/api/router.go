// Package api holds the HTTP handlers and routing for codescan.
package api

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"

	"github.com/4yi-ai/codescan/internal/scan"
	"github.com/4yi-ai/codescan/internal/source"
	"github.com/4yi-ai/codescan/internal/store"
)

const extraAllowedHostsSetting = "extra_allowed_hosts"

// Server bundles the dependencies the HTTP handlers need.
type Server struct {
	store  *store.Store
	mgr    *scan.Manager
	guards source.Guards
	web    fs.FS // embedded web assets (templates/*, static/*)
	pages  *pages
}

// NewServer builds a Server. webFS is the embedded web/ directory.
func NewServer(st *store.Store, mgr *scan.Manager, guards source.Guards, webFS fs.FS) *Server {
	return &Server{store: st, mgr: mgr, guards: guards, web: webFS, pages: parsePages(webFS)}
}

// Routes returns the HTTP handler with all routes registered.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Async scan API (see plan §5).
	mux.HandleFunc("POST /api/scans", s.handleCreateScan)
	mux.HandleFunc("GET /api/scans", s.handleListScans)
	mux.HandleFunc("PUT /api/settings/allowed-hosts", s.handleUpdateAllowedHosts)
	mux.HandleFunc("GET /api/scans/{id}", s.handleGetScan)
	mux.HandleFunc("GET /api/scans/{id}/findings", s.handleListFindings)
	mux.HandleFunc("GET /api/scans/{id}/export", s.handleExport)
	mux.HandleFunc("POST /api/scans/{id}/cancel", s.handleCancelScan)
	mux.HandleFunc("DELETE /api/scans/{id}", s.handleDeleteScan)

	// Server-rendered pages.
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /scans/{id}", s.handleScanPage)
	mux.Handle("GET /static/", http.FileServerFS(s.web))
	return mux
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
