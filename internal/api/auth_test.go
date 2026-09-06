package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/4yi-ai/codescan/internal/scan"
	"github.com/4yi-ai/codescan/internal/source"
	"github.com/4yi-ai/codescan/internal/store"
	"github.com/4yi-ai/codescan/web"
)

// newTestServer builds a Routes() handler. CODESCAN_API_KEY must be set (or unset)
// via t.Setenv before calling, since NewServer snapshots it.
func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	mgr := scan.NewManager(st, scan.Config{JobsDir: t.TempDir()})
	return NewServer(st, mgr, source.DefaultGuards(), web.FS).Routes()
}

func TestAPIKey_HealthzAlwaysOpen(t *testing.T) {
	t.Setenv("CODESCAN_API_KEY", "s3cret")
	srv := newTestServer(t)

	// No key on /healthz must still return 200 (4YI probe carries no key, §6).
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz without key = %d, want 200", rec.Code)
	}
}

func TestAPIKey_MissingOrWrongRejected(t *testing.T) {
	t.Setenv("CODESCAN_API_KEY", "s3cret")
	srv := newTestServer(t)

	cases := []struct {
		name string
		key  string
	}{
		{"missing", ""},
		{"wrong", "nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/scans/00000000-0000-0000-0000-000000000000", nil)
			if tc.key != "" {
				req.Header.Set("Authorization", "Bearer "+tc.key)
			}
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s key = %d, want 401", tc.name, rec.Code)
			}
		})
	}
}

func TestAPIKey_CorrectPasses(t *testing.T) {
	t.Setenv("CODESCAN_API_KEY", "s3cret")
	srv := newTestServer(t)

	// Correct key via the canonical Authorization: Bearer header passes the auth
	// layer; an unknown job id then yields 404 (not 401).
	req := httptest.NewRequest(http.MethodGet, "/api/scans/00000000-0000-0000-0000-000000000000", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("correct key was rejected with 401")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("correct key + unknown job = %d, want 404", rec.Code)
	}
}

// TestAPIKey_LegacyHeaderStillAccepted locks in the transition guarantee: older
// PIAQEE clients sending the correct key via X-API-Key still pass.
func TestAPIKey_LegacyHeaderStillAccepted(t *testing.T) {
	t.Setenv("CODESCAN_API_KEY", "s3cret")
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/scans/00000000-0000-0000-0000-000000000000", nil)
	req.Header.Set(legacyAPIKeyHeader, "s3cret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("legacy X-API-Key with correct key was rejected with 401")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("legacy header + unknown job = %d, want 404", rec.Code)
	}
}

// TestAPIKey_FailClosedWhenAuthRequired locks in the fail-closed path: an empty
// configured key with CODESCAN_AUTH_REQUIRED=true must reject every /api/*
// request with 503, so the engine never serves unauthenticated when it's meant
// to be protected but the secret hasn't been injected yet.
func TestAPIKey_FailClosedWhenAuthRequired(t *testing.T) {
	t.Setenv("CODESCAN_API_KEY", "")
	t.Setenv("CODESCAN_AUTH_REQUIRED", "true")
	srv := newTestServer(t)

	// /healthz must still be open even when failing closed (4YI probe carries no key).
	health := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	hrec := httptest.NewRecorder()
	srv.ServeHTTP(hrec, health)
	if hrec.Code != http.StatusOK {
		t.Fatalf("healthz while fail-closed = %d, want 200", hrec.Code)
	}

	// Any /api/* request fails closed with 503, regardless of headers sent.
	req := httptest.NewRequest(http.MethodGet, "/api/scans/00000000-0000-0000-0000-000000000000", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("fail-closed /api = %d, want 503", rec.Code)
	}
}

func TestAPIKey_DisabledWhenUnset(t *testing.T) {
	t.Setenv("CODESCAN_API_KEY", "")
	srv := newTestServer(t)

	// With no configured key, /api is open (dev/test mode) — unknown job → 404, not 401.
	req := httptest.NewRequest(http.MethodGet, "/api/scans/00000000-0000-0000-0000-000000000000", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unset key + unknown job = %d, want 404", rec.Code)
	}
}

// TestListRouteNotRegistered locks in §3③: the cross-tenant list route is gone.
func TestListRouteNotRegistered(t *testing.T) {
	t.Setenv("CODESCAN_API_KEY", "")
	srv := newTestServer(t)

	// POST /api/scans is still registered, so GET on the same path yields 405
	// (Method Not Allowed) from ServeMux — proving the GET list handler is NOT
	// wired. A registered list route would return 200.
	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/scans (list) = %d, want 405 (list handler must not be registered)", rec.Code)
	}
}
