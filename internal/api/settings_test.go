package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/4yi-ai/codescan/internal/scan"
	"github.com/4yi-ai/codescan/internal/source"
	"github.com/4yi-ai/codescan/internal/store"
	"github.com/4yi-ai/codescan/web"
)

func TestAllowedHostsCanBeUpdatedFromApp(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	mgr := scan.NewManager(st, scan.Config{JobsDir: t.TempDir()})
	srv := NewServer(st, mgr, source.DefaultGuards(), web.FS).Routes()

	body, _ := json.Marshal(map[string]any{
		"source_type": "git",
		"source_ref":  "https://gitlab.bieases.com/team/repo.git",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("before update status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	updateBody, _ := json.Marshal(map[string]any{"hosts": "gitlab.bieases.com"})
	req = httptest.NewRequest(http.MethodPut, "/api/settings/allowed-hosts", bytes.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d, want %d", rec.Code, http.StatusOK)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("after update status = %d, want %d (body=%s)", rec.Code, http.StatusAccepted, rec.Body.String())
	}

	if raw, err := st.GetSetting(ctx, extraAllowedHostsSetting); err != nil || raw != "gitlab.bieases.com" {
		t.Fatalf("stored hosts = %q err=%v, want gitlab.bieases.com", raw, err)
	}
}

func TestAllowedHostsReadAndStaleUpdate(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	mgr := scan.NewManager(st, scan.Config{JobsDir: t.TempDir()})
	srv := NewServer(st, mgr, source.DefaultGuards(), web.FS).Routes()
	read := httptest.NewRecorder()
	srv.ServeHTTP(read, httptest.NewRequest(http.MethodGet, "/api/settings/allowed-hosts", nil))
	if read.Code != 200 {
		t.Fatalf("GET = %d", read.Code)
	}
	var config struct {
		Revision string   `json:"revision"`
		Base     []string `json:"base_allowed_hosts"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if config.Revision == "" || len(config.Base) != 2 {
		t.Fatalf("invalid config: %s", read.Body.String())
	}
	save := func(host string, revision string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"hosts": host})
		req := httptest.NewRequest(http.MethodPut, "/api/settings/allowed-hosts", bytes.NewReader(body))
		req.Header.Set("If-Match", revision)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}
	if rec := save("git.internal.example", config.Revision); rec.Code != 200 {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if rec := save("other.internal.example", config.Revision); rec.Code != 412 {
		t.Fatalf("stale save: %d", rec.Code)
	}
	raw, _ := st.GetSetting(context.Background(), extraAllowedHostsSetting)
	if raw != "git.internal.example" {
		t.Fatalf("overwritten: %s", raw)
	}
}

func TestAllowedHostsSettingsRequireAPIKey(t *testing.T) {
	t.Setenv("CODESCAN_API_KEY", "settings-test-key")
	srv := newTestServer(t)
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(method, "/api/settings/allowed-hosts", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without key = %d", method, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/settings/allowed-hosts", nil)
	req.Header.Set("Authorization", "Bearer settings-test-key")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated GET = %d", rec.Code)
	}
}
