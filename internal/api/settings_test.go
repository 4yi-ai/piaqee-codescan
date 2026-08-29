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
