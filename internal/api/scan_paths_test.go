package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGitScanAcceptsRepositoryDirectories(t *testing.T) {
	t.Setenv("CODESCAN_API_KEY", "example-key")
	srv := newTestServer(t)
	for _, tc := range []struct {
		paths  string
		status int
	}{
		{`["services/api", "apps/portal"]`, http.StatusAccepted},
		{`["../outside"]`, http.StatusBadRequest},
		{`["/absolute"]`, http.StatusBadRequest},
		{`["apps/*"]`, http.StatusBadRequest},
	} {
		t.Run(tc.paths, func(t *testing.T) {
			body := `{"source_type":"git","source_ref":"https://github.com/example/repository.git","branch":"main","scan_paths":` + tc.paths + `}`
			req := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer example-key")
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d; %s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}
