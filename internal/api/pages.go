package api

import (
	"bytes"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"

	"github.com/4yi-ai/codescan/internal/store"
)

const recentScansPerPage = 20

// pages holds the parsed HTML templates. Each page is base.html + its own body,
// executed via the "base" template.
type pages struct {
	index *template.Template
	scan  *template.Template
}

// parsePages parses the embedded templates once at startup. It panics on a parse
// error because the templates are compiled into the binary — a failure is a
// build-time bug, not a runtime condition.
func parsePages(webFS fs.FS) *pages {
	must := func(name string) *template.Template {
		t, err := template.ParseFS(webFS, "templates/base.html", "templates/"+name)
		if err != nil {
			panic("parse templates (" + name + "): " + err.Error())
		}
		return t
	}
	return &pages{
		index: must("index.html"),
		scan:  must("scan.html"),
	}
}

// render executes t's "base" template into a buffer first, so a template error
// produces a 500 instead of a half-written 200 response.
func (s *Server) render(w http.ResponseWriter, t *template.Template, data any) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// handleIndex renders the new-scan page with the recent-scans list.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	page := parsePage(r.URL.Query().Get("page"))
	totalJobs, err := s.store.CountJobs(r.Context())
	if err != nil {
		http.Error(w, "could not load scans", http.StatusInternalServerError)
		return
	}
	totalPages := totalJobs / recentScansPerPage
	if totalJobs%recentScansPerPage != 0 {
		totalPages++
	}
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	offset := (page - 1) * recentScansPerPage
	jobs, err := s.store.ListJobsPage(r.Context(), recentScansPerPage, offset)
	if err != nil {
		http.Error(w, "could not load scans", http.StatusInternalServerError)
		return
	}
	jobs = sanitizeJobsForView(jobs)
	allowedHosts, err := s.currentAllowedHosts(r.Context())
	if err != nil {
		http.Error(w, "could not load allowed hosts", http.StatusInternalServerError)
		return
	}
	extraHosts, err := s.extraAllowedHosts(r.Context())
	if err != nil {
		http.Error(w, "could not load allowed hosts", http.StatusInternalServerError)
		return
	}
	s.render(w, s.pages.index, map[string]any{
		"Scans":                jobs,
		"AllowedHosts":         joinHosts(allowedHosts),
		"ExtraAllowedHosts":    joinHosts(extraHosts),
		"ExtraAllowedHostList": extraHosts,
		"ScanCount":            totalJobs,
		"Page":                 page,
		"PerPage":              recentScansPerPage,
		"TotalPages":           totalPages,
		"HasPrevPage":          page > 1,
		"HasNextPage":          page < totalPages,
		"PrevPage":             page - 1,
		"NextPage":             page + 1,
	})
}

// handleScanPage renders one scan's result page.
func (s *Server) handleScanPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, err := s.store.GetJob(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "could not load scan", http.StatusInternalServerError)
		return
	}
	job = sanitizeJobForView(job)
	findings, err := s.store.ListFindings(r.Context(), id, store.FindingFilter{})
	if err != nil {
		http.Error(w, "could not load findings", http.StatusInternalServerError)
		return
	}
	s.render(w, s.pages.scan, map[string]any{
		"Job":      job,
		"Findings": findings,
		"Stats":    buildStats(findings),
		"Tiers":    buildTiers(findings),
	})
}

func parsePage(raw string) int {
	if raw == "" {
		return 1
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 1
	}
	return n
}

func sanitizeJobsForView(jobs []*store.Job) []*store.Job {
	if len(jobs) == 0 {
		return jobs
	}
	out := make([]*store.Job, 0, len(jobs))
	for _, job := range jobs {
		out = append(out, sanitizeJobForView(job))
	}
	return out
}

func sanitizeJobForView(job *store.Job) *store.Job {
	if job == nil {
		return nil
	}
	cp := *job
	if isTerminalStatus(cp.Status) {
		cp.Progress = ""
	}
	return &cp
}

func isTerminalStatus(status string) bool {
	return status == store.StatusDone || status == store.StatusFailed || status == store.StatusCanceled
}
