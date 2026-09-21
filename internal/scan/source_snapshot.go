package scan

import (
	"encoding/json"
	"github.com/4yi-ai/codescan/internal/store"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

type sourceSnapshot struct {
	Version       int    `json:"version"`
	File          string `json:"file"`
	Content       string `json:"content"`
	StartLine     int    `json:"startLine"`
	HighlightLine int    `json:"highlightLine"`
	JobID         string `json:"jobId"`
	Commit        string `json:"commit,omitempty"`
}

var credentialLine = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[=:]`)

// Store bounded excerpts from this checkout only; never follow repository symlinks.
func attachSourceSnapshots(root, jobID, commit string, findings []store.Finding) {
	secretFiles := map[string]bool{}
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Category), "secret") {
			secretFiles[f.FilePath] = true
		}
	}
	for i := range findings {
		f := &findings[i]
		name := f.FilePath
		if name == "" || filepath.IsAbs(name) || strings.Contains(name, "\\") {
			continue
		}
		unsafe := false
		current := root
		for _, part := range strings.Split(name, "/") {
			if part == ".." || part == ".git" {
				unsafe = true
				break
			}
			current = filepath.Join(current, part)
			stat, err := os.Lstat(current)
			if err != nil || stat.Mode()&os.ModeSymlink != 0 {
				unsafe = true
				break
			}
		}
		if unsafe {
			continue
		}
		stat, err := os.Stat(current)
		if err != nil || !stat.Mode().IsRegular() || stat.Size() > 512*1024 {
			continue
		}
		file, err := os.Open(current)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(file, 512*1024+1))
		file.Close()
		if err != nil || len(data) > 512*1024 || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
			continue
		}
		lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
		line := f.Line
		if line < 1 && f.PkgName != "" {
			for n, text := range lines {
				if strings.Contains(text, f.PkgName) {
					line = n + 1
					break
				}
			}
		}
		if line < 1 || line > len(lines) {
			continue
		}
		start, end := line-11, line+10
		if start < 0 {
			start = 0
		}
		if end > len(lines) {
			end = len(lines)
		}
		privateBlock := false
		for n, text := range lines {
			if strings.Contains(text, "-----BEGIN") && strings.Contains(text, "PRIVATE KEY") {
				privateBlock = true
			}
			redact := privateBlock || secretFiles[name] || credentialLine.MatchString(text)
			if strings.Contains(text, "-----END") && strings.Contains(text, "PRIVATE KEY") {
				privateBlock = false
			}
			if redact {
				lines[n] = "[REDACTED]"
			}
		}
		content := strings.Join(lines[start:end], "\n")
		if len(content) > 32768 {
			continue
		}
		snapshot := sourceSnapshot{1, name, content, start + 1, line, jobID, commit}
		raw := map[string]json.RawMessage{}
		_ = json.Unmarshal([]byte(f.Raw), &raw)
		if raw == nil {
			raw = map[string]json.RawMessage{}
		}
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			continue
		}
		raw["source_snapshot"] = encoded
		encoded, err = json.Marshal(raw)
		if err == nil {
			f.Raw = string(encoded)
		}
	}
}
