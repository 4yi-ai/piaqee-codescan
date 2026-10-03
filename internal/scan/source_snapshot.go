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

var assignmentPrefix = regexp.MustCompile(`^(\s*(?:(?:export|const|let|var)\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*[:=]\s*)`)

// Keep only the field name, never a value or trailing comment on a sensitive line.
func redactSourceLine(text string) string {
 if prefix := assignmentPrefix.FindString(text); prefix != "" {
  return prefix + "[REDACTED]"
 }
 return "[REDACTED]"
}

func hasClosingQuote(text string, quote byte) bool {
 for i := 0; i < len(text); i++ {
  if text[i] == '\\' && quote == '"' { i++; continue }
  if text[i] == quote {
   if quote == '\'' && i+1 < len(text) && text[i+1] == quote { i++; continue }
   return true
  }
 }
 return false
}

var credentialLine = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[=:]`)
var privateKeyBegin = regexp.MustCompile(`-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----`)

// Store bounded excerpts from this checkout only; never follow repository symlinks.
func attachSourceSnapshots(root, jobID, commit string, findings []store.Finding) {
 secretLines := map[string]map[int]bool{}
 unknownSecretFiles := map[string]bool{}
 for _, f := range findings {
  if !strings.Contains(strings.ToLower(f.Category), "secret") { continue }
  if f.Line < 1 { unknownSecretFiles[f.FilePath] = true; continue }
  var raw struct { Location struct { EndLine int `json:"endLine"` } `json:"secret_location"` }
  if f.Raw != "" && json.Unmarshal([]byte(f.Raw), &raw) != nil { unknownSecretFiles[f.FilePath] = true; continue }
  end := raw.Location.EndLine
  if end == 0 { end = f.Line }
  if end < f.Line || end-f.Line > 512*1024 { unknownSecretFiles[f.FilePath] = true; continue }
  if secretLines[f.FilePath] == nil { secretLines[f.FilePath] = map[int]bool{} }
  for line := f.Line; line <= end; line++ { secretLines[f.FilePath][line] = true }
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
		limit := int64(512 * 1024)
		if filepath.Base(name) == "package-lock.json" {
			limit = 16 * 1024 * 1024
		}
		stat, err := os.Stat(current)
		if err != nil || !stat.Mode().IsRegular() || stat.Size() > limit {
			continue
		}
		file, err := os.Open(current)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(file, limit+1))
		file.Close()
		if err != nil || int64(len(data)) > limit || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
			continue
		}
		lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
		line := f.Line
		if line < 1 && f.PkgName != "" {
			line = dependencySourceLine(lines, name, f.PkgName, f.PkgVer)
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
  // An invalid location cannot safely narrow the redaction to individual lines.
  for n := range secretLines[name] {
   if n > len(lines) { unknownSecretFiles[name] = true }
  }
  privateBlock := ""
  blockIndent := -1
  var openQuote byte
  for n, text := range lines {
   if marker := privateKeyBegin.FindStringSubmatch(text); privateBlock == "" && marker != nil { privateBlock = marker[1] }
   indent := len(text) - len(strings.TrimLeft(text, " \t"))
   continuation := blockIndent >= 0 && (strings.TrimSpace(text) == "" || indent > blockIndent)
   if blockIndent >= 0 && !continuation { blockIndent = -1 }
   quotedContinuation := openQuote != 0
   if quotedContinuation && hasClosingQuote(text, openQuote) { openQuote = 0 }
   sensitive := secretLines[name][n+1] || credentialLine.MatchString(text)
   // Assignments inside a secret value are content, not new values. Restarting
   // quote/block tracking here can hide unrelated code after the value closes.
   if sensitive && !quotedContinuation && !continuation && privateBlock == "" {
    if prefix := assignmentPrefix.FindString(text); prefix != "" {
     value := strings.TrimSpace(strings.TrimPrefix(text, prefix))
     if len(value) > 0 && (value[0] == '\'' || value[0] == '"') && !hasClosingQuote(value[1:], value[0]) { openQuote = value[0] }
     // Hide YAML block values even when scanner location metadata is absent.
     if value == "" || strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">") || strings.HasPrefix(value, "#") { blockIndent = indent }
    }
   }
   switch {
   case unknownSecretFiles[name], privateBlock != "", continuation, quotedContinuation:
    lines[n] = "[REDACTED]"
   case sensitive:
    lines[n] = redactSourceLine(text)
   }
   if privateBlock != "" && strings.Contains(text, "-----END " + privateBlock + "-----") { privateBlock = "" }
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

// Prefer package records over dependency references and require exact names.
func dependencySourceLine(lines []string, file, name, version string) int {
	if filepath.Base(file) == "package-lock.json" {
		record := regexp.MustCompile(`^\s*"(?:[^" ]*/)?node_modules/` + regexp.QuoteMeta(name) + `"\s*:\s*\{`)
		legacy := regexp.MustCompile(`^\s*"` + regexp.QuoteMeta(name) + `"\s*:\s*\{`)
		ver := regexp.MustCompile(`^\s*"version"\s*:\s*"` + regexp.QuoteMeta(version) + `"`)
		for _, pattern := range []*regexp.Regexp{record, legacy} {
			for i, text := range lines {
				if !pattern.MatchString(text) {
					continue
				}
				if version == "" {
					return i + 1
				}
				for n := i + 1; n < len(lines) && n <= i+8; n++ {
					if ver.MatchString(lines[n]) {
						return i + 1
					}
					if strings.Contains(lines[n], "}") {
						break
					}
				}
			}
		}
		return 0
	}
	exact := regexp.MustCompile(`(^|[\s"'])` + regexp.QuoteMeta(name) + `([\s"':]|$)`)
	for i, text := range lines {
		if exact.MatchString(text) {
			return i + 1
		}
	}
	return 0
}
