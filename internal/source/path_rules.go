package source

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// PathRules apply to non-secret detectors. Secret scanning keeps the original checkout.
type PathRules struct {
	Include []string            `json:"include,omitempty"`
	Exclude map[string][]string `json:"exclude,omitempty"`
}

func NormalizePathRules(rules *PathRules) (*PathRules, error) {
	if rules == nil {
		return nil, nil
	}
	include, err := normalizePatterns(rules.Include)
	if err != nil {
		return nil, err
	}
	result := &PathRules{Include: include, Exclude: make(map[string][]string)}
	for detector, patterns := range rules.Exclude {
		if detector != "sast" && detector != "sca" && detector != "iac" {
			return nil, fmt.Errorf("path exclusions are supported for sast, sca and iac")
		}
		values, err := normalizePatterns(patterns)
		if err != nil {
			return nil, err
		}
		if len(values) > 0 {
			result.Exclude[detector] = values
		}
	}
	if len(result.Include) == 0 && len(result.Exclude) == 0 {
		return nil, nil
	}
	return result, nil
}

func normalizePatterns(patterns []string) ([]string, error) {
	if len(patterns) > 20 {
		return nil, fmt.Errorf("each path rule list accepts at most 20 patterns")
	}
	values := make([]string, 0, len(patterns))
	for _, raw := range patterns {
		pattern := strings.TrimRight(strings.TrimSpace(raw), "/")
		parts := strings.Split(pattern, "/")
		if len(pattern) > 512 || len(parts) > 40 || strings.ContainsAny(pattern, `\:[]!#<>|`) || strings.ContainsFunc(pattern, unicode.IsControl) {
			return nil, fmt.Errorf("invalid repository-relative scan path pattern")
		}
		for _, part := range parts {
			if part == "" || part == "." || part == ".." || strings.EqualFold(part, ".git") || (strings.Contains(part, "**") && part != "**") {
				return nil, fmt.Errorf("invalid repository-relative scan path pattern")
			}
		}
		values = append(values, pattern)
	}
	slices.Sort(values)
	return slices.Compact(values), nil
}

func patternMatches(pattern []string, file []string) bool {
	// A matched directory includes descendants. Memoization bounds multiple ** segments.
	type state struct{ rule, part int }
	seen := make(map[state]bool)
	var match func(int, int) bool
	match = func(rule, part int) bool {
		if rule == len(pattern) {
			return true
		}
		position := state{rule, part}
		if seen[position] {
			return false
		}
		seen[position] = true
		if pattern[rule] == "**" {
			return match(rule+1, part) || part < len(file) && match(rule, part+1)
		}
		if part == len(file) {
			return false
		}
		ok, _ := path.Match(pattern[rule], file[part])
		return ok && match(rule+1, part+1)
	}
	return match(0, 0)
}

// StageFilteredTree projects regular files only. The checkout and projections
// share a disposable job directory; scanner CLI invocations are read-only.
func StageFilteredTree(ctx context.Context, checkout, target string, includes, excludes []string) error {
	if err := os.MkdirAll(target, 0o750); err != nil {
		return err
	}
	compile := func(patterns []string) [][]string {
		parts := make([][]string, len(patterns))
		for i, pattern := range patterns {
			parts[i] = strings.Split(pattern, "/")
			if len(parts[i]) == 1 && pattern != "**" && strings.ContainsAny(pattern, "*?") {
				parts[i] = []string{"**", pattern}
			}
		}
		return parts
	}
	allow, deny := compile(includes), compile(excludes)
	covered := false
	err := filepath.WalkDir(checkout, func(filename string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if strings.EqualFold(entry.Name(), ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(checkout, filename)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		matches := func(pattern []string) bool { return patternMatches(pattern, parts) }
		if len(allow) > 0 && !slices.ContainsFunc(allow, matches) {
			return nil
		}
		covered = true
		if slices.ContainsFunc(deny, matches) {
			return nil
		}
		result := filepath.Join(target, relative)
		if err := os.MkdirAll(filepath.Dir(result), 0o750); err != nil {
			return err
		}
		return os.Link(filename, result)
	})
	if err != nil {
		return err
	}
	if len(allow) > 0 && !covered {
		return fmt.Errorf("scan include patterns did not match any source files")
	}
	return nil
}
