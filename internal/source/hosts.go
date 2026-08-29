package source

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var hostLabelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// DefaultAllowedHosts returns the built-in git hosts that are always allowed.
func DefaultAllowedHosts() []string {
	return []string{"github.com", "gitlab.com"}
}

// NormalizeHost validates a single exact-match hostname for the git allowlist.
func NormalizeHost(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("host is empty")
	}
	host := strings.ToLower(trimmed)
	if strings.Contains(host, "://") {
		u, err := url.Parse(trimmed)
		if err != nil {
			return "", fmt.Errorf("invalid host or repo URL %q", raw)
		}
		if u.Scheme != "https" {
			return "", fmt.Errorf("host URL must be https (got %q)", u.Scheme)
		}
		if u.User != nil {
			return "", fmt.Errorf("host URL must not embed credentials")
		}
		if u.Port() != "" {
			return "", fmt.Errorf("host URL must use the default port")
		}
		host = strings.ToLower(u.Hostname())
		if host == "" {
			return "", fmt.Errorf("invalid host or repo URL %q", raw)
		}
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/:@?#") {
		return "", fmt.Errorf("invalid host %q", raw)
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !hostLabelRe.MatchString(label) {
			return "", fmt.Errorf("invalid host %q", raw)
		}
	}
	return host, nil
}

// ParseAllowedHostsCSV parses a comma-separated host list, normalizing and
// de-duplicating entries while preserving their first-seen order.
func ParseAllowedHostsCSV(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	raw = strings.NewReplacer("\r\n", ",", "\n", ",", ";", ",").Replace(raw)
	var out []string
	seen := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		host, err := NormalizeHost(part)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out, nil
}

// MergeAllowedHosts de-duplicates multiple host lists into one stable list.
func MergeAllowedHosts(lists ...[]string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, list := range lists {
		for _, host := range list {
			host = strings.ToLower(strings.TrimSpace(host))
			if host == "" {
				continue
			}
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			out = append(out, host)
		}
	}
	return out
}
