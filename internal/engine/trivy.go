package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/4yi-ai/codescan/internal/store"
)

// TrivyFS runs `trivy fs` with the vuln, secret and misconfig scanners in one
// pass (license scanning is off — see Scan). The vulnerability DB is cached via
// TRIVY_CACHE_DIR (set in the environment), so it is not re-downloaded per scan.
type TrivyFS struct{}

// NewTrivyFS builds the engine.
func NewTrivyFS() *TrivyFS { return &TrivyFS{} }

func (e *TrivyFS) Name() string { return "trivy" }

func (e *TrivyFS) Available() bool { return available("trivy") }

func (e *TrivyFS) Scan(ctx context.Context, dir string) ([]store.Finding, error) {
	return e.ScanDetectors(ctx, dir, []string{"vuln", "secret", "misconfig"})
}

func (e *TrivyFS) ScanDetectors(ctx context.Context, dir string, detectors []string) ([]store.Finding, error) {
	args := []string{
		"fs",
		// license scanning is intentionally OFF: it emits one finding per
		// dependency license (mostly MIT/ISC/etc. — compliance info, not security)
		// and on a real project drowns out the actual vulnerabilities. Security
		// scanners only. (Re-add "license" here if a compliance view is wanted.)
		"--scanners", strings.Join(detectors, ","),
		"--format", "json",
		"--quiet",
		"--no-progress",
		// --offline-scan: never reach out to external registries (e.g. Maven
		// Central) to resolve dependencies. The 4YI pod has restricted egress and
		// external repos rate-limit (429) the shared IP; offline keeps SCA working
		// from local lockfiles/manifests instead of failing the whole scan.
		"--offline-scan",
		dir,
	}
	// trivy returns 0 even with findings (default exit-code); accept 0 only.
	out, err := runJSON(ctx, map[int]bool{0: true}, "trivy", args...)
	if err != nil {
		return nil, err
	}
	return parseTrivy(out, dir)
}

// trivyReport is the subset of `trivy fs --format json` we consume.
type trivyReport struct {
	Results []struct {
		Target string `json:"Target"`
		Class  string `json:"Class"`
		// Packages carries the dependency graph metadata; Relationship tells us
		// whether a package is a direct dependency or pulled in transitively.
		Packages []struct {
			ID           string `json:"ID"`
			Name         string `json:"Name"`
			Version      string `json:"Version"`
			Relationship string `json:"Relationship"` // direct | indirect | root | workspace | ...
		} `json:"Packages"`
		Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
		Secrets         []struct {
			RuleID    string `json:"RuleID"`
			Severity  string `json:"Severity"`
			Title     string `json:"Title"`
			StartLine int    `json:"StartLine"`
			EndLine   int    `json:"EndLine"`
		} `json:"Secrets"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			Title         string `json:"Title"`
			Description   string `json:"Description"`
			Severity      string `json:"Severity"`
			Message       string `json:"Message"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
		Licenses []struct {
			Severity string `json:"Severity"`
			PkgName  string `json:"PkgName"`
			Name     string `json:"Name"`
			FilePath string `json:"FilePath"`
			Category string `json:"Category"`
		} `json:"Licenses"`
	} `json:"Results"`
}

type trivyVulnerability struct {
	VulnerabilityID  string
	PkgID            string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	AffectedVersion  string
	Severity         string
	Title            string
	Description      string
	PrimaryURL       string
	References       []string
	SeveritySource   string
	CVSS             map[string]struct {
		V3Score  *float64
		V3Vector string
		V4Score  *float64
		V4Vector string
	}
}

func (v trivyVulnerability) dependencyRaw() string {
	type dependency struct {
		PackageName      string   `json:"packageName,omitempty"`
		InstalledVersion string   `json:"installedVersion,omitempty"`
		FixedVersion     string   `json:"fixedVersion,omitempty"`
		AffectedVersions string   `json:"affectedVersions,omitempty"`
		Advisory         string   `json:"advisory,omitempty"`
		References       []string `json:"references,omitempty"`
		Score            *float64 `json:"score,omitempty"`
		Vector           string   `json:"vector,omitempty"`
	}
	info := dependency{PackageName: v.PkgName, InstalledVersion: v.InstalledVersion, FixedVersion: v.FixedVersion, AffectedVersions: v.AffectedVersion, Advisory: v.VulnerabilityID}
	for _, reference := range append([]string{v.PrimaryURL}, v.References...) {
		if len(info.References) == 5 {
			break
		}
		if strings.HasPrefix(reference, "https://") && len(reference) <= 1000 && !slices.Contains(info.References, reference) {
			info.References = append(info.References, reference)
		}
	}
	var sources []string
	for name := range v.CVSS {
		sources = append(sources, name)
	}
	slices.Sort(sources)
	for _, name := range append([]string{v.SeveritySource, "nvd"}, sources...) {
		rating := v.CVSS[name]
		if rating.V4Vector != "" {
			info.Score, info.Vector = rating.V4Score, rating.V4Vector
			break
		}
		if rating.V3Vector != "" {
			info.Score, info.Vector = rating.V3Score, rating.V3Vector
			break
		}
	}
	encoded, _ := json.Marshal(struct {
		Dependency dependency `json:"dependency"`
	}{info})
	return string(encoded)
}

func parseTrivy(data []byte, dir string) ([]store.Finding, error) {
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}
	var out []store.Finding
	for _, res := range rep.Results {
		target := relPath(dir, res.Target)

		// Build a package -> direct/indirect map for this result. Key by PkgID
		// (e.g. "tar@6.1.0") and by name@version as a fallback.
		rel := make(map[string]string, len(res.Packages))
		for _, p := range res.Packages {
			r := normRelationship(p.Relationship)
			if r == "" {
				continue
			}
			if p.ID != "" {
				rel[p.ID] = r
			}
			if p.Name != "" && p.Version != "" {
				rel[p.Name+"@"+p.Version] = r
			}
		}

		for _, v := range res.Vulnerabilities {
			r := rel[v.PkgID]
			if r == "" {
				r = rel[v.PkgName+"@"+v.InstalledVersion]
			}
			out = append(out, store.Finding{
				Tool:         "trivy",
				Category:     "sca",
				Severity:     normSeverity(v.Severity),
				RuleID:       v.VulnerabilityID,
				CVE:          v.VulnerabilityID,
				Title:        firstNonEmpty(v.Title, v.VulnerabilityID),
				Message:      strings.TrimSpace(v.Description),
				FilePath:     target,
				PkgName:      v.PkgName,
				PkgVer:       v.InstalledVersion,
				FixedVer:     v.FixedVersion,
				Relationship: r,
				Raw:          v.dependencyRaw(),
			})
		}
		for _, s := range res.Secrets {
			// Persist location metadata only; Trivy secret values must never enter Raw.
			location := fmt.Sprintf(`{"secret_location":{"endLine":%d}}`, s.EndLine)
			out = append(out, store.Finding{
				Tool:     "trivy",
				Category: "secret",
				Severity: normSeverity(s.Severity),
				RuleID:   s.RuleID,
				Title:    firstNonEmpty(s.Title, s.RuleID),
				FilePath: target,
				Line:     s.StartLine,
				Raw:      location,
			})
		}
		for _, m := range res.Misconfigurations {
			out = append(out, store.Finding{
				Tool:     "trivy",
				Category: "iac",
				Severity: normSeverity(m.Severity),
				RuleID:   m.ID,
				Title:    firstNonEmpty(m.Title, m.ID),
				Message:  firstNonEmpty(strings.TrimSpace(m.Message), strings.TrimSpace(m.Description)),
				FilePath: target,
				Line:     m.CauseMetadata.StartLine,
			})
		}
		for _, l := range res.Licenses {
			path := target
			if l.FilePath != "" {
				path = relPath(dir, l.FilePath)
			}
			out = append(out, store.Finding{
				Tool:     "trivy",
				Category: "license",
				Severity: normSeverity(l.Severity),
				RuleID:   l.Name,
				Title:    firstNonEmpty(l.Name, "license"),
				Message:  strings.TrimSpace(l.Category),
				FilePath: path,
				PkgName:  l.PkgName,
			})
		}
	}
	return out, nil
}

// normRelationship maps Trivy's Relationship enum to codescan's direct/indirect.
// root and workspace packages are top-level, so treat them as direct.
func normRelationship(r string) string {
	switch strings.ToLower(strings.TrimSpace(r)) {
	case "direct", "root", "workspace":
		return "direct"
	case "indirect":
		return "indirect"
	default:
		return ""
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
