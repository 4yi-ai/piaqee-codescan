package api

import (
	"sort"
	"strings"

	"github.com/4yi-ai/codescan/internal/store"
)

// This file builds the view-model for the web scan page: the category x severity
// stats table and the type-based priority tiers. It mirrors the PDF layout
// (drawStatsTable + priority tiers in pdf.go) so the web and PDF reports tell the
// same story. tierOf/isCustomRule/sevRank are shared from pdf.go.

// StatsRow is one row of the category x severity count table.
type StatsRow struct {
	Label                           string
	Crit, High, Med, Low, Info, Tot int
}

// TierGroup is one rendered priority tier (P1..P4) with its findings.
type TierGroup struct {
	Num      int
	Label    string
	Subtitle string
	Class    string // css suffix: p1..p4
	Findings []store.Finding
}

// webTiers is the display metadata for the 5 priority tiers, in order.
var webTiers = []struct{ label, subtitle, class string }{
	{"P1 · Confirmed Code Vulnerabilities", "CodeScan custom rules found auth bypass, SQL injection, or SSRF issues. Fix these first.", "p1"},
	{"P2 · Code Issues (SAST)", "Static analysis of your own code: injections, weak crypto, insecure TLS, and code smells. Sorted by severity.", "p2"},
	{"P3 · Direct Dependencies", "Packages you explicitly depend on. Usually fixed by upgrading the package version. Sorted by severity.", "p3"},
	{"P4 · Secrets & Configuration", "Exposed secrets, credentials, Dockerfile issues, and other configuration problems. Rotate leaked secrets immediately.", "p4"},
	{"P5 · Transitive Dependencies", "Issues introduced indirectly by other packages. Usually fixed by upgrading the parent dependency. Sorted by severity.", "p5"},
}

// buildStats returns the category x severity table rows (only categories that
// have findings), in a fixed display order.
func buildStats(findings []store.Finding) []StatsRow {
	rows := []struct{ key, label string }{
		{"sca", "SCA (Dependencies)"},
		{"sast", "SAST (Code)"},
		{"iac", "IaC (Configuration)"},
		{"secret", "Secrets"},
	}
	counts := map[string]map[string]int{}
	for i := range findings {
		cat := strings.ToLower(findings[i].Category)
		if counts[cat] == nil {
			counts[cat] = map[string]int{}
		}
		counts[cat][strings.ToLower(findings[i].Severity)]++
	}
	var out []StatsRow
	for _, r := range rows {
		cc := counts[r.key]
		if cc == nil {
			continue
		}
		row := StatsRow{Label: r.label,
			Crit: cc["critical"], High: cc["high"], Med: cc["medium"],
			Low: cc["low"], Info: cc["info"]}
		row.Tot = row.Crit + row.High + row.Med + row.Low + row.Info
		out = append(out, row)
	}
	return out
}

// buildTiers buckets findings into the 4 priority tiers (most actionable first),
// each sorted by severity. Empty tiers are omitted.
func buildTiers(findings []store.Finding) []TierGroup {
	buckets := map[int][]store.Finding{}
	for _, f := range findings {
		t := tierOf(&f)
		buckets[t] = append(buckets[t], f)
	}
	var out []TierGroup
	for i, meta := range webTiers {
		fs := buckets[i+1]
		if len(fs) == 0 {
			continue
		}
		sort.SliceStable(fs, func(a, b int) bool {
			return sevRank(fs[a].Severity) < sevRank(fs[b].Severity)
		})
		out = append(out, TierGroup{
			Num: i + 1, Label: meta.label, Subtitle: meta.subtitle,
			Class: meta.class, Findings: fs,
		})
	}
	return out
}
