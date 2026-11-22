package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/4yi-ai/codescan/internal/reach"
	"github.com/4yi-ai/codescan/internal/source"
	"github.com/4yi-ai/codescan/internal/store"
)

// Engine is one scanning tool (semgrep, trivy fs) run over a source directory.
// Available lets the runner skip a tool that isn't installed (e.g. a dev laptop
// without trivy) instead of failing the whole job.
type Engine interface {
	Name() string
	Available() bool
	Scan(ctx context.Context, dir string) ([]store.Finding, error)
}

// realRunner fetches the source then runs each available engine, normalizing
// results into findings + a summary. It replaces stubRunner from M2 onward.
type realRunner struct {
	store   *store.Store
	jobsDir string
	guards  source.Guards
	engines []Engine
}

// NewRunner builds the production Runner.
func NewRunner(st *store.Store, jobsDir string, guards source.Guards, engines ...Engine) Runner {
	return &realRunner{store: st, jobsDir: jobsDir, guards: guards, engines: engines}
}

func (r *realRunner) Run(ctx context.Context, job *store.Job, sec Secret) error {
	srcDir := filepath.Join(r.jobsDir, job.ID, "src")

	// ---- fetch phase ----
	if err := r.store.SetStatus(ctx, job.ID, store.StatusFetching, "fetching source"); err != nil {
		return err
	}
	commit, err := r.fetch(ctx, job, sec, srcDir)
	if err != nil {
		return err
	}
	if len(sec.ScanPaths) > 0 && sec.PathRules == nil {
		// The scanners work from the staged tree, so an excluded file cannot
		// influence results even when its path would match a scanner's default.
		scopedRoot := filepath.Join(r.jobsDir, job.ID, "scoped")
		if err := source.StageScanPaths(ctx, srcDir, scopedRoot, sec.ScanPaths); err != nil {
			return err
		}
		srcDir = scopedRoot
	}
	steps, err := r.scanSteps(ctx, srcDir, filepath.Join(r.jobsDir, job.ID), sec)
	if err != nil {
		return err
	}

	// ---- scan phase ----
	if err := r.store.SetStatus(ctx, job.ID, store.StatusScanning, "scanning"); err != nil {
		return err
	}
	var all []store.Finding
	var engineErrs []string
	ran := 0
	var completedEngines []string
	engineDetails := make(map[string]store.EngineDetails)
	remaining := make(map[string]int)
	for _, step := range steps {
		remaining[step.engine.Name()]++
	}
	secretsFullSource := false
	for _, step := range steps {
		e := step.engine
		if err := ctx.Err(); err != nil {
			return err
		}
		if !e.Available() {
			log.Printf("job %s: engine %s unavailable, skipping", job.ID, e.Name())
			continue
		}
		_ = r.store.SetStatus(ctx, job.ID, store.StatusScanning, "running "+e.Name())
		found, err := step.scan(ctx)
		if err != nil {
			// One engine failing must not discard the other engine's results:
			// record the error and keep going (plan: scanner should be resilient).
			// If the context was canceled/timed out, that's fatal for the whole job.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("job %s: engine %s failed: %v", job.ID, e.Name(), err)
			engineErrs = append(engineErrs, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		ran++
		remaining[e.Name()]--
		if remaining[e.Name()] == 0 {
			completedEngines = append(completedEngines, e.Name())
			if reporter, ok := e.(interface {
				Details(context.Context) store.EngineDetails
			}); ok {
				engineDetails[e.Name()] = reporter.Details(ctx)
			}
		}
		if step.root == srcDir && slices.Contains(step.detectors, "secret") {
			secretsFullSource = true
		}
		for i := range found {
			found[i].JobID = job.ID
		}
		all = append(all, found...)
	}

	// ---- reachability (lightweight) + persist ----
	tagReachability(srcDir, all)
	all = dedupe(all)
	attachSourceSnapshots(srcDir, job.ID, commit, all)
	if err := r.store.InsertFindings(ctx, all); err != nil {
		return err
	}
	summary := summarize(all)
	summary.Commit = commit
	summary.EngineDetails = engineDetails
	summary.Coverage = &store.Coverage{Version: 1, Path: ".", Engines: completedEngines, Complete: ran == len(steps) && ran > 0}
	if len(sec.ScanPaths) > 0 {
		summary.Coverage.Version = 2
		summary.Coverage.Path = ""
		summary.Coverage.Paths = sec.ScanPaths
	}
	if sec.PathRules != nil {
		encoded, err := json.Marshal(sec.PathRules)
		if err != nil {
			return err
		}
		summary.Coverage.Version = 3
		summary.Coverage.Path = ""
		summary.Coverage.PathRules = encoded
		summary.Coverage.SecretsFullSource = secretsFullSource
		summary.Coverage.Complete = summary.Coverage.Complete && secretsFullSource
	}
	if err := r.store.SetSummary(ctx, job.ID, summary); err != nil {
		return err
	}

	switch {
	case sec.PathRules != nil && !secretsFullSource:
		return fmt.Errorf("secret scan did not complete over the full source")
	case ran == 0 && len(engineErrs) > 0:
		// Every engine failed → the scan failed.
		return fmt.Errorf("%s", strings.Join(engineErrs, "; "))
	case len(engineErrs) > 0:
		// Partial success: keep the results we have, but surface a warning so the
		// user knows one scanner did not complete.
		return r.store.SetError(ctx, job.ID, "some scanners did not complete: "+strings.Join(engineErrs, "; "))
	}
	return nil
}

// fetch materializes the source into srcDir per job.SourceType.
func (r *realRunner) fetch(ctx context.Context, job *store.Job, sec Secret, srcDir string) (string, error) {
	switch job.SourceType {
	case store.SourceGit:
		commit, branch, err := source.CloneGitResolved(ctx, job.SourceRef, sec.Token, sec.Branch, srcDir, r.guards)
		if err != nil {
			return "", err
		}
		if branch != "" {
			if err := r.store.SetBranch(ctx, job.ID, branch); err != nil {
				return "", err
			}
			job.Branch = branch
		}
		return commit, nil
	case store.SourceZip:
		if sec.UploadPath == "" {
			return "", fmt.Errorf("no uploaded archive for zip job")
		}
		return "", source.ExtractArchive(ctx, sec.UploadPath, srcDir, r.guards)
	case store.SourceImage:
		return "", fmt.Errorf("image scanning is deferred to v2")
	default:
		return "", fmt.Errorf("unknown source type %q", job.SourceType)
	}
}

// tagReachability marks each DIRECT npm-dependency finding as "used" or
// "unused_suspected" by checking whether the package is imported anywhere in the
// project's own source. Best-effort and package-level only (see internal/reach);
// on any error it leaves findings untagged. Only direct deps are tagged —
// transitive deps are never imported directly, so "unused" is meaningless there.
func tagReachability(srcDir string, fs []store.Finding) {
	need := false
	for i := range fs {
		if isDirectNPM(&fs[i]) {
			need = true
			break
		}
	}
	if !need {
		return
	}
	used, err := reach.UsedNPMPackages(srcDir)
	if err != nil {
		return
	}
	for i := range fs {
		f := &fs[i]
		if !isDirectNPM(f) {
			continue
		}
		if used[f.PkgName] {
			f.Usage = "used"
		} else {
			f.Usage = "unused_suspected"
		}
	}
}

func isDirectNPM(f *store.Finding) bool {
	return f.Relationship == "direct" && f.PkgName != "" && reach.IsNPMLockPath(f.FilePath)
}

// dedupe collapses redundant findings while preserving distinct ones:
//   - dependency findings (have a package) are keyed by CVE+package+version and
//     the containing DIRECTORY, so the same dep listed in two lockfiles side by
//     side (e.g. package-lock.json + yarn.lock) counts once, while the same
//     package in a different sub-project stays separate.
//   - code/secret/IaC findings are keyed by rule + exact file:line.
//
// It keeps the first occurrence and preserves order.
func dedupe(fs []store.Finding) []store.Finding {
	seen := make(map[string]struct{}, len(fs))
	out := fs[:0:0] // new backing array, don't mutate the input
	for _, f := range fs {
		var key string
		if f.PkgName != "" {
			key = "pkg\x00" + f.Category + "\x00" + f.RuleID + "\x00" +
				f.PkgName + "\x00" + f.PkgVer + "\x00" + dirOf(f.FilePath)
		} else {
			key = "code\x00" + f.Category + "\x00" + f.RuleID + "\x00" +
				f.FilePath + "\x00" + strconv.Itoa(f.Line)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

// dirOf returns the directory portion of a slash- or backslash-separated path.
func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[:i]
	}
	return ""
}

// summarize counts findings by severity.
func summarize(fs []store.Finding) store.Summary {
	var s store.Summary
	for _, f := range fs {
		switch strings.ToLower(f.Severity) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}
