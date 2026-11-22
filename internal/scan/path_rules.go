package scan

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/4yi-ai/codescan/internal/source"
	"github.com/4yi-ai/codescan/internal/store"
)

type detectorScanner interface {
	ScanDetectors(context.Context, string, []string) ([]store.Finding, error)
}

type scanStep struct {
	engine    Engine
	root      string
	detectors []string
}

func (step scanStep) scan(ctx context.Context) ([]store.Finding, error) {
	if len(step.detectors) == 0 {
		return step.engine.Scan(ctx, step.root)
	}
	return step.engine.(detectorScanner).ScanDetectors(ctx, step.root, step.detectors)
}

func (r *realRunner) scanSteps(ctx context.Context, checkout, jobDir string, sec Secret) ([]scanStep, error) {
	var steps []scanStep
	if sec.PathRules == nil {
		for _, engine := range r.engines {
			steps = append(steps, scanStep{engine: engine, root: checkout})
		}
		return steps, nil
	}
	base := checkout
	if len(sec.ScanPaths) > 0 {
		if err := source.ValidateScanPaths(checkout, sec.ScanPaths); err != nil {
			return nil, err
		}
		base = filepath.Join(jobDir, "included-directories")
		if err := source.StageFilteredTree(ctx, checkout, base, sec.ScanPaths, nil); err != nil {
			return nil, err
		}
	}
	if len(sec.PathRules.Include) > 0 {
		included := filepath.Join(jobDir, "included-patterns")
		if err := source.StageFilteredTree(ctx, base, included, sec.PathRules.Include, nil); err != nil {
			return nil, err
		}
		base = included
	}
	roots := map[string]string{"": base}
	for _, detector := range []string{"sast", "sca", "iac"} {
		patterns := sec.PathRules.Exclude[detector]
		key := strings.Join(patterns, "\x00")
		if _, exists := roots[key]; exists {
			continue
		}
		root := filepath.Join(jobDir, "detector-"+detector)
		if err := source.StageFilteredTree(ctx, base, root, nil, patterns); err != nil {
			return nil, err
		}
		roots[key] = root
	}
	rootFor := func(detector string) string { return roots[strings.Join(sec.PathRules.Exclude[detector], "\x00")] }
	for _, engine := range r.engines {
		switch engine.Name() {
		case "semgrep":
			steps = append(steps, scanStep{engine: engine, root: rootFor("sast")})
		case "trivy":
			if _, ok := engine.(detectorScanner); !ok {
				return nil, fmt.Errorf("scanner cannot separate secret scan coverage")
			}
			var trivy []scanStep
			for _, input := range []struct{ root, detector string }{{rootFor("sca"), "vuln"}, {rootFor("iac"), "misconfig"}, {checkout, "secret"}} {
				index := slices.IndexFunc(trivy, func(step scanStep) bool { return step.root == input.root })
				if index >= 0 {
					trivy[index].detectors = append(trivy[index].detectors, input.detector)
				} else {
					trivy = append(trivy, scanStep{engine: engine, root: input.root, detectors: []string{input.detector}})
				}
			}
			steps = append(steps, trivy...)
		default:
			return nil, fmt.Errorf("scanner %s cannot apply path rules", engine.Name())
		}
	}
	return steps, nil
}
