package scan

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/4yi-ai/codescan/internal/source"
	"github.com/4yi-ai/codescan/internal/store"
)

type scopeInspector struct {
	mockEngine
	check func(string, []string)
}

func (e scopeInspector) Scan(_ context.Context, root string) ([]store.Finding, error) {
	e.check(root, nil)
	return nil, nil
}

func (e scopeInspector) ScanDetectors(_ context.Context, root string, detectors []string) ([]store.Finding, error) {
	e.check(root, detectors)
	return nil, nil
}

func TestZipPathRulesPreserveFullSecretCoverage(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "source.zip")
	out, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(out)
	for _, name := range []string{"src/service.ts", "src/service.test.ts", "docs/example.txt"} {
		w, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("configuration example\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	check := func(root, name string, expected bool) {
		t.Helper()
		_, err := os.Stat(filepath.Join(root, name))
		if (err == nil) != expected {
			t.Fatalf("%s expected=%v: %v", name, expected, err)
		}
	}
	semgrep := scopeInspector{mockEngine: mockEngine{name: "semgrep"}, check: func(root string, _ []string) {
		check(root, "src/service.ts", true)
		check(root, "src/service.test.ts", false)
		check(root, "docs/example.txt", false)
	}}
	trivy := scopeInspector{mockEngine: mockEngine{name: "trivy"}, check: func(root string, detectors []string) {
		check(root, "src/service.test.ts", true)
		check(root, "docs/example.txt", slices.Contains(detectors, "secret"))
	}}
	ctx := context.Background()
	st := openStore(t)
	job, err := st.CreateJob(ctx, "scope-run", store.SourceZip, "source.zip", "")
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(st, t.TempDir(), source.DefaultGuards(), semgrep, trivy)
	err = runner.Run(ctx, job, Secret{UploadPath: archive, PathRules: &source.PathRules{Include: []string{"src/**"}, Exclude: map[string][]string{"sast": {"*.test.ts"}}}})
	if err != nil {
		t.Fatal(err)
	}
	job, err = st.GetJob(ctx, job.ID)
	if err != nil || job.Summary == nil || !job.Summary.Coverage.SecretsFullSource || job.Summary.Coverage.Version != 3 || !job.Summary.Coverage.Complete {
		t.Fatalf("unexpected full-secret coverage: %+v %v", job, err)
	}
}
