package scan

import (
	"context"
	"encoding/json"
	"github.com/4yi-ai/codescan/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceSnapshots(t *testing.T) {
	dir := t.TempDir()
	lines := make([]string, 40)
	for i := range lines {
		lines[i] = "safe code"
	}
	lines[19] = "secret-value"
	if err := os.WriteFile(filepath.Join(dir, "code.py"), []byte(strings.Join(lines, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	findings := []store.Finding{{FilePath: "code.py", Line: 21, Category: "sast"}, {FilePath: "code.py", Line: 20, Category: "secrets"}, {FilePath: "../outside", Line: 1}}
	attachSourceSnapshots(dir, "job-1", strings.Repeat("a", 40), findings)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(findings[0].Raw), &raw); err != nil {
		t.Fatal(err)
	}
	var snapshot sourceSnapshot
	if err := json.Unmarshal(raw["source_snapshot"], &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.StartLine != 11 || snapshot.HighlightLine != 21 || snapshot.JobID != "job-1" || len(strings.Split(snapshot.Content, "\n")) != 21 {
		t.Fatalf("bad snapshot: %+v", snapshot)
	}
	if strings.Contains(snapshot.Content, "secret-value") {
		t.Fatal("secret leaked into neighboring finding")
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err := st.CreateJob(ctx, "job-1", store.SourceGit, "https://git.example.com/repo", "main"); err != nil {
		t.Fatal(err)
	}
	findings[0].JobID = "job-1"
	if err := st.InsertFindings(ctx, findings[:1]); err != nil {
		t.Fatal(err)
	}
	saved, err := st.ListFindings(ctx, "job-1", store.FindingFilter{})
	if err != nil || len(saved) != 1 || saved[0].Raw != findings[0].Raw {
		t.Fatalf("snapshot persistence failed: %v", err)
	}
	if findings[2].Raw != "" {
		t.Fatal("unsafe path read")
	}
}
func TestSnapshotRejectsSymlinkAndUnlocatedFinding(t *testing.T) {
	dir := t.TempDir()
	external := filepath.Join(t.TempDir(), "private")
	os.WriteFile(external, []byte("private"), 0600)
	os.Symlink(external, filepath.Join(dir, "link"))
	f := []store.Finding{{FilePath: "link", Line: 1}, {FilePath: "missing", Line: 0}}
	attachSourceSnapshots(dir, "job", "", f)
	for _, item := range f {
		if item.Raw != "" {
			t.Fatal("unexpected snapshot")
		}
	}
}
