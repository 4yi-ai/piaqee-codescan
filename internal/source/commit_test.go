package source

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloneCapturesCommitBeforeRemovingMetadata(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	repo := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init")
	os.WriteFile(filepath.Join(repo, "code.txt"), []byte("code"), 0600)
	run("add", "code.txt")
	run("-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "fixture")
	expected := run("rev-parse", "HEAD")
	dest := filepath.Join(t.TempDir(), "checkout")
	commit, branch, err := CloneGitResolved(context.Background(), repo, "", "", dest, DefaultGuards())
	if err != nil {
		t.Fatal(err)
	}
	if branch != run("symbolic-ref", "--short", "HEAD") {
		t.Fatalf("wrong resolved branch: %q", branch)
	}
	if commit != expected {
		t.Fatalf("commit=%q want=%q", commit, expected)
	}
	if _, err := os.Stat(filepath.Join(dest, ".git")); !os.IsNotExist(err) {
		t.Fatal("git metadata retained")
	}
}
