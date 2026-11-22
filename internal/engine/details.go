package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/4yi-ai/codescan/internal/store"
)

var scannerVersion = regexp.MustCompile(`(?im)^(?:version:\s*)?(v?\d[0-9.a-z+_-]*)\s*$`)

func toolVersion(ctx context.Context, name string) string {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, "--version").Output()
	if err != nil {
		return ""
	}
	match := scannerVersion.FindStringSubmatch(string(output))
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func (e *Semgrep) Details(ctx context.Context) store.EngineDetails {
	details := store.EngineDetails{Version: toolVersion(ctx, "semgrep")}
	if e.configArg() != e.rulesDir {
		details.Ruleset = e.configArg()
		return details
	}
	hash := sha256.New()
	err := filepath.WalkDir(e.rulesDir, func(file string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		ext := strings.ToLower(filepath.Ext(file))
		if !entry.Type().IsRegular() || (ext != ".yaml" && ext != ".yml") {
			return nil
		}
		name, err := filepath.Rel(e.rulesDir, file)
		if err != nil {
			return err
		}
		_, _ = io.WriteString(hash, filepath.ToSlash(name)+"\x00")
		stream, err := os.Open(file)
		if err != nil {
			return err
		}
		defer stream.Close()
		if _, err := io.Copy(hash, stream); err != nil {
			return err
		}
		_, _ = io.WriteString(hash, "\x00")
		return nil
	})
	if err == nil {
		details.Ruleset = "sha256:" + hex.EncodeToString(hash.Sum(nil))
	}
	return details
}

func (e *TrivyFS) Details(ctx context.Context) store.EngineDetails {
	details := store.EngineDetails{Version: toolVersion(ctx, "trivy")}
	cache := os.Getenv("TRIVY_CACHE_DIR")
	if cache == "" {
		return details
	}
	if raw, err := os.ReadFile(filepath.Join(cache, "db", "metadata.json")); err == nil {
		var metadata struct{ UpdatedAt time.Time }
		if json.Unmarshal(raw, &metadata) == nil && !metadata.UpdatedAt.IsZero() {
			details.Ruleset = "trivy-db@" + metadata.UpdatedAt.UTC().Format(time.RFC3339)
		}
	}
	return details
}
