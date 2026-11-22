package source

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// NormalizeScanPaths accepts literal repository-relative directories. A parent
// directory already includes its descendants, so overlapping selections collapse.
func NormalizeScanPaths(paths []string) ([]string, error) {
	if len(paths) > 20 {
		return nil, fmt.Errorf("scan_paths accepts at most 20 directories")
	}
	canonical := make([]string, 0, len(paths))
	for _, raw := range paths {
		directory := strings.TrimRight(strings.TrimSpace(raw), "/")
		if len(directory) == 0 || len(directory) > 512 || strings.ContainsAny(directory, `\:*?[]`) || strings.ContainsFunc(directory, unicode.IsControl) {
			return nil, fmt.Errorf("scan_paths must contain repository-relative directory names")
		}
		for _, part := range strings.Split(directory, "/") {
			if part == "" || part == "." || part == ".." || strings.EqualFold(part, ".git") {
				return nil, fmt.Errorf("scan_paths must contain repository-relative directory names")
			}
		}
		canonical = append(canonical, directory)
	}
	slices.Sort(canonical)
	roots := make([]string, 0, len(canonical))
	for _, directory := range canonical {
		covered := slices.ContainsFunc(roots, func(root string) bool {
			return directory == root || strings.HasPrefix(directory, root+"/")
		})
		if !covered {
			roots = append(roots, directory)
		}
	}
	return roots, nil
}

// StageScanPaths moves directories from a disposable checkout into an isolated
// scanner root. Repository-relative paths stay intact for findings and previews.
func StageScanPaths(ctx context.Context, checkout, target string, directories []string) error {
	for _, directory := range directories {
		current := checkout
		for _, part := range strings.Split(directory, "/") {
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if err != nil || !info.IsDir() {
				return fmt.Errorf("scan directory unavailable on this branch: %s", directory)
			}
		}
	}
	for _, directory := range directories {
		if err := ctx.Err(); err != nil {
			return err
		}
		staged := filepath.Join(target, directory)
		if err := os.MkdirAll(filepath.Dir(staged), 0o750); err != nil {
			return err
		}
		if err := os.Rename(filepath.Join(checkout, directory), staged); err != nil {
			return err
		}
		// Links in Git can point outside the checkout or into excluded directories.
		// Remove them from the disposable tree before either scanner can open them.
		if err := filepath.WalkDir(staged, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return os.Remove(path)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
