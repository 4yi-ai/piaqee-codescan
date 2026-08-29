package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestPutAndGetSetting(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if got, err := st.GetSetting(ctx, "missing"); err != nil || got != "" {
		t.Fatalf("missing setting = %q err=%v, want empty", got, err)
	}

	if err := st.PutSetting(ctx, "extra_allowed_hosts", "gitlab.bieases.com"); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.GetSetting(ctx, "extra_allowed_hosts")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != "gitlab.bieases.com" {
		t.Fatalf("got %q, want gitlab.bieases.com", got)
	}

	if err := st.PutSetting(ctx, "extra_allowed_hosts", "git.internal.com"); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err = st.GetSetting(ctx, "extra_allowed_hosts")
	if err != nil {
		t.Fatalf("get updated: %v", err)
	}
	if got != "git.internal.com" {
		t.Fatalf("got %q, want git.internal.com", got)
	}
}
