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

func TestCompareAndSwapSetting(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		expected, value string
		want            bool
	}{
		{"missing", "wrong", false},
		{"", "first", true},
		{"", "stale", false},
		{"first", "second", true},
		{"first", "stale", false},
		{"second", "", true},
		{"", "restored", true},
	} {
		got, err := st.CompareAndSwapSetting(ctx, "allowed_hosts", tc.expected, tc.value)
		if err != nil || got != tc.want {
			t.Fatalf("CAS(%q,%q) = %v, %v; want %v", tc.expected, tc.value, got, err, tc.want)
		}
	}
	got, err := st.GetSetting(ctx, "allowed_hosts")
	if err != nil || got != "restored" {
		t.Fatalf("stored = %q, %v", got, err)
	}
}

func TestAllowedHostsSurviveStoreReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "scan.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := st.CompareAndSwapSetting(ctx, "extra_allowed_hosts", "", "git.example.com")
	if err != nil || !saved {
		t.Fatalf("save: saved=%v err=%v", saved, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetSetting(ctx, "extra_allowed_hosts")
	if err != nil || got != "git.example.com" {
		t.Fatalf("after reopen: got=%q err=%v", got, err)
	}
}
