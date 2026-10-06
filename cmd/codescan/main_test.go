package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/4yi-ai/codescan/internal/scan"
	"github.com/4yi-ai/codescan/internal/store"
)

func TestScanConfigTimeout(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        time.Duration
		invalid     bool
	}{
		{"default", "", 15 * time.Minute, false},
		{"large repository", "45m", 45 * time.Minute, false},
		{"seconds", "90s", 90 * time.Second, false},
		{"zero", "0s", 0, true},
		{"negative", "-1m", 0, true},
		{"missing unit", "45", 0, true},
		{"invalid", "forever", 0, true},
		{"overflow", "999999999999999999999h", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CODESCAN_JOB_TIMEOUT", tc.value)
			cfg, err := scanConfigFromEnv("test-jobs")
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid timeout was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.JobTimeout != tc.want {
				t.Fatalf("timeout = %s, want %s", cfg.JobTimeout, tc.want)
			}
			if cfg.JobsDir != "test-jobs" {
				t.Fatalf("jobs directory changed: %q", cfg.JobsDir)
			}
		})
	}
}

type deadlineRunner struct{ budget chan time.Duration }

func (r deadlineRunner) Run(ctx context.Context, job *store.Job, sec scan.Secret) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		r.budget <- 0
	} else {
		r.budget <- time.Until(deadline)
	}
	return nil
}

func TestConfiguredTimeoutReachesScanWorker(t *testing.T) {
	t.Setenv("CODESCAN_JOB_TIMEOUT", "45m")
	cfg, err := scanConfigFromEnv(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	budget := make(chan time.Duration, 1)
	mgr := scan.NewManager(st, cfg)
	mgr.SetRunner(deadlineRunner{budget})
	job, err := st.CreateJob(context.Background(), "configured-budget", store.SourceZip, "test.zip", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Enqueue(job.ID, scan.Secret{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	select {
	case got := <-budget:
		if got < 45*time.Minute-2*time.Second || got > 45*time.Minute {
			t.Fatalf("worker budget = %s, want 45m", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scan worker did not start")
	}
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		got, err := st.GetJob(context.Background(), job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status == store.StatusDone {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("configured job did not complete")
}
