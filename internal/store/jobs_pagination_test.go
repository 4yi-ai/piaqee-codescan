package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

func TestListJobsPageAndCount(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("job-%d", i)
		if _, err := st.CreateJob(ctx, id, SourceGit, fmt.Sprintf("repo-%d.git", i), fmt.Sprintf("branch-%d", i)); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}

	total, err := st.CountJobs(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 5 {
		t.Fatalf("total = %d, want 5", total)
	}

	page1, err := st.ListJobsPage(ctx, 2, 0)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("page1 len = %d, want 2", len(page1))
	}
	if page1[0].ID != "job-4" || page1[1].ID != "job-3" {
		t.Fatalf("page1 order = [%s %s], want [job-4 job-3]", page1[0].ID, page1[1].ID)
	}
	if page1[0].Branch != "branch-4" {
		t.Fatalf("page1[0] branch = %q, want branch-4", page1[0].Branch)
	}

	page2, err := st.ListJobsPage(ctx, 2, 2)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page2 len = %d, want 2", len(page2))
	}
	if page2[0].ID != "job-2" || page2[1].ID != "job-1" {
		t.Fatalf("page2 order = [%s %s], want [job-2 job-1]", page2[0].ID, page2[1].ID)
	}

	page3, err := st.ListJobsPage(ctx, 2, 4)
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(page3) != 1 || page3[0].ID != "job-0" {
		t.Fatalf("page3 = %#v, want [job-0]", page3)
	}
}
