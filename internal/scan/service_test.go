package scan

import (
	"testing"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/models"
)

func TestRepoReportIsFlagged(t *testing.T) {
	cases := []struct {
		name   string
		report RepoReport
		want   bool
	}{
		{
			name: "clean",
			report: RepoReport{
				RepoID: "owner/repo",
			},
			want: false,
		},
		{
			name: "malicious repo",
			report: RepoReport{
				RepoID:      "owner/repo",
				IsMalicious: true,
			},
			want: true,
		},
		{
			name: "repo heuristic",
			report: RepoReport{
				RepoID: "owner/repo",
				RepoFlags: []models.HeuristicResult{
					{Name: "SparseProjectHeuristic", Flag: true},
				},
			},
			want: true,
		},
		{
			name: "owner suspicious",
			report: RepoReport{
				RepoID:        "owner/repo",
				OwnerAnalysis: &UserReport{Username: "owner", Suspicious: true},
			},
			want: true,
		},
	}

	for _, tc := range cases {
		if got := tc.report.IsFlagged(); got != tc.want {
			t.Fatalf("%s: IsFlagged() = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestSearchReportCounts(t *testing.T) {
	report := SearchReport{
		Results: []RepoReport{
			{RepoID: "one/repo", Skipped: true},
			{RepoID: "two/repo", IsMalicious: true},
			{RepoID: "three/repo"},
			{RepoID: "four/repo", OwnerAnalysis: &UserReport{Suspicious: true}},
		},
	}

	if got := report.AnalyzedCount(); got != 3 {
		t.Fatalf("AnalyzedCount() = %d, want 3", got)
	}
	if got := report.FlaggedCount(); got != 2 {
		t.Fatalf("FlaggedCount() = %d, want 2", got)
	}
}

func TestSearchReportFilter(t *testing.T) {
	report := SearchReport{
		Results: []RepoReport{
			{RepoID: "one/repo", Skipped: true},
			{RepoID: "two/repo", IsMalicious: true},
			{RepoID: "three/repo"},
			{RepoID: "four/repo", OwnerAnalysis: &UserReport{Suspicious: true}},
		},
	}

	filtered := report.Filter(true, false)
	if got := len(filtered.Results); got != 2 {
		t.Fatalf("Filter(true, false) len = %d, want 2", got)
	}
	for _, result := range filtered.Results {
		if !result.IsFlagged() {
			t.Fatalf("Filter(true, false) returned non-flagged result: %+v", result)
		}
		if result.Skipped {
			t.Fatalf("Filter(true, false) returned skipped result: %+v", result)
		}
	}
}

func TestSearchReportFilterPreservesMetadata(t *testing.T) {
	report := SearchReport{
		CheckpointName:    "backlog",
		ProfileName:       "recent",
		BaseQuery:         "stars:>5",
		Query:             "stars:>5 updated:>=2026-03-06",
		Since:             "2026-03-06",
		UpdatedBefore:     "2026-03-13",
		NextUpdatedBefore: "2026-03-12T23:59:59Z",
		Results: []RepoReport{
			{RepoID: "flagged/repo", IsMalicious: true},
			{RepoID: "clean/repo"},
		},
	}

	filtered := report.Filter(true, true)
	if len(filtered.Results) != 1 {
		t.Fatalf("Filter(true, true) len = %d, want 1", len(filtered.Results))
	}
	if filtered.ProfileName != "recent" {
		t.Fatalf("ProfileName = %q, want recent", filtered.ProfileName)
	}
	if filtered.BaseQuery != "stars:>5" {
		t.Fatalf("BaseQuery = %q, want stars:>5", filtered.BaseQuery)
	}
	if filtered.Query != "stars:>5 updated:>=2026-03-06" {
		t.Fatalf("Query = %q", filtered.Query)
	}
	if filtered.Since != "2026-03-06" || filtered.UpdatedBefore != "2026-03-13" {
		t.Fatalf("date metadata not preserved: %+v", filtered)
	}
	if filtered.CheckpointName != "backlog" || filtered.NextUpdatedBefore != "2026-03-12T23:59:59Z" {
		t.Fatalf("checkpoint metadata not preserved: %+v", filtered)
	}
}

func TestFilterSearchItemsByUpdatedAt(t *testing.T) {
	items := []models.RepoItem{
		{Name: "old", UpdatedAt: time.Date(2026, 3, 5, 4, 19, 40, 0, time.UTC)},
		{Name: "inside", UpdatedAt: time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)},
		{Name: "late", UpdatedAt: time.Date(2026, 3, 14, 0, 0, 1, 0, time.UTC)},
	}

	filtered, err := filterSearchItemsByUpdatedAt(items, "2026-03-10", "2026-03-13")
	if err != nil {
		t.Fatalf("filterSearchItemsByUpdatedAt() error = %v", err)
	}
	if len(filtered) != 1 || filtered[0].Name != "inside" {
		t.Fatalf("filterSearchItemsByUpdatedAt() = %+v", filtered)
	}
}

func TestParseSearchBoundary(t *testing.T) {
	lower, err := parseSearchBoundary("2026-03-10", false)
	if err != nil {
		t.Fatalf("parseSearchBoundary(date lower) error = %v", err)
	}
	if !lower.Equal(time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("parseSearchBoundary(date lower) = %s", lower)
	}

	upper, err := parseSearchBoundary("2026-03-13", true)
	if err != nil {
		t.Fatalf("parseSearchBoundary(date upper) error = %v", err)
	}
	if !upper.Equal(time.Date(2026, 3, 13, 23, 59, 59, int(time.Second-time.Nanosecond), time.UTC)) {
		t.Fatalf("parseSearchBoundary(date upper) = %s", upper)
	}

	exact, err := parseSearchBoundary("2026-03-13T12:34:56Z", true)
	if err != nil {
		t.Fatalf("parseSearchBoundary(rfc3339) error = %v", err)
	}
	if !exact.Equal(time.Date(2026, 3, 13, 12, 34, 56, 0, time.UTC)) {
		t.Fatalf("parseSearchBoundary(rfc3339) = %s", exact)
	}
}
