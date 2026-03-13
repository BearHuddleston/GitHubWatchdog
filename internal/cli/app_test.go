package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/db"
	"github.com/arkouda/github/GitHubWatchdog/internal/models"
	"github.com/arkouda/github/GitHubWatchdog/internal/scan"
)

func TestParseRepoRef(t *testing.T) {
	owner, repo, err := parseRepoRef("octocat/hello-world")
	if err != nil {
		t.Fatalf("parseRepoRef() error = %v", err)
	}
	if owner != "octocat" || repo != "hello-world" {
		t.Fatalf("parseRepoRef() = %q, %q", owner, repo)
	}
}

func TestParseRepoRefRejectsInvalidInput(t *testing.T) {
	if _, _, err := parseRepoRef("octocat"); err == nil {
		t.Fatal("parseRepoRef() expected error for missing slash")
	}
}

func TestValidateFormat(t *testing.T) {
	if err := validateFormat("json"); err != nil {
		t.Fatalf("validateFormat(json) error = %v", err)
	}
	if err := validateFormat("text"); err != nil {
		t.Fatalf("validateFormat(text) error = %v", err)
	}
	if err := validateFormat("ndjson"); err != nil {
		t.Fatalf("validateFormat(ndjson) error = %v", err)
	}
	if err := validateFormat("yaml"); err == nil {
		t.Fatal("validateFormat(yaml) expected error")
	}
}

func TestHelpRequested(t *testing.T) {
	if !helpRequested([]string{"-h"}) {
		t.Fatal("helpRequested(-h) = false, want true")
	}
	if !helpRequested([]string{"--help"}) {
		t.Fatal("helpRequested(--help) = false, want true")
	}
	if helpRequested([]string{"octocat"}) {
		t.Fatal("helpRequested(octocat) = true, want false")
	}
}

func TestListProfilesRequested(t *testing.T) {
	if !listProfilesRequested([]string{"--list-profiles"}) {
		t.Fatal("listProfilesRequested(--list-profiles) = false, want true")
	}
	if !listProfilesRequested([]string{"-list-profiles"}) {
		t.Fatal("listProfilesRequested(-list-profiles) = false, want true")
	}
	if listProfilesRequested([]string{"recent"}) {
		t.Fatal("listProfilesRequested(recent) = true, want false")
	}
}

func TestExitErrorCarriesExitCode(t *testing.T) {
	err := exitError{code: exitCodeFindings}
	var withCode interface{ ExitCode() int }
	if !errors.As(err, &withCode) {
		t.Fatal("errors.As(exitError) = false, want true")
	}
	if withCode.ExitCode() != exitCodeFindings {
		t.Fatalf("ExitCode() = %d, want %d", withCode.ExitCode(), exitCodeFindings)
	}
}

func TestShouldEmitSearchResult(t *testing.T) {
	flagged := scan.RepoReport{RepoID: "flagged/repo", IsMalicious: true}
	skipped := scan.RepoReport{RepoID: "skipped/repo", Skipped: true}
	clean := scan.RepoReport{RepoID: "clean/repo"}

	if !shouldEmitSearchResult(flagged, true, false) {
		t.Fatal("flagged result should be emitted when onlyFlagged is true")
	}
	if shouldEmitSearchResult(clean, true, true) {
		t.Fatal("clean result should not be emitted when onlyFlagged is true")
	}
	if shouldEmitSearchResult(skipped, false, false) {
		t.Fatal("skipped result should not be emitted when includeSkipped is false")
	}
	if !shouldEmitSearchResult(clean, false, false) {
		t.Fatal("clean result should be emitted when filters allow it")
	}
}

func TestBuildSearchQuery(t *testing.T) {
	query, err := buildSearchQuery("stars:>5", "2026-03-01", "2026-03-13")
	if err != nil {
		t.Fatalf("buildSearchQuery() error = %v", err)
	}
	want := "stars:>5 updated:>=2026-03-01 updated:<=2026-03-13"
	if query != want {
		t.Fatalf("buildSearchQuery() = %q, want %q", query, want)
	}
}

func TestBuildSearchQueryRejectsDuplicateUpdatedQualifier(t *testing.T) {
	if _, err := buildSearchQuery("stars:>5 updated:>=2026-03-01", "2026-03-02", ""); err == nil {
		t.Fatal("buildSearchQuery() expected error when query already contains updated:")
	}
}

func TestNormalizeSearchDate(t *testing.T) {
	if got, err := normalizeSearchDate("2026-03-13"); err != nil || got != "2026-03-13" {
		t.Fatalf("normalizeSearchDate(date) = %q, %v", got, err)
	}
	if got, err := normalizeSearchDate("2026-03-13T12:34:56-05:00"); err != nil || got != "2026-03-13T17:34:56Z" {
		t.Fatalf("normalizeSearchDate(rfc3339) = %q, %v", got, err)
	}
	if _, err := normalizeSearchDate("03/13/2026"); err == nil {
		t.Fatal("normalizeSearchDate() expected error for invalid date")
	}
}

func TestResolveSearchProfile(t *testing.T) {
	profile, err := resolveSearchProfile("recent")
	if err != nil {
		t.Fatalf("resolveSearchProfile(recent) error = %v", err)
	}
	if profile.Name != "recent" {
		t.Fatalf("resolveSearchProfile(recent).Name = %q", profile.Name)
	}
	if profile.Query == "" || profile.Since == "" {
		t.Fatalf("resolveSearchProfile(recent) = %+v, want populated query/since", profile)
	}
	if _, err := resolveSearchProfile("missing"); err == nil {
		t.Fatal("resolveSearchProfile(missing) expected error")
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "value", "later"); got != "value" {
		t.Fatalf("firstNonEmpty() = %q, want value", got)
	}
}

func TestWriteSearchProfiles(t *testing.T) {
	var buf bytes.Buffer
	writeSearchProfiles(&buf)

	output := buf.String()
	for _, needle := range []string{"recent", "high-signal", "backfill"} {
		if !strings.Contains(output, needle) {
			t.Fatalf("writeSearchProfiles() missing %q in output: %s", needle, output)
		}
	}
}

func TestNextUpdatedBefore(t *testing.T) {
	oldest := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	if got := nextUpdatedBefore(oldest); got != "2026-03-13T11:59:59Z" {
		t.Fatalf("nextUpdatedBefore() = %q", got)
	}
	if got := nextUpdatedBefore(time.Time{}); got != "" {
		t.Fatalf("nextUpdatedBefore(zero) = %q, want empty", got)
	}
}

func TestValidateCheckpointFormat(t *testing.T) {
	if err := validateCheckpointFormat("json"); err != nil {
		t.Fatalf("validateCheckpointFormat(json) error = %v", err)
	}
	if err := validateCheckpointFormat("text"); err != nil {
		t.Fatalf("validateCheckpointFormat(text) error = %v", err)
	}
	if err := validateCheckpointFormat("ndjson"); err == nil {
		t.Fatal("validateCheckpointFormat(ndjson) expected error")
	}
}

func TestWriteCheckpointList(t *testing.T) {
	var buf bytes.Buffer
	err := writeCheckpointList(&buf, "text", []db.SearchCheckpoint{
		{
			Name:              "recent",
			ProfileName:       "recent",
			NextUpdatedBefore: "2026-03-13T11:59:59Z",
			CompletedAt:       time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatalf("writeCheckpointList() error = %v", err)
	}
	output := buf.String()
	for _, needle := range []string{"recent", "next-updated-before=2026-03-13T11:59:59Z", "completed=2026-03-13T12:00:00Z"} {
		if !strings.Contains(output, needle) {
			t.Fatalf("writeCheckpointList() missing %q in %q", needle, output)
		}
	}
}

func TestDecodeCheckpointImportObject(t *testing.T) {
	checkpoints, err := decodeCheckpointImport([]byte(`{"name":"recent","base_query":"stars:>5"}`))
	if err != nil {
		t.Fatalf("decodeCheckpointImport(object) error = %v", err)
	}
	if len(checkpoints) != 1 || checkpoints[0].Name != "recent" {
		t.Fatalf("decodeCheckpointImport(object) = %+v", checkpoints)
	}
}

func TestDecodeCheckpointImportArray(t *testing.T) {
	checkpoints, err := decodeCheckpointImport([]byte(`[{"name":"one"},{"name":"two"}]`))
	if err != nil {
		t.Fatalf("decodeCheckpointImport(array) error = %v", err)
	}
	if len(checkpoints) != 2 || checkpoints[1].Name != "two" {
		t.Fatalf("decodeCheckpointImport(array) = %+v", checkpoints)
	}
}

func TestDecodeCheckpointImportRejectsEmpty(t *testing.T) {
	if _, err := decodeCheckpointImport([]byte("   ")); err == nil {
		t.Fatal("decodeCheckpointImport(empty) expected error")
	}
}

func TestWriteCheckpointImportResult(t *testing.T) {
	var buf bytes.Buffer
	if err := writeCheckpointImportResult(&buf, "text", 2); err != nil {
		t.Fatalf("writeCheckpointImportResult() error = %v", err)
	}
	if got := buf.String(); got != "Imported 2 checkpoint(s).\n" {
		t.Fatalf("writeCheckpointImportResult() = %q", got)
	}
}

func TestSummarizeRepoReport(t *testing.T) {
	summary := summarizeRepoReport(scan.RepoReport{
		RepoID:      "owner/repo",
		IsMalicious: true,
		RepoFlags: []models.HeuristicResult{
			{Category: "Spam Behavior", Name: "BoilerplateReadmeHeuristic", Flag: true},
		},
		OwnerAnalysis: &scan.UserReport{Username: "owner", Suspicious: true},
		Errors:        []string{"repo fetch failed"},
	})
	if !summary.IsFlagged || !summary.IsMalicious || !summary.OwnerSuspicious {
		t.Fatalf("summarizeRepoReport() = %+v", summary)
	}
	if summary.RepoFlagCount != 1 || len(summary.RepoFlags) != 1 || summary.RepoFlags[0] != "Spam Behavior:BoilerplateReadmeHeuristic" {
		t.Fatalf("summarizeRepoReport() flags = %+v", summary)
	}
}

func TestSummarizeUserReport(t *testing.T) {
	summary := summarizeUserReport(scan.UserReport{
		Username:      "octocat",
		Suspicious:    true,
		Contributions: 4,
		TotalStars:    50,
		Heuristics: []models.HeuristicResult{
			{Category: "Automated Activity", Name: "GeneratedPortfolioHeuristic", Flag: true},
			{Category: "Spam Behavior", Name: "RecentHeuristic", Flag: false},
		},
		Errors: []string{"user fetch failed"},
	})
	if !summary.IsSuspicious || summary.HeuristicCount != 1 {
		t.Fatalf("summarizeUserReport() = %+v", summary)
	}
	if len(summary.Heuristics) != 1 || summary.Heuristics[0] != "Automated Activity:GeneratedPortfolioHeuristic" {
		t.Fatalf("summarizeUserReport() heuristics = %+v", summary)
	}
}

func TestWriteRepoSummary(t *testing.T) {
	var buf bytes.Buffer
	err := writeRepoSummary(&buf, "text", repoSummary{
		RepoID:          "owner/repo",
		IsFlagged:       true,
		IsMalicious:     false,
		OwnerSuspicious: true,
		RepoFlagCount:   1,
		RepoFlags:       []string{"Spam Behavior:BoilerplateReadmeHeuristic"},
	})
	if err != nil {
		t.Fatalf("writeRepoSummary() error = %v", err)
	}
	output := buf.String()
	for _, needle := range []string{"Repository: owner/repo", "Flagged: true", "Owner suspicious: true", "Flag: Spam Behavior:BoilerplateReadmeHeuristic"} {
		if !strings.Contains(output, needle) {
			t.Fatalf("writeRepoSummary() missing %q in %q", needle, output)
		}
	}
}

func TestVerdictTargetShape(t *testing.T) {
	if strings.Count("owner/repo", "/") != 1 {
		t.Fatal("expected repo target to contain exactly one slash")
	}
	if strings.Count("octocat", "/") != 0 {
		t.Fatal("expected user target to contain no slash")
	}
}

func TestParseVerdictTargets(t *testing.T) {
	targets, err := parseVerdictTargets([]byte("\n owner/repo \n\noctocat\n"))
	if err != nil {
		t.Fatalf("parseVerdictTargets() error = %v", err)
	}
	if len(targets) != 2 || targets[0] != "owner/repo" || targets[1] != "octocat" {
		t.Fatalf("parseVerdictTargets() = %#v", targets)
	}
}

func TestParseVerdictTargetsRejectsEmpty(t *testing.T) {
	if _, err := parseVerdictTargets([]byte(" \n\t\n")); err == nil {
		t.Fatal("parseVerdictTargets(empty) expected error")
	}
}

func TestVerdictHasFindings(t *testing.T) {
	if !verdictHasFindings(repoSummary{IsFlagged: true}) {
		t.Fatal("verdictHasFindings(repo flagged) = false, want true")
	}
	if !verdictHasFindings(userSummary{IsSuspicious: true}) {
		t.Fatal("verdictHasFindings(user suspicious) = false, want true")
	}
	if verdictHasFindings(repoSummary{}) {
		t.Fatal("verdictHasFindings(clean repo) = true, want false")
	}
}

func TestWriteVerdictSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := writeVerdictSummary(&buf, "text", repoSummary{RepoID: "owner/repo", IsFlagged: true}); err != nil {
		t.Fatalf("writeVerdictSummary(repo) error = %v", err)
	}
	if !strings.Contains(buf.String(), "Repository: owner/repo") {
		t.Fatalf("writeVerdictSummary(repo) = %q", buf.String())
	}

	buf.Reset()
	if err := writeVerdictSummary(&buf, "text", userSummary{Username: "octocat", IsSuspicious: true}); err != nil {
		t.Fatalf("writeVerdictSummary(user) error = %v", err)
	}
	if !strings.Contains(buf.String(), "User: octocat") {
		t.Fatalf("writeVerdictSummary(user) = %q", buf.String())
	}
}

func TestWriteVerdictBatchJSON(t *testing.T) {
	var buf bytes.Buffer
	err := writeVerdictBatch(&buf, "json", []interface{}{
		repoSummary{EntityType: "repo", RepoID: "owner/repo", IsFlagged: true},
		userSummary{EntityType: "user", Username: "octocat", IsSuspicious: true},
	})
	if err != nil {
		t.Fatalf("writeVerdictBatch(json) error = %v", err)
	}

	var decoded []map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("writeVerdictBatch(json) produced invalid JSON: %v\n%s", err, buf.String())
	}
	if len(decoded) != 2 {
		t.Fatalf("writeVerdictBatch(json) decoded len = %d", len(decoded))
	}
}

func TestWriteVerdictBatchText(t *testing.T) {
	var buf bytes.Buffer
	err := writeVerdictBatch(&buf, "text", []interface{}{
		repoSummary{RepoID: "owner/repo", IsFlagged: true},
		userSummary{Username: "octocat", IsSuspicious: true},
	})
	if err != nil {
		t.Fatalf("writeVerdictBatch(text) error = %v", err)
	}
	output := buf.String()
	for _, needle := range []string{"Repository: owner/repo", "User: octocat"} {
		if !strings.Contains(output, needle) {
			t.Fatalf("writeVerdictBatch(text) missing %q in %q", needle, output)
		}
	}
}

func TestWriteUserSummary(t *testing.T) {
	var buf bytes.Buffer
	err := writeUserSummary(&buf, "text", userSummary{
		Username:       "octocat",
		IsSuspicious:   true,
		HeuristicCount: 1,
		Heuristics:     []string{"Automated Activity:GeneratedPortfolioHeuristic"},
		Contributions:  4,
		TotalStars:     50,
	})
	if err != nil {
		t.Fatalf("writeUserSummary() error = %v", err)
	}
	output := buf.String()
	for _, needle := range []string{"User: octocat", "Suspicious: true", "Heuristic: Automated Activity:GeneratedPortfolioHeuristic"} {
		if !strings.Contains(output, needle) {
			t.Fatalf("writeUserSummary() missing %q in %q", needle, output)
		}
	}
}
