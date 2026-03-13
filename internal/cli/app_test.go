package cli

import (
	"errors"
	"testing"

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
