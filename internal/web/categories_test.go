package web

import (
	"strings"
	"testing"
	"time"
)

func TestDeriveUserCategoriesFromFlagsAndMetrics(t *testing.T) {
	categories := deriveUserCategories(userCategoryInput{
		CreatedAt:            time.Now().Add(-24 * time.Hour),
		TotalStars:           25,
		EmptyCount:           30,
		SuspiciousEmptyCount: 6,
		Contributions:        2,
		IsSuspicious:         true,
		HeuristicFlags: []string{
			"[Mass Repository Creation] OriginalHeuristic: User has sufficient total stars and empty repositories.",
			"NewHeuristic: User has many suspicious empty repos and low contributions.",
		},
	})

	expected := []string{
		categoryMassRepoCreation,
		categoryAutomatedActivity,
		categorySpamBehavior,
	}

	if len(categories) != len(expected) {
		t.Fatalf("expected %d categories, got %d: %v", len(expected), len(categories), categories)
	}
	for i, category := range expected {
		if categories[i] != category {
			t.Fatalf("expected category %q at index %d, got %q", category, i, categories[i])
		}
	}
}

func TestBuildUserReportSummaryIncludesCategoriesAndFlags(t *testing.T) {
	summary := buildUserReportSummary(UserReportResponse{
		Username:       "octocat",
		ProfileURL:     "https://github.com/octocat",
		IsSuspicious:   true,
		Categories:     []string{categoryAutomatedActivity},
		TotalStars:     10,
		Contributions:  1,
		EmptyCount:     8,
		HeuristicFlags: []string{"[Automated Activity] NewHeuristic: suspicious empty repos"},
	})

	for _, fragment := range []string{
		"https://github.com/octocat",
		"Status: SUSPICIOUS",
		"Categories: Automated Activity",
		"Detected flags:",
	} {
		if !strings.Contains(summary, fragment) {
			t.Fatalf("expected summary to contain %q, got %q", fragment, summary)
		}
	}
}
