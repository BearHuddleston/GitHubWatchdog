package analyzer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/logger"
	"github.com/arkouda/github/GitHubWatchdog/internal/models"
)

func TestAnalyzeUserReturnsStoredErrorForFailedHolder(t *testing.T) {
	a := &Analyzer{
		logger: logger.New(false),
	}

	holder := &ResultHolder{
		Err:   errors.New("boom"),
		Ready: make(chan struct{}),
	}
	close(holder.Ready)
	a.processedUsers.Store("octocat", holder)

	_, err := a.AnalyzeUser(context.Background(), "octocat")
	if err == nil {
		t.Fatal("expected stored error to be returned")
	}

	if _, ok := a.processedUsers.Load("octocat"); ok {
		t.Fatal("expected failed holder to be removed so future calls can retry")
	}
}

func TestEvaluateUserHeuristicsSuppressesEstablishedContributors(t *testing.T) {
	data := models.UserData{
		CreatedAt:     time.Now().Add(-365 * 24 * time.Hour),
		Contributions: 100,
	}
	repos := make([]models.RepoData, 0, 25)
	for i := 0; i < 25; i++ {
		repos = append(repos, models.RepoData{
			Name:           "repo",
			DiskUsage:      0,
			StargazerCount: 1,
		})
	}
	repos[0].StargazerCount = 15

	results, suspicious := EvaluateUserHeuristics(data, repos)
	if suspicious {
		t.Fatal("expected established contributor to avoid suspicious classification")
	}
	for _, result := range results {
		if result.Flag {
			t.Fatalf("expected heuristic %s to be suppressed for established contributor", result.Name)
		}
	}
}

func TestGeneratedPortfolioHeuristicFlagsRepeatedGeneratedNames(t *testing.T) {
	data := models.UserData{
		CreatedAt:     time.Now().Add(-7 * 24 * time.Hour),
		Contributions: 1,
	}
	repos := []models.RepoData{
		{Name: "WeatherForecast-1409", DiskUsage: 2},
		{Name: "WeatherForecast-1410", DiskUsage: 4},
		{Name: "WeatherForecast-1411", DiskUsage: 1},
		{Name: "TaskManager-5001", DiskUsage: 0},
		{Name: "TaskManager-5002", DiskUsage: 3},
	}

	results, suspicious := EvaluateUserHeuristics(data, repos)
	if !suspicious {
		t.Fatal("expected repeated generated naming patterns to be suspicious")
	}

	found := false
	for _, result := range results {
		if result.Name == "GeneratedPortfolioHeuristic" && result.Flag {
			found = true
		}
	}
	if !found {
		t.Fatal("expected GeneratedPortfolioHeuristic to flag repeated generated repo names")
	}
}

func TestEvaluateRepoHeuristicsFlagsGeneratedRepoSignals(t *testing.T) {
	results := EvaluateRepoHeuristics(models.RepoData{
		Name:        "WeatherForecast-1409",
		Readme:      "A cool open-source project with AI-generated code.",
		TreeEntries: []string{"README.md", "main.py"},
	})

	expected := map[string]bool{
		"GeneratedRepoNamingHeuristic": false,
		"BoilerplateReadmeHeuristic":   false,
		"SparseProjectHeuristic":       false,
	}

	for _, result := range results {
		expected[result.Name] = result.Flag
	}

	for name, flagged := range expected {
		if !flagged {
			t.Fatalf("expected %s to flag generated repo signals", name)
		}
	}
}

func TestEvaluateRepoHeuristicsFlagsPromotionSpamReadme(t *testing.T) {
	results := EvaluateRepoHeuristics(models.RepoData{
		Name:   "token-hub-3001",
		Readme: "Join Telegram to claim your airdrop reward now.",
	})

	for _, result := range results {
		if result.Name == "PromotionSpamReadmeHeuristic" && result.Flag {
			return
		}
	}

	t.Fatal("expected PromotionSpamReadmeHeuristic to flag incentive-driven README spam")
}
