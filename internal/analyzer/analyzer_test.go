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
