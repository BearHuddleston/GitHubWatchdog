package analyzer

import (
	"context"
	"strings"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/github"
	"github.com/arkouda/github/GitHubWatchdog/internal/models"
)

// UserHeuristic represents a heuristic that can be applied to user data
type UserHeuristic interface {
	Evaluate(data models.UserData, repos []models.RepoData) models.HeuristicResult
}

// OriginalHeuristic is the original heuristic for detecting suspicious users
type OriginalHeuristic struct{}

// Evaluate evaluates the original heuristic
func (h *OriginalHeuristic) Evaluate(data models.UserData, repos []models.RepoData) models.HeuristicResult {
	totalStars, emptyCount, _ := computeRepoMetrics(repos)
	flag := totalStars >= 10 && emptyCount >= 20
	return models.HeuristicResult{
		Flag:        flag,
		Name:        "OriginalHeuristic",
		Description: "User has sufficient total stars and empty repositories.",
	}
}

// NewHeuristic is a newer heuristic for detecting suspicious users
type NewHeuristic struct{}

// Evaluate evaluates the new heuristic
func (h *NewHeuristic) Evaluate(data models.UserData, repos []models.RepoData) models.HeuristicResult {
	_, _, suspiciousEmptyCount := computeRepoMetrics(repos)
	flag := suspiciousEmptyCount >= 5 && data.Contributions <= 5
	return models.HeuristicResult{
		Flag:        flag,
		Name:        "NewHeuristic",
		Description: "User has many suspicious empty repos and low contributions.",
	}
}

// RecentHeuristic is a heuristic for detecting suspicious recent users
type RecentHeuristic struct{}

// Evaluate evaluates the recent user heuristic
func (h *RecentHeuristic) Evaluate(data models.UserData, repos []models.RepoData) models.HeuristicResult {
	totalStars, _, _ := computeRepoMetrics(repos)
	flag := time.Since(data.CreatedAt) < (10*24*time.Hour) && totalStars >= 10
	return models.HeuristicResult{
		Flag:        flag,
		Name:        "RecentHeuristic",
		Description: "User is recent and has gathered enough stars.",
	}
}

// RepoChecker represents a checker that can be applied to repository data
type RepoChecker interface {
	Check(ctx context.Context, repo models.RepoData) (bool, error)
}

// ReadmeChecker checks repository README files for suspicious content
type ReadmeChecker struct{}

// Check evaluates a repository's README
func (rc *ReadmeChecker) Check(ctx context.Context, repo models.RepoData) (bool, error) {
	if repo.Readme == "" {
		return false, nil
	}
	
	lower := strings.ToLower(repo.Readme)
	if strings.Contains(lower, "download link") && strings.Contains(lower, "password : 2025") {
		return true, nil
	}
	
	return false, nil
}

// LoaderChecker checks repositories for suspicious loader files
type LoaderChecker struct {
	Client *github.Client
}

// Check evaluates a repository for suspicious loader files
func (lc *LoaderChecker) Check(ctx context.Context, repo models.RepoData) (bool, error) {
	// Check tree entries for loader files
	for _, entry := range repo.TreeEntries {
		lower := strings.ToLower(entry)
		if lower == "loader.zip" || lower == "loader.rar" {
			return true, nil
		}
	}
	
	// Check releases for loader files
	found, err := lc.Client.CheckRepoReleases(ctx, repo.Owner, repo.Name)
	if err != nil {
		return false, err
	}
	
	return found, nil
}