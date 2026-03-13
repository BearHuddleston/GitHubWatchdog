// Package analyzer provides repository and user analysis functionality
package analyzer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/github"
	"github.com/arkouda/github/GitHubWatchdog/internal/logger"
	"github.com/arkouda/github/GitHubWatchdog/internal/models"
)

// ResultHolder holds an analysis result and a channel to signal completion
type ResultHolder struct {
	Result models.AnalysisResult
	Err    error
	Ready  chan struct{}
}

// Analyzer analyzes GitHub users and repositories for suspicious activity
type Analyzer struct {
	client         *github.Client
	userCache      sync.Map // map[string]models.AnalysisResult
	processedUsers sync.Map // used for coordinating analysis, map[string]*ResultHolder
	flaggedUsers   sync.Map // map[string]bool to record flag insertion
	logger         *logger.Logger
}

// New creates a new analyzer
func New(client *github.Client) *Analyzer {
	return &Analyzer{
		client: client,
		logger: client.GetLogger(),
	}
}

// GetLogger returns the analyzer's logger
func (a *Analyzer) GetLogger() *logger.Logger {
	return a.logger
}

// AnalyzeUser analyzes a GitHub user for suspicious activity
func (a *Analyzer) AnalyzeUser(ctx context.Context, username string) (models.AnalysisResult, error) {
	// Check cache first
	if val, ok := a.userCache.Load(username); ok {
		result := val.(models.AnalysisResult)
		a.logger.Debug("Cache hit for user %s: %+v", username, result)
		return result, nil
	}

	// Use a resultHolder to coordinate concurrent calls
	holderInterface, loaded := a.processedUsers.LoadOrStore(username, &ResultHolder{
		Ready: make(chan struct{}),
	})
	holder := holderInterface.(*ResultHolder)

	if loaded {
		// Another goroutine is processing the user. Wait until it's done
		<-holder.Ready
		if holder.Err != nil {
			a.logger.Debug("User %s processing previously failed: %v", username, holder.Err)
			a.processedUsers.Delete(username)
			return models.AnalysisResult{}, holder.Err
		}
		a.logger.Debug("User %s already being processed; returning cached result.", username)
		return holder.Result, nil
	}

	// This goroutine is responsible for computing the analysis
	a.logger.Debug("Starting analysis for user %s", username)
	data, err := a.fetchUserData(ctx, username)
	if err != nil {
		holder.Err = fmt.Errorf("fetching user data: %w", err)
		close(holder.Ready)
		a.processedUsers.Delete(username)
		return models.AnalysisResult{}, holder.Err
	}

	if len(data.Repositories) == 0 {
		a.logger.Debug("User %s has no repositories.", username)
		holder.Result = models.AnalysisResult{
			CreatedAt:  data.CreatedAt,
			Suspicious: false,
		}
		close(holder.Ready)
		a.processedUsers.Delete(username)
		a.userCache.Store(username, holder.Result)
		return holder.Result, nil
	}

	// Analyze the user's repositories
	repos := data.Repositories
	totalStars, emptyCount, suspiciousEmptyCount := computeRepoMetrics(repos)
	heuristicResults, overallSuspicious := EvaluateUserHeuristics(data, repos)

	analysisResult := models.AnalysisResult{
		CreatedAt:            data.CreatedAt,
		Suspicious:           overallSuspicious,
		TotalStars:           totalStars,
		EmptyCount:           emptyCount,
		SuspiciousEmptyCount: suspiciousEmptyCount,
		Contributions:        data.Contributions,
		HeuristicResults:     heuristicResults,
	}

	// Store the result and signal completion
	holder.Result = analysisResult
	close(holder.Ready)
	a.processedUsers.Delete(username)
	a.userCache.Store(username, analysisResult)
	a.logger.Debug("User %s processed: %+v", username, analysisResult)
	return analysisResult, nil
}

// fetchUserData fetches user data from GitHub
func (a *Analyzer) fetchUserData(ctx context.Context, username string) (models.UserData, error) {
	var data models.UserData

	// Fetch user creation date
	createdAt, err := a.client.GetUserInfo(ctx, username)
	if err != nil {
		return data, err
	}
	data.CreatedAt = createdAt

	// Fetch user repositories
	repos, err := a.client.GetUserRepositories(ctx, username)
	if err != nil {
		return data, err
	}

	// Convert to internal repository data format
	var repoDataList []models.RepoData
	for _, r := range repos {
		repoDataList = append(repoDataList, models.RepoData{
			Name:           r.Name,
			DiskUsage:      r.DiskUsage,
			StargazerCount: r.StargazerCount,
		})
	}
	data.Repositories = repoDataList

	// Fetch user contributions
	contributions, err := a.client.GetUserContributions(ctx, username)
	if err != nil {
		return data, err
	}
	data.Contributions = contributions

	return data, nil
}

// IsUserFlagged checks if a user has been flagged
func (a *Analyzer) IsUserFlagged(username string) bool {
	_, flagged := a.flaggedUsers.Load(username)
	return flagged
}

// MarkUserFlagged marks a user as flagged
func (a *Analyzer) MarkUserFlagged(username string) {
	a.flaggedUsers.Store(username, true)
}

// computeRepoMetrics computes metrics for repositories
func computeRepoMetrics(repos []models.RepoData) (totalStars, emptyCount, suspiciousEmptyCount int) {
	const emptyThreshold = 10
	for _, repo := range repos {
		totalStars += repo.StargazerCount
		if repo.DiskUsage < emptyThreshold {
			emptyCount++
			if repo.StargazerCount >= 5 {
				suspiciousEmptyCount++
			}
		}
	}
	return
}

// EvaluateUserHeuristics evaluates user data against all heuristics
func EvaluateUserHeuristics(data models.UserData, repos []models.RepoData) ([]models.HeuristicResult, bool) {
	heuristics := []UserHeuristic{&OriginalHeuristic{}, &NewHeuristic{}, &RecentHeuristic{}}
	var suspicious bool
	var results []models.HeuristicResult
	legitimateActivity := hasLegitimateActivitySignals(data, repos)

	for _, h := range heuristics {
		result := h.Evaluate(data, repos)
		if legitimateActivity {
			result.Flag = false
		}
		if result.Flag {
			suspicious = true
		}
		results = append(results, result)
	}

	return results, suspicious
}

func hasLegitimateActivitySignals(data models.UserData, repos []models.RepoData) bool {
	accountAge := time.Since(data.CreatedAt)
	if accountAge < 180*24*time.Hour {
		return false
	}

	if data.Contributions >= 50 {
		return true
	}

	totalStars, _, _ := computeRepoMetrics(repos)
	return data.Contributions >= 20 && totalStars >= 100
}

// IsRepoMalicious checks if a repository is malicious
func (a *Analyzer) IsRepoMalicious(ctx context.Context, repo models.RepoData) (bool, error) {
	checkers := []RepoChecker{
		&ReadmeChecker{},
		&LoaderChecker{Client: a.client},
	}

	for _, checker := range checkers {
		malicious, err := checker.Check(ctx, repo)
		if err != nil {
			return false, err
		}
		if malicious {
			return true, nil
		}
	}

	return false, nil
}

// CheckRepoFiles checks a repository's files for malicious content
func (a *Analyzer) CheckRepoFiles(ctx context.Context, owner, name, defaultBranch string) (models.RepoData, bool, error) {
	var repo models.RepoData
	repo.Owner = owner
	repo.Name = name

	// Get README
	readme, err := a.client.GetRepoReadme(ctx, owner, name)
	if err != nil {
		a.logger.Debug("Error fetching readme for %s/%s: %v", owner, name, err)
	}
	repo.Readme = readme

	// Get tree entries
	entries, err := a.client.GetRepoTree(ctx, owner, name, defaultBranch)
	if err != nil {
		a.logger.Debug("Error fetching tree for %s/%s: %v", owner, name, err)
	}
	repo.TreeEntries = entries

	// Check if repository is malicious
	isMalicious, err := a.IsRepoMalicious(ctx, repo)
	if err != nil {
		return repo, false, err
	}

	return repo, isMalicious, nil
}
