package analyzer

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/shurcooL/githubv4"
	"githubwatchdog.bearhuddleston/internal/db"
)

// Thresholds for flagging user accounts.
const (
	minTotalStarsForOriginal      = 10
	minEmptyCountForOriginal      = 20
	minSuspiciousReposCountForNew = 5
	maxContributionsForNew        = 5
	minTotalStarsForRecent        = 10
	maxAccountAgeForRecent        = 10 * 24 * time.Hour // 10 days
)

// AnalysisResult holds aggregated metrics for a GitHub user.
type AnalysisResult struct {
	Suspicious           bool
	TotalStars           int
	EmptyCount           int
	SuspiciousEmptyCount int
	Contributions        int
	FlagOriginal         bool
	FlagNew              bool
	FlagRecent           bool
}

// Analyzer caches user analysis results to avoid duplicate processing.
type Analyzer struct {
	processedUsers sync.Map // key: username, value: AnalysisResult
	userCache      sync.Map // key: username, value: AnalysisResult
}

// NewAnalyzer returns a new Analyzer instance.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// userData holds fetched GitHub user details.
type userData struct {
	CreatedAt     time.Time
	Contributions int
	Repositories  []repoData
}

// repoData holds minimal repository information.
type repoData struct {
	Name           string
	DiskUsage      int
	StargazerCount int
}

// AnalyzeUser coordinates fetching data and computing analysis metrics for a user.
func (a *Analyzer) AnalyzeUser(ctx context.Context, client *githubv4.Client, username string) (AnalysisResult, error) {
	// Return from cache if available.
	if val, ok := a.userCache.Load(username); ok {
		result := val.(AnalysisResult)
		log.Printf("Cache hit for user %s: %+v", username, result)
		return result, nil
	}
	if val, processed := a.processedUsers.Load(username); processed {
		result := val.(AnalysisResult)
		log.Printf("User %s already processed: %+v", username, result)
		return result, nil
	}

	// Fetch user data from GitHub.
	data, err := a.fetchUserData(ctx, client, username)
	if err != nil {
		return AnalysisResult{}, err
	}

	// If the user has no repositories, return an empty analysis.
	if len(data.Repositories) == 0 {
		log.Printf("User %s has no repositories.", username)
		result := AnalysisResult{Suspicious: false}
		a.userCache.Store(username, result)
		a.processedUsers.Store(username, result)
		return result, nil
	}

	totalStars, emptyCount, suspiciousEmptyCount := computeRepoMetrics(data.Repositories)
	accountAge := time.Since(data.CreatedAt)
	log.Printf("User %s: age=%v, totalStars=%d, emptyCount=%d, suspiciousEmptyRepos=%d, contributions=%d",
		username, accountAge, totalStars, emptyCount, suspiciousEmptyCount, data.Contributions)

	// Determine heuristic flags.
	flagOriginal := totalStars >= minTotalStarsForOriginal && emptyCount >= minEmptyCountForOriginal
	flagNew := suspiciousEmptyCount >= minSuspiciousReposCountForNew && data.Contributions <= maxContributionsForNew
	flagRecent := accountAge < maxAccountAgeForRecent && totalStars >= minTotalStarsForRecent
	suspicious := flagOriginal || flagNew || flagRecent

	analysisResult := AnalysisResult{
		Suspicious:           suspicious,
		TotalStars:           totalStars,
		EmptyCount:           emptyCount,
		SuspiciousEmptyCount: suspiciousEmptyCount,
		Contributions:        data.Contributions,
		FlagOriginal:         flagOriginal,
		FlagNew:              flagNew,
		FlagRecent:           flagRecent,
	}

	// Cache and record the result.
	a.userCache.Store(username, analysisResult)
	a.processedUsers.Store(username, analysisResult)

	if suspicious {
		log.Printf("User %s flagged as suspicious (Original=%v, New=%v, Recent=%v)", username, flagOriginal, flagNew, flagRecent)
	}

	return analysisResult, nil
}

// fetchUserData retrieves the user's creation date, contributions, and repository list.
func (a *Analyzer) fetchUserData(ctx context.Context, client *githubv4.Client, username string) (userData, error) {
	var data userData
	oneYearAgo := time.Now().Add(-365 * 24 * time.Hour)
	now := time.Now()
	perPage := 100

	var repos []repoData
	var cursor *githubv4.String
	var contributions int
	firstCall := true

	// GraphQL query definition.
	var q struct {
		User struct {
			CreatedAt               githubv4.DateTime
			ContributionsCollection struct {
				TotalCommitContributions            int
				TotalIssueContributions             int
				TotalPullRequestContributions       int
				TotalPullRequestReviewContributions int
			} `graphql:"contributionsCollection(from: $from, to: $to)"`
			Repositories struct {
				PageInfo struct {
					HasNextPage bool
					EndCursor   githubv4.String
				}
				Nodes []struct {
					Name           githubv4.String
					DiskUsage      int
					StargazerCount int
				}
			} `graphql:"repositories(first: $perPage, ownerAffiliations: OWNER, after: $cursor)"`
		} `graphql:"user(login: $login)"`
	}

	// Loop to paginate through repositories.
	for {
		variables := map[string]interface{}{
			"login":   githubv4.String(username),
			"perPage": githubv4.Int(perPage),
			"cursor":  cursor,
		}
		// On the first call, include the contributions date range.
		if firstCall {
			variables["from"] = githubv4.DateTime{Time: oneYearAgo}
			variables["to"] = githubv4.DateTime{Time: now}
		}

		if err := client.Query(ctx, &q, variables); err != nil {
			log.Printf("Error fetching data for user %s: %v", username, err)
			return data, err
		}

		if firstCall {
			contributions = q.User.ContributionsCollection.TotalCommitContributions +
				q.User.ContributionsCollection.TotalIssueContributions +
				q.User.ContributionsCollection.TotalPullRequestContributions +
				q.User.ContributionsCollection.TotalPullRequestReviewContributions
			firstCall = false
		}

		// Append fetched repository data.
		for _, node := range q.User.Repositories.Nodes {
			repos = append(repos, repoData{
				Name:           string(node.Name),
				DiskUsage:      node.DiskUsage,
				StargazerCount: node.StargazerCount,
			})
		}

		if !q.User.Repositories.PageInfo.HasNextPage {
			break
		}
		cursor = &q.User.Repositories.PageInfo.EndCursor
	}

	data.CreatedAt = q.User.CreatedAt.Time
	data.Contributions = contributions
	data.Repositories = repos
	return data, nil
}

// computeRepoMetrics calculates total stars, number of empty repositories,
// and counts empty repositories with at least 5 stars (suspicious repos).
func computeRepoMetrics(repos []repoData) (totalStars, emptyCount, suspiciousEmptyCount int) {
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

// Repo represents a GitHub repository with selected fields.
type Repo struct {
	Owner          string
	Name           string
	UpdatedAt      time.Time
	DiskUsage      int
	StargazerCount int
}

// AnalyzeRepo checks a repository’s README for malware markers and, if found,
// processes stargazer data to record heuristic flags.
func AnalyzeRepo(ctx context.Context, client *githubv4.Client, database *db.Database, owner, repoName string) (bool, error) {
	// Query the repository's README.
	var q struct {
		Repository struct {
			Readme *struct {
				Blob struct {
					Text string
				} `graphql:"... on Blob"`
			} `graphql:"readme: object(expression: \"HEAD:README.md\")"`
		} `graphql:"repository(owner: $owner, name: $name)"`
	}
	variables := map[string]interface{}{
		"owner": githubv4.String(owner),
		"name":  githubv4.String(repoName),
	}
	if err := client.Query(ctx, &q, variables); err != nil {
		return false, fmt.Errorf("fetching README for %s/%s: %w", owner, repoName, err)
	}

	// If no README exists, skip further analysis.
	if q.Repository.Readme == nil {
		log.Printf("Repository %s/%s missing README.md – skipping.", owner, repoName)
		return false, nil
	}
	content := q.Repository.Readme.Blob.Text

	// Only flag the repository if both malware markers are present.
	if !(strings.Contains(content, "# [DOWNLOAD LINK]") && strings.Contains(content, "# PASSWORD : 2025")) {
		return false, nil
	}
	log.Printf("Repository %s/%s identified as malicious.", owner, repoName)

	// Process stargazers to flag malicious interest.
	var sgQuery struct {
		Repository struct {
			Stargazers struct {
				PageInfo struct {
					HasNextPage bool
					EndCursor   githubv4.String
				}
				Nodes []struct {
					Login githubv4.String
				}
			} `graphql:"stargazers(first: $perPage, after: $after)"`
		} `graphql:"repository(owner: $owner, name: $name)"`
	}
	perPage := 100
	var cursor *githubv4.String
	for {
		vars := map[string]interface{}{
			"owner":   githubv4.String(owner),
			"name":    githubv4.String(repoName),
			"perPage": githubv4.Int(perPage),
			"after":   cursor,
		}
		if err := client.Query(ctx, &sgQuery, vars); err != nil {
			log.Printf("Error fetching stargazers for %s/%s: %v", owner, repoName, err)
			break
		}
		for _, user := range sgQuery.Repository.Stargazers.Nodes {
			login := string(user.Login)
			flagDescription := fmt.Sprintf("Malicious stargazer detected in repository %s/%s", owner, repoName)
			if err := database.InsertHeuristicFlag("stargazer", login, flagDescription); err != nil {
				log.Printf("Error inserting flag for stargazer %s: %v", login, err)
			}
		}
		if !sgQuery.Repository.Stargazers.PageInfo.HasNextPage {
			break
		}
		cursor = &sgQuery.Repository.Stargazers.PageInfo.EndCursor
	}

	return true, nil
}
