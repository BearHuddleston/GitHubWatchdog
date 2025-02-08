package analyzer

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/shurcooL/githubv4"
)

const (
	minTotalStarsForOriginal      = 10
	minEmptyCountForOriginal      = 20
	minSuspiciousReposCountForNew = 5
	maxContributionsForNew        = 5
	minTotalStarsForRecent        = 10
	maxAccountAgeForRecent        = 10 * 24 * time.Hour // 10 days
)

// Analyzer holds caches to avoid duplicate work.
type Analyzer struct {
	processedUsers sync.Map // key: username, value: bool
	userCache      sync.Map // key: username, value: bool
}

// NewAnalyzer creates a new Analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) contributionsLastYear(ctx context.Context, client *githubv4.Client, username string) int {
	oneYearAgo := time.Now().Add(-365 * 24 * time.Hour)
	now := time.Now()
	var q struct {
		User struct {
			ContributionsCollection struct {
				TotalCommitContributions            int
				TotalIssueContributions             int
				TotalPullRequestContributions       int
				TotalPullRequestReviewContributions int
			} `graphql:"contributionsCollection(from: $from, to: $to)"`
		} `graphql:"user(login: $login)"`
	}
	variables := map[string]interface{}{
		"login": githubv4.String(username),
		"from":  githubv4.DateTime{Time: oneYearAgo},
		"to":    githubv4.DateTime{Time: now},
	}
	err := client.Query(ctx, &q, variables)
	if err != nil {
		log.Printf("Error fetching contributions for user %s: %v", username, err)
		return 0
	}
	total := q.User.ContributionsCollection.TotalCommitContributions +
		q.User.ContributionsCollection.TotalIssueContributions +
		q.User.ContributionsCollection.TotalPullRequestContributions +
		q.User.ContributionsCollection.TotalPullRequestReviewContributions
	return total
}

func (a *Analyzer) AnalyzeUser(ctx context.Context, client *githubv4.Client, username string) bool {
	if val, ok := a.userCache.Load(username); ok {
		result := val.(bool)
		log.Printf("User %s analysis result retrieved from cache: %v", username, result)
		return result
	}
	if _, processed := a.processedUsers.Load(username); processed {
		log.Printf("User %s has already been scanned.", username)
		return false
	}
	a.processedUsers.Store(username, true)

	var q struct {
		User struct {
			CreatedAt    githubv4.DateTime
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
	perPage := 100
	var allRepos []struct {
		Name           string
		DiskUsage      int
		StargazerCount int
	}
	var cursor *githubv4.String
	for {
		variables := map[string]interface{}{
			"login":   githubv4.String(username),
			"perPage": githubv4.Int(perPage),
			"cursor":  cursor,
		}
		err := client.Query(ctx, &q, variables)
		if err != nil {
			log.Printf("Error fetching user %s: %v", username, err)
			return false
		}
		for _, node := range q.User.Repositories.Nodes {
			allRepos = append(allRepos, struct {
				Name           string
				DiskUsage      int
				StargazerCount int
			}{
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

	if len(allRepos) == 0 {
		log.Printf("User %s has no repositories.", username)
		return false
	}

	var totalStars, emptyCount, suspiciousEmptyCount int
	const emptyThreshold = 10
	for _, repo := range allRepos {
		stars := repo.StargazerCount
		totalStars += stars
		if repo.DiskUsage < emptyThreshold {
			emptyCount++
			if stars >= 5 {
				suspiciousEmptyCount++
			}
		}
	}

	contributions := a.contributionsLastYear(ctx, client, username)
	accountAge := time.Since(q.User.CreatedAt.Time)
	log.Printf("User %s: age=%v, totalStars=%d, emptyCount=%d, suspiciousEmptyRepos=%d, contributions=%d",
		username, accountAge, totalStars, emptyCount, suspiciousEmptyCount, contributions)

	flagOriginal := totalStars >= minTotalStarsForOriginal && emptyCount >= minEmptyCountForOriginal
	flagNew := suspiciousEmptyCount >= minSuspiciousReposCountForNew && contributions <= maxContributionsForNew
	flagRecent := accountAge < maxAccountAgeForRecent && totalStars >= minTotalStarsForRecent

	result := flagOriginal || flagNew || flagRecent

	a.userCache.Store(username, result)

	if result {
		log.Printf("User %s flagged (original=%v, new=%v, recent=%v)", username, flagOriginal, flagNew, flagRecent)
	}
	return result
}
