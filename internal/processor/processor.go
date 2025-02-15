package processor

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/shurcooL/githubv4"
	"golang.org/x/sync/errgroup"

	"githubwatchdog.bearhuddleston/internal/analyzer"
	"githubwatchdog.bearhuddleston/internal/config"
	"githubwatchdog.bearhuddleston/internal/db"
)

// SearchAndProcessRepositories searches GitHub for repositories matching the query,
// then processes each repository concurrently while limiting parallelism.
func SearchAndProcessRepositories(
	ctx context.Context,
	client *githubv4.Client,
	queryStr string,
	cfg *config.Config,
	anlz *analyzer.Analyzer,
	database *db.Database,
	processedUsers map[string]bool, // For safe concurrent access, consider using sync.Map.
) (time.Time, error) {
	var oldest time.Time
	var cursor *githubv4.String
	var oldestMu sync.Mutex

	// Iterate through pages until there are no more results or max pages reached.
	for page := 1; page <= cfg.MaxPages; page++ {
		var q struct {
			RateLimit struct {
				Cost      int
				Remaining int
				ResetAt   githubv4.DateTime
			}
			Search struct {
				PageInfo struct {
					HasNextPage bool
					EndCursor   githubv4.String
				}
				Nodes []struct {
					Repository struct {
						Name           githubv4.String
						UpdatedAt      githubv4.DateTime
						DiskUsage      int
						StargazerCount int
						Owner          struct {
							Login githubv4.String
						}
					} `graphql:"... on Repository"`
				}
			} `graphql:"search(query: $query, type: REPOSITORY, first: $perPage, after: $after)"`
		}

		variables := map[string]interface{}{
			"query":   githubv4.String(queryStr),
			"perPage": githubv4.Int(cfg.PerPage),
			"after":   cursor,
		}

		if err := client.Query(ctx, &q, variables); err != nil {
			return oldest, fmt.Errorf("error on page %d searching repositories: %w", page, err)
		}

		// If rate limits are nearly exceeded, sleep until the reset time.
		if q.RateLimit.Remaining < 100 {
			resetTime := q.RateLimit.ResetAt.Time
			sleepDuration := time.Until(resetTime) + time.Second
			log.Printf("Rate limit low (%d remaining). Sleeping for %v", q.RateLimit.Remaining, sleepDuration)
			time.Sleep(sleepDuration)
		}

		log.Printf("Page %d: Found %d repositories", page, len(q.Search.Nodes))
		if len(q.Search.Nodes) == 0 {
			break
		}

		// Use errgroup and a semaphore to process repositories concurrently.
		eg, egCtx := errgroup.WithContext(ctx)
		sem := make(chan struct{}, cfg.MaxConcurrent)

		for _, node := range q.Search.Nodes {
			node := node // capture range variable
			sem <- struct{}{}
			eg.Go(func() error {
				defer func() { <-sem }()

				repoItem := &analyzer.Repo{
					Owner:          string(node.Repository.Owner.Login),
					Name:           string(node.Repository.Name),
					UpdatedAt:      node.Repository.UpdatedAt.Time,
					DiskUsage:      node.Repository.DiskUsage,
					StargazerCount: node.Repository.StargazerCount,
				}
				repoID := fmt.Sprintf("%s/%s", repoItem.Owner, repoItem.Name)

				// Avoid re‑processing an unchanged repository.
				alreadyProcessed, err := database.WasRepoProcessed(repoID, repoItem.UpdatedAt)
				if err != nil {
					log.Printf("Error checking processed repo %s: %v", repoID, err)
				} else if alreadyProcessed {
					log.Printf("Repository %s already processed; skipping.", repoID)
					return nil
				}

				// Process small repositories' users if needed.
				if repoItem.DiskUsage < 10 {
					if processedUsers[repoItem.Owner] {
						log.Printf("User %s already processed; skipping analysis.", repoItem.Owner)
					} else {
						log.Printf("Repository %s is small; analyzing user %s.", repoID, repoItem.Owner)
						analysis, err := anlz.AnalyzeUser(egCtx, client, repoItem.Owner)
						if err != nil {
							log.Printf("Error analyzing user %s: %v", repoItem.Owner, err)
						} else {
							if analysis.Suspicious {
								if err := database.InsertHeuristicFlag("user", repoItem.Owner, "Suspicious user detected"); err != nil {
									log.Printf("Error recording suspicious user %s: %v", repoItem.Owner, err)
								} else {
									log.Printf("Suspicious user detected: %s", repoItem.Owner)
								}
							}
							if err := database.InsertProcessedUser(
								repoItem.Owner,
								time.Now(),
								analysis.TotalStars,
								analysis.EmptyCount,
								analysis.SuspiciousEmptyCount,
								analysis.Contributions,
								analysis.Suspicious,
							); err != nil {
								log.Printf("Error recording processed user %s: %v", repoItem.Owner, err)
							}
						}
						processedUsers[repoItem.Owner] = true
					}
				}

				// Analyze repository README if applicable.
				var isMalicious bool
				if repoItem.DiskUsage > 0 {
					isMalicious, err = analyzer.AnalyzeRepo(egCtx, client, database, repoItem.Owner, repoItem.Name)
					if err != nil {
						if strings.Contains(err.Error(), "403") {
							return err
						}
						log.Printf("Error analyzing repository %s: %v", repoID, err)
					}
				} else {
					log.Printf("Skipping README analysis for repository %s due to low disk usage.", repoID)
				}

				// Record the processed repository.
				if err := database.InsertProcessedRepo(
					repoID,
					repoItem.Owner,
					repoItem.Name,
					repoItem.UpdatedAt,
					repoItem.DiskUsage,
					repoItem.StargazerCount,
					isMalicious,
				); err != nil {
					log.Printf("Error recording processed repository %s: %v", repoID, err)
				}

				// Update oldest timestamp.
				oldestMu.Lock()
				if oldest.IsZero() || repoItem.UpdatedAt.Before(oldest) {
					oldest = repoItem.UpdatedAt
				}
				oldestMu.Unlock()
				return nil
			})
		}

		// Wait for all repository processing routines to finish.
		if err := eg.Wait(); err != nil {
			return oldest, err
		}

		if !q.Search.PageInfo.HasNextPage {
			break
		}
		cursor = &q.Search.PageInfo.EndCursor
	}

	return oldest, nil
}
