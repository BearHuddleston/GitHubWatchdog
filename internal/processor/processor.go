package processor

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/shurcooL/githubv4"
	"githubwatchdog.bearhuddleston/internal/analyzer"
	"githubwatchdog.bearhuddleston/internal/config"
	"githubwatchdog.bearhuddleston/internal/fileutil"
	"githubwatchdog.bearhuddleston/internal/repo"
)

// State holds a map of processed repository IDs.
type State struct {
	processedRepos sync.Map // key: repoID, value: bool
}

func NewState(initial map[string]bool) *State {
	s := &State{}
	for k, v := range initial {
		s.processedRepos.Store(k, v)
	}
	return s
}

// worker processes repository jobs.
func worker(ctx context.Context, client *githubv4.Client, jobs <-chan *repo.Repo, state *State, anlz *analyzer.Analyzer,
	recordFile, suspiciousUserRecordFile, malRepoFile, malStargazerFile string, wg *sync.WaitGroup) {
	defer wg.Done()
	for r := range jobs {
		repoID := fmt.Sprintf("%s/%s", r.Owner, r.Name)
		if _, ok := state.processedRepos.Load(repoID); ok {
			log.Printf("Repository %s already processed.", repoID)
			continue
		}

		if r.DiskUsage < 10 {
			log.Printf("Repository %s is small; checking user...", repoID)
			if anlz.AnalyzeUser(ctx, client, r.Owner) {
				log.Printf("Suspicious user detected: %s", r.Owner)
				if err := fileutil.AppendSuspiciousUser(suspiciousUserRecordFile, r.Owner); err != nil {
					log.Printf("Recording suspicious user %s: %v", r.Owner, err)
				}
			}
		}

		if r.DiskUsage > 0 {
			if err := repo.AnalyzeRepo(ctx, client, r.Owner, r.Name, malRepoFile, malStargazerFile); err != nil {
				log.Printf("Analyzing repository %s: %v", repoID, err)
			}
		} else {
			log.Printf("Skipping README analysis for repository %s due to low disk usage.", repoID)
		}

		if err := fileutil.AppendProcessedRepo(recordFile, repoID); err != nil {
			log.Printf("Recording processed repository %s: %v", repoID, err)
		}
		state.processedRepos.Store(repoID, true)
	}
}

// SearchAndProcessRepositories queries GitHub and dispatches jobs.
func SearchAndProcessRepositories(ctx context.Context, client *githubv4.Client, queryStr string,
	cfg *config.Config, state *State, anlz *analyzer.Analyzer) (time.Time, error) {

	jobs := make(chan *repo.Repo)
	var wg sync.WaitGroup

	for i := 0; i < cfg.NumWorkers; i++ {
		wg.Add(1)
		go worker(ctx, client, jobs, state, anlz,
			cfg.RecordFile, cfg.SuspiciousUserRecordFile, cfg.MalRepoFile, cfg.MalStargazerFile, &wg)
	}

	var oldest time.Time
	var cursor *githubv4.String

PAGE_LOOP:
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

		err := client.Query(ctx, &q, variables)
		if err != nil {
			close(jobs)
			return oldest, fmt.Errorf("searching repositories on page %d: %w", page, err)
		}

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
		for _, node := range q.Search.Nodes {
			r := &repo.Repo{
				Owner:          string(node.Repository.Owner.Login),
				Name:           string(node.Repository.Name),
				UpdatedAt:      node.Repository.UpdatedAt.Time,
				DiskUsage:      node.Repository.DiskUsage,
				StargazerCount: node.Repository.StargazerCount,
			}
			jobs <- r
			if oldest.IsZero() || r.UpdatedAt.Before(oldest) {
				oldest = r.UpdatedAt
			}
		}
		if !q.Search.PageInfo.HasNextPage {
			break PAGE_LOOP
		}
		cursor = &q.Search.PageInfo.EndCursor
	}
	close(jobs)
	wg.Wait()
	return oldest, nil
}
