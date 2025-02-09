package repo

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/shurcooL/githubv4"
	"githubwatchdog.bearhuddleston/internal/fileutil"
)

// Repo represents a GitHub repository with selected fields.
type Repo struct {
	Owner          string
	Name           string
	UpdatedAt      time.Time
	DiskUsage      int
	StargazerCount int
}

// AnalyzeRepo checks a repository’s README for malware markers.
func AnalyzeRepo(ctx context.Context, client *githubv4.Client, owner, repoName, malRepoFile, malStargazerFile string) error {
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
	err := client.Query(ctx, &q, variables)
	if err != nil {
		return fmt.Errorf("fetching README for %s/%s: %w", owner, repoName, err)
	}

	// If there's no README, avoid further API calls.
	if q.Repository.Readme == nil {
		log.Printf("Repository %s/%s has no README.md – skipping analysis.", owner, repoName)
		return nil
	}

	content := q.Repository.Readme.Blob.Text

	// Only proceed if the malware markers are found.
	if !(strings.Contains(content, "# [DOWNLOAD LINK]") && strings.Contains(content, "# PASSWORD : 2025")) {
		return nil
	}

	log.Printf("Repository %s/%s categorized as malware.", owner, repoName)
	repoID := fmt.Sprintf("%s/%s", owner, repoName)
	if err := fileutil.AppendMaliciousRepo(malRepoFile, repoID); err != nil {
		log.Printf("Recording malware repo %s: %v", repoID, err)
	}

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
		err := client.Query(ctx, &sgQuery, vars)
		if err != nil {
			log.Printf("Fetching stargazers for %s/%s: %v", owner, repoName, err)
			break
		}
		for _, user := range sgQuery.Repository.Stargazers.Nodes {
			login := string(user.Login)
			if err := fileutil.AppendMaliciousStargazer(malStargazerFile, login); err != nil {
				log.Printf("Recording malicious stargazer %s: %v", login, err)
			}
		}
		if !sgQuery.Repository.Stargazers.PageInfo.HasNextPage {
			break
		}
		cursor = &sgQuery.Repository.Stargazers.PageInfo.EndCursor
	}

	return nil
}
