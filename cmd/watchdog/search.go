package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/google/go-github/v68/github"
)

// appendProcessedRepo appends a repository ID (owner/repo) to the processed record file.
func appendProcessedRepo(filename, repoID string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(repoID + "\n"); err != nil {
		return err
	}
	return nil
}

func searchAndProcessRepositories(ctx context.Context, client *github.Client, query string, processedRepos, processedUsers map[string]bool) error {
	opts := &github.SearchOptions{
		Sort:  "updated",
		Order: "desc",
		ListOptions: github.ListOptions{
			PerPage: perPage,
		},
	}

	for page := 1; page <= maxPages; page++ {
		opts.Page = page
		result, resp, err := client.Search.Repositories(ctx, query, opts)
		if err != nil {
			return fmt.Errorf("error searching repositories on page %d: %v", page, err)
		}
		log.Printf("HTTP Response Status: %s; Page %d: Found %d repositories", resp.Status, page, len(result.Repositories))
		if len(result.Repositories) == 0 {
			break
		}

		for _, repo := range result.Repositories {
			processRepository(ctx, client, repo, processedRepos, processedUsers)
		}
	}
	return nil
}

func processRepository(ctx context.Context, client *github.Client, repo *github.Repository, processedRepos, processedUsers map[string]bool) {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	repoID := fmt.Sprintf("%s/%s", owner, repoName)

	if processedRepos[repoID] {
		log.Printf("Repository %s already processed, skipping.", repoID)
		return
	}

	if repo.GetSize() < 10 {
		log.Printf("Repository %s is considered empty; analyzing user %s.", repoID, owner)
		if !processedUsers[owner] {
			if analyzeUser(ctx, client, owner) {
				log.Printf("Suspicious user detected: %s", owner)
				if err := appendSuspiciousUser(suspiciousUserRecordFile, owner); err != nil {
					log.Printf("Error recording suspicious user %s: %v", owner, err)
				}
			}
			processedUsers[owner] = true
		}
	}

	if err := appendProcessedRepo(recordFile, repoID); err != nil {
		log.Printf("Error recording repository %s as processed: %v", repoID, err)
	} else {
		processedRepos[repoID] = true
	}
}
