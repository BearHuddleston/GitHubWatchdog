package main

import (
	"context"
	"fmt"
	"log"

	"github.com/google/go-github/v68/github"
)

func appendProcessedRepo(filename, repoID string) error {
	return writeLineToFile(filename, repoID)
}

// searchAndProcessRepositories searches for repositories using the provided query
// and then processes each repository.
func searchAndProcessRepositories(ctx context.Context, client *github.Client, query string,
	maxPages, perPage int, processedRepos, processedUsers map[string]bool, analyzer *Analyzer,
	recordFile, suspiciousUserRecordFile, malRepoFile, malStargazerFile string) error {

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
			return fmt.Errorf("searching repositories on page %d: %w", page, err)
		}
		log.Printf("HTTP Response: %s; Page %d: Found %d repositories", resp.Status, page, len(result.Repositories))
		if len(result.Repositories) == 0 {
			break
		}

		for _, repo := range result.Repositories {
			processRepository(ctx, client, repo, processedRepos, processedUsers, analyzer,
				recordFile, suspiciousUserRecordFile, malRepoFile, malStargazerFile)
		}
	}
	return nil
}

// processRepository analyzes a repository and its owner.
// It records processed repositories and (if necessary) suspicious users.
func processRepository(ctx context.Context, client *github.Client, repo *github.Repository,
	processedRepos, processedUsers map[string]bool, analyzer *Analyzer,
	recordFile, suspiciousUserRecordFile, malRepoFile, malStargazerFile string) {

	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	repoID := fmt.Sprintf("%s/%s", owner, repoName)

	if processedRepos[repoID] {
		log.Printf("Repository %s already processed.", repoID)
		return
	}

	if repo.GetSize() < 10 {
		log.Printf("Repository %s (owner: %s) is small; checking user...", repoID, owner)
		if !processedUsers[owner] {
			if analyzer.analyzeUser(ctx, client, owner) {
				log.Printf("Suspicious user detected: %s", owner)
				if err := appendSuspiciousUser(suspiciousUserRecordFile, owner); err != nil {
					log.Printf("Recording suspicious user %s: %v", owner, err)
				}
			}
			processedUsers[owner] = true
		} else {
			log.Printf("User %s already processed.", owner)
		}
	}

	if err := analyzeRepo(ctx, client, owner, repoName, malRepoFile, malStargazerFile); err != nil {
		log.Printf("Analyzing repository %s: %v", repoID, err)
	}

	if err := appendProcessedRepo(recordFile, repoID); err != nil {
		log.Printf("Recording processed repository %s: %v", repoID, err)
	} else {
		processedRepos[repoID] = true
	}
}
