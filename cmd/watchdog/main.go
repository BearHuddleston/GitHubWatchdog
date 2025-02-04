package main

import (
	"context"
	"log"
	"os"

	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"
)

const (
	recordFile               = "processed_repos.txt"
	suspiciousUserRecordFile = "suspicious_users.txt"
	maxPages                 = 10
	perPage                  = 100
	gitHubQuery              = "created:>2025-02-02 stars:>5"
)

// initializeGitHubClient creates a GitHub client using a personal access token.
func initializeGitHubClient(token string) *github.Client {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

func main() {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("Please set the GITHUB_TOKEN environment variable")
	}
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	log.Println("GitHub token loaded successfully. Starting repository search.")

	client := initializeGitHubClient(token)
	ctx := context.Background()

	processedRepos, err := loadProcessedRepos(recordFile)
	if err != nil {
		log.Printf("Warning: could not load processed repos record: %v", err)
		processedRepos = make(map[string]bool)
	}

	processedUsers := make(map[string]bool)

	log.Printf("Searching for repositories with query: '%s'", gitHubQuery)
	if err := searchAndProcessRepositories(ctx, client, gitHubQuery, processedRepos, processedUsers); err != nil {
		log.Fatalf("Failed processing repositories: %v", err)
	}
}
