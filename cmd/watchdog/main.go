package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"
)

type config struct {
	recordFile               string
	suspiciousUserRecordFile string
	malRepoFile              string
	malStargazerFile         string
	maxPages                 int
	perPage                  int
	gitHubQuery              string
	token                    string
}

func newConfig() (*config, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("please set the GITHUB_TOKEN environment variable")
	}
	return &config{
		recordFile:               "processed_repos.txt",
		suspiciousUserRecordFile: "suspicious_users.txt",
		malRepoFile:              "malicious_repos.txt",
		malStargazerFile:         "malicious_stargazers.txt",
		maxPages:                 10,
		perPage:                  100,
		gitHubQuery:              "created:>2025-02-04 stars:>5",
		token:                    token,
	}, nil
}

func newGitHubClient(token string) *github.Client {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

func main() {
	cfg, err := newConfig()
	if err != nil {
		log.Fatal(err)
	}

	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	log.Println("GitHub token loaded. Starting repository search.")

	client := newGitHubClient(cfg.token)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	processedRepos, err := loadProcessedRepos(cfg.recordFile)
	if err != nil {
		log.Printf("Warning: loading processed repos: %v", err)
		processedRepos = make(map[string]bool)
	}
	processedUsers := make(map[string]bool)
	analyzer := NewAnalyzer()

	log.Printf("Searching for repositories with query: '%s'", cfg.gitHubQuery)
	if err := searchAndProcessRepositories(ctx, client, cfg.gitHubQuery,
		cfg.maxPages, cfg.perPage, processedRepos, processedUsers, analyzer,
		cfg.recordFile, cfg.suspiciousUserRecordFile, cfg.malRepoFile, cfg.malStargazerFile); err != nil {
		log.Fatalf("Failed processing repositories: %v", err)
	}
}
