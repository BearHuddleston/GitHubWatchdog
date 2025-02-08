package config

import (
	"fmt"
	"os"
)

// Config holds the application settings.
type Config struct {
	RecordFile               string
	SuspiciousUserRecordFile string
	MalRepoFile              string
	MalStargazerFile         string
	MaxPages                 int
	PerPage                  int
	GitHubQuery              string
	Token                    string
	NumWorkers               int
}

// New returns a new configuration by reading environment variables and setting defaults.
func New() (*Config, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("please set the GITHUB_TOKEN environment variable")
	}
	return &Config{
		RecordFile:               "processed_repos.txt",
		SuspiciousUserRecordFile: "suspicious_users.txt",
		MalRepoFile:              "malicious_repos.txt",
		MalStargazerFile:         "malicious_stargazers.txt",
		MaxPages:                 10,
		PerPage:                  100,                            // maximum per page
		GitHubQuery:              "created:>2025-01-31 stars:>5", // base query
		Token:                    token,
		NumWorkers:               5,
	}, nil
}
