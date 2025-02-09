package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds the application settings.
type Config struct {
	RecordFile               string `json:"record_file"`
	SuspiciousUserRecordFile string `json:"suspicious_user_record_file"`
	MalRepoFile              string `json:"mal_repo_file"`
	MalStargazerFile         string `json:"mal_stargazer_file"`
	MaxPages                 int    `json:"max_pages"`
	PerPage                  int    `json:"per_page"`
	GitHubQuery              string `json:"github_query"`
	Token                    string `json:"token"`
	NumWorkers               int    `json:"num_workers"`
}

// New returns a new configuration by reading defaults from a config file
// (config.json) and environment variables (which override file values).
func New() (*Config, error) {
	// Set default values
	conf := Config{
		RecordFile:               "processed_repos.txt",
		SuspiciousUserRecordFile: "suspicious_users.txt",
		MalRepoFile:              "malicious_repos.txt",
		MalStargazerFile:         "malicious_stargazers.txt",
		MaxPages:                 10,
		PerPage:                  100,                            // maximum per page
		GitHubQuery:              "created:>2025-01-31 stars:>5", // base query
		Token:                    "",
		NumWorkers:               5,
	}

	// Try to read the config file if it exists.
	configFilePath := "config.json"
	if _, err := os.Stat(configFilePath); err == nil {
		data, err := os.ReadFile(configFilePath)
		if err != nil {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		if err := json.Unmarshal(data, &conf); err != nil {
			return nil, fmt.Errorf("error parsing config file: %w", err)
		}
	}

	// Override token with environment variable if available.
	if tokenEnv := os.Getenv("GITHUB_TOKEN"); tokenEnv != "" {
		conf.Token = tokenEnv
	}

	if conf.Token == "" {
		return nil, fmt.Errorf("please set the GITHUB_TOKEN environment variable or add it to the config file")
	}

	return &conf, nil
}
