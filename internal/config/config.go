package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	MaxPages      int    `json:"max_pages"`
	PerPage       int    `json:"per_page"`
	GitHubQuery   string `json:"github_query"`
	Token         string `json:"token"`
	MaxConcurrent int    `json:"max_concurrent"`
}

func New() (*Config, error) {
	// Set default values
	conf := Config{
		MaxPages:      10,
		PerPage:       100,                            // maximum per page
		GitHubQuery:   "created:>2025-01-31 stars:>5", // base query
		Token:         "",
		MaxConcurrent: 10,
	}

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
