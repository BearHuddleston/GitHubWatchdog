// Package config provides configuration management for the application
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Config holds application configuration. Optional fields use pointers.
type Config struct {
	MaxPages        *int   `json:"max_pages"`
	PerPage         *int   `json:"per_page"`
	GitHubQuery     string `json:"github_query"` // mandatory
	Token           string `json:"-"`            // loaded from env vars or gh auth
	MaxConcurrent   *int   `json:"max_concurrent"`
	RateLimitBuffer *int   `json:"rate_limit_buffer"` // minimum remaining rate limit before pausing
	CacheTTL        *int   `json:"cache_ttl"`         // cache time-to-live in minutes
	Verbose         *bool  `json:"verbose"`           // enable verbose logging
}

// New loads configuration from config.json and env variables.
func New(configPath string) (*Config, error) {
	// defaults
	maxPages := 10
	perPage := 100
	maxConcurrent := 10
	rateLimitBuffer := 500
	cacheTTL := 60 // 1 hour cache TTL
	verbose := false
	conf := Config{
		MaxPages:        &maxPages,
		PerPage:         &perPage,
		GitHubQuery:     "stars:>5",
		MaxConcurrent:   &maxConcurrent,
		RateLimitBuffer: &rateLimitBuffer,
		CacheTTL:        &cacheTTL,
		Verbose:         &verbose,
	}

	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := json.Unmarshal(data, &conf); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	if conf.GitHubQuery == "" {
		return nil, errors.New("github_query must be set in config.json")
	}

	conf.Token = resolveGitHubToken()
	if conf.Token == "" {
		return nil, errors.New("please set GITHUB_TOKEN or GH_TOKEN, or authenticate gh")
	}
	return &conf, nil
}

func resolveGitHubToken() string {
	return resolveGitHubTokenWith(os.Getenv, ghAuthToken)
}

func resolveGitHubTokenWith(getenv func(string) string, ghToken func() (string, error)) string {
	for _, name := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if token := strings.TrimSpace(getenv(name)); token != "" {
			return token
		}
	}
	if token, err := ghToken(); err == nil {
		return strings.TrimSpace(token)
	}
	return ""
}

func ghAuthToken() (string, error) {
	for _, candidate := range []string{"gh", "/home/linuxbrew/.linuxbrew/bin/gh"} {
		if candidate == "gh" {
			if _, err := exec.LookPath(candidate); err != nil {
				continue
			}
		} else {
			if _, err := os.Stat(candidate); err != nil {
				continue
			}
		}
		output, err := exec.Command(candidate, "auth", "token").Output()
		if err != nil {
			continue
		}
		if token := strings.TrimSpace(string(output)); token != "" {
			return token, nil
		}
	}
	return "", errors.New("gh auth token unavailable")
}
