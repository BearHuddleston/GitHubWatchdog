// Package config provides configuration management for the application
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// OllamaConfig holds configuration for the Ollama API
type OllamaConfig struct {
	Enabled  *bool  `json:"enabled"`   // Whether to use Ollama for analysis
	Endpoint string `json:"endpoint"`  // Ollama API endpoint
	Model    string `json:"model"`     // Model to use for analysis
}

// Config holds application configuration. Optional fields use pointers.
type Config struct {
	MaxPages        *int          `json:"max_pages"`
	PerPage         *int          `json:"per_page"`
	GitHubQuery     string        `json:"github_query"` // mandatory
	Token           string        `json:"-"`            // loaded from env var
	MaxConcurrent   *int          `json:"max_concurrent"`
	RateLimitBuffer *int          `json:"rate_limit_buffer"` // minimum remaining rate limit before pausing
	CacheTTL        *int          `json:"cache_ttl"`         // cache time-to-live in minutes
	Verbose         *bool         `json:"verbose"`           // enable verbose logging
	Ollama          *OllamaConfig `json:"ollama"`            // Ollama API configuration
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
	ollamaEnabled := false
	
	conf := Config{
		MaxPages:        &maxPages,
		PerPage:         &perPage,
		GitHubQuery:     "created:>2025-01-31 stars:>5",
		MaxConcurrent:   &maxConcurrent,
		RateLimitBuffer: &rateLimitBuffer,
		CacheTTL:        &cacheTTL,
		Verbose:         &verbose,
		Ollama: &OllamaConfig{
			Enabled:  &ollamaEnabled,
			Endpoint: "http://localhost:11434",
			Model:    "llama3.2",
		},
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

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		conf.Token = token
	}
	if conf.Token == "" {
		return nil, errors.New("please set the GITHUB_TOKEN environment variable")
	}

	// Override Ollama settings from environment variables
	if endpoint := os.Getenv("OLLAMA_ENDPOINT"); endpoint != "" {
		conf.Ollama.Endpoint = endpoint
	}
	
	if model := os.Getenv("OLLAMA_MODEL"); model != "" {
		conf.Ollama.Model = model
	}
	
	if enabledStr := os.Getenv("OLLAMA_ENABLED"); enabledStr != "" {
		enabled := strings.ToLower(enabledStr) == "true" || enabledStr == "1"
		conf.Ollama.Enabled = &enabled
	}

	return &conf, nil
}