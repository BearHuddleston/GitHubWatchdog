// Package models contains shared data structures used throughout the application
package models

import (
	"time"
)

// RepoItem represents a repository from GitHub's REST API
type RepoItem struct {
	Name            string    `json:"name"`
	FullName        string    `json:"full_name"`
	UpdatedAt       time.Time `json:"updated_at"`
	Size            int       `json:"size"`
	StargazersCount int       `json:"stargazers_count"`
	Owner           struct {
		Login string `json:"login"`
	} `json:"owner"`
	DefaultBranch string `json:"default_branch"`
}

// SearchResult represents the result of a GitHub search API call
type SearchResult struct {
	TotalCount int        `json:"total_count"`
	Items      []RepoItem `json:"items"`
}

// Repo represents repository data for internal processing
type Repo struct {
	Owner          string
	Name           string
	UpdatedAt      time.Time
	DiskUsage      int
	StargazerCount int
}

// RepoData represents repository data for malicious checks
type RepoData struct {
	Owner          string
	Name           string
	Readme         string
	TreeEntries    []string
	DiskUsage      int
	StargazerCount int
}

// UserData represents user data for analysis
type UserData struct {
	CreatedAt     time.Time
	Contributions int
	Repositories  []RepoData
}

// RepoMetrics represents repository metrics for a user
type RepoMetrics struct {
	Name           string
	DiskUsage      int
	StargazerCount int
}

// AnalysisResult represents the result of analyzing a user
type AnalysisResult struct {
	Suspicious           bool
	TotalStars           int
	EmptyCount           int
	SuspiciousEmptyCount int
	Contributions        int
	HeuristicResults     []HeuristicResult
}

// HeuristicResult represents the result of a single heuristic check
type HeuristicResult struct {
	Flag        bool
	Name        string
	Description string
}

// CacheEntry represents a cached API response
type CacheEntry struct {
	Data      []byte
	Timestamp time.Time
}

// QueryParams holds global parameters for API queries
type QueryParams struct {
	APICache    interface{} // Will be APICache in github package
	RateLimiter interface{} // Will be RateLimiter in github package
	Token       string
	CacheTTL    time.Duration
}