// Package github provides GitHub API client functionality
package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/logger"
	"github.com/arkouda/github/GitHubWatchdog/internal/models"
)

// Client handles GitHub API requests with rate limiting and caching
type Client struct {
	httpClient  *http.Client
	token       string
	apiCache    *APICache
	rateLimiter *RateLimiter
	cacheTTL    time.Duration
	logger      *logger.Logger
}

// NewClient creates a new GitHub client
func NewClient(token string, bufferSize int, cacheTTLMinutes int, verbose bool) *Client {
	cacheTTL := time.Duration(cacheTTLMinutes) * time.Minute
	log := logger.New(verbose)

	return &Client{
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		token:       token,
		apiCache:    NewAPICache(),
		rateLimiter: NewRateLimiter(bufferSize),
		cacheTTL:    cacheTTL,
		logger:      log,
	}
}

// GetLogger returns the client's logger
func (c *Client) GetLogger() *logger.Logger {
	return c.logger
}

// QueryParams gets the client's query parameters
func (c *Client) QueryParams() *models.QueryParams {
	return &models.QueryParams{
		APICache:    c.apiCache,
		RateLimiter: c.rateLimiter,
		Token:       c.token,
		CacheTTL:    c.cacheTTL,
	}
}

// SearchRepositories searches for repositories using the GitHub search API
func (c *Client) SearchRepositories(ctx context.Context, query string, page, perPage int) (*models.SearchResult, error) {
	// First check if context is already canceled
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Check rate limits, but don't hang if we can't proceed
	if !c.rateLimiter.CheckSearchRateLimit() {
		return nil, fmt.Errorf("search rate limit exceeded, please retry after reset time")
	}

	reqURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&page=%d&per_page=%d", url.QueryEscape(query), page, perPage)
	cacheKey := fmt.Sprintf("search:%s:%d:%d", query, page, perPage)

	var responseBody []byte

	// Try to get from cache first
	if cachedData, found := c.apiCache.Get(cacheKey, c.cacheTTL); found {
		c.logger.Debug("Cache hit for query '%s' page %d", query, page)
		responseBody = cachedData
	} else {
		c.logger.Debug("Cache miss for query '%s' page %d, fetching from API", query, page)

		// Create request with context to respect timeouts
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "token "+c.token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		// Perform request with timeout from context
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		// Update rate limits
		c.rateLimiter.UpdateFromResponse(resp)

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == http.StatusForbidden {
				c.logger.Error("Rate limit exceeded: %s - %s", resp.Status, string(bodyBytes))

				// Handle rate limiting
				if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
					if d, err := time.ParseDuration(retryAfter + "s"); err == nil {
						c.logger.Info("Rate limited. Waiting %v seconds.", d)
						time.Sleep(d)
						return c.SearchRepositories(ctx, query, page, perPage)
					}
				} else {
					// If no Retry-After, avoid recursion that could cause a hang
					c.logger.Info("Rate limited with no retry header. Returning error.")
					return nil, fmt.Errorf("search rate limit exceeded, please retry later")
				}
			}
			return nil, fmt.Errorf("search failed: %s - %s", resp.Status, string(bodyBytes))
		}

		// Read the response body
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}

		// Cache the response
		c.apiCache.Set(cacheKey, responseBody)
		c.logger.Debug("Cached response for '%s' (%d bytes)", cacheKey, len(responseBody))
	}

	// Parse the response
	var result models.SearchResult
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("decoding search results: %w", err)
	}

	c.logger.Info("Page %d: Found %d repositories", page, len(result.Items))
	return &result, nil
}

// GetUserInfo fetches user info from GitHub
func (c *Client) GetUserInfo(ctx context.Context, username string) (time.Time, error) {
	c.rateLimiter.CheckCoreRateLimit()

	url := fmt.Sprintf("https://api.github.com/users/%s", username)
	cacheKey := fmt.Sprintf("user:%s", username)

	var responseBody []byte

	// Try from cache first
	if cachedData, found := c.apiCache.Get(cacheKey, c.cacheTTL); found {
		c.logger.Debug("Cache hit for user '%s'", username)
		responseBody = cachedData
	} else {
		c.logger.Debug("Cache miss for user '%s', fetching from API", username)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return time.Time{}, err
		}

		req.Header.Set("Authorization", "token "+c.token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return time.Time{}, err
		}
		defer resp.Body.Close()

		// Update rate limits
		c.rateLimiter.UpdateFromResponse(resp)

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return time.Time{}, fmt.Errorf("failed to fetch user info: %s - %s", resp.Status, string(bodyBytes))
		}

		// Read response body
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			return time.Time{}, fmt.Errorf("reading response body: %w", err)
		}

		// Cache the response
		c.apiCache.Set(cacheKey, responseBody)
		c.logger.Debug("Cached user info for '%s'", username)
	}

	// Parse the user data
	var userInfo struct {
		CreatedAt string `json:"created_at"`
	}

	if err := json.Unmarshal(responseBody, &userInfo); err != nil {
		return time.Time{}, fmt.Errorf("decoding user info: %w", err)
	}

	createdAt, err := time.Parse(time.RFC3339, userInfo.CreatedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing user creation date: %w", err)
	}

	return createdAt, nil
}

// GetUserRepositories fetches a user's repositories from GitHub
func (c *Client) GetUserRepositories(ctx context.Context, username string) ([]models.RepoMetrics, error) {
	var repos []models.RepoMetrics
	page := 1

	for {
		c.rateLimiter.CheckCoreRateLimit()

		url := fmt.Sprintf("https://api.github.com/users/%s/repos?per_page=100&page=%d", username, page)
		cacheKey := fmt.Sprintf("repos:%s:%d", username, page)

		var responseBody []byte

		// Try from cache first
		if cachedData, found := c.apiCache.Get(cacheKey, c.cacheTTL); found {
			c.logger.Debug("Cache hit for repos of user '%s' page %d", username, page)
			responseBody = cachedData
		} else {
			c.logger.Debug("Cache miss for repos of user '%s' page %d, fetching from API", username, page)

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return nil, err
			}

			req.Header.Set("Authorization", "token "+c.token)
			req.Header.Set("Accept", "application/vnd.github.v3+json")

			resp, err := c.httpClient.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			// Update rate limits
			c.rateLimiter.UpdateFromResponse(resp)

			if resp.StatusCode != http.StatusOK {
				bodyBytes, _ := io.ReadAll(resp.Body)
				return nil, fmt.Errorf("failed to fetch user repos: %s - Body: %s", resp.Status, string(bodyBytes))
			}

			// Read response body
			responseBody, err = io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("reading response body: %w", err)
			}

			// Cache the response
			c.apiCache.Set(cacheKey, responseBody)
			c.logger.Debug("Cached repos for user '%s' page %d", username, page)
		}

		// Parse the repositories
		var userRepos []struct {
			Name            string `json:"name"`
			Size            int    `json:"size"`
			StargazersCount int    `json:"stargazers_count"`
		}

		if err := json.Unmarshal(responseBody, &userRepos); err != nil {
			return nil, fmt.Errorf("decoding user repositories: %w", err)
		}

		if len(userRepos) == 0 {
			break
		}

		for _, r := range userRepos {
			repos = append(repos, models.RepoMetrics{
				Name:           r.Name,
				DiskUsage:      r.Size,
				StargazerCount: r.StargazersCount,
			})
		}

		if len(userRepos) < 100 {
			break
		}

		page++
	}

	return repos, nil
}

// GetUserContributions fetches a user's contributions from GitHub
func (c *Client) GetUserContributions(ctx context.Context, username string) (int, error) {
	c.rateLimiter.CheckCoreRateLimit()

	url := fmt.Sprintf("https://api.github.com/users/%s/events/public?per_page=100", username)
	cacheKey := fmt.Sprintf("events:%s", username)

	var responseBody []byte

	// Try from cache first
	if cachedData, found := c.apiCache.Get(cacheKey, c.cacheTTL); found {
		c.logger.Debug("Cache hit for events of user '%s'", username)
		responseBody = cachedData
	} else {
		c.logger.Debug("Cache miss for events of user '%s', fetching from API", username)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return 0, err
		}

		req.Header.Set("Authorization", "token "+c.token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()

		// Update rate limits
		c.rateLimiter.UpdateFromResponse(resp)

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return 0, fmt.Errorf("failed to fetch user events: %s - %s", resp.Status, string(bodyBytes))
		}

		// Read response body
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			return 0, fmt.Errorf("reading response body: %w", err)
		}

		// Cache the response
		c.apiCache.Set(cacheKey, responseBody)
		c.logger.Debug("Cached events for user '%s'", username)
	}

	// Parse the events
	var events []struct {
		CreatedAt string `json:"created_at"`
	}

	if err := json.Unmarshal(responseBody, &events); err != nil {
		return 0, fmt.Errorf("decoding user events: %w", err)
	}

	oneYearAgo := time.Now().Add(-365 * 24 * time.Hour)
	count := 0

	for _, e := range events {
		t, err := time.Parse(time.RFC3339, e.CreatedAt)
		if err == nil && t.After(oneYearAgo) {
			count++
		}
	}

	return count, nil
}

// GetRepoReadme fetches a repository's README from GitHub
func (c *Client) GetRepoReadme(ctx context.Context, owner, repo string) (string, error) {
	c.rateLimiter.CheckCoreRateLimit()

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/readme", owner, repo)
	cacheKey := fmt.Sprintf("readme:%s:%s", owner, repo)

	var responseBody []byte

	// Try from cache first
	if cachedData, found := c.apiCache.Get(cacheKey, c.cacheTTL); found {
		c.logger.Debug("Cache hit for readme of %s/%s", owner, repo)
		responseBody = cachedData
	} else {
		c.logger.Debug("Cache miss for readme of %s/%s, fetching from API", owner, repo)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return "", err
		}

		req.Header.Set("Authorization", "token "+c.token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		// Update rate limits
		c.rateLimiter.UpdateFromResponse(resp)

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			c.logger.Debug("Non-OK response for readme: status=%s, body=%s", resp.Status, string(bodyBytes))

			if resp.StatusCode == http.StatusNotFound {
				return "", nil
			}

			return "", fmt.Errorf("fetching readme: %s - body: %s", resp.Status, string(bodyBytes))
		}

		// Read the response body
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("reading readme body: %w", err)
		}

		// Cache the response
		c.apiCache.Set(cacheKey, responseBody)
		c.logger.Debug("Cached readme for %s/%s", owner, repo)
	}

	// Parse the readme data
	var data struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}

	if err := json.Unmarshal(responseBody, &data); err != nil {
		return "", fmt.Errorf("decoding readme: %w", err)
	}

	if data.Encoding != "base64" {
		return "", fmt.Errorf("unexpected readme encoding: %s", data.Encoding)
	}

	decoded, err := base64.StdEncoding.DecodeString(data.Content)
	if err != nil {
		return "", fmt.Errorf("decoding readme content: %w", err)
	}

	return string(decoded), nil
}

// GetRepoTree fetches a repository's file tree from GitHub
func (c *Client) GetRepoTree(ctx context.Context, owner, repo, branch string) ([]string, error) {
	c.rateLimiter.CheckCoreRateLimit()

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1", owner, repo, branch)
	cacheKey := fmt.Sprintf("tree:%s:%s:%s", owner, repo, branch)

	var responseBody []byte

	// Try from cache first
	if cachedData, found := c.apiCache.Get(cacheKey, c.cacheTTL); found {
		c.logger.Debug("Cache hit for tree of %s/%s:%s", owner, repo, branch)
		responseBody = cachedData
	} else {
		c.logger.Debug("Cache miss for tree of %s/%s:%s, fetching from API", owner, repo, branch)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "token "+c.token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		// Update rate limits
		c.rateLimiter.UpdateFromResponse(resp)

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			c.logger.Debug("Non-OK response for tree: status=%s, body=%s", resp.Status, string(bodyBytes))
			return nil, fmt.Errorf("fetching repo tree: %s", resp.Status)
		}

		// Read the response body
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading tree body: %w", err)
		}

		// Cache the response
		c.apiCache.Set(cacheKey, responseBody)
		c.logger.Debug("Cached tree for %s/%s:%s", owner, repo, branch)
	}

	// Parse the tree data
	var data struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}

	if err := json.Unmarshal(responseBody, &data); err != nil {
		return nil, fmt.Errorf("decoding repo tree: %w", err)
	}

	var entries []string
	for _, entry := range data.Tree {
		if entry.Type == "blob" {
			entries = append(entries, entry.Path)
		}
	}

	return entries, nil
}

// CheckRepoReleases checks a repository's releases for malicious files
func (c *Client) CheckRepoReleases(ctx context.Context, owner, repo string) (bool, error) {
	c.rateLimiter.CheckCoreRateLimit()

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases", owner, repo)
	cacheKey := fmt.Sprintf("releases:%s:%s", owner, repo)

	var responseBody []byte

	// Try from cache first
	if cachedData, found := c.apiCache.Get(cacheKey, c.cacheTTL); found {
		c.logger.Debug("Cache hit for releases of %s/%s", owner, repo)
		responseBody = cachedData
	} else {
		c.logger.Debug("Cache miss for releases of %s/%s, fetching from API", owner, repo)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return false, err
		}

		req.Header.Set("Authorization", "token "+c.token)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()

		// Update rate limits
		c.rateLimiter.UpdateFromResponse(resp)

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			c.logger.Debug("Non-OK response for releases: status=%s, body=%s", resp.Status, string(bodyBytes))
			return false, fmt.Errorf("failed to fetch releases: %s", resp.Status)
		}

		// Read the response body
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("reading releases body: %w", err)
		}

		// Cache the response
		c.apiCache.Set(cacheKey, responseBody)
		c.logger.Debug("Cached releases for %s/%s", owner, repo)
	}

	// Parse the releases data
	var releases []struct {
		Assets []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}

	if err := json.Unmarshal(responseBody, &releases); err != nil {
		return false, fmt.Errorf("decoding releases: %w", err)
	}

	for _, rel := range releases {
		for _, asset := range rel.Assets {
			lower := strings.ToLower(asset.Name)
			if lower == "loader.zip" || lower == "loader.rar" {
				c.logger.Info("Found suspicious asset in releases of %s/%s: %s", owner, repo, asset.Name)
				return true, nil
			}
		}
	}

	return false, nil
}

// FetchRateLimits gets GitHub API rate limit information
func (c *Client) FetchRateLimits(ctx context.Context) error {
	return c.rateLimiter.FetchRateLimits(ctx, c.token)
}
