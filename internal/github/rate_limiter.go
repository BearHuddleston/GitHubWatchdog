package github

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimiter handles GitHub API rate limiting
type RateLimiter struct {
	mutex              sync.Mutex
	coreRemaining      int
	coreReset          time.Time
	searchRemaining    int
	searchReset        time.Time
	coreLimitBuffer    int  // Buffer for core API (5000/hour)
	searchLimitBuffer  int  // Buffer for search API (30/minute)
	lastCheck          time.Time
	checkInterval      time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(buffer int) *RateLimiter {
	// For search API, use 10% of total as buffer (3 of 30)
	// For core API, use the provided buffer
	return &RateLimiter{
		coreRemaining:     5000, // GitHub core API default
		searchRemaining:   30,   // GitHub search API default
		coreLimitBuffer:   buffer,
		searchLimitBuffer: 3,    // Fixed buffer for search (10% of 30)
		checkInterval:     5 * time.Minute,
	}
}

// UpdateFromResponse updates rate limit info from response headers
func (r *RateLimiter) UpdateFromResponse(resp *http.Response) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	
	// Determine if this is a search or core API request based on URL
	isSearchRequest := strings.Contains(resp.Request.URL.Path, "/search/")
	
	if remaining := resp.Header.Get("X-RateLimit-Remaining"); remaining != "" {
		if val, err := strconv.Atoi(remaining); err == nil {
			if isSearchRequest {
				r.searchRemaining = val
			} else {
				r.coreRemaining = val
			}
		} else {
			log.Printf("Error parsing X-RateLimit-Remaining: %v", err)
		}
	}
	
	if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
		if val, err := strconv.ParseInt(reset, 10, 64); err == nil {
			if isSearchRequest {
				r.searchReset = time.Unix(val, 0)
			} else {
				r.coreReset = time.Unix(val, 0)
			}
		} else {
			log.Printf("Error parsing X-RateLimit-Reset: %v", err)
		}
	}

	r.lastCheck = time.Now()
	
	if isSearchRequest {
		log.Printf("Search API limit: %d remaining, resets at %s", 
			r.searchRemaining, r.searchReset)
	} else {
		log.Printf("Core API limit: %d remaining, resets at %s", 
			r.coreRemaining, r.coreReset)
	}
}

// CheckRateLimit checks if we're approaching rate limit
// Returns true if we should proceed, false if we should wait
// The apiType parameter should be "search" or "core"
func (r *RateLimiter) CheckRateLimit(apiType string) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var remaining, buffer int
	var resetTime time.Time
	
	// Select the appropriate rate limit based on API type
	if apiType == "search" {
		remaining = r.searchRemaining
		buffer = r.searchLimitBuffer
		resetTime = r.searchReset
	} else {
		// Default to core API
		remaining = r.coreRemaining
		buffer = r.coreLimitBuffer
		resetTime = r.coreReset
	}

	// Check if we're approaching the rate limit
	// We should have at least buffer requests available
	if remaining < buffer {
		// Rate limit approaching, continue to wait logic
	} else {
		return true // We have enough remaining requests
	}

	// If reset time is in the past, we can proceed (but this should be updated soon)
	if time.Now().After(resetTime) {
		return true
	}

	// We're approaching rate limit, calculate wait time
	waitTime := time.Until(resetTime) + 5*time.Second
	
	log.Printf("%s API rate limit approaching (%d remaining). Waiting until reset + 5s: %s",
		apiType, remaining, waitTime)
	
	time.Sleep(waitTime)

	// After waiting, reset our remaining count to avoid immediate re-wait
	// Next API call will update this with actual values
	if apiType == "search" {
		r.searchRemaining = r.searchLimitBuffer + 1
	} else {
		r.coreRemaining = r.coreLimitBuffer + 1
	}
	
	log.Printf("%s API rate limit wait complete. Proceeding with requests.", apiType)
	return true
}

// CheckSearchRateLimit convenience method for checking search API rate limit
func (r *RateLimiter) CheckSearchRateLimit() bool {
	return r.CheckRateLimit("search")
}

// CheckCoreRateLimit convenience method for checking core API rate limit 
func (r *RateLimiter) CheckCoreRateLimit() bool {
	return r.CheckRateLimit("core")
}

// FetchRateLimits explicitly gets current rate limit status
func (r *RateLimiter) FetchRateLimits(ctx context.Context, token string) error {
	// Only check rate limits at most once per check interval
	if time.Since(r.lastCheck) < r.checkInterval {
		return nil
	}

	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/rate_limit", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch rate limit: %s", resp.Status)
	}

	var rateLimit struct {
		Resources struct {
			Core struct {
				Limit     int   `json:"limit"`
				Remaining int   `json:"remaining"`
				Reset     int64 `json:"reset"`
			} `json:"core"`
			Search struct {
				Limit     int   `json:"limit"`
				Remaining int   `json:"remaining"`
				Reset     int64 `json:"reset"`
			} `json:"search"`
		} `json:"resources"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rateLimit); err != nil {
		return fmt.Errorf("decoding rate limit response: %w", err)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Update both core and search rate limits
	r.coreRemaining = rateLimit.Resources.Core.Remaining
	r.coreReset = time.Unix(rateLimit.Resources.Core.Reset, 0)
	r.searchRemaining = rateLimit.Resources.Search.Remaining
	r.searchReset = time.Unix(rateLimit.Resources.Search.Reset, 0)
	r.lastCheck = time.Now()
	
	log.Printf("Current rate limits - Core: %d/%d (resets at %s), Search: %d/%d (resets at %s)", 
		rateLimit.Resources.Core.Remaining, rateLimit.Resources.Core.Limit,
		r.coreReset.Format(time.RFC3339),
		rateLimit.Resources.Search.Remaining, rateLimit.Resources.Search.Limit,
		r.searchReset.Format(time.RFC3339))

	return nil
}