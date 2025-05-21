package github

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/arkouda/github/GitHubWatchdog/internal/models"
)

func TestNewClient(t *testing.T) {
	token := "test-token"
	bufferSize := 10
	cacheTTLMinutes := 5
	verbose := true

	client := NewClient(token, bufferSize, cacheTTLMinutes, verbose)

	assert.NotNil(t, client)
	assert.Equal(t, token, client.token)
	assert.NotNil(t, client.httpClient)
	assert.Equal(t, 30*time.Second, client.httpClient.Timeout)
	assert.NotNil(t, client.apiCache)
	assert.NotNil(t, client.rateLimiter)
	assert.Equal(t, time.Duration(cacheTTLMinutes)*time.Minute, client.cacheTTL)
	assert.NotNil(t, client.logger)
	assert.True(t, client.logger.IsVerbose())

	// Test with zero bufferSize
	clientZeroBuffer := NewClient(token, 0, cacheTTLMinutes, verbose)
	assert.NotNil(t, clientZeroBuffer)
	assert.NotNil(t, clientZeroBuffer.rateLimiter) // NewRateLimiter handles 0 by setting a default

	// Test with negative bufferSize
	clientNegativeBuffer := NewClient(token, -1, cacheTTLMinutes, verbose)
	assert.NotNil(t, clientNegativeBuffer)
	assert.NotNil(t, clientNegativeBuffer.rateLimiter) // NewRateLimiter handles negative by setting a default

	// Test with zero cacheTTLMinutes
	clientZeroCacheTTL := NewClient(token, bufferSize, 0, verbose)
	assert.NotNil(t, clientZeroCacheTTL)
	assert.Equal(t, time.Duration(0), clientZeroCacheTTL.cacheTTL)

	// Test with negative cacheTTLMinutes
	clientNegativeCacheTTL := NewClient(token, bufferSize, -5, verbose)
	assert.NotNil(t, clientNegativeCacheTTL)
	assert.Equal(t, time.Duration(-5)*time.Minute, clientNegativeCacheTTL.cacheTTL)
}

func TestGetLogger(t *testing.T) {
	client := NewClient("test-token", 10, 5, true)
	logger := client.GetLogger()
	assert.NotNil(t, logger)
	assert.True(t, logger.IsVerbose())
}

func TestQueryParams(t *testing.T) {
	token := "test-token"
	bufferSize := 10
	cacheTTLMinutes := 5
	client := NewClient(token, bufferSize, cacheTTLMinutes, false)

	expectedCacheTTL := time.Duration(cacheTTLMinutes) * time.Minute
	expectedQueryParams := &models.QueryParams{
		APICache:    client.apiCache,
		RateLimiter: client.rateLimiter,
		Token:       token,
		CacheTTL:    expectedCacheTTL,
	}

	queryParams := client.QueryParams()
	assert.Equal(t, expectedQueryParams, queryParams)
}
