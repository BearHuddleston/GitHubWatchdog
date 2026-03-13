package github

import (
	"sync"
	"time"
)

// APICache holds cached API responses
type APICache struct {
	data sync.Map // map[string]cacheEntry
}

type cacheEntry struct {
	data      []byte
	timestamp time.Time
}

// NewAPICache creates a new API cache
func NewAPICache() *APICache {
	return &APICache{}
}

// Get retrieves a cached response if it exists and is not expired
func (c *APICache) Get(key string, ttl time.Duration) ([]byte, bool) {
	if val, ok := c.data.Load(key); ok {
		entry := val.(cacheEntry)
		if time.Since(entry.timestamp) < ttl {
			return entry.data, true
		}
	}
	return nil, false
}

// Set stores a response in the cache
func (c *APICache) Set(key string, data []byte) {
	c.data.Store(key, cacheEntry{
		data:      data,
		timestamp: time.Now(),
	})
}

// Clear empties the cache
func (c *APICache) Clear() {
	c.data = sync.Map{}
}
