package github

import (
	"sync"
	"time"
	
	"github.com/arkouda/github/GitHubWatchdog/internal/models"
)

// APICache holds cached API responses
type APICache struct {
	data      sync.Map // map[string]models.CacheEntry
	cacheLock sync.RWMutex
}

// NewAPICache creates a new API cache
func NewAPICache() *APICache {
	return &APICache{
		data: sync.Map{},
	}
}

// Get retrieves a cached response if it exists and is not expired
func (c *APICache) Get(key string, ttl time.Duration) ([]byte, bool) {
	c.cacheLock.RLock()
	defer c.cacheLock.RUnlock()
	
	if val, ok := c.data.Load(key); ok {
		entry := val.(models.CacheEntry)
		if time.Since(entry.Timestamp) < ttl {
			return entry.Data, true
		}
	}
	return nil, false
}

// Set stores a response in the cache
func (c *APICache) Set(key string, data []byte) {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	
	c.data.Store(key, models.CacheEntry{
		Data:      data,
		Timestamp: time.Now(),
	})
}

// Clear empties the cache
func (c *APICache) Clear() {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	
	c.data = sync.Map{}
}