// Copyright 2026 vArmor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package status implements token cache for manager
package status

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

var defaultTokenCacheTTL = 24 * time.Hour

// TokenCacheEntry stores the authentication result and expiration time for a token.
type TokenCacheEntry struct {
	authenticated bool
	expires       time.Time
}

// TokenCache provides a thread-safe cache for token validation results with TTL.
// It uses SHA256 hash of the token as the cache key to avoid storing raw tokens in memory.
type TokenCache struct {
	cache   sync.Map // key: token SHA256 hash, value: *TokenCacheEntry
	ttl     time.Duration
	log     logr.Logger
	metrics *TokenCacheMetrics
}

// TokenCacheMetrics tracks cache performance metrics.
type TokenCacheMetrics struct {
	hits   uint64
	misses uint64
	evicts uint64
}

// NewTokenCache creates a new TokenCache with the specified TTL.
// The TTL should be shorter than the token rotation interval to ensure
// revoked tokens are invalidated promptly.
func NewTokenCache(ttl time.Duration, log logr.Logger) *TokenCache {
	return &TokenCache{
		ttl:     ttl,
		log:     log,
		metrics: &TokenCacheMetrics{},
	}
}

// Get retrieves the cached authentication result for a token.
// Returns (authenticated, found) where:
//   - authenticated is true if the token was previously validated successfully
//   - found is true if the token exists in cache and has not expired
func (tc *TokenCache) Get(token string) (bool, bool) {
	if tc == nil {
		return false, false
	}

	key := hashToken(token)
	value, ok := tc.cache.Load(key)
	if !ok {
		tc.RecordMiss()
		return false, false
	}

	entry := value.(*TokenCacheEntry)
	if time.Now().Before(entry.expires) {
		// Cache hit
		tc.RecordHit()
		return entry.authenticated, true
	}

	// Entry expired, remove it
	tc.cache.Delete(key)
	tc.RecordEvict()
	return false, false
}

// Set stores the authentication result for a token with the configured TTL.
func (tc *TokenCache) Set(token string, authenticated bool) {
	if tc == nil {
		return
	}

	key := hashToken(token)
	entry := &TokenCacheEntry{
		authenticated: authenticated,
		expires:       time.Now().Add(tc.ttl),
	}
	tc.cache.Store(key, entry)
}

// Delete removes a token from the cache.
func (tc *TokenCache) Delete(token string) {
	if tc == nil {
		return
	}

	key := hashToken(token)
	tc.cache.Delete(key)
}

// StartCleanup starts a background goroutine that periodically removes expired entries.
// The cleanup interval is set to half of the TTL to ensure entries are removed
// promptly without excessive overhead.
func (tc *TokenCache) StartCleanup(stopCh <-chan struct{}) {
	if tc == nil {
		return
	}

	cleanupInterval := tc.ttl / 2
	if cleanupInterval < time.Minute {
		cleanupInterval = time.Minute
	}

	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				tc.cleanup()
			case <-stopCh:
				return
			}
		}
	}()

	tc.log.Info("token cache cleanup started", "interval", cleanupInterval)
}

// cleanup removes all expired entries from the cache.
func (tc *TokenCache) cleanup() {
	now := time.Now()
	var evictedCount uint64

	tc.cache.Range(func(key, value interface{}) bool {
		entry := value.(*TokenCacheEntry)
		if now.After(entry.expires) {
			tc.cache.Delete(key)
			evictedCount++
			tc.RecordEvict()
		}
		return true
	})

	if evictedCount > 0 {
		tc.log.V(2).Info("token cache cleanup", "evicted", evictedCount)
	}
}

// hashToken computes the SHA256 hash of a token for use as a cache key.
// This avoids storing raw tokens in memory for security.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// RecordHit increments the cache hit counter.
func (tc *TokenCache) RecordHit() {
	if tc != nil && tc.metrics != nil {
		tc.metrics.hits++
	}
}

// RecordMiss increments the cache miss counter.
func (tc *TokenCache) RecordMiss() {
	if tc != nil && tc.metrics != nil {
		tc.metrics.misses++
	}
}

// RecordEvict increments the cache evict counter.
func (tc *TokenCache) RecordEvict() {
	if tc != nil && tc.metrics != nil {
		tc.metrics.evicts++
	}
}

// GetMetrics returns a copy of the current metrics.
func (tc *TokenCache) GetMetrics() TokenCacheMetrics {
	if tc == nil || tc.metrics == nil {
		return TokenCacheMetrics{}
	}

	return TokenCacheMetrics{
		hits:   tc.metrics.hits,
		misses: tc.metrics.misses,
		evicts: tc.metrics.evicts,
	}
}

// Size returns the approximate number of entries in the cache.
func (tc *TokenCache) Size() int {
	if tc == nil {
		return 0
	}

	size := 0
	tc.cache.Range(func(_, _ interface{}) bool {
		size++
		return true
	})
	return size
}
