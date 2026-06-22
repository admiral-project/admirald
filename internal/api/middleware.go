// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/logging"
)

func AdminAuthMiddleware(log *logging.Logger, adminToken string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("X-Admiral-Token")
		if reqToken == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				reqToken = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if reqToken == "" {
			logAuthFailure(log, "WARN", "admin_token", "missing_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(reqToken), []byte(adminToken)) != 1 {
			logAuthFailure(log, "WARN", "admin_token", "invalid_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}

		// Strip client-supplied admin-user header to prevent audit trail forgery.
		// Only AdminAuthMiddleware is authorized to set this header.
		r.Header.Del("X-Admiral-Admin-User")
		r.Header.Del("X-Admiral-Operator")

		next(w, r)
	}
}

// MaxBody wraps a handler with http.MaxBytesReader to limit request body size.
// maxBytes: 1<<20 = 1 MiB for JSON, 5<<20 = 5 MiB for YAML.
func MaxBody(maxBytes int64, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next(w, r)
	}
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string][]time.Time
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{buckets: make(map[string][]time.Time)}
}

func (rl *RateLimiter) Allow(key string, maxAttempts int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	entries := rl.buckets[key]
	var recent []time.Time
	for _, t := range entries {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= maxAttempts {
		rl.buckets[key] = recent
		return false
	}
	recent = append(recent, now)
	rl.buckets[key] = recent
	return true
}

func RateLimit(limiter *RateLimiter, key string, maxAttempts int, window time.Duration, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r.RemoteAddr)
		fullKey := key + ":" + ip
		if !limiter.Allow(fullKey, maxAttempts, window) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
			return
		}
		next(w, r)
	}
}
