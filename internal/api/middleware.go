// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"
)

func AuthMiddleware(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("X-Admiral-Token")
		if reqToken == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				reqToken = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if subtle.ConstantTimeCompare([]byte(reqToken), []byte(token)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized: invalid token"}`))
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
