// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
)

func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none';")
		next.ServeHTTP(w, r)
	})
}

func AdminAuthMiddleware(log *logging.Logger, adminToken string, trustedProxies []string, next http.HandlerFunc) http.HandlerFunc {
	limiter := NewRateLimiter()
	return func(w http.ResponseWriter, r *http.Request) {
		key := "admin_token:" + getClientIP(r, trustedProxies)
		if blocked, retryAfter := limiter.IsBlocked(key, authFailureLimit, authFailureWindow); blocked {
			seconds := int(retryAfter / time.Second)
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			logAuthFailure(log, "WARN", "admin_token", "ip_temporarily_blocked", http.StatusTooManyRequests, r, nil)
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many authentication failures"})
			return
		}

		reqToken := r.Header.Get("X-Admiral-Token")
		if reqToken == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				reqToken = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if reqToken == "" {
			limiter.Allow(key, authFailureLimit, authFailureWindow)
			logAuthFailure(log, "WARN", "admin_token", "missing_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(reqToken), []byte(adminToken)) != 1 {
			limiter.Allow(key, authFailureLimit, authFailureWindow)
			logAuthFailure(log, "WARN", "admin_token", "invalid_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}
		limiter.Reset(key)

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

func (rl *RateLimiter) IsBlocked(key string, maxAttempts int, window time.Duration) (bool, time.Duration) {
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
	rl.buckets[key] = recent
	if len(recent) < maxAttempts {
		return false, 0
	}
	retryAfter := window - now.Sub(recent[0])
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	return true, retryAfter
}

func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, key)
}

type Limiter interface {
	Allow(key string, maxAttempts int, window time.Duration) bool
	IsBlocked(key string, maxAttempts int, window time.Duration) (bool, time.Duration)
	Reset(key string)
}

type DBRateLimiter struct {
	db *database.DB
}

func NewDBRateLimiter(db *database.DB) *DBRateLimiter {
	return &DBRateLimiter{db: db}
}

func (rl *DBRateLimiter) Allow(key string, maxAttempts int, window time.Duration) bool {
	allowed, _, err := rl.db.CheckRateLimit(key, maxAttempts, window.Seconds())
	if err != nil {
		return true
	}
	return allowed
}

func (rl *DBRateLimiter) IsBlocked(key string, maxAttempts int, window time.Duration) (bool, time.Duration) {
	allowed, remaining, err := rl.db.CheckRateLimit(key, maxAttempts, window.Seconds())
	if err != nil {
		return false, 0
	}
	return !allowed, time.Duration(remaining) * time.Second
}

func (rl *DBRateLimiter) Reset(key string) {
	_ = rl.db.ResetRateLimit(key)
}

func RateLimit(limiter Limiter, key string, maxAttempts int, window time.Duration, trustedProxies []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r, trustedProxies)
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
