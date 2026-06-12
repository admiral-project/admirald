// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
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
			w.Write([]byte(`{"error":"unauthorized: invalid token"}`))
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

func bodyLimitError(w http.ResponseWriter, err error) {
	if err != nil {
		if strings.Contains(err.Error(), "http: request body too large") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			fmt.Fprintf(w, `{"error":"request body too large"}`)
			return
		}
	}
}
