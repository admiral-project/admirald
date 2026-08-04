// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const (
	contextKeyNodeID    contextKey = "node_id"
	contextKeyTokenType contextKey = "token_type"
)

func NodeAuthMiddleware(log *logging.Logger, db *database.DB, pepper string, expectedTokenType string, trustedProxies []string, next http.HandlerFunc, callbackKeys ...string) http.HandlerFunc {
	limiter := NewRateLimiter()
	return func(w http.ResponseWriter, r *http.Request) {
		key := "node_token:" + getClientIP(r, trustedProxies)
		if blocked, retryAfter := limiter.IsBlocked(key, authFailureLimit, authFailureWindow); blocked {
			seconds := int(retryAfter / time.Second)
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			logAuthFailure(log, "WARN", "node_token", "ip_temporarily_blocked", http.StatusTooManyRequests, r, nil)
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
			logAuthFailure(log, "WARN", "node_token", "missing_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}

		identifier := nodeTokenIdentifier(reqToken, pepper)
		node, nodeToken, err := db.GetNodeTokenByIdentifier(identifier)
		if err != nil {
			limiter.Allow(key, authFailureLimit, authFailureWindow)
			logAuthFailure(log, "ERROR", "node_token", "auth_db_error", http.StatusUnauthorized, r, err)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}
		if node == nil || nodeToken == nil {
			limiter.Allow(key, authFailureLimit, authFailureWindow)
			logAuthFailure(log, "WARN", "node_token", "invalid_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}
		if node.ManualDisabled {
			limiter.Allow(key, authFailureLimit, authFailureWindow)
			logAuthFailure(log, "WARN", "node_token", "node_manual_disabled", http.StatusForbidden, r, nil)
			writeGenericAuthError(w, http.StatusForbidden)
			return
		}
		if nodeToken.TokenStatus != "active" && nodeToken.TokenStatus != "consumed" {
			limiter.Allow(key, authFailureLimit, authFailureWindow)
			logAuthFailure(log, "WARN", "node_token", "inactive_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}
		if nodeToken.TokenExpiresAt != nil && !nodeToken.TokenExpiresAt.After(time.Now()) {
			limiter.Allow(key, authFailureLimit, authFailureWindow)
			logAuthFailure(log, "WARN", "node_token", "expired_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}
		if expectedTokenType != "" && nodeToken.TokenType != expectedTokenType {
			limiter.Allow(key, authFailureLimit, authFailureWindow)
			logAuthFailure(log, "WARN", "node_token", "token_type_mismatch", http.StatusForbidden, r, nil)
			writeGenericAuthError(w, http.StatusForbidden)
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(nodeToken.TokenHash), []byte(reqToken)); err != nil {
			limiter.Allow(key, authFailureLimit, authFailureWindow)
			logAuthFailure(log, "WARN", "node_token", "invalid_token", http.StatusUnauthorized, r, err)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}

		// Fleet se comunica con admirald a través de la VPN WireGuard.
		// Verificamos que la IP origen coincida con la WireGuard IP registrada del nodo.
		// ADMIRAL_DEV_MODE=true    -> permite localhost (--dev-node, desarrollo).
		// ADMIRAL_SINGLE_NODE=true -> permite localhost (--single-node, diseño intencional:
		//   no es un fallo de seguridad; en single-node fleet y admirald corren en el
		//   mismo host y se comunican por loopback; no hay VPN de por medio).
		devBypass := os.Getenv("ADMIRAL_DEV_MODE") == "true" || os.Getenv("ADMIRAL_SINGLE_NODE") == "true"
		if !devBypass && node.WireguardIP == "" {
			limiter.Allow(key, authFailureLimit, authFailureWindow)
			logAuthFailure(log, "WARN", "node_token", "wireguard_ip_missing", http.StatusForbidden, r, nil)
			writeGenericAuthError(w, http.StatusForbidden)
			return
		}
		if !devBypass {
			clientIPAddr := getClientIP(r, trustedProxies)
			if clientIPAddr != node.WireguardIP {
				limiter.Allow(key, authFailureLimit, authFailureWindow)
				logAuthFailure(log, "WARN", "node_token", "wireguard_ip_mismatch", http.StatusForbidden, r, nil)
				writeGenericAuthError(w, http.StatusForbidden)
				return
			}
		}
		if node.WireguardIP != "" {
			clientIPAddr := getClientIP(r, trustedProxies)
			if clientIPAddr == "127.0.0.1" || clientIPAddr == "::1" {
				log.Warn("admiral-fleet connected from localhost (wireguard IP check bypassed)",
					map[string]interface{}{
						"node_id":   node.ID,
						"client_ip": clientIPAddr,
						"reason":    "ADMIRAL_DEV_MODE or ADMIRAL_SINGLE_NODE",
						"wg_ip":     node.WireguardIP,
					})
			}
		}
		limiter.Reset(key)
		if r.URL.Path == "/api/v1/fleet/callback" {
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				writeGenericAuthError(w, http.StatusUnauthorized)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			callbackKey := reqToken
			if len(callbackKeys) > 0 && strings.TrimSpace(callbackKeys[0]) != "" {
				callbackKey = callbackKeys[0]
			}
			signingInput := body
			timestamp := r.Header.Get("X-Admiral-Task-Timestamp")
			if len(callbackKeys) > 0 && strings.TrimSpace(callbackKeys[0]) != "" {
				signedAt, err := strconv.ParseInt(timestamp, 10, 64)
				if err != nil || signedAt <= 0 {
					logAuthFailure(log, "WARN", "node_callback", "invalid_signature_timestamp", http.StatusUnauthorized, r, nil)
					writeGenericAuthError(w, http.StatusUnauthorized)
					return
				}
				const callbackSignatureWindow = 15 * time.Minute
				if delta := time.Since(time.Unix(signedAt, 0)); delta > callbackSignatureWindow || delta < -callbackSignatureWindow {
					logAuthFailure(log, "WARN", "node_callback", "stale_signature_timestamp", http.StatusUnauthorized, r, nil)
					writeGenericAuthError(w, http.StatusUnauthorized)
					return
				}
				signingInput = append([]byte(timestamp+"."), body...)
			}
			provided, decodeErr := hex.DecodeString(r.Header.Get("X-Admiral-Task-Signature"))
			mac := hmac.New(sha256.New, []byte(callbackKey))
			_, _ = mac.Write(signingInput)
			if decodeErr != nil || !hmac.Equal(provided, mac.Sum(nil)) {
				logAuthFailure(log, "WARN", "node_callback", "invalid_signature", http.StatusUnauthorized, r, nil)
				writeGenericAuthError(w, http.StatusUnauthorized)
				return
			}
		}

		ctx := context.WithValue(r.Context(), contextKeyNodeID, node.ID)
		ctx = context.WithValue(ctx, contextKeyTokenType, nodeToken.TokenType)
		next(w, r.WithContext(ctx))
	}
}

func NodeIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(contextKeyNodeID).(string)
	return id, ok
}

func TokenTypeFromContext(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(contextKeyTokenType).(string)
	return t, ok
}

func nodeTokenIdentifier(rawToken, pepper string) string {
	h := sha256.Sum256([]byte(rawToken + pepper))
	return hex.EncodeToString(h[:])
}
