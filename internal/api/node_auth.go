// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const (
	contextKeyNodeID    contextKey = "node_id"
	contextKeyTokenType contextKey = "token_type"
)

func NodeAuthMiddleware(log *logging.Logger, db *database.DB, pepper string, expectedTokenType string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("X-Admiral-Token")
		if reqToken == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				reqToken = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}
		if reqToken == "" {
			logAuthFailure(log, "WARN", "node_token", "missing_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}

		identifier := nodeTokenIdentifier(reqToken, pepper)
		node, nodeToken, err := db.GetNodeTokenByIdentifier(identifier)
		if err != nil {
			logAuthFailure(log, "ERROR", "node_token", "auth_db_error", http.StatusUnauthorized, r, err)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}
		if node == nil || nodeToken == nil {
			logAuthFailure(log, "WARN", "node_token", "invalid_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}
		if nodeToken.TokenStatus != "active" && nodeToken.TokenStatus != "consumed" {
			logAuthFailure(log, "WARN", "node_token", "inactive_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}
		if expectedTokenType != "" && nodeToken.TokenType != expectedTokenType {
			logAuthFailure(log, "WARN", "node_token", "token_type_mismatch", http.StatusForbidden, r, nil)
			writeGenericAuthError(w, http.StatusForbidden)
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(nodeToken.TokenHash), []byte(reqToken)); err != nil {
			logAuthFailure(log, "WARN", "node_token", "invalid_token", http.StatusUnauthorized, r, err)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}

		// Fleet se comunica con admirald únicamente a través de la VPN WireGuard.
		// Verificamos que la IP origen coincida con la WireGuard IP registrada del nodo.
		// Peticiones desde 127.0.0.1/::1 (mismo host) se confían siempre.
		if node.WireguardIP != "" {
			clientIPAddr := clientIP(r.RemoteAddr)
			if clientIPAddr != node.WireguardIP && clientIPAddr != "127.0.0.1" && clientIPAddr != "::1" {
				logAuthFailure(log, "WARN", "node_token", "wireguard_ip_mismatch", http.StatusForbidden, r, nil)
				writeGenericAuthError(w, http.StatusForbidden)
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
