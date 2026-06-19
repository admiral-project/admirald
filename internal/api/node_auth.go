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
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const (
	contextKeyNodeID    contextKey = "node_id"
	contextKeyTokenType contextKey = "token_type"
)

func NodeAuthMiddleware(db *database.DB, pepper string, expectedTokenType string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("X-Admiral-Token")
		if reqToken == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				reqToken = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}
		if reqToken == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized: missing token"}`))
			return
		}

		identifier := nodeTokenIdentifier(reqToken, pepper)
		node, nodeToken, err := db.GetNodeTokenByIdentifier(identifier)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Authentication error")
			return
		}
		if node == nil || nodeToken == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized: invalid token"}`))
			return
		}
		if nodeToken.TokenStatus != "active" && nodeToken.TokenStatus != "consumed" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized: token not active"}`))
			return
		}
		if expectedTokenType != "" && nodeToken.TokenType != expectedTokenType {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden: token type mismatch"}`))
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(nodeToken.TokenHash), []byte(reqToken)); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized: invalid token"}`))
			return
		}

		// Fleet se comunica con admirald únicamente a través de la VPN WireGuard.
		// Verificamos que la IP origen coincida con la WireGuard IP registrada del nodo.
		// Peticiones desde 127.0.0.1/::1 (mismo host) se confían siempre.
		if node.WireguardIP != "" {
			clientIPAddr := clientIP(r.RemoteAddr)
			if clientIPAddr != node.WireguardIP && clientIPAddr != "127.0.0.1" && clientIPAddr != "::1" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden: request IP does not match registered node WireGuard IP"}`))
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
