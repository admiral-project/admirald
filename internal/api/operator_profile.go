// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func (h *APIHandlers) HandleOperatorProfile(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Admiral-Admin-User")
	if username == "" {
		writeGenericAuthError(w, http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		p, err := h.db.GetOperatorProfile(username)
		if err != nil {
			writeError(w, 500, "Database error")
			return
		}
		writeJSON(w, 200, profileResponse(p))
	case http.MethodPut:
		var req struct {
			Email           string `json:"email"`
			EmailVerified   bool   `json:"email_verified"`
			MFAEmailEnabled bool   `json:"mfa_email_enabled"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			writeError(w, 400, "Invalid JSON payload")
			return
		}
		email := strings.TrimSpace(strings.ToLower(req.Email))
		if req.MFAEmailEnabled && (!req.EmailVerified || email == "") {
			writeError(w, 400, "a verified email is required to enable MFA")
			return
		}
		if err := h.db.UpdateOperatorProfile(username, email, req.EmailVerified, req.MFAEmailEnabled); err != nil {
			writeError(w, 500, "Database error")
			return
		}
		p, _ := h.db.GetOperatorProfile(username)
		h.auditEvent("operator_profile_updated", map[string]interface{}{"operator": username, "mfa_email_enabled": p.MFAEmailEnabled})
		writeJSON(w, 200, profileResponse(p))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func profileResponse(p database.OperatorProfile) admiral.OperatorProfileResponse {
	out := admiral.OperatorProfileResponse{Username: p.Username, Email: p.Email, MFAEmailEnabled: p.MFAEmailEnabled}
	if p.EmailVerifiedAt != nil {
		out.EmailVerifiedAt = p.EmailVerifiedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func (h *APIHandlers) HandleOperatorTokens(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("X-Admiral-Admin-User")
	if username == "" {
		writeGenericAuthError(w, 401)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/tokens/")
	switch r.Method {
	case http.MethodGet:
		items, err := h.db.ListOperatorTokens(username)
		if err != nil {
			writeError(w, 500, "Database error")
			return
		}
		out := make([]admiral.OperatorTokenResponse, 0, len(items))
		for _, item := range items {
			out = append(out, tokenResponse(item, false, ""))
		}
		writeJSON(w, 200, out)
	case http.MethodPost:
		if id != "" {
			writeError(w, 404, "Token route not found")
			return
		}
		var req admiral.OperatorTokenRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			writeError(w, 400, "Invalid JSON payload")
			return
		}
		req.Label = strings.TrimSpace(req.Label)
		if req.Label == "" || len(req.Label) > 100 {
			writeError(w, 400, "token label is required and must be at most 100 characters")
			return
		}
		if req.Scope != "read" && req.Scope != "write" && req.Scope != "admin" {
			writeError(w, 400, "token scope must be read, write, or admin")
			return
		}
		var expires *time.Time
		if req.ExpiresAt != "" {
			parsed, err := time.Parse(time.RFC3339, req.ExpiresAt)
			if err != nil || !parsed.After(time.Now()) {
				writeError(w, 400, "expires_at must be a future RFC3339 timestamp")
				return
			}
			expires = &parsed
		}
		secret, err := newOperatorToken()
		if err != nil {
			writeError(w, 500, "Failed to create token")
			return
		}
		record := database.OperatorToken{ID: generateID("opt"), Username: username, Label: req.Label, TokenPrefix: secret[:15], TokenHash: h.hashToken(secret), Scope: req.Scope, ExpiresAt: expires, CreatedAt: time.Now()}
		if err = h.db.CreateOperatorToken(record); err != nil {
			writeError(w, 500, "Failed to create token")
			return
		}
		h.auditEvent("operator_token_created", map[string]interface{}{"operator": username, "token_id": record.ID, "scope": record.Scope})
		writeJSON(w, 201, tokenResponse(record, true, secret))
	case http.MethodDelete:
		if id == "" || strings.Contains(id, "/") {
			writeError(w, 404, "Token route not found")
			return
		}
		ok, err := h.db.RevokeOperatorToken(id, username)
		if err != nil {
			writeError(w, 500, "Database error")
			return
		}
		if !ok {
			writeError(w, 404, "Token not found")
			return
		}
		h.auditEvent("operator_token_revoked", map[string]interface{}{"operator": username, "token_id": id})
		writeJSON(w, 200, map[string]bool{"success": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
func tokenResponse(t database.OperatorToken, reveal bool, secret string) admiral.OperatorTokenResponse {
	r := admiral.OperatorTokenResponse{ID: t.ID, Label: t.Label, Prefix: t.TokenPrefix, Scope: t.Scope, CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339)}
	if reveal {
		r.Token = secret
	}
	if t.ExpiresAt != nil {
		r.ExpiresAt = t.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if t.RevokedAt != nil {
		r.RevokedAt = t.RevokedAt.UTC().Format(time.RFC3339)
	}
	if t.LastUsedAt != nil {
		r.LastUsedAt = t.LastUsedAt.UTC().Format(time.RFC3339)
	}
	return r
}
