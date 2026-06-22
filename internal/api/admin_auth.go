// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/security"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func (h *APIHandlers) hashToken(input string) string {
	mac := hmac.New(sha256.New, []byte(h.hmacKey))
	mac.Write([]byte(input))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) AdminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.blockAuthAttempt(w, r, "admin_session") {
			return
		}

		token := r.Header.Get("X-Admiral-Admin-Token")
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if token == "" {
			s.recordAuthFailure(r, "admin_session")
			logAuthFailure(s.log, "WARN", "admin_session", "missing_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}

		tokenHash := s.handlers.hashToken(token)
		username, expiresAt, lastActivity, err := s.handlers.db.GetAdminSession(tokenHash)
		if err != nil {
			s.recordAuthFailure(r, "admin_session")
			logAuthFailure(s.log, "ERROR", "admin_session", "auth_db_error", http.StatusUnauthorized, r, err)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}

		if username == "" {
			s.recordAuthFailure(r, "admin_session")
			logAuthFailure(s.log, "WARN", "admin_session", "invalid_token", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}

		now := time.Now()
		// Check global expiration
		if now.After(expiresAt) {
			_ = s.handlers.db.DeleteAdminSession(tokenHash)
			s.recordAuthFailure(r, "admin_session")
			logAuthFailure(s.log, "WARN", "admin_session", "session_expired", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}

		// Check inactivity (max 30 minutes)
		if now.Sub(lastActivity) > 30*time.Minute {
			_ = s.handlers.db.DeleteAdminSession(tokenHash)
			s.recordAuthFailure(r, "admin_session")
			logAuthFailure(s.log, "WARN", "admin_session", "session_expired", http.StatusUnauthorized, r, nil)
			writeGenericAuthError(w, http.StatusUnauthorized)
			return
		}

		// Update activity
		_ = s.handlers.db.UpdateAdminSessionActivity(tokenHash, now)
		s.resetAuthFailures(r, "admin_session")

		// Pass username in headers for downstream
		r.Header.Set("X-Admiral-Admin-User", username)
		next(w, r)
	}
}

// POST /api/admin/auth/login
func (h *APIHandlers) HandleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req admiral.AdminLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	ip := clientIP(r)
	if h.server != nil && h.server.blockAuthAttempt(w, r, "admin_login") {
		return
	}
	if !h.loginLimiter.Allow("login:"+ip, 5, 1*time.Minute) {
		h.log.Warn("Login rate limit exceeded", map[string]interface{}{"ip": ip})
		writeError(w, http.StatusTooManyRequests, "Too many login attempts. Try again later.")
		return
	}

	storedHash, mustChange, err := h.db.GetAdminUser(req.Username)
	if err != nil {
		if h.server != nil {
			h.server.recordAuthFailure(r, "admin_login")
		}
		h.log.Error("Failed to fetch admin user", err, map[string]interface{}{"username": req.Username})
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if storedHash == "" {
		if h.server != nil {
			h.server.recordAuthFailure(r, "admin_login")
		}
		h.log.Warn("authentication failed", map[string]interface{}{
			"auth_kind": "admin_login",
			"reason":    "invalid_credentials",
			"username":  req.Username,
			"status":    http.StatusUnauthorized,
			"path":      r.URL.Path,
			"method":    r.Method,
			"remote_ip": clientIP(r),
		})
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	ok, err := security.VerifyPassword(req.Password, storedHash)
	if err != nil {
		if h.server != nil {
			h.server.recordAuthFailure(r, "admin_login")
		}
		h.log.Error("Failed to verify admin password hash", err, map[string]interface{}{"username": req.Username})
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if !ok {
		if h.server != nil {
			h.server.recordAuthFailure(r, "admin_login")
		}
		h.log.Warn("authentication failed", map[string]interface{}{
			"auth_kind": "admin_login",
			"reason":    "invalid_credentials",
			"username":  req.Username,
			"status":    http.StatusUnauthorized,
			"path":      r.URL.Path,
			"method":    r.Method,
			"remote_ip": clientIP(r),
		})
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Generate session token (also when must_change_password is true, so
	// the first-login password change flow can authenticate via session)
	token := generateID("adm_tok")
	tokenHash := h.hashToken(token)
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour) // Max session duration

	if err := h.db.CreateAdminSession(tokenHash, req.Username, expiresAt, now); err != nil {
		h.log.Error("Failed to create admin session", err, map[string]interface{}{"username": req.Username})
		writeError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}
	if h.server != nil {
		h.server.resetAuthFailures(r, "admin_login")
	}

	writeJSON(w, http.StatusOK, admiral.AdminLoginResponse{
		Token:                  token,
		ExpiresAt:              expiresAt.Format(time.RFC3339),
		PasswordChangeRequired: mustChange,
	})
}

// POST /api/admin/auth/logout
func (h *APIHandlers) HandleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("X-Admiral-Admin-Token")
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}

	if token == "" {
		writeGenericAuthError(w, http.StatusUnauthorized)
		return
	}

	tokenHash := h.hashToken(token)
	_ = h.db.DeleteAdminSession(tokenHash)

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// GET /api/admin/auth/me
func (h *APIHandlers) HandleAdminMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	username := r.Header.Get("X-Admiral-Admin-User")
	if username == "" {
		writeGenericAuthError(w, http.StatusUnauthorized)
		return
	}
	createdAt, err := h.db.GetAdminUserCreatedAt(username)
	if err != nil {
		h.log.Error("Failed to fetch admin user metadata", err, map[string]interface{}{"username": username})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	writeJSON(w, http.StatusOK, admiral.AdminMeResponse{
		Username:  username,
		CreatedAt: createdAt.UTC().Format(time.RFC3339),
	})
}

// POST /api/admin/auth/change-password
func (h *APIHandlers) HandleAdminChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req admiral.AdminChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}

	if req.CurrentPassword == req.NewPassword {
		writeError(w, http.StatusBadRequest, "new password must be different from current password")
		return
	}

	username := r.Header.Get("X-Admiral-Admin-User")
	if username == "" {
		writeGenericAuthError(w, http.StatusUnauthorized)
		return
	}

	if !h.loginLimiter.Allow("change-password:"+username+":"+clientIP(r), 5, 1*time.Minute) {
		h.log.Warn("Change-password rate limit exceeded", map[string]interface{}{"username": username, "ip": clientIP(r)})
		writeError(w, http.StatusTooManyRequests, "Too many password change attempts. Try again later.")
		return
	}

	storedHash, _, err := h.db.GetAdminUser(username)
	if err != nil {
		h.log.Error("Failed to fetch admin user for password change", err, map[string]interface{}{"username": username})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if storedHash == "" {
		writeError(w, http.StatusUnauthorized, "Admin user not found")
		return
	}

	ok, err := security.VerifyPassword(req.CurrentPassword, storedHash)
	if err != nil {
		h.log.Error("Failed to verify current password", err, map[string]interface{}{"username": username})
		writeError(w, http.StatusInternalServerError, "Authentication configuration error")
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	if err := security.ValidateInitialAdminPassword(username, req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	newHash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		h.log.Error("Failed to hash new password", err, nil)
		writeError(w, http.StatusInternalServerError, "Failed to process new password")
		return
	}

	if err := h.db.UpdateAdminPassword(username, newHash); err != nil {
		h.log.Error("Failed to update admin password", err, map[string]interface{}{"username": username})
		writeError(w, http.StatusInternalServerError, "Failed to update password")
		return
	}

	h.log.Info("Admin password changed", map[string]interface{}{"username": username})
	writeJSON(w, http.StatusOK, admiral.AdminChangePasswordResponse{Success: true})
}

// GET /api/admin/instances & actions
