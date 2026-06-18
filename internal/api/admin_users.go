package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/security"
)

func (h *APIHandlers) HandleAdminUsers(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(strings.Trim(r.URL.Path, "/"), "api/admin/users")
	path = strings.TrimPrefix(path, "/")
	var parts []string
	if path != "" {
		parts = strings.Split(path, "/")
	}

	switch r.Method {
	case http.MethodGet:
		if len(parts) != 0 {
			writeError(w, http.StatusNotFound, "User route not found")
			return
		}
		users, err := h.db.ListAdminUsers()
		if err != nil {
			h.log.Error("Failed to list admin users", err, nil)
			writeError(w, http.StatusInternalServerError, "Database error")
			return
		}
		items := make([]map[string]interface{}, 0, len(users))
		for _, user := range users {
			items = append(items, map[string]interface{}{
				"username":             user.Username,
				"role":                 "admin",
				"must_change_password": user.MustChangePassword,
				"created_at":           user.CreatedAt.Format(time.RFC3339),
			})
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost:
		if len(parts) == 0 {
			var req struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "Invalid JSON payload")
				return
			}
			if strings.TrimSpace(req.Username) == "" || req.Password == "" {
				writeError(w, http.StatusBadRequest, "username and password are required")
				return
			}
			if err := security.ValidateInitialAdminPassword(req.Username, req.Password); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			passwordHash, err := security.HashPassword(req.Password)
			if err != nil {
				h.log.Error("Failed to hash password for admin user creation", err, map[string]interface{}{"username": req.Username})
				writeError(w, http.StatusInternalServerError, "Failed to process password")
				return
			}
			if err := h.db.CreateAdminUser(req.Username, passwordHash, false); err != nil {
				h.log.Error("Failed to create admin user", err, map[string]interface{}{"username": req.Username})
				writeError(w, http.StatusInternalServerError, "Failed to create user")
				return
			}
			writeJSON(w, http.StatusCreated, map[string]interface{}{
				"username": req.Username,
				"role":     "admin",
			})
			return
		}
		if len(parts) == 2 && parts[1] == "set-password" {
			username := strings.TrimSpace(parts[0])
			if username == "" {
				writeError(w, http.StatusBadRequest, "username is required")
				return
			}
			var req struct {
				NewPassword string `json:"new_password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "Invalid JSON payload")
				return
			}
			if req.NewPassword == "" {
				writeError(w, http.StatusBadRequest, "new_password is required")
				return
			}
			if err := security.ValidateInitialAdminPassword(username, req.NewPassword); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			passwordHash, err := security.HashPassword(req.NewPassword)
			if err != nil {
				h.log.Error("Failed to hash password for admin user update", err, map[string]interface{}{"username": username})
				writeError(w, http.StatusInternalServerError, "Failed to process password")
				return
			}
			if err := h.db.UpdateAdminPassword(username, passwordHash); err != nil {
				h.log.Error("Failed to update admin user password", err, map[string]interface{}{"username": username})
				writeError(w, http.StatusInternalServerError, "Failed to update password")
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
			return
		}
		writeError(w, http.StatusNotFound, "User route not found")
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
