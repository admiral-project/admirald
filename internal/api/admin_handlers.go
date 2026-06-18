// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/security"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

type pagedResponse struct {
	Items    interface{} `json:"items"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
	Total    int         `json:"total"`
}

func parsePagination(r *http.Request) (int, int) {
	page := 1
	pageSize := defaultPageSize

	if raw := r.URL.Query().Get("page"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if raw := r.URL.Query().Get("page_size"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			pageSize = parsed
		}
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}

func clientIP(remoteAddr string) string {
	ip := remoteAddr
	if idx := strings.LastIndex(ip, ":"); idx >= 0 {
		ip = ip[:idx]
	}
	return ip
}

func (s *Server) AdminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admiral-Admin-Token")
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if token == "" {
			writeError(w, http.StatusUnauthorized, "Admin token required")
			return
		}

		tokenHash := s.handlers.hashToken(token)
		username, expiresAt, lastActivity, err := s.handlers.db.GetAdminSession(tokenHash)
		if err != nil {
			s.log.Error("Database error during admin auth check", err, nil)
			writeError(w, http.StatusInternalServerError, "Auth database error")
			return
		}

		if username == "" {
			writeError(w, http.StatusUnauthorized, "Invalid administrative session")
			return
		}

		now := time.Now()
		// Check global expiration
		if now.After(expiresAt) {
			_ = s.handlers.db.DeleteAdminSession(tokenHash)
			writeError(w, http.StatusUnauthorized, "Administrative session expired")
			return
		}

		// Check inactivity (max 30 minutes)
		if now.Sub(lastActivity) > 30*time.Minute {
			_ = s.handlers.db.DeleteAdminSession(tokenHash)
			writeError(w, http.StatusUnauthorized, "Administrative session expired due to inactivity")
			return
		}

		// Update activity
		_ = s.handlers.db.UpdateAdminSessionActivity(tokenHash, now)

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

	ip := clientIP(r.RemoteAddr)
	if !h.loginLimiter.Allow("login:"+ip, 5, 1*time.Minute) {
		h.log.Warn("Login rate limit exceeded", map[string]interface{}{"ip": ip})
		writeError(w, http.StatusTooManyRequests, "Too many login attempts. Try again later.")
		return
	}

	storedHash, mustChange, err := h.db.GetAdminUser(req.Username)
	if err != nil {
		h.log.Error("Failed to fetch admin user", err, map[string]interface{}{"username": req.Username})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if storedHash == "" {
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	ok, err := security.VerifyPassword(req.Password, storedHash)
	if err != nil {
		h.log.Error("Failed to verify admin password hash", err, map[string]interface{}{"username": req.Username})
		writeError(w, http.StatusInternalServerError, "Authentication configuration error")
		return
	}
	if !ok {
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

	if token != "" {
		tokenHash := h.hashToken(token)
		_ = h.db.DeleteAdminSession(tokenHash)
	}

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
		writeError(w, http.StatusUnauthorized, "Missing administrative identity")
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
		writeError(w, http.StatusUnauthorized, "admin identity is required")
		return
	}

	if !h.loginLimiter.Allow("change-password:"+username+":"+clientIP(r.RemoteAddr), 5, 1*time.Minute) {
		h.log.Warn("Change-password rate limit exceeded", map[string]interface{}{"username": username, "ip": clientIP(r.RemoteAddr)})
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
func (h *APIHandlers) HandleAdminInstances(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var instanceID string
	if len(parts) >= 4 {
		instanceID = parts[3]
	}

	switch r.Method {
	case http.MethodGet:
		if instanceID != "" && len(parts) >= 5 && parts[4] == "inspect" {
			inst, _ := h.db.GetCustomerApp(instanceID)
			if inst == nil {
				writeError(w, http.StatusNotFound, "Instance not found")
				return
			}
			if inst.InspectData == "" {
				writeError(w, http.StatusNotFound, "No inspect data available for this instance")
				return
			}
			var inspectResult interface{}
			if err := json.Unmarshal([]byte(inst.InspectData), &inspectResult); err != nil {
				writeError(w, http.StatusInternalServerError, "Failed to parse stored inspect data")
				return
			}
			writeJSON(w, http.StatusOK, inspectResult)
			return
		}
		if instanceID != "" {
			inst, _ := h.db.GetCustomerApp(instanceID)
			if inst == nil {
				writeError(w, http.StatusNotFound, "Instance not found")
				return
			}
			writeJSON(w, http.StatusOK, inst)
			return
		}

		page, pageSize := parsePagination(r)
		apps, total, err := h.db.GetCustomerAppsPage(pageSize, (page-1)*pageSize, "")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, pagedResponse{
			Items:    apps,
			Page:     page,
			PageSize: pageSize,
			Total:    total,
		})

	case http.MethodPost:
		if instanceID != "" && len(parts) >= 5 {
			action := parts[4]
			// Delegate all backup sub-paths to HandleAdminBackups
			if action == "backups" {
				h.HandleAdminBackups(w, r)
				return
			}
			if action == "inspect" {
				inst, _ := h.db.GetCustomerApp(instanceID)
				if inst == nil {
					writeError(w, http.StatusNotFound, "Instance not found")
					return
				}
				if inst.NodeID == nil || *inst.NodeID == "" {
					writeError(w, http.StatusServiceUnavailable, "App not scheduled")
					return
				}
				// Create operational inspect app task
				opID := generateID("op")
				_ = h.db.CreateOperation(opID, instanceID, *inst.NodeID, "inspect_app", "pending_dispatch", operatorFromRequest(r))
				appDef, _ := h.db.GetAppDefinition(inst.AppDefinitionName)
				tiers, _ := h.db.GetAppTiers(inst.AppDefinitionName)
				var matchedTier database.AppTier
				for _, t := range tiers {
					if t.Name == inst.TierName {
						matchedTier = t
						break
					}
				}
				h.dispatchTask(opID, instanceID, *inst.NodeID, inst.CustomerID, appDef.RawYAML, matchedTier, admiral.TaskAction("inspect_app"))

				writeJSON(w, http.StatusAccepted, admiral.OperationResponse{
					OperationID: opID,
					Status:      "queued",
				})
				return
			}

			if action == "migrate" {
				h.HandleMigrateInstance(w, r)
				return
			}

			// Reuse HandleCustomerAppAction, passing tier query param if present
			tierParam := r.URL.Query().Get("tier")
			bodyMap := map[string]string{"instance_id": instanceID, "action": action}
			if tierParam != "" {
				bodyMap["tier"] = tierParam
			}
			jsonBody, _ := json.Marshal(bodyMap)
			r.Body = io.NopCloser(bytes.NewReader(jsonBody))
			h.HandleCustomerAppAction(w, r)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// GET & POST & DELETE /api/admin/backups
func (h *APIHandlers) HandleAdminBackups(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var backupID string
	if len(parts) >= 4 {
		backupID = parts[3]
	}

	// Nested instances route: /api/admin/instances/{instance_id}/backups/database or volumes
	if len(parts) >= 6 && parts[1] == "admin" && parts[2] == "instances" {
		instanceID := parts[3]
		backupType := parts[5] // database or volumes
		h.HandleTriggerBackup(w, r, instanceID, backupType)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if backupID != "" {
			rec, _ := h.db.GetBackupRecord(backupID)
			if rec == nil {
				writeError(w, http.StatusNotFound, "Backup record not found")
				return
			}
			writeJSON(w, http.StatusOK, rec)
			return
		}

		instanceID := r.URL.Query().Get("instance_id")
		page, pageSize := parsePagination(r)
		recs, total, err := h.db.GetBackupRecordsPage(instanceID, pageSize, (page-1)*pageSize)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, pagedResponse{
			Items:    recs,
			Page:     page,
			PageSize: pageSize,
			Total:    total,
		})

	case http.MethodPost:
		if backupID == "prune" {
			h.HandleAdminPrune(w, r)
			return
		}
		w.WriteHeader(http.StatusBadRequest)

	case http.MethodDelete:
		if backupID != "" {
			rec, _ := h.db.GetBackupRecord(backupID)
			if rec == nil {
				writeError(w, http.StatusNotFound, "Backup record not found")
				return
			}
			// Create operational delete_backup task
			opID := generateID("op")
			_ = h.db.CreateOperation(opID, rec.InstanceID, rec.NodeID, "delete_backup", "pending_dispatch", operatorFromRequest(r))

			// Mark backup record as deleted
			rec.Status = "deleted"
			_ = h.db.UpdateBackupRecord(rec)

			task := &admiral.FleetTask{
				TaskID:      generateID("task"),
				OperationID: opID,
				NodeID:      rec.NodeID,
				Action:      admiral.TaskAction("delete_backup"),
				InstanceID:  rec.InstanceID,
				Storage: &admiral.StorageConfig{
					Backend:  rec.StorageBackend,
					Key:      rec.StorageKey,
					BackupID: rec.ID,
				},
			}
			storageCfg, _ := h.db.GetActiveBackupStorageConfig()
			if storageCfg != nil {
				task.Storage.Endpoint = storageCfg.Endpoint
				task.Storage.Region = storageCfg.Region
				task.Storage.Bucket = storageCfg.Bucket
				task.Storage.Prefix = storageCfg.Prefix
				task.Storage.ForcePathStyle = storageCfg.ForcePathStyle
				task.Storage.AccessKeyEnv = storageCfg.AccessKeyEnv
				task.Storage.SecretKeyEnv = storageCfg.SecretKeyEnv
				task.Storage.SessionTokenEnv = storageCfg.SessionTokenEnv
			}
			h.enqueueRawTask(task)

			writeJSON(w, http.StatusAccepted, admiral.OperationResponse{
				OperationID: opID,
				Status:      "queued",
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// POST /api/admin/instances/{instance_id}/backups/database or volumes
func (h *APIHandlers) HandleTriggerBackup(w http.ResponseWriter, r *http.Request, instanceID, backupType string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	inst, _ := h.db.GetCustomerApp(instanceID)
	if inst == nil {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	if inst.NodeID == nil || *inst.NodeID == "" {
		writeError(w, http.StatusServiceUnavailable, "Node offline")
		return
	}

	appDef, err := h.db.GetAppDefinition(inst.AppDefinitionName)
	if err != nil || appDef == nil {
		h.log.Error("Failed to get app definition for backup target", err, map[string]interface{}{"instance_id": instanceID})
		writeError(w, http.StatusInternalServerError, "Failed to get app definition")
		return
	}
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(appDef.RawYAML), &payload); err != nil { //nolint:gosec // appDef.RawYAML from trusted DB data
		h.log.Error("Failed to parse app definition YAML", err, map[string]interface{}{"app_name": inst.AppDefinitionName})
		writeError(w, http.StatusInternalServerError, "Failed to parse app definition")
		return
	}

	var action admiral.TaskAction
	var contractType string
	if backupType == "database" {
		action = admiral.ActionBackupDatabase
		contractType = "database"
	} else if backupType == "volumes" {
		action = admiral.TaskAction("backup_volumes")
		contractType = "volume"
	} else {
		writeError(w, http.StatusBadRequest, "Invalid backup type")
		return
	}
	targets := backupTargetsByType(payload, contractType)
	if len(targets) == 0 {
		writeError(w, http.StatusConflict, fmt.Sprintf("No services declare backup type %s", contractType))
		return
	}
	if len(targets) > 1 {
		writeError(w, http.StatusConflict, fmt.Sprintf("Multiple services declare backup type %s; use a service-specific backup action", contractType))
		return
	}
	target := targets[0]

	opID := generateID("op")
	_ = h.db.UpdateCustomerAppStatus(instanceID, "", "backup_running")
	_ = h.db.CreateOperation(opID, instanceID, *inst.NodeID, string(action), "pending_dispatch", operatorFromRequest(r))

	// Get active storage config
	storageCfg, _ := h.db.GetActiveBackupStorageConfig()
	var backend, key string
	if storageCfg != nil {
		backend = storageCfg.Backend
		key = fmt.Sprintf("%s/%s/%s/%s-%s-%s", storageCfg.Prefix, *inst.NodeID, instanceID, target.ServiceName, backupType, opID)
	} else {
		backend = "local"
		key = fmt.Sprintf("/var/lib/admiral/backups/%s/%s-%s", instanceID, target.ServiceName, opID)
	}

	// Register BackupRecord in PENDING state before dispatching
	bkRec := &admiral.BackupRecord{
		ID:                          generateID("bk"),
		InstanceID:                  instanceID,
		AppID:                       inst.AppDefinitionName,
		TierID:                      inst.TierName,
		NodeID:                      *inst.NodeID,
		BackupType:                  contractType,
		DatabaseType:                "none",
		Status:                      "pending",
		StorageBackend:              backend,
		StorageKey:                  key,
		TriggeredBy:                 "manual",
		TierSnapshotJSON:            inst.TierSnapshotJSON,
		RetentionPolicySnapshotJSON: `{"count":7,"days":30}`,
	}
	if action == admiral.ActionBackupDatabase {
		bkRec.DatabaseType = target.Backup.Engine
	}
	_ = h.db.CreateBackupRecord(bkRec)

	tiers, _ := h.db.GetAppTiers(inst.AppDefinitionName)
	var matchedTier database.AppTier
	for _, t := range tiers {
		if t.Name == inst.TierName {
			matchedTier = t
			break
		}
	}

	// Build and enqueue task synchronously so it's persisted before response
	allSecretValues, _ := h.decryptedSecretMap(instanceID)
	secretValues := scopeTaskSecrets(action, payload, allSecretValues, target.ServiceName)

	services := buildServiceInfos(payload, matchedTier, instanceID, inst.CustomerID, secretValues)

	task := &admiral.FleetTask{
		TaskID:      generateID("task"),
		OperationID: opID,
		NodeID:      *inst.NodeID,
		Action:      action,
		InstanceID:  instanceID,
		App: admiral.AppInfo{
			Name:    payload.Name,
			Version: "latest",
		},
		Tier: admiral.TierInfo{
			Name:        matchedTier.Name,
			CPU:         matchedTier.CPU,
			Memory:      matchedTier.Memory,
			Storage:     matchedTier.Storage,
			Environment: matchedTier.Environment,
		},
		Services: services,
	}
	task.Backup = buildTaskBackupInfo(target)

	task.Storage = &admiral.StorageConfig{
		Backend: backend,
		Key:     key,
	}
	if storageCfg != nil {
		task.Storage.Endpoint = storageCfg.Endpoint
		task.Storage.Region = storageCfg.Region
		task.Storage.Bucket = storageCfg.Bucket
		task.Storage.Prefix = storageCfg.Prefix
		task.Storage.ForcePathStyle = storageCfg.ForcePathStyle
		task.Storage.AccessKeyEnv = storageCfg.AccessKeyEnv
		task.Storage.SecretKeyEnv = storageCfg.SecretKeyEnv
		task.Storage.SessionTokenEnv = storageCfg.SessionTokenEnv
	}
	task.Storage.BackupID = bkRec.ID

	h.enqueueRawTask(task)

	writeJSON(w, http.StatusAccepted, admiral.OperationResponse{
		OperationID: opID,
		Status:      "queued",
	})
}

// POST /api/admin/backups/prune
// GET & PUT & POST /api/admin/settings/backup-storage
// POST /api/admin/backups/restore
