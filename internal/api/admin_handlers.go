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
func (h *APIHandlers) HandleAdminPrune(w http.ResponseWriter, r *http.Request) {
	recs, _ := h.db.GetBackupRecords("")
	// Group backups by instance and type
	grouped := make(map[string][]admiral.BackupRecord)
	for _, rec := range recs {
		if rec.Status == "succeeded" {
			k := fmt.Sprintf("%s-%s", rec.InstanceID, rec.BackupType)
			grouped[k] = append(grouped[k], rec)
		}
	}

	prunedCount := 0
	for _, backups := range grouped {
		if len(backups) <= 1 {
			continue
		}
		// Read retention policy from the first backup record's snapshot
		retCount := 7 // default fallback
		if len(backups) > 0 {
			var policy struct {
				Count int `json:"count"`
				Days  int `json:"days"`
			}
			if err := json.Unmarshal([]byte(backups[0].RetentionPolicySnapshotJSON), &policy); err == nil && policy.Count > 0 {
				retCount = policy.Count
			}
		}
		// Keep the first N succeeded backups (based on retention policy), prune others
		for i, rec := range backups {
			if i >= retCount {
				// Create prune task
				opID := generateID("op")
				_ = h.db.CreateOperation(opID, rec.InstanceID, rec.NodeID, "delete_backup", "pending_dispatch", operatorFromRequest(r))

				rec.Status = "deleted"
				_ = h.db.UpdateBackupRecord(&rec)

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
				prunedCount++
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "pruned_backups_count": prunedCount})
}

// GET & PUT & POST /api/admin/settings/backup-storage
func (h *APIHandlers) HandleAdminSettingsStorage(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	isTest := len(parts) >= 5 && parts[4] == "test"

	switch r.Method {
	case http.MethodGet:
		cfg, _ := h.db.GetBackupStorageConfig("global")
		if cfg == nil {
			cfg = &admiral.BackupStorageConfig{
				ID:      "global",
				Backend: "local",
				Enabled: true,
			}
		}
		// Mask secrets
		cfg.AccessKeyEnv = ""
		cfg.SecretKeyEnv = ""
		writeJSON(w, http.StatusOK, cfg)

	case http.MethodPut:
		var req admiral.BackupStorageConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}

		if req.Backend != "local" && req.Backend != "s3" {
			writeError(w, http.StatusBadRequest, "Invalid backend, must be local or s3")
			return
		}

		if req.Backend == "s3" && !strings.HasPrefix(req.Endpoint, "https://") {
			if !strings.HasPrefix(req.Endpoint, "http://localhost") && !strings.HasPrefix(req.Endpoint, "http://127.0.0.1") {
				writeError(w, http.StatusBadRequest, "S3 endpoint must use HTTPS for non-localhost endpoints")
				return
			}
		}

		req.ID = "global"
		err := h.db.SaveBackupStorageConfig(&req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	case http.MethodPost:
		if isTest {
			// Trigger backup storage connectivity check
			cfg, _ := h.db.GetBackupStorageConfig("global")
			if cfg == nil || !cfg.Enabled {
				writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "Local storage always active"})
				return
			}
			// Dispatch test task
			nodes, _ := h.db.GetNodes()
			var activeNode string
			for _, n := range nodes {
				if n.Status == "active" {
					activeNode = n.ID
					break
				}
			}
			if activeNode == "" && len(nodes) > 0 {
				activeNode = nodes[0].ID
			}

			opID := generateID("op")
			if err := h.db.CreateOperation(opID, "", activeNode, "test_backup_storage", "pending_dispatch", operatorFromRequest(r)); err != nil {
				h.log.Error("Failed to create operation for storage test", err, nil)
				writeError(w, http.StatusInternalServerError, "Failed to create operation")
				return
			}

			if activeNode != "" {
				task := &admiral.FleetTask{
					TaskID:      generateID("task"),
					OperationID: opID,
					NodeID:      activeNode,
					Action:      admiral.TaskAction("test_backup_storage"),
					InstanceID:  "",
					Storage: &admiral.StorageConfig{
						Backend:        cfg.Backend,
						Endpoint:       cfg.Endpoint,
						Region:         cfg.Region,
						Bucket:         cfg.Bucket,
						Prefix:         cfg.Prefix,
						ForcePathStyle: cfg.ForcePathStyle,
						AccessKeyEnv:   cfg.AccessKeyEnv,
						SecretKeyEnv:   cfg.SecretKeyEnv,
					},
				}
				h.enqueueRawTask(task)
			}

			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "operation_id": opID})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// POST /api/admin/backups/restore
func (h *APIHandlers) HandleAdminRestoreBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req admiral.RestoreBackupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	if req.BackupID == "" || req.TargetAppID == "" || req.Service == "" {
		writeError(w, http.StatusBadRequest, "backup_id, target_app_id, and service are required")
		return
	}

	bk, err := h.db.GetBackupRecord(req.BackupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error retrieving backup")
		return
	}
	if bk == nil {
		writeError(w, http.StatusNotFound, "Backup not found")
		return
	}
	inst, err := h.db.GetCustomerApp(req.TargetAppID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error retrieving instance")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Target instance not found")
		return
	}
	if err := admiral.ValidateRestoreSource(req.Source, bk); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if inst.TechnicalStatus != "paused" && inst.TechnicalStatus != "stopped" {
		writeError(w, http.StatusConflict, "Restore is only allowed when the app is paused")
		return
	}
	if req.TargetNodeID != "" {
		if inst.NodeID == nil || *inst.NodeID != req.TargetNodeID {
			writeError(w, http.StatusConflict, "Target node does not match the paused instance node")
			return
		}
	}

	appDef, err := h.db.GetAppDefinition(inst.AppDefinitionName)
	if err != nil || appDef == nil {
		writeError(w, http.StatusInternalServerError, "Failed retrieving app definition")
		return
	}
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(appDef.RawYAML), &payload); err != nil {
		writeError(w, http.StatusInternalServerError, "Stored application definition is invalid")
		return
	}
	tiers, err := h.db.GetAppTiers(inst.AppDefinitionName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error validating tiers")
		return
	}
	var matchedTier database.AppTier
	for _, t := range tiers {
		if t.Name == inst.TierName {
			matchedTier = t
			break
		}
	}

	opID := generateID("op")
	nodeID := ""
	if inst.NodeID != nil {
		nodeID = *inst.NodeID
	}
	_ = h.db.CreateOperation(opID, inst.ID, nodeID, string(admiral.ActionRestoreBackup), "pending_dispatch", operatorFromRequest(r))
	_ = h.db.UpdateCustomerAppStatus(inst.ID, "", "restoring")

	allSecretValues, err := h.decryptedSecretMap(inst.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed preparing restore secrets")
		return
	}

	services := buildServiceInfos(payload, matchedTier, inst.ID, inst.CustomerID, allSecretValues)

	srcType := strings.ToLower(strings.TrimSpace(req.Source.Type))
	srcURI := strings.TrimSpace(req.Source.URI)
	if srcType == "" {
		srcType = strings.ToLower(strings.TrimSpace(bk.StorageBackend))
		srcURI = bk.StorageKey
	}
	if srcType == "" || srcType == "local" {
		srcType = "local_path"
	}
	if srcURI == "" {
		srcURI = bk.StorageKey
	}

	target, err := resolveRestoreTarget(payload, bk.BackupType, req.Service)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	task := &admiral.FleetTask{
		TaskID:      generateID("task"),
		OperationID: opID,
		NodeID:      req.TargetNodeID,
		Action:      admiral.ActionRestoreBackup,
		InstanceID:  inst.ID,
		App:         admiral.AppInfo{Name: payload.Name, Version: "latest"},
		Tier:        admiral.TierInfo{Name: matchedTier.Name, CPU: matchedTier.CPU, Memory: matchedTier.Memory, Storage: matchedTier.Storage, Environment: matchedTier.Environment},
		Services:    services,
		Backup:      buildTaskBackupInfo(target),
		Restore: &admiral.RestoreInfo{
			BackupID:       bk.ID,
			StorageBackend: srcType,
			StorageKey:     srcURI,
			BackupType:     bk.BackupType,
			DatabaseType:   bk.DatabaseType,
			Service:        target.ServiceName,
			ChecksumSHA256: bk.ChecksumSHA256,
			VerifyChecksum: req.VerifyChecksum,
		},
	}
	if task.NodeID == "" && inst.NodeID != nil {
		task.NodeID = *inst.NodeID
	}

	if srcType == "s3" {
		storageCfg, _ := h.db.GetActiveBackupStorageConfig()
		if storageCfg != nil && storageCfg.Backend == "s3" {
			task.Storage = &admiral.StorageConfig{
				Backend:        storageCfg.Backend,
				Endpoint:       storageCfg.Endpoint,
				Region:         storageCfg.Region,
				Bucket:         storageCfg.Bucket,
				Prefix:         storageCfg.Prefix,
				ForcePathStyle: storageCfg.ForcePathStyle,
				AccessKeyEnv:   storageCfg.AccessKeyEnv,
				SecretKeyEnv:   storageCfg.SecretKeyEnv,
			}
		}
	}
	if srcType == "s3" && task.Storage == nil {
		h.log.Error("Failed to load S3 storage config for restore", nil,
			map[string]interface{}{"instance_id": inst.ID, "backup_id": bk.ID})
	}

	h.enqueueRawTask(task)

	writeJSON(w, http.StatusAccepted, admiral.RestoreBackupResponse{OperationID: opID, Status: "queued"})
}

func (h *APIHandlers) HandleAdminHealthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var report admiral.HealthReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	if report.InstanceID == "" || report.NodeID == "" || report.HealthStatus == "" {
		writeError(w, http.StatusBadRequest, "instance_id, node_id, and health_status are required")
		return
	}

	inst, err := h.db.GetCustomerApp(report.InstanceID)
	if err != nil {
		h.log.Error("Failed to fetch customer app for health report check", err, map[string]interface{}{"instance_id": report.InstanceID})
		writeError(w, http.StatusInternalServerError, "Failed to verify instance node ownership")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	if inst.NodeID != nil && *inst.NodeID != "" && *inst.NodeID != report.NodeID {
		h.log.Error("Health report instance node_id mismatch", nil, map[string]interface{}{
			"instance_id":   report.InstanceID,
			"expected_node": *inst.NodeID,
			"received_node": report.NodeID,
		})
		writeError(w, http.StatusForbidden, "Instance does not belong to the reporting node")
		return
	}

	techStatus := healthToTechStatus(report.HealthStatus)
	if err := h.db.UpdateInstanceHealthAndTechStatus(report.InstanceID, string(report.HealthStatus), techStatus, report.Message); err != nil {
		h.log.Error("Failed to update instance health", err, map[string]interface{}{"instance_id": report.InstanceID})
		writeError(w, http.StatusInternalServerError, "Failed to update health")
		return
	}

	if len(report.HostPorts) > 0 && h.networking != nil {
		if err := h.networking.ActivateInstanceRoutes(r.Context(), report.InstanceID, report.HostPorts); err != nil {
			h.log.Warn("Route reconciliation from health check failed", map[string]interface{}{
				"instance_id": report.InstanceID,
				"error":       err.Error(),
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *APIHandlers) HandleStorageReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var report admiral.StorageReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	if report.InstanceID == "" || report.NodeID == "" || report.StorageState == "" {
		writeError(w, http.StatusBadRequest, "instance_id, node_id, and storage_state are required")
		return
	}

	inst, err := h.db.GetCustomerApp(report.InstanceID)
	if err != nil {
		h.log.Error("Failed to fetch customer app for storage report check", err, map[string]interface{}{"instance_id": report.InstanceID})
		writeError(w, http.StatusInternalServerError, "Failed to verify instance node ownership")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	if inst.NodeID != nil && *inst.NodeID != "" && *inst.NodeID != report.NodeID {
		h.log.Error("Storage report instance node_id mismatch", nil, map[string]interface{}{
			"instance_id":   report.InstanceID,
			"expected_node": *inst.NodeID,
			"received_node": report.NodeID,
		})
		writeError(w, http.StatusForbidden, "Instance does not belong to the reporting node")
		return
	}

	prevState := inst.StorageState

	exceeded := string(report.StorageState) == string(admiral.StorageOverQuota)
	if err := h.db.UpdateInstanceStorage(
		report.InstanceID,
		string(report.StorageState),
		report.StorageMessage,
		report.StorageLimitBytes,
		report.StorageUsedBytes,
		report.StorageUsedPct,
		exceeded,
	); err != nil {
		h.log.Error("Failed to update instance storage", err, map[string]interface{}{"instance_id": report.InstanceID})
		writeError(w, http.StatusInternalServerError, "Failed to update storage")
		return
	}

	newState := string(report.StorageState)
	if prevState != newState {
		h.log.Info("Storage state changed", map[string]interface{}{
			"instance_id":  report.InstanceID,
			"node_id":      report.NodeID,
			"prev_state":   prevState,
			"new_state":    newState,
			"used_bytes":   report.StorageUsedBytes,
			"used_percent": report.StorageUsedPct,
			"limit_bytes":  report.StorageLimitBytes,
		})
	}

	// Manage grace period based on storage state
	if inst != nil {
		isOverQuota := string(report.StorageState) == string(admiral.StorageOverQuota)
		inGrace := inst.GracePeriodEndsAt != nil && inst.GracePeriodEndsAt.After(time.Now())

		if isOverQuota && !inGrace && inst.GracePeriodStartsAt == nil {
			endsAt := time.Now().Add(5 * 24 * time.Hour)
			if err := h.db.SetGracePeriod(report.InstanceID, endsAt); err != nil {
				h.log.Error("Failed to set grace period", err, map[string]interface{}{"instance_id": report.InstanceID})
			} else {
				h.log.Info("Storage grace period started", map[string]interface{}{
					"instance_id": report.InstanceID,
					"ends_at":     endsAt.Format(time.RFC3339),
				})
			}
		} else if !isOverQuota && inst.GracePeriodStartsAt != nil {
			if err := h.db.ClearGracePeriod(report.InstanceID); err != nil {
				h.log.Error("Failed to clear grace period", err, map[string]interface{}{"instance_id": report.InstanceID})
			} else {
				h.log.Info("Storage grace period cleared - usage below quota", map[string]interface{}{
					"instance_id": report.InstanceID,
				})
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// healthToTechStatus maps instance health status to technical status for
// automatic reconciliation after node recovery.
func healthToTechStatus(h admiral.HealthStatus) string {
	switch h {
	case admiral.HealthHealthy:
		return "running"
	case admiral.HealthStopped:
		return "stopped"
	case admiral.HealthUnhealthy:
		return "failed"
	default:
		return ""
	}
}

// HandleMigrateInstance starts an offline migration of an instance to a target node.
// POST /api/admin/instances/{id}/migrate
func (h *APIHandlers) HandleMigrateInstance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		writeError(w, http.StatusBadRequest, "instance_id is required")
		return
	}
	instanceID := parts[3]

	var req admiral.MigrateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	if req.TargetNodeID == "" {
		writeError(w, http.StatusBadRequest, "target_node_id is required")
		return
	}

	inst, err := h.db.GetCustomerApp(instanceID)
	if err != nil {
		h.log.Error("Database error fetching instance for migration", err, map[string]interface{}{"instance_id": instanceID})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	if inst.NodeID == nil || *inst.NodeID == "" {
		writeError(w, http.StatusConflict, "Instance is not assigned to any node")
		return
	}
	sourceNodeID := *inst.NodeID
	if sourceNodeID == req.TargetNodeID {
		writeError(w, http.StatusConflict, "Instance is already on the target node")
		return
	}

	sourceNode, err := h.db.GetNode(sourceNodeID)
	if err != nil {
		h.log.Error("Database error fetching source node for migration", err, map[string]interface{}{"node_id": sourceNodeID})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if sourceNode == nil {
		writeError(w, http.StatusNotFound, "Source node not found")
		return
	}

	targetNode, err := h.db.GetNode(req.TargetNodeID)
	if err != nil {
		h.log.Error("Database error fetching target node", err, map[string]interface{}{"node_id": req.TargetNodeID})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if targetNode == nil {
		writeError(w, http.StatusNotFound, "Target node not found")
		return
	}
	if targetNode.Status != "active" {
		writeError(w, http.StatusConflict, "Target node is not active")
		return
	}
	if !targetNode.AvailableForProvisioning {
		writeError(w, http.StatusConflict, "Target node is not available for provisioning")
		return
	}

	if inst.TechnicalStatus != "running" {
		writeError(w, http.StatusConflict, "Instance must be in running state to migrate")
		return
	}

	// Check for concurrent migration on the same instance
	existingOps, err := h.db.GetRunningOperationsByInstance(instanceID)
	if err == nil {
		for _, op := range existingOps {
			if op.Action == "migrate" {
				writeError(w, http.StatusConflict, "Instance is already being migrated")
				return
			}
		}
	}

	appDef, err := h.db.GetAppDefinition(inst.AppDefinitionName)
	if err != nil || appDef == nil {
		writeError(w, http.StatusInternalServerError, "Failed retrieving app definition")
		return
	}

	var matchedTier database.AppTier
	if err := json.Unmarshal([]byte(inst.TierSnapshotJSON), &matchedTier); err != nil {
		writeError(w, http.StatusInternalServerError, "Invalid tier snapshot on instance")
		return
	}

	opID := generateID("op")
	meta := &database.OperationMetadata{
		TargetNodeID:      req.TargetNodeID,
		SourceNodeID:      sourceNodeID,
		LogicalInstanceID: inst.LogicalInstanceID,
		MigrationStep:     "starting",
	}
	if err := h.db.CreateOperationWithMetadata(opID, instanceID, sourceNodeID, "migrate", "running", operatorFromRequest(r), meta); err != nil {
		h.log.Error("Failed to create migration operation", err, map[string]interface{}{"instance_id": instanceID})
		writeError(w, http.StatusInternalServerError, "Failed to create operation")
		return
	}

	go h.runMigration(opID, instanceID, inst.CustomerID, sourceNodeID, req.TargetNodeID, appDef.RawYAML, matchedTier, inst.LogicalInstanceID)

	writeJSON(w, http.StatusAccepted, admiral.MigrateAppResponse{
		OperationID:       opID,
		InstanceID:        instanceID,
		LogicalInstanceID: inst.LogicalInstanceID,
		Status:            "running",
	})
}
