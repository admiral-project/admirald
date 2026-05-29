package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

func hashSHA256(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

// EnsureDefaultAdmin checks if any admin exists and creates 'admin' / 'secret' if empty
func EnsureDefaultAdmin(db *database.DB) error {
	passwordHash, err := db.GetAdminUser("admin")
	if err != nil {
		return err
	}
	if passwordHash == "" {
		// Auto-create default admin
		hash := hashSHA256("secret")
		if err := db.CreateAdminUser("admin", hash); err != nil {
			return fmt.Errorf("create default admin: %w", err)
		}
	}
	return nil
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

		tokenHash := hashSHA256(token)
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

	storedHash, err := h.db.GetAdminUser(req.Username)
	if err != nil {
		h.log.Error("Failed to fetch admin user", err, map[string]interface{}{"username": req.Username})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}

	inputHash := hashSHA256(req.Password)
	if storedHash == "" || storedHash != inputHash {
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Generate session token
	token := generateID("adm_tok")
	tokenHash := hashSHA256(token)
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour) // Max session duration

	if err := h.db.CreateAdminSession(tokenHash, req.Username, expiresAt, now); err != nil {
		h.log.Error("Failed to create admin session", err, map[string]interface{}{"username": req.Username})
		writeError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	writeJSON(w, http.StatusOK, admiral.AdminLoginResponse{
		Token:     token,
		ExpiresAt: expiresAt.Format(time.RFC3339),
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
		tokenHash := hashSHA256(token)
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
	writeJSON(w, http.StatusOK, admiral.AdminMeResponse{
		Username:  username,
		CreatedAt: time.Now().Format(time.RFC3339),
	})
}

// GET & POST & PUT /api/admin/apps
func (h *APIHandlers) HandleAdminApps(w http.ResponseWriter, r *http.Request) {
	// Extract app ID if present
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var appID string
	if len(parts) >= 4 {
		appID = parts[3]
	}

	switch r.Method {
	case http.MethodGet:
		if appID != "" {
			// Sub-routes logic
			if len(parts) >= 5 && parts[4] == "yaml" {
				app, _ := h.db.GetAppDefinition(appID)
				if app == nil {
					writeError(w, http.StatusNotFound, "App not found")
					return
				}
				w.Header().Set("Content-Type", "application/x-yaml")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(app.RawYAML))
				return
			}
			if len(parts) >= 5 && parts[4] == "versions" {
				writeJSON(w, http.StatusOK, []string{"latest"})
				return
			}
			if len(parts) >= 5 && parts[4] == "tiers" {
				tiers, _ := h.db.GetAppTiers(appID)
				writeJSON(w, http.StatusOK, tiers)
				return
			}

			app, _ := h.db.GetAppDefinition(appID)
			if app == nil {
				writeError(w, http.StatusNotFound, "App not found")
				return
			}
			writeJSON(w, http.StatusOK, app)
			return
		}

		apps, err := h.db.GetAppDefinitions()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, apps)

	case http.MethodPost, http.MethodPut:
		// Sub-routes logic for tiers
		if appID != "" && len(parts) >= 5 && parts[4] == "tiers" {
			h.HandleAdminAppTiers(w, r, appID)
			return
		}

		h.HandleApps(w, r) // Reuse existing validation and logic
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Handles App Tiers nested operations
func (h *APIHandlers) HandleAdminAppTiers(w http.ResponseWriter, r *http.Request, appID string) {
	app, _ := h.db.GetAppDefinition(appID)
	if app == nil {
		writeError(w, http.StatusNotFound, "App not found")
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var tierID string
	if len(parts) >= 6 {
		tierID = parts[5]
	}

	switch r.Method {
	case http.MethodGet:
		tiers, _ := h.db.GetAppTiers(appID)
		if tierID != "" {
			for _, t := range tiers {
				if t.Name == tierID {
					writeJSON(w, http.StatusOK, t)
					return
				}
			}
			writeError(w, http.StatusNotFound, "Tier not found")
			return
		}
		writeJSON(w, http.StatusOK, tiers)

	case http.MethodPost, http.MethodPut:
		var req struct {
			Name         string                `json:"name"`
			CPU          int                   `json:"cpu"`
			Memory       string                `json:"memory"`
			Storage      string                `json:"storage"`
			PriceMonthly float64               `json:"price_monthly"`
			Backups      *admiral.BackupPolicy `json:"backups,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}

		if req.Name == "" || req.CPU <= 0 || req.Memory == "" || req.Storage == "" {
			writeError(w, http.StatusBadRequest, "Missing required tier fields")
			return
		}

		var backupPolicyJSON string
		if req.Backups != nil && req.Backups.Enabled {
			if req.Backups.Schedule != "disabled" && req.Backups.Schedule != "daily" && req.Backups.Schedule != "weekly" {
				writeError(w, http.StatusBadRequest, "Invalid backup schedule")
				return
			}
			if req.Backups.Retention.Count < 1 || req.Backups.Retention.Days < 1 {
				writeError(w, http.StatusBadRequest, "Invalid backup retention")
				return
			}
			bBytes, _ := json.Marshal(req.Backups)
			backupPolicyJSON = string(bBytes)
		}

		tiers, _ := h.db.GetAppTiers(appID)
		var updatedTiers []database.AppTier
		for _, t := range tiers {
			if t.Name != req.Name {
				updatedTiers = append(updatedTiers, t)
			}
		}
		updatedTiers = append(updatedTiers, database.AppTier{
			AppName:          appID,
			Name:             req.Name,
			CPU:              req.CPU,
			Memory:           req.Memory,
			Storage:          req.Storage,
			PriceMonthly:     req.PriceMonthly,
			BackupPolicyJSON: backupPolicyJSON,
		})

		err := h.db.SaveAppDefinition(app.Name, app.DisplayName, app.Description, app.RawYAML, updatedTiers)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	}
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
		if instanceID != "" {
			inst, _ := h.db.GetCustomerApp(instanceID)
			if inst == nil {
				writeError(w, http.StatusNotFound, "Instance not found")
				return
			}
			writeJSON(w, http.StatusOK, inst)
			return
		}

		apps, err := h.db.GetCustomerApps()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, apps)

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
				_ = h.db.CreateOperation(opID, instanceID, "inspect_app", "queued")
				appDef, _ := h.db.GetAppDefinition(inst.AppDefinitionName)
				tiers, _ := h.db.GetAppTiers(inst.AppDefinitionName)
				var matchedTier database.AppTier
				for _, t := range tiers {
					if t.Name == inst.TierName {
						matchedTier = t
						break
					}
				}
				h.dispatchTask(opID, instanceID, *inst.NodeID, appDef.RawYAML, matchedTier, admiral.TaskAction("inspect_app"))

				writeJSON(w, http.StatusAccepted, admiral.OperationResponse{
					OperationID: opID,
					Status:      "queued",
				})
				return
			}

			// Reuse HandleCustomerAppAction
			r.Body = io.NopCloser(strings.NewReader(fmt.Sprintf(`{"instance_id":"%s","action":"%s"}`, instanceID, action)))
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
		recs, err := h.db.GetBackupRecords(instanceID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, recs)

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
			_ = h.db.CreateOperation(opID, rec.InstanceID, "delete_backup", "queued")

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

	appDef, _ := h.db.GetAppDefinition(inst.AppDefinitionName)
	var payload admiral.AppDefinitionPayload
	_ = yaml.Unmarshal([]byte(appDef.RawYAML), &payload)

	var action admiral.TaskAction
	if backupType == "database" {
		action = admiral.ActionBackupDatabase
	} else if backupType == "volumes" {
		action = admiral.TaskAction("backup_volumes")
	} else {
		writeError(w, http.StatusBadRequest, "Invalid backup type")
		return
	}

	opID := generateID("op")
	_ = h.db.UpdateCustomerAppStatus(instanceID, "", "backup_running")
	_ = h.db.CreateOperation(opID, instanceID, string(action), "queued")

	// Get active storage config
	storageCfg, _ := h.db.GetActiveBackupStorageConfig()
	var backend, key string
	if storageCfg != nil {
		backend = storageCfg.Backend
		key = fmt.Sprintf("%s/%s/%s/%s-%s", storageCfg.Prefix, *inst.NodeID, instanceID, backupType, opID)
	} else {
		backend = "local"
		key = fmt.Sprintf("/var/lib/admiral/backups/%s/%s", instanceID, opID)
	}

	// Register BackupRecord in PENDING state before dispatching
	bkRec := &admiral.BackupRecord{
		ID:                          generateID("bk"),
		InstanceID:                  instanceID,
		AppID:                       inst.AppDefinitionName,
		TierID:                      inst.TierName,
		NodeID:                      *inst.NodeID,
		BackupType:                  backupType,
		DatabaseType:                "postgresql",
		Status:                      "pending",
		StorageBackend:              backend,
		StorageKey:                  key,
		TriggeredBy:                 "manual",
		TierSnapshotJSON:            inst.TierSnapshotJSON,
		RetentionPolicySnapshotJSON: `{"count":7,"days":30}`,
	}
	if payload.Backup != nil && payload.Backup.Engine != "" {
		bkRec.DatabaseType = payload.Backup.Engine
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
	secretValues := scopeTaskSecrets(action, payload, allSecretValues)

	var services []admiral.ServiceInfo
	for name, s := range payload.Services {
		services = append(services, admiral.ServiceInfo{
			Name:    name,
			Image:   s.Image,
			Port:    s.Port,
			Volume:  s.Volume,
			Env:     s.Env,
			Secrets: secretValues[name],
		})
	}

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
			Name:    matchedTier.Name,
			CPU:     matchedTier.CPU,
			Memory:  matchedTier.Memory,
			Storage: matchedTier.Storage,
		},
		Services: services,
	}
	if payload.Backup != nil {
		dbType := payload.Backup.Engine
		if dbType == "" {
			dbType = payload.Backup.Type
		}
		task.Backup = &admiral.BackupInfo{
			Type:         payload.Backup.Type,
			Service:      payload.Backup.Service,
			DatabaseType: dbType,
			DatabaseEnv:  payload.Backup.DatabaseEnv,
			UsernameEnv:  payload.Backup.UsernameEnv,
			PasswordEnv:  payload.Backup.PasswordEnv,
		}
	}

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
		// Policy check: count=7, days=30
		retCount := 7
		// Keep the first 7 succeeded backups, prune others
		for i, rec := range backups {
			if i >= retCount {
				// Create prune task
				opID := generateID("op")
				_ = h.db.CreateOperation(opID, rec.InstanceID, "delete_backup", "queued")

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
			opID := generateID("op")
			_ = h.db.CreateOperation(opID, "system", "test_backup_storage", "queued")

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

			if activeNode != "" {
				task := &admiral.FleetTask{
					TaskID:      generateID("task"),
					OperationID: opID,
					NodeID:      activeNode,
					Action:      admiral.TaskAction("test_backup_storage"),
					InstanceID:  "system",
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

// GET /api/admin/nodes & tasks
func (h *APIHandlers) HandleAdminNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var nodeID string
	if len(parts) >= 4 {
		nodeID = parts[3]
	}

	if nodeID != "" {
		if len(parts) >= 5 && parts[4] == "status" {
			writeJSON(w, http.StatusOK, map[string]interface{}{"node_status": "online", "pods_count": 0})
			return
		}
		node, _ := h.db.GetNode(nodeID)
		if node == nil {
			writeError(w, http.StatusNotFound, "Node not found")
			return
		}
		writeJSON(w, http.StatusOK, node)
		return
	}

	nodes, err := h.db.GetNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (h *APIHandlers) HandleAdminTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var taskID string
	if len(parts) >= 4 {
		taskID = parts[3]
	}

	if taskID != "" {
		// Mock task fetch since they are dispatched in RabbitMQ, we can return details from operations
		op, _ := h.db.GetOperation(taskID)
		if op == nil {
			writeError(w, http.StatusNotFound, "Task not found")
			return
		}
		writeJSON(w, http.StatusOK, op)
		return
	}

	ops, err := h.db.GetOperations()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ops)
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
	if req.BackupID == "" || req.TargetAppID == "" {
		writeError(w, http.StatusBadRequest, "backup_id and target_app_id are required")
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
	if payload.Backup == nil {
		writeError(w, http.StatusConflict, "Application definition does not declare a backup source")
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
	_ = h.db.CreateOperation(opID, inst.ID, string(admiral.ActionRestoreBackup), "queued")
	_ = h.db.UpdateCustomerAppStatus(inst.ID, "", "restoring")

	allSecretValues, err := h.decryptedSecretMap(inst.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed preparing restore secrets")
		return
	}

	services := make([]admiral.ServiceInfo, 0, len(payload.Services))
	for name, svc := range payload.Services {
		services = append(services, admiral.ServiceInfo{
			Name:    name,
			Image:   svc.Image,
			Port:    svc.Port,
			Volume:  svc.Volume,
			Env:     svc.Env,
			Secrets: allSecretValues[name],
		})
	}

	srcType := strings.ToLower(strings.TrimSpace(req.Source.Type))
	srcURI := strings.TrimSpace(req.Source.URI)
	if srcType == "" {
		srcType = strings.ToLower(strings.TrimSpace(bk.StorageBackend))
		srcURI = bk.StorageKey
	}
	if srcType == "" {
		srcType = "local_path"
	}
	if srcURI == "" {
		srcURI = bk.StorageKey
	}

	dbType := payload.Backup.Engine
	if dbType == "" {
		dbType = payload.Backup.Type
	}

	task := &admiral.FleetTask{
		TaskID:      generateID("task"),
		OperationID: opID,
		NodeID:      req.TargetNodeID,
		Action:      admiral.ActionRestoreBackup,
		InstanceID:  inst.ID,
		App:         admiral.AppInfo{Name: payload.Name, Version: "latest"},
		Tier:        admiral.TierInfo{Name: matchedTier.Name, CPU: matchedTier.CPU, Memory: matchedTier.Memory, Storage: matchedTier.Storage},
		Services:    services,
		Backup: &admiral.BackupInfo{
			Type:         payload.Backup.Type,
			Service:      payload.Backup.Service,
			DatabaseType: dbType,
			DatabaseEnv:  payload.Backup.DatabaseEnv,
			UsernameEnv:  payload.Backup.UsernameEnv,
			PasswordEnv:  payload.Backup.PasswordEnv,
		},
		Restore: &admiral.RestoreInfo{
			BackupID:       bk.ID,
			StorageBackend: srcType,
			StorageKey:     srcURI,
			BackupType:     bk.BackupType,
			DatabaseType:   bk.DatabaseType,
			Service:        payload.Backup.Service,
			ChecksumSHA256: bk.ChecksumSHA256,
			VerifyChecksum: req.VerifyChecksum,
		},
	}
	if task.NodeID == "" && inst.NodeID != nil {
		task.NodeID = *inst.NodeID
	}

	h.enqueueRawTask(task)

	writeJSON(w, http.StatusAccepted, admiral.RestoreBackupResponse{OperationID: opID, Status: "queued"})
}
