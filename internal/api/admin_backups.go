package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

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
