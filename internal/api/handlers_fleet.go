package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func parseHostPortsFromMetadata(metadata string) map[string]int {
	var data struct {
		HostPorts map[string]int `json:"host_ports"`
	}
	if err := json.Unmarshal([]byte(metadata), &data); err != nil {
		return nil
	}
	return data.HostPorts
}

// PATCH /api/v1/apps/{id}/availability — change app availability

func handleBackupCallback(h *APIHandlers, op *database.Operation, res admiral.TaskResult, success bool) {
	if success {
		var cbData struct {
			Backup struct {
				BackupID       string `json:"backup_id"`
				StorageBackend string `json:"storage_backend"`
				StorageKey     string `json:"storage_key"`
				SizeBytes      int64  `json:"size_bytes"`
				ChecksumSHA256 string `json:"checksum_sha256"`
				CompletedAt    string `json:"completed_at"`
			} `json:"backup"`
		}
		if uerr := json.Unmarshal([]byte(res.Metadata), &cbData); uerr != nil {
			h.log.Error("Failed to parse backup metadata from callback", uerr, map[string]interface{}{"operation_id": res.OperationID})
		}

		bkID := cbData.Backup.BackupID
		if bkID == "" {
			recs, err := h.db.GetBackupRecords(op.InstanceID)
			if err != nil {
				h.log.Error("Failed to get backup records for fallback", err, map[string]interface{}{"instance_id": op.InstanceID})
			}
			for _, r := range recs {
				if r.Status == "pending" {
					bkID = r.ID
					break
				}
			}
		}

		if bkID != "" {
			rec, err := h.db.GetBackupRecord(bkID)
			if err != nil {
				h.log.Error("Failed to get backup record", err, map[string]interface{}{"backup_id": bkID})
			}
			if rec != nil {
				rec.Status = "succeeded"
				rec.SizeBytes = cbData.Backup.SizeBytes
				rec.ChecksumSHA256 = cbData.Backup.ChecksumSHA256
				if cbData.Backup.StorageBackend != "" {
					rec.StorageBackend = cbData.Backup.StorageBackend
				}
				if cbData.Backup.StorageKey != "" && cbData.Backup.StorageBackend == "local" {
					cleaned := filepath.Clean(cbData.Backup.StorageKey)
					if filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "..") {
						h.log.Error("Rejected local backup storage_key with path traversal", nil, map[string]interface{}{
							"operation_id": res.OperationID,
							"storage_key":  cbData.Backup.StorageKey,
						})
					} else {
						rec.StorageKey = cbData.Backup.StorageKey
					}
				}
				rec.CompletedAt = time.Now().Format(time.RFC3339)
				rec.ExpiresAt = time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
				if uerr := h.db.UpdateBackupRecord(rec); uerr != nil {
					h.log.Error("Failed to update backup record", uerr, map[string]interface{}{"backup_id": bkID})
				}
			}
		}
	} else {
		recs, err := h.db.GetBackupRecords(op.InstanceID)
		if err != nil {
			h.log.Error("Failed to get backup records for failure", err, map[string]interface{}{"instance_id": op.InstanceID})
			return
		}
		for _, r := range recs {
			if r.Status == "pending" {
				r.Status = "failed"
				if uerr := h.db.UpdateBackupRecord(&r); uerr != nil {
					h.log.Error("Failed to update backup record as failed", uerr, map[string]interface{}{"backup_id": r.ID})
				}
				break
			}
		}
	}
}

func (h *APIHandlers) HandleFleetCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var res admiral.TaskResult
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	h.log.Info("Received fleet task callback", map[string]interface{}{
		"operation_id": res.OperationID,
		"task_id":      res.TaskID,
		"node_id":      res.NodeID,
		"success":      res.Success,
	})

	op, err := h.db.GetOperation(res.OperationID)
	if err != nil {
		h.log.Error("Failed to get operation from callback", err, map[string]interface{}{"operation_id": res.OperationID})
	}
	if op == nil {
		writeError(w, http.StatusNotFound, "Operation not found for callback")
		return
	}

	if op.NodeID != "" && op.NodeID != res.NodeID {
		h.log.Error("Callback node_id mismatch", nil, map[string]interface{}{
			"operation_id":  res.OperationID,
			"expected_node": op.NodeID,
			"received_node": res.NodeID,
		})
		writeError(w, http.StatusForbidden, "Callback node_id does not match operation")
		return
	}

	if op.TaskID != "" && op.TaskID != res.TaskID {
		h.log.Error("Callback task_id mismatch", nil, map[string]interface{}{
			"operation_id":  res.OperationID,
			"expected_task": op.TaskID,
			"received_task": res.TaskID,
		})
		writeError(w, http.StatusForbidden, "Callback task_id does not match operation")
		return
	}

	status := "succeeded"
	if !res.Success {
		status = "failed"
	}

	if uerr := h.db.UpdateOperation(res.OperationID, status, res.Error); uerr != nil {
		h.log.Error("Failed to update operation from callback", uerr, map[string]interface{}{"operation_id": res.OperationID})
	}

	var nextTechStatus string
	if res.Success {
		switch op.Action {
		case string(admiral.ActionProvisionApp), string(admiral.ActionStartApp), string(admiral.ActionResumeApp), string(admiral.ActionReactivateApp):
			nextTechStatus = "running"
			if h.networking != nil {
				hostPorts := parseHostPortsFromMetadata(res.Metadata)
				if err := h.networking.ActivateInstanceRoutes(r.Context(), op.InstanceID, hostPorts); err != nil {
					h.log.Error("Activate public routes failed", err, map[string]interface{}{"instance_id": op.InstanceID})
				}
			}
		case string(admiral.ActionStopApp), string(admiral.ActionPauseApp):
			nextTechStatus = "stopped"
		case string(admiral.ActionPauseAppStorage):
			nextTechStatus = "paused_for_storage"
		case string(admiral.ActionResizeApp):
			nextTechStatus = "running"
			h.handleResizeCallback(op, res, true)
		case string(admiral.ActionDeprovisionApp):
			nextTechStatus = "deprovisioned"
			if uerr := h.db.UpdateCustomerAppStatus(op.InstanceID, "cancelled", "deprovisioned"); uerr != nil {
				h.log.Error("Failed to update instance as deprovisioned", uerr, map[string]interface{}{"instance_id": op.InstanceID})
			}
			// Release committed capacity
			if inst, ierr := h.db.GetCustomerApp(op.InstanceID); ierr == nil && inst != nil && inst.NodeID != nil {
				var tier database.AppTier
				if jerr := json.Unmarshal([]byte(inst.TierSnapshotJSON), &tier); jerr == nil {
					r := database.ParseSizeBytes(tier.Memory)
					d := database.ParseSizeBytes(tier.Storage)
					if r > 0 && d > 0 {
						if cerr := h.db.ReleaseNodeCommitment(*inst.NodeID, r, d); cerr != nil {
							h.log.Error("Failed to release capacity on deprovision", cerr, map[string]interface{}{"node_id": *inst.NodeID, "instance_id": op.InstanceID})
						} else if rerr := h.recomputeNodePolicy(*inst.NodeID); rerr != nil {
							h.log.Error("Failed to recompute node policy after deprovision release", rerr, map[string]interface{}{"node_id": *inst.NodeID, "instance_id": op.InstanceID})
						} else {
							h.auditCapacityEvent("node_capacity_released", *inst.NodeID, op.InstanceID, op.ID, admiral.ActionDeprovisionApp, r, d)
						}
					}
				}
			}
			if h.networking != nil {
				if err := h.networking.DeleteInstanceRoutes(r.Context(), op.InstanceID); err != nil {
					h.log.Error("Delete public routes failed", err, map[string]interface{}{"instance_id": op.InstanceID})
				}
			}
		case string(admiral.ActionRestoreBackup):
			nextTechStatus = "running"
		case string(admiral.ActionInspectApp):
			nextTechStatus = ""
			if res.Metadata != "" {
				if ierr := h.db.UpdateCustomerAppInspectData(op.InstanceID, res.Metadata); ierr != nil {
					h.log.Error("Failed to persist inspect data", ierr, map[string]interface{}{"instance_id": op.InstanceID})
				}
			}
		case string(admiral.ActionBackupDatabase), "backup_volumes":
			nextTechStatus = "running"
			handleBackupCallback(h, op, res, true)
		}
	} else {
		isBackup := op.Action == string(admiral.ActionBackupDatabase) || op.Action == "backup_volumes"
		if isBackup {
			// Backup failure does not make the instance failed — restore running status.
			nextTechStatus = "running"
			handleBackupCallback(h, op, res, false)
		} else {
			nextTechStatus = "failed"
		}
		if op.Action == string(admiral.ActionProvisionApp) {
			// Release capacity on provisioning failure
			if inst, ierr := h.db.GetCustomerApp(op.InstanceID); ierr == nil && inst != nil && inst.NodeID != nil {
				var tier database.AppTier
				if jerr := json.Unmarshal([]byte(inst.TierSnapshotJSON), &tier); jerr == nil {
					r := database.ParseSizeBytes(tier.Memory)
					d := database.ParseSizeBytes(tier.Storage)
					if r > 0 && d > 0 {
						if cerr := h.db.ReleaseNodeCommitment(*inst.NodeID, r, d); cerr != nil {
							h.log.Error("Failed to release capacity on provision failure", cerr, map[string]interface{}{"node_id": *inst.NodeID, "instance_id": op.InstanceID})
						} else if rerr := h.recomputeNodePolicy(*inst.NodeID); rerr != nil {
							h.log.Error("Failed to recompute node policy after provision failure release", rerr, map[string]interface{}{"node_id": *inst.NodeID, "instance_id": op.InstanceID})
						} else {
							h.auditCapacityEvent("node_capacity_released", *inst.NodeID, op.InstanceID, op.ID, admiral.ActionProvisionApp, r, d)
						}
					}
				}
			}
			if h.networking != nil {
				routes, err := h.db.GetPublicRoutes()
				if err == nil {
					for _, route := range routes {
						if route.AppInstanceID != op.InstanceID {
							continue
						}
						route.Status = string(admiral.RouteStatusFailed)
						route.LastError = res.Error
						now := time.Now().UTC()
						route.LastHealthCheckedAt = &now
						route.LastHealthStatus = "unhealthy"
						if uerr := h.db.UpdatePublicRoute(&route); uerr != nil {
							h.log.Error("Failed to update route status", uerr, map[string]interface{}{"hostname": route.Hostname})
						}
					}
				}
				if uerr := h.networking.Sync(r.Context()); uerr != nil {
					h.log.Error("Failed to sync routes after failure", uerr, nil)
				}
			}
		}
		if op.Action == string(admiral.ActionResizeApp) {
			h.handleResizeCallback(op, res, false)
		}
	}

	if nextTechStatus != "" && op.Action != string(admiral.ActionDeprovisionApp) {
		if uerr := h.db.UpdateCustomerAppStatus(op.InstanceID, "", nextTechStatus); uerr != nil {
			h.log.Error("Failed to update instance status after callback", uerr, map[string]interface{}{"instance_id": op.InstanceID})
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func parseResizeTargetTier(metadata string) (database.AppTier, bool) {
	if strings.TrimSpace(metadata) == "" {
		return database.AppTier{}, false
	}
	var payload struct {
		Action     string           `json:"action"`
		TargetTier admiral.TierInfo `json:"target_tier"`
	}
	if err := json.Unmarshal([]byte(metadata), &payload); err != nil {
		return database.AppTier{}, false
	}
	if payload.Action != string(admiral.ActionResizeApp) || payload.TargetTier.Name == "" {
		return database.AppTier{}, false
	}
	return database.AppTier{
		Name:        payload.TargetTier.Name,
		CPU:         payload.TargetTier.CPU,
		Memory:      payload.TargetTier.Memory,
		Storage:     payload.TargetTier.Storage,
		Environment: payload.TargetTier.Environment,
	}, true
}

func currentTierFromInstance(inst *database.CustomerApp) database.AppTier {
	if inst == nil || strings.TrimSpace(inst.TierSnapshotJSON) == "" {
		return database.AppTier{}
	}
	var tier database.AppTier
	if err := json.Unmarshal([]byte(inst.TierSnapshotJSON), &tier); err != nil {
		return database.AppTier{}
	}
	return tier
}

func (h *APIHandlers) handleResizeCallback(op *database.Operation, res admiral.TaskResult, success bool) {
	targetTier, ok := parseResizeTargetTier(res.Metadata)
	if !ok {
		h.log.Error("Failed to parse resize metadata from callback", fmt.Errorf("missing target tier metadata"), map[string]interface{}{"operation_id": op.ID, "instance_id": op.InstanceID})
		return
	}
	inst, err := h.db.GetCustomerApp(op.InstanceID)
	if err != nil || inst == nil || inst.NodeID == nil {
		return
	}
	currentTier := currentTierFromInstance(inst)
	currentRAM := database.ParseSizeBytes(currentTier.Memory)
	currentDisk := database.ParseSizeBytes(currentTier.Storage)
	targetRAM := database.ParseSizeBytes(targetTier.Memory)
	targetDisk := database.ParseSizeBytes(targetTier.Storage)
	if success {
		tierBytes, err := json.Marshal(targetTier)
		if err == nil {
			if uerr := h.db.UpdateCustomerAppTier(op.InstanceID, targetTier.Name, string(tierBytes)); uerr != nil {
				h.log.Error("Failed to update instance tier after resize", uerr, map[string]interface{}{"instance_id": op.InstanceID})
			}
		}
		releaseRAM := currentRAM - targetRAM
		releaseDisk := currentDisk - targetDisk
		if releaseRAM > 0 || releaseDisk > 0 {
			if err := h.db.ReleaseNodeCommitment(*inst.NodeID, maxInt64(releaseRAM, 0), maxInt64(releaseDisk, 0)); err != nil {
				h.log.Error("Failed to release commitment after downsize", err, map[string]interface{}{"instance_id": op.InstanceID, "node_id": *inst.NodeID})
			} else if rerr := h.recomputeNodePolicy(*inst.NodeID); rerr != nil {
				h.log.Error("Failed to recompute node policy after resize success", rerr, map[string]interface{}{"instance_id": op.InstanceID, "node_id": *inst.NodeID})
			} else {
				h.auditCapacityEvent("node_capacity_released", *inst.NodeID, op.InstanceID, op.ID, admiral.ActionResizeApp, maxInt64(releaseRAM, 0), maxInt64(releaseDisk, 0))
			}
		}
		return
	}
	releaseRAM := targetRAM - currentRAM
	releaseDisk := targetDisk - currentDisk
	if releaseRAM > 0 || releaseDisk > 0 {
		if err := h.db.ReleaseNodeCommitment(*inst.NodeID, maxInt64(releaseRAM, 0), maxInt64(releaseDisk, 0)); err != nil {
			h.log.Error("Failed to release reserved capacity after resize failure", err, map[string]interface{}{"instance_id": op.InstanceID, "node_id": *inst.NodeID})
		} else if rerr := h.recomputeNodePolicy(*inst.NodeID); rerr != nil {
			h.log.Error("Failed to recompute node policy after resize failure", rerr, map[string]interface{}{"instance_id": op.InstanceID, "node_id": *inst.NodeID})
		} else {
			h.auditCapacityEvent("node_capacity_released", *inst.NodeID, op.InstanceID, op.ID, admiral.ActionResizeApp, maxInt64(releaseRAM, 0), maxInt64(releaseDisk, 0))
		}
	}
}

func maxInt64(v, floor int64) int64 {
	if v < floor {
		return floor
	}
	return v
}
