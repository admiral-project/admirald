package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func (h *APIHandlers) HandleCustomerAppAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req admiral.InstanceActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	if req.InstanceID == "" || req.Action == "" {
		writeError(w, http.StatusBadRequest, "instance_id and action are required")
		return
	}

	inst, err := h.db.GetCustomerApp(req.InstanceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error validating instance")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Customer application instance not found")
		return
	}

	if inst.NodeID == nil || *inst.NodeID == "" {
		writeError(w, http.StatusServiceUnavailable, "Application is not scheduled on any active node")
		return
	}
	if req.NodeID != "" && req.NodeID != *inst.NodeID {
		writeError(w, http.StatusConflict, fmt.Sprintf("Instance is assigned to node %q and cannot execute this action on node %q", *inst.NodeID, req.NodeID))
		return
	}

	appDef, err := h.db.GetAppDefinition(inst.AppDefinitionName)
	if err != nil || appDef == nil {
		writeError(w, http.StatusInternalServerError, "Failed retrieving application details")
		return
	}

	tiers, err := h.db.GetAppTiers(inst.AppDefinitionName)
	if err != nil {
		h.log.Error("Failed to get app tiers", err, map[string]interface{}{"app_name": inst.AppDefinitionName})
	}
	var matchedTier database.AppTier
	for _, t := range tiers {
		if t.Name == inst.TierName {
			matchedTier = t
			break
		}
	}

	var action admiral.TaskAction
	var nextTechStatus string
	var currentTier database.AppTier
	var resizeReservedRAM int64
	var resizeReservedDisk int64

	switch req.Action {
	case "pause":
		action = admiral.ActionPauseApp
		nextTechStatus = "stopped"
	case "resume":
		action = admiral.ActionResumeApp
		nextTechStatus = "running"
	case "start":
		action = admiral.ActionStartApp
		nextTechStatus = "running"
	case "stop":
		action = admiral.ActionStopApp
		nextTechStatus = "stopped"
	case "backup":
		nextTechStatus = "backup_running"
		payload := parseAppPayload(appDef.RawYAML)
		if payload == nil {
			writeError(w, http.StatusInternalServerError, "Stored application definition is invalid")
			return
		}
		target, err := resolveBackupTarget(*payload, req.Service)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if target.Backup.Type == "volume" {
			action = admiral.ActionBackupVolumes
		} else {
			action = admiral.ActionBackupDatabase
		}
	case "deprovision":
		action = admiral.ActionDeprovisionApp
		nextTechStatus = "deprovisioning"
	case "reactivate":
		action = admiral.ActionReactivateApp
		nextTechStatus = "running"
	case "resize":
		tierName := req.Tier
		if tierName == "" {
			writeError(w, http.StatusBadRequest, "tier is required for resize")
			return
		}
		currentTier = matchedTier
		if currentTier.Name == "" && strings.TrimSpace(inst.TierSnapshotJSON) != "" {
			_ = json.Unmarshal([]byte(inst.TierSnapshotJSON), &currentTier)
		}
		matchedTier = database.AppTier{}
		for _, t := range tiers {
			if t.Name == tierName {
				matchedTier = t
				break
			}
		}
		if matchedTier.Name == "" {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("tier %q not found", tierName))
			return
		}
		currentRAM := database.ParseSizeBytes(currentTier.Memory)
		currentDisk := database.ParseSizeBytes(currentTier.Storage)
		targetRAM := database.ParseSizeBytes(matchedTier.Memory)
		targetDisk := database.ParseSizeBytes(matchedTier.Storage)
		if targetRAM <= 0 || targetDisk <= 0 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("tier %q has invalid resource definition", tierName))
			return
		}
		if targetRAM > currentRAM {
			resizeReservedRAM = targetRAM - currentRAM
		}
		if targetDisk > currentDisk {
			resizeReservedDisk = targetDisk - currentDisk
		}
		if resizeReservedRAM > 0 || resizeReservedDisk > 0 {
			node, nerr := h.db.GetNode(*inst.NodeID)
			if nerr != nil {
				writeError(w, http.StatusInternalServerError, "Database error validating node capacity")
				return
			}
			if node == nil {
				writeError(w, http.StatusNotFound, "Assigned node not found")
				return
			}
			evaluation := h.evaluateNodeForTier(*node, resizeReservedRAM, resizeReservedDisk)
			if !evaluation.Eligible {
				if err := h.recordBlockedWorkloadAttempt(w, r, admiral.ActionResizeApp, req.InstanceID, inst.AppDefinitionName, inst.CustomerID, *inst.NodeID, matchedTier, []admiral.NodeProvisioningEvaluation{evaluation}); err != nil {
					h.log.Error("Record blocked resize attempt failed", err, map[string]interface{}{"instance_id": req.InstanceID, "requested_node_id": *inst.NodeID, "tier_name": tierName})
					writeError(w, http.StatusInternalServerError, "Failed recording blocked resize attempt")
				}
				return
			}
		}
		action = admiral.ActionResizeApp
		nextTechStatus = "running"
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Unsupported action %q", req.Action))
		return
	}

	operationID := generateID("op")

	// Create a backup_record before dispatching so HandleFleetCallback can find it.
	var backupID string
	if action == admiral.ActionBackupDatabase || action == admiral.ActionBackupVolumes {
		backupID = generateID("bk")
		backupType := "database"
		backupPrefix := "database"
		if action == admiral.ActionBackupVolumes {
			backupType = "volume"
			backupPrefix = "volumes"
		}
		storageCfg, _ := h.db.GetActiveBackupStorageConfig()
		var backend, key string
		if storageCfg != nil {
			backend = storageCfg.Backend
			key = fmt.Sprintf("%s/%s/%s/%s-%s-%s", storageCfg.Prefix, *inst.NodeID, req.InstanceID, req.Service, backupPrefix, operationID)
		} else {
			backend = "local"
			key = fmt.Sprintf("/var/lib/admiral/backups/%s/%s-%s", req.InstanceID, req.Service, operationID)
		}
		bkRec := &admiral.BackupRecord{
			ID:                          backupID,
			InstanceID:                  req.InstanceID,
			AppID:                       inst.AppDefinitionName,
			TierID:                      inst.TierName,
			NodeID:                      *inst.NodeID,
			BackupType:                  backupType,
			Status:                      "pending",
			StorageBackend:              backend,
			StorageKey:                  key,
			TriggeredBy:                 "manual",
			TierSnapshotJSON:            inst.TierSnapshotJSON,
			RetentionPolicySnapshotJSON: `{"count":7,"days":30}`,
		}
		if action == admiral.ActionBackupDatabase {
			payload := parseAppPayload(appDef.RawYAML)
			if payload == nil {
				writeError(w, http.StatusInternalServerError, "Stored application definition is invalid")
				return
			}
			target, err := resolveBackupTarget(*payload, req.Service)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			bkRec.DatabaseType = target.Backup.Engine
		} else {
			bkRec.DatabaseType = "none"
		}
		_ = h.db.CreateBackupRecord(bkRec)
	}

	if uerr := h.db.UpdateCustomerAppStatus(req.InstanceID, "", nextTechStatus); uerr != nil {
		h.log.Error("Failed to update instance status before action", uerr, map[string]interface{}{"instance_id": req.InstanceID})
	}

	nodeID := ""
	if inst.NodeID != nil {
		nodeID = *inst.NodeID
	}
	if action == admiral.ActionResizeApp && (resizeReservedRAM > 0 || resizeReservedDisk > 0) {
		if err := h.db.ReserveNodeCapacity(nodeID, resizeReservedRAM, resizeReservedDisk); err != nil {
			if err == database.ErrNodeCapacityPolicyBlocked {
				evaluations := h.refreshNodeEvaluationsForTier(matchedTier, nodeID)
				if recErr := h.recordBlockedWorkloadAttempt(w, r, admiral.ActionResizeApp, req.InstanceID, inst.AppDefinitionName, inst.CustomerID, nodeID, matchedTier, evaluations); recErr != nil {
					h.log.Error("Record blocked resize attempt after reserve race failed", recErr, map[string]interface{}{"instance_id": req.InstanceID, "requested_node_id": nodeID, "tier_name": matchedTier.Name})
					writeError(w, http.StatusInternalServerError, "Failed recording blocked resize attempt")
				}
				return
			}
			h.log.Error("Reserve node capacity for resize failed", err, map[string]interface{}{"instance_id": req.InstanceID, "node_id": nodeID, "tier_name": matchedTier.Name})
			writeError(w, http.StatusInternalServerError, "Failed reserving node capacity for resize")
			return
		}
		h.auditCapacityEvent("node_capacity_reserved", nodeID, req.InstanceID, operationID, admiral.ActionResizeApp, resizeReservedRAM, resizeReservedDisk)
		if err := h.recomputeNodePolicy(nodeID); err != nil {
			h.log.Error("Failed to recompute node policy after resize reservation", err, map[string]interface{}{"instance_id": req.InstanceID, "node_id": nodeID})
		}
	}
	if err := h.db.CreateOperation(operationID, req.InstanceID, nodeID, string(action), "pending_dispatch", operatorFromRequest(r)); err != nil {
		h.log.Error("Create action operation failed", err, nil)
		if action == admiral.ActionResizeApp && (resizeReservedRAM > 0 || resizeReservedDisk > 0) {
			if uerr := h.db.ReleaseNodeCommitment(nodeID, resizeReservedRAM, resizeReservedDisk); uerr != nil {
				h.log.Error("Failed to release reserved resize capacity after operation create error", uerr, map[string]interface{}{"instance_id": req.InstanceID, "node_id": nodeID})
			} else if uerr := h.recomputeNodePolicy(nodeID); uerr != nil {
				h.log.Error("Failed to recompute node policy after resize rollback", uerr, map[string]interface{}{"instance_id": req.InstanceID, "node_id": nodeID})
			} else {
				h.auditCapacityEvent("node_capacity_released", nodeID, req.InstanceID, operationID, admiral.ActionResizeApp, resizeReservedRAM, resizeReservedDisk)
			}
		}
		writeError(w, http.StatusInternalServerError, "Failed recording operation")
		return
	}

	h.enqueueTask(operationID, req.InstanceID, *inst.NodeID, inst.CustomerID, appDef.RawYAML, matchedTier, action, backupID, req.Service)

	// Clear grace period on reactivate
	if req.Action == "reactivate" {
		if err := h.db.ClearGracePeriod(req.InstanceID); err != nil {
			h.log.Error("Failed to clear grace period on reactivate", err, map[string]interface{}{"instance_id": req.InstanceID})
		} else {
			h.log.Info("Grace period cleared on reactivate", map[string]interface{}{"instance_id": req.InstanceID})
		}
	}

	writeJSON(w, http.StatusAccepted, admiral.OperationResponse{
		OperationID: operationID,
		Status:      "queued",
	})
}
