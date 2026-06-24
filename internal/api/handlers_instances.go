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

func (h *APIHandlers) HandleCustomerApps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		customerID := r.URL.Query().Get("customer_id")
		apps, err := h.db.GetCustomerApps(customerID)
		if err != nil {
			h.log.Error("Get customer apps failed", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to fetch customer applications")
			return
		}
		writeJSON(w, http.StatusOK, apps)

	case http.MethodPost:
		var req admiral.ProvisionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}

		if req.AppDefinitionName == "" || req.TierName == "" || req.CustomerID == "" {
			writeError(w, http.StatusBadRequest, "app_definition_name, tier_name, and customer_id are required")
			return
		}

		appDef, err := h.db.GetAppDefinition(req.AppDefinitionName)
		if err != nil {
			h.log.Error("Get app definition failed on provision", err, map[string]interface{}{"app_name": req.AppDefinitionName})
			writeError(w, http.StatusInternalServerError, "Database error validating app")
			return
		}
		if appDef == nil {
			writeError(w, http.StatusNotFound, "App definition not found")
			return
		}
		if strings.ToLower(strings.TrimSpace(appDef.Status)) != "active" {
			writeError(w, http.StatusConflict, "App definition is inactive and cannot be provisioned")
			return
		}

		var payload admiral.AppDefinitionPayload
		if err := yaml.Unmarshal([]byte(appDef.RawYAML), &payload); err != nil {
			writeError(w, http.StatusInternalServerError, "Stored application definition is invalid")
			return
		}

		tiers, err := h.db.GetAppTiers(req.AppDefinitionName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Database error validating tiers")
			return
		}
		var matchedTier *database.AppTier
		for _, t := range tiers {
			if t.Name == req.TierName {
				tierCopy := t
				matchedTier = &tierCopy
				break
			}
		}
		if matchedTier == nil {
			writeError(w, http.StatusNotFound, "Tier not found for this app definition")
			return
		}
		if req.NodeID != "" {
			node, err := h.db.GetNode(req.NodeID)
			if err != nil {
				h.log.Error("Get requested node failed on provision", err, map[string]interface{}{"node_id": req.NodeID})
				writeError(w, http.StatusInternalServerError, "Database error validating requested node")
				return
			}
			if node == nil {
				writeError(w, http.StatusNotFound, "Requested node not found")
				return
			}
		}

		selection, err := h.selectNodeForTier(*matchedTier, req.NodeID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Database error selecting node")
			return
		}
		if selection.NodeID == "" {
			if err := h.recordBlockedWorkloadAttempt(w, r, admiral.ActionProvisionApp, "", req.AppDefinitionName, req.CustomerID, req.NodeID, *matchedTier, selection.Evaluations); err != nil {
				h.log.Error("Record blocked provisioning attempt failed", err, map[string]interface{}{"app_name": req.AppDefinitionName, "tier_name": req.TierName, "requested_node_id": req.NodeID})
				writeError(w, http.StatusInternalServerError, "Failed recording blocked provisioning attempt")
			}
			return
		}

		instanceID := generateID("inst")
		operationID := generateID("op")
		nodeID := selection.NodeID

		tierBytes, err := json.Marshal(matchedTier)
		if err != nil {
			h.log.Error("Failed to marshal tier snapshot", err, map[string]interface{}{"tier": req.TierName})
		}
		tierSnapshotJSON := string(tierBytes)

		lid := req.LogicalInstanceID
		ramBytes := database.ParseSizeBytes(matchedTier.Memory)
		diskBytes := database.ParseSizeBytes(matchedTier.Storage)
		if err := h.db.ReserveNodeCapacityAndCreateApp(instanceID, req.CustomerID, req.AppDefinitionName, req.TierName, nodeID, tierSnapshotJSON, lid, ramBytes, diskBytes); err != nil {
			if err == database.ErrNodeCapacityPolicyBlocked {
				evaluations := h.refreshNodeEvaluationsForTier(*matchedTier, nodeID)
				if recErr := h.recordBlockedWorkloadAttempt(w, r, admiral.ActionProvisionApp, "", req.AppDefinitionName, req.CustomerID, nodeID, *matchedTier, evaluations); recErr != nil {
					h.log.Error("Record blocked provisioning attempt after reserve race failed", recErr, map[string]interface{}{"app_name": req.AppDefinitionName, "tier_name": req.TierName, "requested_node_id": nodeID})
					writeError(w, http.StatusInternalServerError, "Failed recording blocked provisioning attempt")
				}
				return
			}
			h.log.Error("Create customer app with capacity reservation failed", err, map[string]interface{}{"node_id": nodeID, "instance_id": instanceID})
			writeError(w, http.StatusInternalServerError, "Failed to create app record")
			return
		}
		h.auditCapacityEvent("node_capacity_reserved", nodeID, instanceID, operationID, admiral.ActionProvisionApp, ramBytes, diskBytes)
		if err := h.recomputeNodePolicy(nodeID); err != nil {
			h.log.Error("Failed to recompute node policy after reservation", err, map[string]interface{}{"node_id": nodeID, "instance_id": instanceID})
		}

		releaseCapacity := func() {
			if ramBytes > 0 && diskBytes > 0 {
				if uerr := h.db.ReleaseNodeCommitment(nodeID, ramBytes, diskBytes); uerr != nil {
					h.log.Error("Failed to release capacity after rollback", uerr, map[string]interface{}{"node_id": nodeID, "instance_id": instanceID})
				} else if uerr := h.recomputeNodePolicy(nodeID); uerr != nil {
					h.log.Error("Failed to recompute node policy after rollback", uerr, map[string]interface{}{"node_id": nodeID, "instance_id": instanceID})
				} else {
					h.auditCapacityEvent("node_capacity_released", nodeID, instanceID, operationID, admiral.ActionProvisionApp, ramBytes, diskBytes)
				}
			}
		}

		credentials, err := h.createInstanceSecrets(instanceID, payload)
		if err != nil {
			h.log.Error("Create instance secrets failed", err, map[string]interface{}{"instance_id": instanceID})
			if uerr := h.db.UpdateCustomerAppStatus(instanceID, "", "failed"); uerr != nil {
				h.log.Error("Failed to mark instance as failed after secrets error", uerr, map[string]interface{}{"instance_id": instanceID})
			}
			releaseCapacity()
			writeError(w, http.StatusInternalServerError, "Failed to create instance secrets")
			return
		}

		if err := h.db.CreateOperation(operationID, instanceID, nodeID, string(admiral.ActionProvisionApp), "pending_dispatch", operatorFromRequest(r)); err != nil {
			h.log.Error("Create operation record failed", err, nil)
			releaseCapacity()
			writeError(w, http.StatusInternalServerError, "Failed to create operation record")
			return
		}

		var hostname string
		var routes []database.PublicRoute
		if h.networking != nil {
			routes, err = h.networking.CreateInstanceRoutes(instanceID, payload, nodeID)
			if err != nil {
				h.log.Error("Create public routes failed", err, map[string]interface{}{"instance_id": instanceID})
				if uerr := h.db.UpdateCustomerAppStatus(instanceID, "", "failed"); uerr != nil {
					h.log.Error("Failed to mark instance as failed after routes error", uerr, map[string]interface{}{"instance_id": instanceID})
				}
				if uerr := h.db.UpdateOperation(operationID, "failed", err.Error()); uerr != nil {
					h.log.Error("Failed to mark operation as failed after routes error", uerr, map[string]interface{}{"operation_id": operationID})
				}
				releaseCapacity()
				writeError(w, http.StatusInternalServerError, "Failed to create public routes")
				return
			}
		}

		if len(routes) > 0 {
			hostname = routes[0].Hostname
		}

		h.enqueueTask(operationID, instanceID, nodeID, req.CustomerID, appDef.RawYAML, *matchedTier, admiral.ActionProvisionApp, "", "")

		// If the app definition includes setup_command on any service,
		// transition to "initializing" so the customer is informed that
		// the application is being set up, not just provisioned.
		if hasSetupCommand(payload) {
			if uerr := h.db.UpdateCustomerAppStatus(instanceID, "", "initializing"); uerr != nil {
				h.log.Error("Failed to set initializing status", uerr, map[string]interface{}{"instance_id": instanceID})
			}
		}

		writeJSON(w, http.StatusAccepted, admiral.ProvisionResponse{
			OperationID: operationID,
			Status:      "queued",
			Hostname:    hostname,
			Credentials: credentials,
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *APIHandlers) HandleCustomerAppByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		writeError(w, http.StatusBadRequest, "instance_id is required")
		return
	}
	instanceID := parts[3]

	// /api/v1/customer-apps/{id}/credentials
	if len(parts) >= 5 && parts[4] == "credentials" {
		h.handleCredentials(w, r, instanceID)
		return
	}

	inst, err := h.db.GetCustomerApp(instanceID)
	if err != nil {
		h.log.Error("Get customer app failed", err, map[string]interface{}{"instance_id": instanceID})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	writeJSON(w, http.StatusOK, inst)
}

func (h *APIHandlers) handleCredentials(w http.ResponseWriter, r *http.Request, instanceID string) {
	secrets, err := h.db.GetExposedInstanceSecrets(instanceID)
	if err != nil {
		h.log.Error("Get exposed secrets failed", err, map[string]interface{}{"instance_id": instanceID})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}

	credentials := make([]admiral.Credential, 0, len(secrets))
	for _, s := range secrets {
		plain, err := h.secrets.Decrypt(s.EncryptedValue)
		if err != nil {
			h.log.Error("Decrypt secret failed", err, nil)
			continue
		}
		credentials = append(credentials, admiral.Credential{
			Service: s.ServiceName,
			Name:    s.EnvName,
			Value:   plain,
		})
	}

	writeJSON(w, http.StatusOK, credentials)
}
