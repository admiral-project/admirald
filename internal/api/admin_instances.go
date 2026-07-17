package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func (h *APIHandlers) runMigration(opID, instID, customerID, sourceNodeID, targetNodeID, rawYAML string, tier database.AppTier, logicalInstanceID string) {
	waitForOp := func(stepOpID string) (bool, string) {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		timeout := time.After(30 * time.Minute)
		for {
			select {
			case <-ticker.C:
				op, err := h.db.GetOperation(stepOpID)
				if err != nil || op == nil {
					continue
				}
				switch op.Status {
				case "succeeded":
					return true, ""
				case "failed":
					errMsg := ""
					if op.ErrorMessage != nil {
						errMsg = *op.ErrorMessage
					}
					return false, errMsg
				}
			case <-timeout:
				return false, "operation timed out after 30 minutes"
			}
		}
	}

	setStep := func(step string) {
		meta := &database.OperationMetadata{
			TargetNodeID:      targetNodeID,
			SourceNodeID:      sourceNodeID,
			LogicalInstanceID: logicalInstanceID,
			MigrationStep:     step,
		}
		_ = h.db.UpdateOperationMetadata(opID, meta)
	}

	subOp := func(action admiral.TaskAction, nodeID string, backupID, backupService string) (string, bool, string) {
		stepOpID := generateID("op")
		if err := h.db.CreateOperation(stepOpID, instID, nodeID, string(action), "pending_dispatch", "system"); err != nil {
			return stepOpID, false, err.Error()
		}
		h.enqueueTask(stepOpID, instID, nodeID, customerID, rawYAML, tier, action, backupID, backupService)
		ok, errMsg := waitForOp(stepOpID)
		return stepOpID, ok, errMsg
	}

	fail := func(msg string) {
		h.log.Error("Migration failed", nil, map[string]interface{}{"operation_id": opID, "instance_id": instID, "error": msg})
		_ = h.db.UpdateOperation(opID, "failed", msg)
	}

	reconcileRoutes := func(nodeID string, routes []database.PublicRoute) error {
		targetNode, err := h.db.GetNode(nodeID)
		if err != nil {
			return err
		}
		if targetNode == nil {
			return fmt.Errorf("target node %q not found for route reconciliation", nodeID)
		}
		targetHost, err := h.runtimeNodeAddress(targetNode)
		if err != nil {
			return err
		}
		for _, route := range routes {
			route.NodeID = &nodeID
			route.TargetHost = targetHost
			route.TargetURL = fmt.Sprintf("http://%s:%d", targetHost, route.TargetPort)
			route.Status = string(admiral.RouteStatusPending)
			if err := h.db.CreatePublicRoute(route); err != nil {
				return err
			}
		}
		if h.networking != nil {
			if err := h.networking.Sync(context.Background()); err != nil {
				return err
			}
		}
		return nil
	}

	sourceStopped := false
	targetProvisioned := false
	cutoverComplete := false

	dbBackupService := "database"
	volBackupService := "volumes"

	// Step 1: Backup database on source
	setStep("backup_db_source")
	if _, ok, errMsg := subOp(admiral.ActionBackupDatabase, sourceNodeID, "", dbBackupService); !ok {
		fail("backup database: " + errMsg)
		_ = h.db.UpdateCustomerAppStatus(instID, "", "failed")
		return
	}

	// Step 2: Backup volumes on source
	setStep("backup_volumes_source")
	if _, ok, errMsg := subOp(admiral.ActionBackupVolumes, sourceNodeID, "", volBackupService); !ok {
		fail("backup volumes: " + errMsg)
		_ = h.db.UpdateCustomerAppStatus(instID, "", "failed")
		return
	}

	// Step 3: Save existing routes before deprovision
	setStep("saving_routes")
	var savedRoutes []database.PublicRoute
	if h.networking != nil {
		savedRoutes, _ = h.db.GetRoutesByInstance(instID)
	}

	rollbackPreCutover := func(reason string) {
		if targetProvisioned {
			setStep("rollback_target_cleanup")
			if _, ok, errMsg := subOp(admiral.ActionDeprovisionApp, targetNodeID, "", ""); !ok {
				reason += "; target cleanup failed: " + errMsg
			}
		}
		if sourceStopped {
			setStep("rollback_source_restart")
			if _, ok, errMsg := subOp(admiral.ActionStartApp, sourceNodeID, "", ""); !ok {
				reason += "; source restart failed: " + errMsg
				_ = h.db.UpdateCustomerAppStatus(instID, "", "failed")
			}
		}
		if len(savedRoutes) > 0 && h.networking != nil {
			setStep("rollback_routes")
			if err := reconcileRoutes(sourceNodeID, savedRoutes); err != nil {
				reason += "; route rollback failed: " + err.Error()
			}
		}
		fail(reason)
	}

	// Step 4: Stop source before cutover
	setStep("stopping_source")
	if _, ok, errMsg := subOp(admiral.ActionStopApp, sourceNodeID, "", ""); !ok {
		fail("stop source: " + errMsg)
		return
	}
	sourceStopped = true

	// Step 5: Provision on target
	setStep("provisioning_target")
	if _, ok, errMsg := subOp(admiral.ActionProvisionApp, targetNodeID, "", ""); !ok {
		rollbackPreCutover("provision target: " + errMsg)
		return
	}
	targetProvisioned = true

	// Step 6: Restore backup on target
	backups, err := h.db.GetBackupRecords(instID)
	if err != nil {
		rollbackPreCutover("get backup records: " + err.Error())
		return
	}
	// Restore only the latest succeeded backup of each type
	restoreTypes := map[string]bool{}
	for _, bk := range backups {
		if bk.Status != "succeeded" {
			continue
		}
		if restoreTypes[bk.BackupType] {
			continue
		}
		restoreTypes[bk.BackupType] = true
		setStep("restoring_" + bk.BackupType)
		stepOpID := generateID("op")
		if err := h.db.CreateOperation(stepOpID, instID, targetNodeID, string(admiral.ActionRestoreBackup), "pending_dispatch", "system"); err != nil {
			rollbackPreCutover("restore create op: " + err.Error())
			return
		}
		h.enqueueRestoreTask(stepOpID, instID, targetNodeID, rawYAML, tier, &bk)
		if ok, errMsg := waitForOp(stepOpID); !ok {
			rollbackPreCutover("restore " + bk.BackupType + ": " + errMsg)
			return
		}
	}

	// Step 7: Start on target
	setStep("starting_target")
	if _, ok, errMsg := subOp(admiral.ActionStartApp, targetNodeID, "", ""); !ok {
		rollbackPreCutover("start target: " + errMsg)
		return
	}

	// Step 8: Validate target before cutover
	setStep("validating_target")
	currentInst, err := h.db.GetCustomerApp(instID)
	if err != nil {
		rollbackPreCutover("validate target instance: " + err.Error())
		return
	}
	if currentInst == nil || currentInst.TechnicalStatus != "running" {
		rollbackPreCutover("target validation failed: instance not running")
		return
	}

	// Step 9: Move node assignment and public routes to target
	setStep("cutover")
	if err := h.db.UpdateCustomerAppNode(instID, targetNodeID); err != nil {
		rollbackPreCutover("update node: " + err.Error())
		return
	}
	if len(savedRoutes) > 0 && h.networking != nil {
		if err := reconcileRoutes(targetNodeID, savedRoutes); err != nil {
			_ = h.db.UpdateCustomerAppNode(instID, sourceNodeID)
			rollbackPreCutover("cutover routes: " + err.Error())
			return
		}
	}
	cutoverComplete = true

	// Step 10: Remove the old application after cutover
	setStep("deprovisioning_source")
	if _, ok, errMsg := subOp(admiral.ActionDeprovisionApp, sourceNodeID, "", ""); !ok {
		h.log.Error("Source cleanup failed after migration cutover", nil, map[string]interface{}{"operation_id": opID, "instance_id": instID, "error": errMsg})
		setStep("cleanup_source_failed")
	}

	setStep("completed")
	_ = h.db.UpdateOperation(opID, "succeeded", "")
	h.log.Info("Migration completed successfully", map[string]interface{}{"operation_id": opID, "instance_id": instID, "cutover_complete": cutoverComplete})
}

// runtimeNodeAddress returns the only address Admiral may use for node-local
// workload routing. General-interface addresses are deliberately rejected in
// production because they bypass the authenticated WireGuard network.
func (h *APIHandlers) runtimeNodeAddress(node *database.Node) (string, error) {
	if os.Getenv("ADMIRAL_SINGLE_NODE") == "true" || (h.server != nil && h.server.devMode) {
		return "127.0.0.1", nil
	}
	if node.WireguardIP == "" {
		return "", fmt.Errorf("node %q has no WireGuard address; refusing general-interface routing", node.ID)
	}
	return node.WireguardIP, nil
}

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
			redactInspectEnvironment(inspectResult)
			writeJSON(w, http.StatusOK, inspectResult)
			return
		}
		if instanceID != "" {
			inst, _ := h.db.GetCustomerApp(instanceID)
			if inst == nil {
				writeError(w, http.StatusNotFound, "Instance not found")
				return
			}
			if appDef, aerr := h.db.GetAppDefinition(inst.AppDefinitionName); aerr == nil && appDef != nil {
				if timeout := maxSetupTimeoutSeconds(appDef.RawYAML); timeout > 0 {
					inst.SetupTimeoutSeconds = timeout
				}
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
			inst, _ := h.db.GetCustomerApp(instanceID)
			if inst == nil {
				writeError(w, http.StatusNotFound, "Instance not found")
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
			r.Header.Set("X-Admiral-Customer-ID", inst.CustomerID)
			h.HandleCustomerAppAction(w, r)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func redactInspectEnvironment(value interface{}) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			if strings.EqualFold(key, "Env") {
				if env, ok := child.([]interface{}); ok {
					for i, entry := range env {
						if text, ok := entry.(string); ok {
							if name, _, found := strings.Cut(text, "="); found {
								env[i] = name + "=[REDACTED]"
							}
						}
					}
					continue
				}
			}
			redactInspectEnvironment(child)
		}
	case []interface{}:
		for _, child := range typed {
			redactInspectEnvironment(child)
		}
	}
}

// GET & POST & DELETE /api/admin/backups
