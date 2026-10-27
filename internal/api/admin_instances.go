package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

func (h *APIHandlers) runMigration(opID, instID, customerID, sourceNodeID, targetNodeID, rawYAML string, tier database.AppTier, logicalInstanceID string) {
	currentStep := "starting"
	var savedRoutes []database.PublicRoute
	var freshBackupIDs []string
	migrationMetadata := func(step string) *database.OperationMetadata {
		return &database.OperationMetadata{
			TargetNodeID:      targetNodeID,
			SourceNodeID:      sourceNodeID,
			LogicalInstanceID: logicalInstanceID,
			MigrationStep:     step,
			MigrationRoutes:   savedRoutes,
			BackupRecordIDs:   freshBackupIDs,
		}
	}

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
				case "failed", "cancelled":
					errMsg := ""
					if op.ErrorMessage != nil {
						errMsg = *op.ErrorMessage
					}
					if errMsg == "" {
						errMsg = "operation " + op.Status
					}
					return false, errMsg
				}
			case <-timeout:
				return false, "operation timed out after 30 minutes"
			}
		}
	}

	waitForBackupRecord := func(backupID string) (bool, string) {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		timeout := time.After(30 * time.Second)
		for {
			select {
			case <-ticker.C:
				rec, err := h.db.GetBackupRecord(backupID)
				if err != nil || rec == nil {
					continue
				}
				switch rec.Status {
				case "succeeded":
					if strings.TrimSpace(rec.StorageKey) == "" {
						return false, "backup completed without a storage key"
					}
					checksum, err := hex.DecodeString(strings.TrimSpace(rec.ChecksumSHA256))
					if err != nil || len(checksum) != 32 {
						return false, "backup completed without a valid SHA-256 checksum"
					}
					if rec.StorageBackend != "s3" {
						return false, "migration requires shared S3 backup storage accessible from both workers"
					}
					return true, ""
				case "failed":
					if strings.TrimSpace(rec.ErrorMessage) != "" {
						return false, rec.ErrorMessage
					}
					return false, "backup record failed"
				}
			case <-timeout:
				return false, "backup record did not reach succeeded after task completion"
			}
		}
	}

	setStep := func(step string) {
		currentStep = step
		_ = h.db.UpdateOperationMetadata(opID, migrationMetadata(step))
	}

	subOp := func(action admiral.TaskAction, nodeID string, backupID, backupService string) (string, bool, string) {
		stepOpID := generateID("op")
		if err := h.db.CreateOperationWithMetadata(stepOpID, instID, nodeID, string(action), "pending_dispatch", "system", migrationMetadata(currentStep)); err != nil {
			return stepOpID, false, err.Error()
		}
		if action == admiral.ActionBackupDatabase || action == admiral.ActionBackupVolumes {
			createdBackupID, err := h.createMigrationBackupRecord(stepOpID, instID, nodeID, rawYAML, tier, action, backupService)
			if err != nil {
				_ = h.db.UpdateOperation(stepOpID, "failed", "create migration backup record: "+err.Error())
				return stepOpID, false, "create migration backup record: " + err.Error()
			}
			backupID = createdBackupID
		}
		if err := h.enqueueTaskWithID(generateID("task"), stepOpID, instID, nodeID, customerID, rawYAML, tier, action, backupID, backupService); err != nil {
			return stepOpID, false, err.Error()
		}
		ok, errMsg := waitForOp(stepOpID)
		if !ok {
			return stepOpID, false, errMsg
		}
		if backupID != "" {
			if ok, errMsg := waitForBackupRecord(backupID); !ok {
				return stepOpID, false, errMsg
			}
			freshBackupIDs = append(freshBackupIDs, backupID)
			if err := h.db.UpdateOperationMetadata(opID, migrationMetadata(currentStep)); err != nil {
				return stepOpID, false, "save migration backup identity: " + err.Error()
			}
		}
		return stepOpID, ok, errMsg
	}

	fail := func(msg string) {
		h.log.Error("Migration failed", nil, map[string]interface{}{"operation_id": opID, "instance_id": instID, "error": msg})
		_ = h.db.UpdateOperation(opID, "failed", msg)
	}
	failForIntervention := func(msg string) {
		if err := h.db.UpdateCustomerAppStatus(instID, "", "failed"); err != nil {
			msg += "; mark instance failed: " + err.Error()
		}
		fail(msg)
	}
	waitForNodeHealthy := func(nodeID string, since time.Time) error {
		deadline := time.NewTimer(2 * time.Minute)
		defer deadline.Stop()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				healthy, err := h.db.MigrationInstanceHealthy(instID, nodeID, since)
				if err == nil && healthy {
					return nil
				}
			case <-deadline.C:
				return fmt.Errorf("node %q did not report a fresh healthy workload within two minutes", nodeID)
			}
		}
	}

	reconcileRoutes := func(nodeID string, routes []database.PublicRoute, hostPorts map[string]int) error {
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
		updated := make([]database.PublicRoute, 0, len(routes))
		for _, route := range routes {
			port := hostPorts[route.ServiceName]
			if port <= 0 {
				return fmt.Errorf("target did not report a host port for service %q", route.ServiceName)
			}
			route.NodeID = &nodeID
			route.TargetHost = targetHost
			route.TargetPort = port
			route.TargetURL = fmt.Sprintf("http://%s:%d", targetHost, route.TargetPort)
			updated = append(updated, route)
		}
		if len(updated) > 0 {
			return h.networking.UpdateRoutesAndSync(context.Background(), updated)
		}
		return nil
	}

	sourceStopped := false
	targetProvisionAttempted := false
	targetCapacityReserved := false
	cutoverComplete := false
	ramBytes := database.ParseSizeBytes(tier.Memory)
	diskBytes := database.ParseSizeBytes(tier.Storage)

	setStep("saving_routes")
	var err error
	savedRoutes, err = h.db.GetRoutesByInstance(instID)
	if err != nil {
		fail("load instance routes: " + err.Error())
		return
	}
	if len(savedRoutes) > 0 && (h.networking == nil || h.networking.Caddy == nil) {
		fail("public routes cannot be put into maintenance without Caddy")
		return
	}
	if err := h.db.UpdateOperationMetadata(opID, migrationMetadata(currentStep)); err != nil {
		fail("save original routes: " + err.Error())
		return
	}
	restoreOriginalRoutes := func() error {
		currentStep = "rollback_routes"
		if err := h.db.UpdateOperationMetadata(opID, migrationMetadata(currentStep)); err != nil {
			return fmt.Errorf("record route rollback: %w", err)
		}
		if len(savedRoutes) > 0 {
			return h.networking.UpdateRoutesAndSync(context.Background(), savedRoutes)
		}
		return nil
	}
	abortBeforeStop := func(reason string) {
		if err := restoreOriginalRoutes(); err != nil {
			reason += "; restore original routes: " + err.Error()
		}
		fail(reason)
	}
	enableMaintenance := func() error {
		currentStep = "maintenance"
		if err := h.db.UpdateOperationMetadata(opID, migrationMetadata(currentStep)); err != nil {
			return fmt.Errorf("record maintenance: %w", err)
		}
		var routes []database.PublicRoute
		for _, original := range savedRoutes {
			route, err := h.db.GetPublicRoute(original.Hostname)
			if err != nil || route == nil {
				return fmt.Errorf("load route %q for maintenance: %v", original.Hostname, err)
			}
			route.Status = string(admiral.RouteStatusDisabled)
			routes = append(routes, *route)
		}
		if len(routes) > 0 {
			return h.networking.UpdateRoutesAndSync(context.Background(), routes)
		}
		return nil
	}
	if len(savedRoutes) > 0 {
		setStep("maintenance")
		if err := enableMaintenance(); err != nil {
			msg := "apply maintenance in Caddy: " + err.Error()
			if rerr := restoreOriginalRoutes(); rerr != nil {
				msg += "; restore original routes: " + rerr.Error()
			}
			fail(msg)
			return
		}
		time.Sleep(30 * time.Second)
	}
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &payload); err != nil {
		abortBeforeStop("parse migration app definition: " + err.Error())
		return
	}
	serviceNames := make([]string, 0, len(payload.Services))
	for name := range payload.Services {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)
	for _, name := range serviceNames {
		backup := payload.Services[name].Backup
		if backup == nil || backup.Type == "none" {
			continue
		}
		var action admiral.TaskAction
		switch backup.Type {
		case "database":
			action = admiral.ActionBackupDatabase
		case "volume":
			action = admiral.ActionBackupVolumes
		default:
			abortBeforeStop(fmt.Sprintf("unsupported backup type %q for service %q", backup.Type, name))
			return
		}
		setStep("backup_" + name)
		if _, ok, errMsg := subOp(action, sourceNodeID, "", name); !ok {
			if rerr := restoreOriginalRoutes(); rerr != nil {
				errMsg += "; restore routes: " + rerr.Error()
			}
			fail("backup " + name + ": " + errMsg)
			return
		}
	}
	releaseMigrationCapacity := func(nodeID string) error {
		if err := h.db.ReleaseNodeCommitment(nodeID, ramBytes, diskBytes); err != nil {
			return fmt.Errorf("release migration capacity on node %q: %w", nodeID, err)
		}
		h.auditCapacityEvent("node_capacity_released", nodeID, instID, opID, admiral.TaskAction("migrate"), ramBytes, diskBytes)
		if err := h.recomputeNodePolicy(nodeID); err != nil {
			h.log.Error("Failed to recompute node policy after migration capacity release", err, map[string]interface{}{"node_id": nodeID, "instance_id": instID, "operation_id": opID})
		}
		return nil
	}

	rollbackPreCutover := func(reason string) {
		targetCleanupSucceeded := !targetProvisionAttempted
		if targetProvisionAttempted {
			setStep("rollback_target_cleanup")
			if _, ok, errMsg := subOp(admiral.ActionDeprovisionApp, targetNodeID, "", ""); !ok {
				reason += "; target cleanup failed: " + errMsg
			} else {
				targetCleanupSucceeded = true
			}
		}
		if targetCapacityReserved && targetCleanupSucceeded {
			if err := releaseMigrationCapacity(targetNodeID); err != nil {
				reason += "; release target capacity: " + err.Error()
			} else {
				targetCapacityReserved = false
			}
		}
		sourceRecovered := true
		if sourceStopped {
			setStep("rollback_source_restart")
			if _, ok, errMsg := subOp(admiral.ActionStartApp, sourceNodeID, "", ""); !ok {
				reason += "; source restart failed: " + errMsg
				sourceRecovered = false
				_ = h.db.UpdateCustomerAppStatus(instID, "", "failed")
			} else if err := waitForNodeHealthy(sourceNodeID, time.Now().UTC()); err != nil {
				reason += "; source health: " + err.Error()
				sourceRecovered = false
				_ = h.db.UpdateCustomerAppStatus(instID, "", "failed")
			} else if err := h.db.UpdateCustomerAppStatus(instID, "", "running"); err != nil {
				reason += "; restore source status: " + err.Error()
				sourceRecovered = false
			}
		}
		if sourceRecovered && len(savedRoutes) > 0 {
			setStep("rollback_routes")
			if err := restoreOriginalRoutes(); err != nil {
				reason += "; route rollback failed: " + err.Error()
			}
		}
		fail(reason)
	}
	if ramBytes <= 0 || diskBytes <= 0 {
		abortBeforeStop("migration tier has invalid RAM or storage capacity")
		return
	}
	if err := h.db.ReserveNodeCapacity(targetNodeID, ramBytes, diskBytes); err != nil {
		abortBeforeStop("reserve target capacity: " + err.Error())
		return
	}
	targetCapacityReserved = true

	// Pause keeps the source workload available for rollback.
	setStep("pausing_source")
	sourceStopped = true // a failed stop can still have stopped some units
	if _, ok, errMsg := subOp(admiral.ActionPauseApp, sourceNodeID, "", ""); !ok {
		rollbackPreCutover("pause source: " + errMsg)
		return
	}
	if err := h.db.UpdateCustomerAppStatus(instID, "", "migrating"); err != nil {
		rollbackPreCutover("mark instance migrating: " + err.Error())
		return
	}

	// Step 5: Provision on target
	setStep("provisioning_target")
	targetProvisionAttempted = true
	if _, ok, errMsg := subOp(admiral.ActionProvisionApp, targetNodeID, "", ""); !ok {
		rollbackPreCutover("provision target: " + errMsg)
		return
	}

	// Step 6: Restore backup on target
	for _, backupID := range freshBackupIDs {
		bk, err := h.db.GetBackupRecord(backupID)
		if err != nil || bk == nil || bk.Status != "succeeded" {
			rollbackPreCutover("migration backup is unavailable: " + backupID)
			return
		}
		setStep("restoring_" + bk.BackupType)
		stepOpID := generateID("op")
		if err := h.db.CreateOperationWithMetadata(stepOpID, instID, targetNodeID, string(admiral.ActionRestoreBackup), "pending_dispatch", "system", migrationMetadata(currentStep)); err != nil {
			rollbackPreCutover("restore create op: " + err.Error())
			return
		}
		h.enqueueRestoreTask(stepOpID, instID, targetNodeID, rawYAML, tier, bk)
		if ok, errMsg := waitForOp(stepOpID); !ok {
			rollbackPreCutover("restore " + bk.BackupType + ": " + errMsg)
			return
		}
	}

	// Step 7: Start on target
	setStep("starting_target")
	targetStartID, ok, errMsg := subOp(admiral.ActionStartApp, targetNodeID, "", "")
	if !ok {
		rollbackPreCutover("start target: " + errMsg)
		return
	}
	targetStart, err := h.db.GetOperation(targetStartID)
	if err != nil || targetStart == nil || targetStart.Metadata == nil {
		rollbackPreCutover("load target start metadata")
		return
	}
	for _, route := range savedRoutes {
		if targetStart.Metadata.HostPorts[route.ServiceName] <= 0 {
			rollbackPreCutover("target did not report a host port for service " + route.ServiceName)
			return
		}
	}

	// Step 8: Validate target before cutover
	setStep("validating_target")
	currentInst, err := h.db.GetCustomerApp(instID)
	if err != nil {
		rollbackPreCutover("validate target instance: " + err.Error())
		return
	}
	if currentInst == nil || currentInst.TechnicalStatus != "migrating" || currentInst.NodeID == nil || *currentInst.NodeID != sourceNodeID {
		rollbackPreCutover("target validation failed: instance migration state changed")
		return
	}

	// Step 9: Move node assignment and public routes to target
	setStep("cutover")
	if err := h.db.UpdateCustomerAppNode(instID, targetNodeID); err != nil {
		rollbackPreCutover("update node: " + err.Error())
		return
	}
	if err := waitForNodeHealthy(targetNodeID, time.Now().UTC()); err != nil {
		if rerr := h.db.UpdateCustomerAppNode(instID, sourceNodeID); rerr != nil {
			failForIntervention("target health: " + err.Error() + "; restore source assignment: " + rerr.Error())
			return
		}
		rollbackPreCutover("target health: " + err.Error())
		return
	}
	if len(savedRoutes) > 0 {
		currentStep = "enabling_target_routes"
		if err := h.db.UpdateOperationMetadata(opID, migrationMetadata(currentStep)); err != nil {
			if rerr := h.db.UpdateCustomerAppNode(instID, sourceNodeID); rerr != nil {
				failForIntervention("record target routes: " + err.Error() + "; restore source assignment: " + rerr.Error())
				return
			}
			rollbackPreCutover("record target routes: " + err.Error())
			return
		}
		if err := reconcileRoutes(targetNodeID, savedRoutes, targetStart.Metadata.HostPorts); err != nil {
			if merr := enableMaintenance(); merr != nil {
				failForIntervention("cutover routes: " + err.Error() + "; restore maintenance: " + merr.Error())
				return
			}
			// Caddy may have accepted traffic on the destination before its
			// response was lost. Preserve both workloads and require operator
			// reconciliation instead of discarding possible target writes.
			failForIntervention("cutover route outcome is uncertain; maintenance restored and both workloads preserved: " + err.Error())
			return
		}
	}
	cutoverComplete = true
	failAfterCutover := func(reason string) {
		if err := h.db.UpdateCustomerAppStatus(instID, "", "running"); err != nil {
			reason += "; update target status: " + err.Error()
		}
		fail(reason)
	}

	// Step 10: Remove the old application after cutover
	setStep("deprovisioning_source")
	if _, ok, errMsg := subOp(admiral.ActionDeprovisionApp, sourceNodeID, "", ""); !ok {
		h.log.Error("Source cleanup failed after migration cutover", nil, map[string]interface{}{"operation_id": opID, "instance_id": instID, "error": errMsg})
		setStep("cleanup_source_failed")
		failAfterCutover("cutover succeeded but source cleanup failed: " + errMsg)
		return
	} else if err := releaseMigrationCapacity(sourceNodeID); err != nil {
		h.log.Error("Failed to release source capacity after migration", err, map[string]interface{}{"operation_id": opID, "instance_id": instID, "node_id": sourceNodeID})
		failAfterCutover("cutover succeeded but source capacity release failed: " + err.Error())
		return
	}
	if err := h.db.ClearCustomerAppRestartRequired(instID); err != nil {
		failAfterCutover("cutover succeeded but restart state could not be cleared: " + err.Error())
		return
	}
	if err := h.db.UpdateCustomerAppStatus(instID, "", "running"); err != nil {
		fail("cutover succeeded but target status could not be updated: " + err.Error())
		return
	}

	setStep("completed")
	_ = h.db.UpdateOperation(opID, "succeeded", "")
	h.log.Info("Migration completed successfully", map[string]interface{}{"operation_id": opID, "instance_id": instID, "cutover_complete": cutoverComplete})
}

func (h *APIHandlers) createMigrationBackupRecord(operationID, instanceID, nodeID, rawYAML string, tier database.AppTier, action admiral.TaskAction, serviceName string) (string, error) {
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &payload); err != nil {
		return "", fmt.Errorf("parse app definition: %w", err)
	}
	target, err := resolveBackupTarget(payload, serviceName)
	if err != nil {
		return "", err
	}
	inst, err := h.db.GetCustomerApp(instanceID)
	if err != nil {
		return "", fmt.Errorf("load instance: %w", err)
	}
	if inst == nil {
		return "", fmt.Errorf("instance %q not found", instanceID)
	}
	storageCfg, err := h.db.GetActiveBackupStorageConfig()
	if err != nil {
		return "", fmt.Errorf("load backup storage configuration: %w", err)
	}
	storageBackend := "local"
	storageKey := fmt.Sprintf("/var/lib/admiral/backups/%s/%s", instanceID, operationID)
	if storageCfg != nil {
		storageBackend = storageCfg.Backend
		backupPrefix := "database"
		if action == admiral.ActionBackupVolumes {
			backupPrefix = "volumes"
		}
		storageKey = fmt.Sprintf("%s/%s/%s/%s-%s-%s", storageCfg.Prefix, nodeID, instanceID, serviceName, backupPrefix, operationID)
	}
	backupType := target.Backup.Type
	databaseType := target.Backup.Engine
	if databaseType == "" && backupType == "volume" {
		databaseType = "none"
	}
	backupID := generateID("bk")
	rec := &admiral.BackupRecord{
		ID:                          backupID,
		InstanceID:                  instanceID,
		AppID:                       inst.AppDefinitionName,
		TierID:                      tier.Name,
		NodeID:                      nodeID,
		BackupType:                  backupType,
		Service:                     serviceName,
		DatabaseType:                databaseType,
		Status:                      "pending",
		StorageBackend:              storageBackend,
		StorageKey:                  storageKey,
		TriggeredBy:                 "system",
		RetentionPolicySnapshotJSON: `{"count":7,"days":30}`,
		TierSnapshotJSON:            inst.TierSnapshotJSON,
	}
	if err := h.db.CreateBackupRecord(rec); err != nil {
		return "", err
	}
	return backupID, nil
}

// runtimeNodeAddress returns the only address Admiral may use for node-local
// workload routing. General-interface addresses are deliberately rejected in
// production because they bypass the authenticated WireGuard network.
func (h *APIHandlers) runtimeNodeAddress(node *database.Node) (string, error) {
	if singleNodeMode(h.server != nil && h.server.devMode) {
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
	if targetNode.NodeRole != "worker" {
		writeError(w, http.StatusConflict, "Target node must be a worker")
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
	if err := h.db.CreateMigrationOperation(opID, instanceID, sourceNodeID, operatorFromRequest(r), meta); err != nil {
		if errors.Is(err, database.ErrMigrationConflict) {
			writeError(w, http.StatusConflict, "Instance state or active operations prevent migration")
			return
		}
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
		needRestarting := r.URL.Query().Get("need_restarting") == "true"
		updateType := r.URL.Query().Get("update_type")
		apps, total, err := h.db.GetCustomerAppsPageFiltered(pageSize, (page-1)*pageSize, "", needRestarting, updateType)
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
