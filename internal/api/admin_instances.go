package api

import (
	"context"
	"fmt"
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
		targetHost := targetNode.WireguardIP
		if targetHost == "" {
			targetHost = targetNode.IP
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
