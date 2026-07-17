package api

import (
	"fmt"
	"strings"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

func (h *APIHandlers) enqueueTask(opID, instID, nodeID, tenantID, rawYAML string, tier database.AppTier, action admiral.TaskAction, backupID, backupService string) {
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &payload); err != nil { //nolint:gosec // rawYAML from stored appDef.RawYAML (trusted DB data)
		h.log.Error("Failed to parse app definition for task dispatch", err, map[string]interface{}{"operation_id": opID})
		if uerr := h.db.UpdateOperation(opID, "failed", "invalid stored app definition"); uerr != nil {
			h.log.Error("Failed to update operation as failed", uerr, map[string]interface{}{"operation_id": opID})
		}
		if uerr := h.db.UpdateCustomerAppStatus(instID, "", "failed"); uerr != nil {
			h.log.Error("Failed to update instance status as failed", uerr, map[string]interface{}{"instance_id": instID})
		}
		return
	}

	var secretValues map[string]map[string]string
	if actionRequiresSecrets(action) {
		allSecretValues, err := h.decryptedSecretMap(instID)
		if err != nil {
			h.log.Error("Failed to decrypt task secrets", err, map[string]interface{}{"operation_id": opID, "instance_id": instID})
			if uerr := h.db.UpdateOperation(opID, "failed", "failed to prepare task secrets"); uerr != nil {
				h.log.Error("Failed to update operation as failed", uerr, map[string]interface{}{"operation_id": opID})
			}
			if uerr := h.db.UpdateCustomerAppStatus(instID, "", "failed"); uerr != nil {
				h.log.Error("Failed to update instance status as failed", uerr, map[string]interface{}{"instance_id": instID})
			}
			return
		}
		secretValues = scopeTaskSecrets(action, payload, allSecretValues, backupService)
	}

	services := buildServiceInfos(payload, tier, instID, tenantID, h.publicBaseURLForInstance(instID), secretValues)

	task := &admiral.FleetTask{
		TaskID:      generateID("task"),
		OperationID: opID,
		NodeID:      nodeID,
		Action:      action,
		InstanceID:  instID,
		App: admiral.AppInfo{
			Name:    payload.Name,
			Version: "latest",
		},
		Tier: admiral.TierInfo{
			Name:        tier.Name,
			CPU:         tier.CPU,
			Memory:      tier.Memory,
			Storage:     tier.Storage,
			Environment: tier.Environment,
		},
		Services:      services,
		SharedVolumes: buildSharedVolumeInfos(payload),
	}

	// Populate setup_completed from the DB so fleet can skip setup
	// if it has already been executed successfully (e.g. on a retry
	// after a lost callback).
	if action == admiral.ActionProvisionApp {
		if inst, ierr := h.db.GetCustomerApp(instID); ierr == nil && inst != nil {
			task.SetupCompleted = inst.SetupCompleted
		}
	}

	if action == admiral.ActionBackupDatabase || action == admiral.ActionBackupVolumes {
		target, err := resolveBackupTarget(payload, backupService)
		if err != nil {
			h.log.Error("Failed to resolve backup target", err, map[string]interface{}{"operation_id": opID, "service": backupService})
			if uerr := h.db.UpdateOperation(opID, "failed", err.Error()); uerr != nil {
				h.log.Error("Failed to update operation as failed", uerr, map[string]interface{}{"operation_id": opID})
			}
			if uerr := h.db.UpdateCustomerAppStatus(instID, "", "failed"); uerr != nil {
				h.log.Error("Failed to update instance status as failed", uerr, map[string]interface{}{"instance_id": instID})
			}
			return
		}
		task.Backup = buildTaskBackupInfo(target)
	}

	if backupID != "" {
		storageCfg, _ := h.db.GetActiveBackupStorageConfig()
		backend := "local"
		key := fmt.Sprintf("/var/lib/admiral/backups/%s/%s", instID, opID)
		if storageCfg != nil {
			backend = storageCfg.Backend
			backupPrefix := "database"
			if action == admiral.ActionBackupVolumes {
				backupPrefix = "volumes"
			}
			key = fmt.Sprintf("%s/%s/%s/%s-%s-%s", storageCfg.Prefix, nodeID, instID, backupService, backupPrefix, opID)
		}
		task.Storage = &admiral.StorageConfig{
			Backend:  backend,
			Key:      key,
			BackupID: backupID,
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
	}

	h.log.Info("Persisting fleet task to queue", map[string]interface{}{
		"task_id":      task.TaskID,
		"operation_id": opID,
		"node_id":      nodeID,
		"action":       action,
	})

	if uerr := h.db.UpdateOperationTaskID(opID, task.TaskID); uerr != nil {
		h.log.Error("Failed to persist task_id on operation", uerr, map[string]interface{}{"task_id": task.TaskID, "operation_id": opID})
	}
	if err := h.publisher.PublishTask(task); err != nil {
		h.log.Error("Failed to persist task to queue database", err, map[string]interface{}{"task_id": task.TaskID, "operation_id": opID})
		if uerr := h.db.UpdateOperation(opID, "failed", err.Error()); uerr != nil {
			h.log.Error("Failed to update operation as failed", uerr, map[string]interface{}{"operation_id": opID})
		}
		if uerr := h.db.UpdateCustomerAppStatus(instID, "", "failed"); uerr != nil {
			h.log.Error("Failed to update instance status as failed", uerr, map[string]interface{}{"instance_id": instID})
		}
		return
	}
	if uerr := h.db.UpdateOperation(opID, "queued", ""); uerr != nil {
		h.log.Error("Failed to update operation as queued", uerr, map[string]interface{}{"operation_id": opID})
	}
}

func (h *APIHandlers) dispatchTask(opID, instID, nodeID, tenantID, rawYAML string, tier database.AppTier, action admiral.TaskAction) {
	h.enqueueTask(opID, instID, nodeID, tenantID, rawYAML, tier, action, "", "")
}

func (h *APIHandlers) enqueueRawTask(task *admiral.FleetTask) {
	_ = h.enqueueRawTaskWithErr(task)
}

func (h *APIHandlers) enqueueRestoreTask(opID, instID, nodeID, rawYAML string, tier database.AppTier, bk *admiral.BackupRecord) {
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &payload); err != nil { //nolint:gosec // rawYAML from stored appDef.RawYAML (trusted DB data)
		h.log.Error("Failed to parse app definition for restore", err, map[string]interface{}{"operation_id": opID})
		_ = h.db.UpdateOperation(opID, "failed", "invalid stored app definition")
		return
	}

	allSecretValues, err := h.decryptedSecretMap(instID)
	if err != nil {
		h.log.Error("Failed to decrypt secrets for restore", err, map[string]interface{}{"operation_id": opID})
		_ = h.db.UpdateOperation(opID, "failed", "failed to prepare restore secrets")
		return
	}

	services := buildServiceInfos(payload, tier, instID, "", h.publicBaseURLForInstance(instID), allSecretValues)

	srcType := strings.ToLower(strings.TrimSpace(bk.StorageBackend))
	srcURI := bk.StorageKey
	if srcType == "" || srcType == "local" {
		srcType = "local_path"
	}

	target, err := resolveRestoreTarget(payload, bk.BackupType, "")
	if err != nil {
		h.log.Error("Failed to resolve restore target", err, map[string]interface{}{"operation_id": opID})
		_ = h.db.UpdateOperation(opID, "failed", err.Error())
		return
	}

	task := &admiral.FleetTask{
		TaskID:        generateID("task"),
		OperationID:   opID,
		NodeID:        nodeID,
		Action:        admiral.ActionRestoreBackup,
		InstanceID:    instID,
		App:           admiral.AppInfo{Name: payload.Name, Version: "latest"},
		Tier:          admiral.TierInfo{Name: tier.Name, CPU: tier.CPU, Memory: tier.Memory, Storage: tier.Storage, Environment: tier.Environment},
		Services:      services,
		SharedVolumes: buildSharedVolumeInfos(payload),
		Backup:        buildTaskBackupInfo(target),
		Restore: &admiral.RestoreInfo{
			BackupID:       bk.ID,
			StorageBackend: srcType,
			StorageKey:     srcURI,
			BackupType:     bk.BackupType,
			DatabaseType:   bk.DatabaseType,
			Service:        target.ServiceName,
			ChecksumSHA256: bk.ChecksumSHA256,
			VerifyChecksum: true,
		},
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

	h.enqueueRawTask(task)
	_ = h.db.UpdateOperationTaskID(opID, task.TaskID)
	_ = h.db.UpdateOperation(opID, "queued", "")
}

func (h *APIHandlers) enqueueRawTaskWithErr(task *admiral.FleetTask) error {
	if uerr := h.db.UpdateOperationTaskID(task.OperationID, task.TaskID); uerr != nil {
		h.log.Error("Failed to persist task_id on operation from raw task", uerr, map[string]interface{}{"task_id": task.TaskID, "operation_id": task.OperationID})
		return fmt.Errorf("persist task id for operation %q: %w", task.OperationID, uerr)
	}
	if err := h.publisher.PublishTask(task); err != nil {
		h.log.Error("Failed to persist raw task to queue database", err, map[string]interface{}{"task_id": task.TaskID, "operation_id": task.OperationID})
		if uerr := h.db.UpdateOperation(task.OperationID, "failed", err.Error()); uerr != nil {
			h.log.Error("Failed to update operation as failed", uerr, map[string]interface{}{"operation_id": task.OperationID})
		}
		return fmt.Errorf("publish raw task %q: %w", task.TaskID, err)
	}
	if uerr := h.db.UpdateOperation(task.OperationID, "queued", ""); uerr != nil {
		h.log.Error("Failed to update operation as queued", uerr, map[string]interface{}{"operation_id": task.OperationID})
		return fmt.Errorf("mark operation %q queued: %w", task.OperationID, uerr)
	}
	return nil
}

func parseAppPayload(rawYAML string) *admiral.AppDefinitionPayload {
	var p admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &p); err != nil {
		return nil
	}
	return &p
}

func (h *APIHandlers) decryptedSecretMap(instanceID string) (map[string]map[string]string, error) {
	rows, err := h.db.GetInstanceSecrets(instanceID)
	if err != nil {
		return nil, err
	}
	result := make(map[string]map[string]string)
	for _, row := range rows {
		plain, err := h.secrets.Decrypt(row.EncryptedValue)
		if err != nil {
			return nil, err
		}
		if result[row.ServiceName] == nil {
			result[row.ServiceName] = make(map[string]string)
		}
		result[row.ServiceName][row.EnvName] = plain
	}
	return result, nil
}

func actionRequiresSecrets(action admiral.TaskAction) bool {
	switch action {
	case admiral.ActionProvisionApp, admiral.ActionRestoreBackup,
		admiral.ActionStartApp, admiral.ActionResumeApp,
		admiral.ActionBackupDatabase:
		return true
	default:
		return false
	}
}

func retryableAction(action admiral.TaskAction) (admiral.TaskAction, string, bool) {
	switch action {
	case admiral.ActionProvisionApp:
		return admiral.ActionProvisionApp, "provisioning", true
	case admiral.ActionStartApp, admiral.ActionResumeApp, admiral.ActionReactivateApp:
		return action, "running", true
	case admiral.ActionStopApp, admiral.ActionPauseApp:
		return action, "stopped", true
	case admiral.ActionResizeApp:
		return admiral.ActionResizeApp, "running", true
	case admiral.ActionDeprovisionApp:
		return admiral.ActionDeprovisionApp, "deprovisioning", true
	default:
		return "", "", false
	}
}

func scopeTaskSecrets(action admiral.TaskAction, payload admiral.AppDefinitionPayload, all map[string]map[string]string, serviceName string) map[string]map[string]string {
	switch action {
	case admiral.ActionProvisionApp, admiral.ActionRestoreBackup,
		admiral.ActionStartApp, admiral.ActionResumeApp:
		return cloneSecretMap(all)
	case admiral.ActionBackupDatabase:
		return scopeBackupSecrets(payload, all, serviceName)
	default:
		return map[string]map[string]string{}
	}
}

func scopeBackupSecrets(payload admiral.AppDefinitionPayload, all map[string]map[string]string, serviceName string) map[string]map[string]string {
	target, err := resolveBackupTarget(payload, serviceName)
	if err != nil || target.Backup.Type != "database" {
		return map[string]map[string]string{}
	}

	serviceSecrets := all[target.ServiceName]
	if len(serviceSecrets) == 0 {
		return map[string]map[string]string{}
	}

	required := map[string]struct{}{
		target.Backup.DatabaseEnv: {},
		target.Backup.UsernameEnv: {},
		target.Backup.PasswordEnv: {},
	}

	filtered := make(map[string]string)
	for name, value := range serviceSecrets {
		if _, ok := required[name]; ok {
			filtered[name] = value
		}
	}
	if len(filtered) == 0 {
		return map[string]map[string]string{}
	}
	return map[string]map[string]string{target.ServiceName: filtered}
}

func cloneSecretMap(all map[string]map[string]string) map[string]map[string]string {
	cloned := make(map[string]map[string]string, len(all))
	for serviceName, serviceSecrets := range all {
		inner := make(map[string]string, len(serviceSecrets))
		for envName, value := range serviceSecrets {
			inner[envName] = value
		}
		cloned[serviceName] = inner
	}
	return cloned
}

func (h *APIHandlers) publicBaseURLForInstance(instanceID string) string {
	routes, err := h.db.GetRoutesByInstance(instanceID)
	if err != nil || len(routes) == 0 {
		return ""
	}
	for _, route := range routes {
		if route.Hostname != "" {
			return "https://" + strings.TrimRight(route.Hostname, "/") + "/"
		}
	}
	return ""
}
