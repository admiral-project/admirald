// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

// StartBackupScheduler launches the background scheduler loop.
func (s *Server) StartBackupScheduler(ctx context.Context) {
	s.log.Info("Starting administrative backup scheduler background worker", nil)
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("Stopping backup scheduler", nil)
			return
		case <-ticker.C:
			s.RunSchedulerIteration()
		}
	}
}

func (s *Server) RunSchedulerIteration() {
	s.checkGracePeriodExpiry()

	instances, err := s.handlers.db.GetCustomerApps("")
	if err != nil {
		s.log.Error("Scheduler failed to query customer apps", err, nil)
		return
	}

	for _, inst := range instances {
		if inst.NodeID == nil || *inst.NodeID == "" || inst.TechnicalStatus != "running" {
			continue
		}

		// Extract tier backup policy
		var policy *admiral.BackupPolicy
		if inst.TierSnapshotJSON != "" {
			var tier admiral.YAMLTier
			if err := json.Unmarshal([]byte(inst.TierSnapshotJSON), &tier); err == nil && tier.Backups != nil {
				policy = tier.Backups
			}
		}

		if policy == nil {
			// Fall back to querying the database for the current tier definition
			tiers, err := s.handlers.db.GetAppTiers(inst.AppDefinitionName)
			if err == nil {
				for _, t := range tiers {
					if t.Name == inst.TierName && t.BackupPolicyJSON != "" {
						var bp admiral.BackupPolicy
						if err := json.Unmarshal([]byte(t.BackupPolicyJSON), &bp); err == nil {
							policy = &bp
						}
						break
					}
				}
			}
		}

		if policy == nil || !policy.Enabled || policy.Schedule == "disabled" {
			continue
		}

		// Determine if it's time to run
		shouldBackup, err := s.EvaluateBackupSchedule(inst.ID, policy, inst.CreatedAt)
		if err != nil {
			s.log.Error("Error evaluating backup schedule", err, map[string]interface{}{"instance_id": inst.ID})
			continue
		}

		if shouldBackup {
			s.log.Info("Scheduler detected backup due for instance", map[string]interface{}{"instance_id": inst.ID, "schedule": policy.Schedule})
			s.TriggerScheduledBackup(inst.ID, policy)
		}
	}
}

func (s *Server) EvaluateBackupSchedule(instanceID string, policy *admiral.BackupPolicy, createdAt time.Time) (bool, error) {
	// Parse timezone
	loc := time.UTC
	if policy.Timezone != "" {
		if l, err := time.LoadLocation(policy.Timezone); err == nil {
			loc = l
		}
	}

	now := time.Now().In(loc)
	schedTime, err := time.ParseInLocation("15:04", policy.Time, loc)
	if err != nil {
		return false, fmt.Errorf("invalid policy time format %q: %w", policy.Time, err)
	}

	// Calculate target execution time on current date
	targetTime := time.Date(now.Year(), now.Month(), now.Day(), schedTime.Hour(), schedTime.Minute(), 0, 0, loc)

	// If current time is before target time today, we don't trigger yet
	if now.Before(targetTime) {
		return false, nil
	}

	// Instance created after today's scheduled window — defer to next cycle.
	// Prevents immediate backup of freshly provisioned instances whose
	// scheduled time has already passed for the current day/week.
	if createdAt.After(targetTime) {
		return false, nil
	}

	// New instances created today should defer their first backup to the next
	// scheduled cycle (tomorrow for daily, next week for weekly).
	// This prevents a race where an instance is provisioned shortly before
	// today's backup window and immediately triggers a backup before the
	// pod containers are ready.
	todayMidnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	if createdAt.After(todayMidnight) {
		return false, nil
	}

	// Retrieve historical backup records for this instance
	recs, err := s.handlers.db.GetBackupRecords(instanceID)
	if err != nil {
		return false, err
	}

	if policy.Schedule == "daily" {
		// Verify if a scheduled backup already ran (or is pending/running) today (UTC day check)
		todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
		for _, r := range recs {
			if r.TriggeredBy == "scheduled" {
				rTime, err := time.Parse(time.RFC3339, r.CreatedAt)
				if err == nil {
					rTimeInLoc := rTime.In(loc)
					if rTimeInLoc.After(todayStart) {
						return false, nil // Already triggered today
					}
				}
			}
		}
		return true, nil
	}

	if policy.Schedule == "weekly" {
		// Check weekday
		weekdayStr := strings.ToLower(now.Weekday().String())
		targetWeekday := strings.ToLower(policy.Weekday)
		if targetWeekday == "" {
			targetWeekday = "sunday" // fallback default
		}
		if weekdayStr != targetWeekday {
			return false, nil
		}

		// Verify if a scheduled backup already ran in the last 6 days
		sixDaysAgo := now.Add(-6 * 24 * time.Hour)
		for _, r := range recs {
			if r.TriggeredBy == "scheduled" {
				rTime, err := time.Parse(time.RFC3339, r.CreatedAt)
				if err == nil {
					rTimeInLoc := rTime.In(loc)
					if rTimeInLoc.After(sixDaysAgo) {
						return false, nil // Already triggered in this weekly cycle
					}
				}
			}
		}
		return true, nil
	}

	return false, nil
}

func (s *Server) checkGracePeriodExpiry() {
	apps, err := s.handlers.db.GetExpiredGracePeriodApps()
	if err != nil {
		s.log.Error("Failed to query expired grace period apps", err, nil)
		return
	}

	for _, app := range apps {
		if app.TechnicalStatus == "stopped" || app.TechnicalStatus == "paused_for_storage" {
			continue
		}
		if app.NodeID == nil || *app.NodeID == "" {
			continue
		}

		s.log.Info("Grace period expired - pausing app for storage", map[string]interface{}{
			"instance_id": app.ID,
			"node_id":     *app.NodeID,
		})

		opID := generateID("op")
		if err := s.handlers.db.CreateOperation(opID, app.ID, *app.NodeID, string(admiral.ActionPauseAppStorage), "pending_dispatch", "system"); err != nil {
			s.log.Error("Failed to create storage pause operation", err, map[string]interface{}{"instance_id": app.ID, "node_id": *app.NodeID})
			continue
		}

		task := &admiral.FleetTask{
			TaskID:      generateID("task"),
			OperationID: opID,
			NodeID:      *app.NodeID,
			Action:      admiral.ActionPauseAppStorage,
			InstanceID:  app.ID,
		}
		if err := s.handlers.enqueueRawTaskWithErr(task); err != nil {
			s.log.Error("Failed to enqueue storage pause task", err, map[string]interface{}{"instance_id": app.ID, "operation_id": opID})
			continue
		}

		if err := s.handlers.db.UpdateCustomerAppStatus(app.ID, "", "paused_for_storage"); err != nil {
			s.log.Error("Failed to update instance storage pause status", err, map[string]interface{}{"instance_id": app.ID, "operation_id": opID})
		}
	}
}

func (s *Server) TriggerScheduledBackup(instanceID string, policy *admiral.BackupPolicy) {
	// Schedule backup triggers tasks database and/or volumes
	inst, err := s.handlers.db.GetCustomerApp(instanceID)
	if err != nil || inst == nil {
		return
	}

	appDef, err := s.handlers.db.GetAppDefinition(inst.AppDefinitionName)
	if err != nil || appDef == nil {
		return
	}

	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(appDef.RawYAML), &payload); err != nil {
		s.log.Error("Failed to parse app definition YAML in scheduler", err, map[string]interface{}{"instance_id": instanceID, "app_name": inst.AppDefinitionName})
		return
	}

	tiers, err := s.handlers.db.GetAppTiers(inst.AppDefinitionName)
	if err != nil {
		s.log.Error("Failed to load tiers for scheduled backup", err, map[string]interface{}{"instance_id": instanceID})
		return
	}

	matchedTier := database.AppTier{Name: inst.TierName}
	for _, t := range tiers {
		if t.Name == inst.TierName {
			matchedTier = t
			break
		}
	}

	// Trigger Database backup if configured
	if policy.BackupDatabase {
		for _, target := range backupTargetsByType(payload, "database") {
			s.log.Info("Triggering scheduled database backup", map[string]interface{}{"instance_id": instanceID, "service": target.ServiceName})
			h := s.handlers

			opID := generateID("op")
			if err := h.db.UpdateCustomerAppStatus(instanceID, "", "backup_running"); err != nil {
				s.log.Error("Failed to set backup_running status for scheduled database backup", err, map[string]interface{}{"instance_id": instanceID, "service": target.ServiceName})
				continue
			}
			if err := h.db.CreateOperation(opID, instanceID, *inst.NodeID, string(admiral.ActionBackupDatabase), "pending_dispatch", "system:scheduler"); err != nil {
				s.log.Error("Failed to create scheduled database backup operation", err, map[string]interface{}{"instance_id": instanceID, "service": target.ServiceName})
				_ = h.db.UpdateCustomerAppStatus(instanceID, "", "failed")
				continue
			}

			storageCfg, _ := h.db.GetActiveBackupStorageConfig()
			backend := "local"
			key := fmt.Sprintf("/var/lib/admiral/backups/%s/%s", instanceID, opID)
			if storageCfg != nil {
				backend = storageCfg.Backend
				key = fmt.Sprintf("%s/%s/%s/%s-database-%s", storageCfg.Prefix, *inst.NodeID, instanceID, target.ServiceName, opID)
			}

			bkRec := &admiral.BackupRecord{
				ID:                          generateID("bk"),
				InstanceID:                  instanceID,
				AppID:                       inst.AppDefinitionName,
				TierID:                      inst.TierName,
				NodeID:                      *inst.NodeID,
				BackupType:                  "database",
				DatabaseType:                target.Backup.Engine,
				Status:                      "pending",
				StorageBackend:              backend,
				StorageKey:                  key,
				TriggeredBy:                 "scheduled",
				TierSnapshotJSON:            inst.TierSnapshotJSON,
				RetentionPolicySnapshotJSON: mustMarshalRetention(policy.Retention.Count, policy.Retention.Days),
			}
			if err := h.db.CreateBackupRecord(bkRec); err != nil {
				s.log.Error("Failed to create scheduled database backup record", err, map[string]interface{}{"instance_id": instanceID, "service": target.ServiceName, "operation_id": opID})
				_ = h.db.UpdateOperation(opID, "failed", err.Error())
				_ = h.db.UpdateCustomerAppStatus(instanceID, "", "failed")
				continue
			}

			allSecretValues, err := h.decryptedSecretMap(instanceID)
			if err != nil {
				s.log.Error("Failed to decrypt scheduled database backup secrets", err, map[string]interface{}{"instance_id": instanceID, "service": target.ServiceName, "operation_id": opID})
				_ = h.db.UpdateOperation(opID, "failed", err.Error())
				_ = h.db.UpdateCustomerAppStatus(instanceID, "", "failed")
				continue
			}
			secretValues := scopeTaskSecrets(admiral.ActionBackupDatabase, payload, allSecretValues, target.ServiceName)
			services := buildServiceInfos(payload, matchedTier, instanceID, inst.CustomerID, secretValues)

			task := &admiral.FleetTask{
				TaskID:      generateID("task"),
				OperationID: opID,
				NodeID:      *inst.NodeID,
				Action:      admiral.ActionBackupDatabase,
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
				Backup:   buildTaskBackupInfo(target),
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

			if err := h.enqueueRawTaskWithErr(task); err != nil {
				s.log.Error("Failed to enqueue scheduled database backup task", err, map[string]interface{}{"instance_id": instanceID, "service": target.ServiceName, "operation_id": opID})
				_ = h.db.UpdateCustomerAppStatus(instanceID, "", "failed")
			}
		}
	}
	// Trigger Volumes backup if configured
	if policy.BackupVolumes {
		for _, target := range backupTargetsByType(payload, "volume") {
			s.log.Info("Triggering scheduled volumes backup", map[string]interface{}{"instance_id": instanceID, "service": target.ServiceName})
			h := s.handlers

			opID := generateID("op")
			if err := h.db.CreateOperation(opID, instanceID, *inst.NodeID, "backup_volumes", "pending_dispatch", "system:scheduler"); err != nil {
				s.log.Error("Failed to create scheduled volume backup operation", err, map[string]interface{}{"instance_id": instanceID, "service": target.ServiceName})
				continue
			}

			storageCfg, _ := h.db.GetActiveBackupStorageConfig()
			backend := "local"
			key := fmt.Sprintf("/var/lib/admiral/backups/%s/%s", instanceID, opID)
			if storageCfg != nil {
				backend = storageCfg.Backend
				key = fmt.Sprintf("%s/%s/%s/%s-volumes-%s", storageCfg.Prefix, *inst.NodeID, instanceID, target.ServiceName, opID)
			}

			bkRec := &admiral.BackupRecord{
				ID:                          generateID("bk"),
				InstanceID:                  instanceID,
				AppID:                       inst.AppDefinitionName,
				TierID:                      inst.TierName,
				NodeID:                      *inst.NodeID,
				BackupType:                  "volume",
				DatabaseType:                "none",
				Status:                      "pending",
				StorageBackend:              backend,
				StorageKey:                  key,
				TriggeredBy:                 "scheduled",
				TierSnapshotJSON:            inst.TierSnapshotJSON,
				RetentionPolicySnapshotJSON: mustMarshalRetention(policy.Retention.Count, policy.Retention.Days),
			}
			if err := h.db.CreateBackupRecord(bkRec); err != nil {
				s.log.Error("Failed to create scheduled volume backup record", err, map[string]interface{}{"instance_id": instanceID, "service": target.ServiceName, "operation_id": opID})
				_ = h.db.UpdateOperation(opID, "failed", err.Error())
				continue
			}

			decryptedSecrets, err := h.decryptedSecretMap(instanceID)
			if err != nil {
				s.log.Error("Failed to decrypt scheduled volume backup secrets", err, map[string]interface{}{"instance_id": instanceID, "service": target.ServiceName, "operation_id": opID})
				_ = h.db.UpdateOperation(opID, "failed", err.Error())
				continue
			}
			secretValues := scopeTaskSecrets(admiral.ActionBackupVolumes, payload, decryptedSecrets, target.ServiceName)
			services := buildServiceInfos(payload, matchedTier, instanceID, inst.CustomerID, secretValues)

			task := &admiral.FleetTask{
				TaskID:      generateID("task"),
				OperationID: opID,
				NodeID:      *inst.NodeID,
				Action:      admiral.TaskAction("backup_volumes"),
				InstanceID:  instanceID,
				App: admiral.AppInfo{
					Name:    payload.Name,
					Version: "latest",
				},
				Tier: admiral.TierInfo{
					Name:        inst.TierName,
					Environment: matchedTier.Environment,
				},
				Services: services,
				Backup:   buildTaskBackupInfo(target),
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

			if err := h.enqueueRawTaskWithErr(task); err != nil {
				s.log.Error("Failed to enqueue scheduled volume backup task", err, map[string]interface{}{"instance_id": instanceID, "service": target.ServiceName, "operation_id": opID})
			}
		}
	}
}

func mustMarshalRetention(count, days int) string {
	data, _ := json.Marshal(map[string]int{"count": count, "days": days})
	return string(data)
}
