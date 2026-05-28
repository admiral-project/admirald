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
	instances, err := s.handlers.db.GetCustomerApps()
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
		shouldBackup, err := s.EvaluateBackupSchedule(inst.ID, policy)
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

func (s *Server) EvaluateBackupSchedule(instanceID string, policy *admiral.BackupPolicy) (bool, error) {
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
	_ = yaml.Unmarshal([]byte(appDef.RawYAML), &payload)

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
	if policy.BackupDatabase && payload.Backup != nil {
		s.log.Info("Triggering scheduled database backup", map[string]interface{}{"instance_id": instanceID})
		h := s.handlers

		opID := generateID("op")
		_ = h.db.UpdateCustomerAppStatus(instanceID, "", "backup_running")
		_ = h.db.CreateOperation(opID, instanceID, string(admiral.ActionBackupDatabase), "queued")

		storageCfg, _ := h.db.GetActiveBackupStorageConfig()
		backend := "local"
		key := fmt.Sprintf("/var/lib/admiral/backups/%s/%s", instanceID, opID)
		if storageCfg != nil {
			backend = storageCfg.Backend
			key = fmt.Sprintf("%s/%s/%s/database-%s", storageCfg.Prefix, *inst.NodeID, instanceID, opID)
		}

		bkRec := &admiral.BackupRecord{
			ID:                          generateID("bk"),
			InstanceID:                  instanceID,
			AppID:                       inst.AppDefinitionName,
			TierID:                      inst.TierName,
			NodeID:                      *inst.NodeID,
			BackupType:                  "database",
			DatabaseType:                payload.Backup.Type,
			Status:                      "pending",
			StorageBackend:              backend,
			StorageKey:                  key,
			TriggeredBy:                 "scheduled",
			TierSnapshotJSON:            inst.TierSnapshotJSON,
			RetentionPolicySnapshotJSON: fmt.Sprintf(`{"count":%d,"days":%d}`, policy.Retention.Count, policy.Retention.Days),
		}
		_ = h.db.CreateBackupRecord(bkRec)

		allSecretValues, _ := h.decryptedSecretMap(instanceID)
		secretValues := scopeTaskSecrets(admiral.ActionBackupDatabase, payload, allSecretValues)

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
			Action:      admiral.ActionBackupDatabase,
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
			Backup: &admiral.BackupInfo{
				Type:        payload.Backup.Type,
				Service:     payload.Backup.Service,
				DatabaseEnv: payload.Backup.DatabaseEnv,
				UsernameEnv: payload.Backup.UsernameEnv,
				PasswordEnv: payload.Backup.PasswordEnv,
			},
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
	}
	// Trigger Volumes backup if configured
	if policy.BackupVolumes {
		s.log.Info("Triggering scheduled volumes backup", map[string]interface{}{"instance_id": instanceID})
		h := s.handlers

		opID := generateID("op")
		_ = h.db.CreateOperation(opID, instanceID, "backup_volumes", "queued")

		storageCfg, _ := h.db.GetActiveBackupStorageConfig()
		backend := "local"
		key := fmt.Sprintf("/var/lib/admiral/backups/%s/%s", instanceID, opID)
		if storageCfg != nil {
			backend = storageCfg.Backend
			key = fmt.Sprintf("%s/%s/%s/volumes-%s", storageCfg.Prefix, *inst.NodeID, instanceID, opID)
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
			RetentionPolicySnapshotJSON: fmt.Sprintf(`{"count":%d,"days":%d}`, policy.Retention.Count, policy.Retention.Days),
		}
		_ = h.db.CreateBackupRecord(bkRec)

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
				Name: inst.TierName,
			},
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
	}
}
