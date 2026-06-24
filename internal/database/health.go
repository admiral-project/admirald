// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"fmt"
	"time"
)

func (d *DB) UpdateInstanceHealth(instanceID, healthStatus, message string) error {
	_, err := d.Exec("UPDATE customer_apps SET health_status = $1, health_message = $2, last_health_checked_at = CURRENT_TIMESTAMP WHERE id = $3",
		healthStatus, message, instanceID)
	return err
}

func (d *DB) UpdateInstanceHealthAndTechStatus(instanceID, healthStatus, techStatus, message string) error {
	_, err := d.Exec("UPDATE customer_apps SET health_status = $1, health_message = $2, technical_status = $3, last_health_checked_at = CURRENT_TIMESTAMP WHERE id = $4",
		healthStatus, message, techStatus, instanceID)
	return err
}

func (d *DB) UpdateInstanceStorage(instanceID, storageState, storageMessage string, limitBytes, usedBytes int64, usedPct float64, exceeded bool) error {
	_, err := d.Exec(`UPDATE customer_apps SET
		storage_limit_bytes = $1, storage_used_bytes = $2, storage_used_percent = $3,
		storage_state = $4, storage_message = $5, storage_checked_at = CURRENT_TIMESTAMP,
		storage_exceeded = $6 WHERE id = $7`,
		limitBytes, usedBytes, usedPct, storageState, storageMessage, exceeded, instanceID)
	return err
}

func (d *DB) SetGracePeriod(instanceID string, endsAt time.Time) error {
	_, err := d.Exec(`UPDATE customer_apps SET
		grace_period_starts_at = CURRENT_TIMESTAMP,
		grace_period_ends_at = $1
		WHERE id = $2`, endsAt, instanceID)
	return err
}

func (d *DB) ClearGracePeriod(instanceID string) error {
	_, err := d.Exec(`UPDATE customer_apps SET
		grace_period_starts_at = NULL,
		grace_period_ends_at = NULL
		WHERE id = $1`, instanceID)
	return err
}

func (d *DB) GetExpiredGracePeriodApps() ([]CustomerApp, error) {
	rows, err := d.Query(`SELECT id, customer_id, app_definition_name, tier_name, node_id,
		commercial_status, technical_status, tier_snapshot_json, created_at,
		COALESCE(health_status, ''), COALESCE(health_message, ''),
		last_health_checked_at,
		COALESCE(storage_limit_bytes, 0), COALESCE(storage_used_bytes, 0),
		COALESCE(storage_used_percent, 0), COALESCE(storage_state, 'unknown'),
		COALESCE(storage_message, ''), storage_checked_at,
		COALESCE(storage_exceeded, FALSE),
		COALESCE(logical_instance_id, '')
		FROM customer_apps
		WHERE grace_period_ends_at IS NOT NULL
		AND grace_period_ends_at < CURRENT_TIMESTAMP
		AND storage_state = 'over_quota'
		AND technical_status NOT IN ('stopped', 'paused_for_storage', 'initializing', 'setup_failed', 'deprovisioning', 'deprovisioned')
		ORDER BY grace_period_ends_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("query expired grace period apps: %w", err)
	}
	defer rows.Close()

	var apps []CustomerApp
	for rows.Next() {
		var a CustomerApp
		if err := rows.Scan(&a.ID, &a.CustomerID, &a.AppDefinitionName, &a.TierName, &a.NodeID,
			&a.CommercialStatus, &a.TechnicalStatus, &a.TierSnapshotJSON, &a.CreatedAt,
			&a.HealthStatus, &a.HealthMessage, &a.LastHealthChecked,
			&a.StorageLimitBytes, &a.StorageUsedBytes, &a.StorageUsedPct,
			&a.StorageState, &a.StorageMessage, &a.StorageCheckedAt,
			&a.StorageExceeded,
			&a.LogicalInstanceID,
		); err != nil {
			return nil, fmt.Errorf("scan expired grace period app: %w", err)
		}
		apps = append(apps, a)
	}
	return apps, nil
}

func (d *DB) UpdateNodeStorageState(nodeID, storageState, storageMsg string) error {
	_, err := d.Exec("UPDATE nodes SET storage_state = $1, storage_message = $2 WHERE id = $3",
		storageState, storageMsg, nodeID)
	return err
}

func (d *DB) UpdateNodeHealth(nodeID, healthStatus, healthReasons string, available bool, unavailableReasons string) error {
	_, err := d.Exec(`UPDATE nodes SET
		health_status = $1, health_reason_codes = $2,
		available_for_provisioning = $3, unavailable_reason_codes = $4
		WHERE id = $5`, healthStatus, healthReasons, available, unavailableReasons, nodeID)
	return err
}

func (d *DB) UpdateNodeCommitLimits(nodeID string, ramCommitLimit, diskCommitLimit int64) error {
	_, err := d.Exec("UPDATE nodes SET ram_commit_limit_bytes = $1, disk_commit_limit_bytes = $2 WHERE id = $3",
		ramCommitLimit, diskCommitLimit, nodeID)
	return err
}

func (d *DB) AddNodeCommitment(nodeID string, ramDelta, diskDelta int64) error {
	_, err := d.Exec("UPDATE nodes SET committed_ram_bytes = committed_ram_bytes + $1, committed_disk_bytes = committed_disk_bytes + $2 WHERE id = $3",
		ramDelta, diskDelta, nodeID)
	return err
}

func (d *DB) ReleaseNodeCommitment(nodeID string, ramDelta, diskDelta int64) error {
	_, err := d.Exec("UPDATE nodes SET committed_ram_bytes = GREATEST(committed_ram_bytes - $1, 0), committed_disk_bytes = GREATEST(committed_disk_bytes - $2, 0) WHERE id = $3",
		ramDelta, diskDelta, nodeID)
	return err
}

func (d *DB) GetCommittedResources(nodeID string) (ram, disk int64, err error) {
	err = d.QueryRow("SELECT COALESCE(committed_ram_bytes, 0), COALESCE(committed_disk_bytes, 0) FROM nodes WHERE id = $1", nodeID).Scan(&ram, &disk)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return
}

func (d *DB) GetInconsistentInstances() ([]CustomerApp, error) {
	rows, err := d.Query(`SELECT ca.id, ca.customer_id, ca.app_definition_name, ca.tier_name, ca.node_id,
		ca.commercial_status, ca.technical_status, ca.tier_snapshot_json, ca.created_at,
		COALESCE(ca.health_status, ''), COALESCE(ca.health_message, ''),
		ca.last_health_checked_at,
		COALESCE(ca.storage_limit_bytes, 0), COALESCE(ca.storage_used_bytes, 0),
		COALESCE(ca.storage_used_percent, 0), COALESCE(ca.storage_state, 'unknown'),
		COALESCE(ca.storage_message, ''), ca.storage_checked_at,
		COALESCE(ca.storage_exceeded, FALSE),
		COALESCE(ca.logical_instance_id, '')
		FROM customer_apps ca
		JOIN nodes n ON ca.node_id = n.id
		WHERE ca.technical_status = 'running'
		  AND n.status = 'offline'`)
	if err != nil {
		return nil, fmt.Errorf("query inconsistent instances: %w", err)
	}
	defer rows.Close()

	var apps []CustomerApp
	for rows.Next() {
		var a CustomerApp
		if err := rows.Scan(&a.ID, &a.CustomerID, &a.AppDefinitionName, &a.TierName, &a.NodeID,
			&a.CommercialStatus, &a.TechnicalStatus, &a.TierSnapshotJSON, &a.CreatedAt,
			&a.HealthStatus, &a.HealthMessage, &a.LastHealthChecked,
			&a.StorageLimitBytes, &a.StorageUsedBytes, &a.StorageUsedPct,
			&a.StorageState, &a.StorageMessage, &a.StorageCheckedAt,
			&a.StorageExceeded,
			&a.LogicalInstanceID,
		); err != nil {
			return nil, fmt.Errorf("scan inconsistent instance: %w", err)
		}
		apps = append(apps, a)
	}
	return apps, nil
}
