// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"fmt"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"time"
)

func (d *DB) CreateBackupRecord(rec *admiral.BackupRecord) error {
	query := `
		INSERT INTO backup_records (id, instance_id, app_id, tier_id, node_id, backup_type, database_type, status, storage_backend, storage_key, storage_uri_admin, size_bytes, checksum_sha256, triggered_by, retention_policy_snapshot_json, tier_snapshot_json, error_message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`
	_, err := d.Exec(query, rec.ID, rec.InstanceID, rec.AppID, rec.TierID, rec.NodeID, rec.BackupType, rec.DatabaseType, rec.Status, rec.StorageBackend, rec.StorageKey, rec.StorageURIAdmin, rec.SizeBytes, rec.ChecksumSHA256, rec.TriggeredBy, rec.RetentionPolicySnapshotJSON, rec.TierSnapshotJSON, rec.ErrorMessage)
	if err != nil {
		return fmt.Errorf("create backup record: %w", err)
	}
	return nil
}

func (d *DB) UpdateBackupRecord(rec *admiral.BackupRecord) error {
	query := `
		UPDATE backup_records
		SET status = $1, storage_backend = $2, storage_key = $3, storage_uri_admin = $4, size_bytes = $5, checksum_sha256 = $6, completed_at = CURRENT_TIMESTAMP, expires_at = $7, error_message = $8
		WHERE id = $9
	`
	var expiresVal interface{}
	if rec.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, rec.ExpiresAt)
		if err == nil {
			expiresVal = parsed
		} else {
			expiresVal = nil
		}
	} else {
		expiresVal = nil
	}

	_, err := d.Exec(query, rec.Status, rec.StorageBackend, rec.StorageKey, rec.StorageURIAdmin, rec.SizeBytes, rec.ChecksumSHA256, expiresVal, rec.ErrorMessage, rec.ID)
	if err != nil {
		return fmt.Errorf("update backup record: %w", err)
	}
	return nil
}

func (d *DB) GetBackupRecords(instanceID string) ([]admiral.BackupRecord, error) {
	records, _, err := d.GetBackupRecordsPage(instanceID, 1000, 0)
	return records, err
}

func (d *DB) GetBackupRecordsPage(instanceID string, limit, offset int) ([]admiral.BackupRecord, int, error) {
	var total int
	var countErr error
	if instanceID != "" {
		countErr = d.QueryRow("SELECT COUNT(*) FROM backup_records WHERE instance_id = $1", instanceID).Scan(&total)
	} else {
		countErr = d.QueryRow("SELECT COUNT(*) FROM backup_records").Scan(&total)
	}
	if countErr != nil {
		return nil, 0, fmt.Errorf("count backup records: %w", countErr)
	}

	var rows *sql.Rows
	var err error
	if instanceID != "" {
		rows, err = d.Query("SELECT id, instance_id, app_id, tier_id, node_id, backup_type, database_type, status, storage_backend, storage_key, storage_uri_admin, size_bytes, checksum_sha256, created_at, completed_at, expires_at, triggered_by, retention_policy_snapshot_json, tier_snapshot_json, error_message FROM backup_records WHERE instance_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3", instanceID, limit, offset)
	} else {
		rows, err = d.Query("SELECT id, instance_id, app_id, tier_id, node_id, backup_type, database_type, status, storage_backend, storage_key, storage_uri_admin, size_bytes, checksum_sha256, created_at, completed_at, expires_at, triggered_by, retention_policy_snapshot_json, tier_snapshot_json, error_message FROM backup_records ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2", limit, offset)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("query backup records: %w", err)
	}
	defer rows.Close()

	var records []admiral.BackupRecord
	for rows.Next() {
		var r admiral.BackupRecord
		var createdAt time.Time
		var completedAt, expiresAt sql.NullTime
		err := rows.Scan(
			&r.ID, &r.InstanceID, &r.AppID, &r.TierID, &r.NodeID,
			&r.BackupType, &r.DatabaseType, &r.Status, &r.StorageBackend,
			&r.StorageKey, &r.StorageURIAdmin, &r.SizeBytes, &r.ChecksumSHA256,
			&createdAt, &completedAt, &expiresAt, &r.TriggeredBy,
			&r.RetentionPolicySnapshotJSON, &r.TierSnapshotJSON, &r.ErrorMessage,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan backup record row: %w", err)
		}
		r.CreatedAt = createdAt.Format(time.RFC3339)
		if completedAt.Valid {
			r.CompletedAt = completedAt.Time.Format(time.RFC3339)
		}
		if expiresAt.Valid {
			r.ExpiresAt = expiresAt.Time.Format(time.RFC3339)
		}
		records = append(records, r)
	}
	return records, total, nil
}

func (d *DB) GetBackupRecord(id string) (*admiral.BackupRecord, error) {
	var r admiral.BackupRecord
	var createdAt time.Time
	var completedAt, expiresAt sql.NullTime
	query := "SELECT id, instance_id, app_id, tier_id, node_id, backup_type, database_type, status, storage_backend, storage_key, storage_uri_admin, size_bytes, checksum_sha256, created_at, completed_at, expires_at, triggered_by, retention_policy_snapshot_json, tier_snapshot_json, error_message FROM backup_records WHERE id = $1"
	err := d.QueryRow(query, id).Scan(
		&r.ID, &r.InstanceID, &r.AppID, &r.TierID, &r.NodeID,
		&r.BackupType, &r.DatabaseType, &r.Status, &r.StorageBackend,
		&r.StorageKey, &r.StorageURIAdmin, &r.SizeBytes, &r.ChecksumSHA256,
		&createdAt, &completedAt, &expiresAt, &r.TriggeredBy,
		&r.RetentionPolicySnapshotJSON, &r.TierSnapshotJSON, &r.ErrorMessage,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("get backup record: %w", err)
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	if completedAt.Valid {
		r.CompletedAt = completedAt.Time.Format(time.RFC3339)
	}
	if expiresAt.Valid {
		r.ExpiresAt = expiresAt.Time.Format(time.RFC3339)
	}
	return &r, nil
}

// --- Task Outbox ---
