// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"fmt"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"time"
)

func (d *DB) SaveBackupStorageConfig(cfg *admiral.BackupStorageConfig) error {
	query := `
		INSERT INTO backup_storage_configs (id, backend, enabled, endpoint, region, bucket, prefix, force_path_style, access_key_env, secret_key_env, session_token_env, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO UPDATE SET
			backend = EXCLUDED.backend,
			enabled = EXCLUDED.enabled,
			endpoint = EXCLUDED.endpoint,
			region = EXCLUDED.region,
			bucket = EXCLUDED.bucket,
			prefix = EXCLUDED.prefix,
			force_path_style = EXCLUDED.force_path_style,
			access_key_env = EXCLUDED.access_key_env,
			secret_key_env = EXCLUDED.secret_key_env,
			session_token_env = EXCLUDED.session_token_env,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := d.Exec(query, cfg.ID, cfg.Backend, cfg.Enabled, cfg.Endpoint, cfg.Region, cfg.Bucket, cfg.Prefix, cfg.ForcePathStyle, cfg.AccessKeyEnv, cfg.SecretKeyEnv, cfg.SessionTokenEnv)
	if err != nil {
		return fmt.Errorf("save backup storage config: %w", err)
	}
	return nil
}

func (d *DB) GetBackupStorageConfig(id string) (*admiral.BackupStorageConfig, error) {
	var c admiral.BackupStorageConfig
	var createdAt, updatedAt time.Time
	query := "SELECT id, backend, enabled, endpoint, region, bucket, prefix, force_path_style, access_key_env, secret_key_env, session_token_env, created_at, updated_at FROM backup_storage_configs WHERE id = $1"
	err := d.QueryRow(query, id).Scan(&c.ID, &c.Backend, &c.Enabled, &c.Endpoint, &c.Region, &c.Bucket, &c.Prefix, &c.ForcePathStyle, &c.AccessKeyEnv, &c.SecretKeyEnv, &c.SessionTokenEnv, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("get backup storage config: %w", err)
	}
	c.CreatedAt = createdAt.Format(time.RFC3339)
	c.UpdatedAt = updatedAt.Format(time.RFC3339)
	return &c, nil
}

func (d *DB) GetActiveBackupStorageConfig() (*admiral.BackupStorageConfig, error) {
	var c admiral.BackupStorageConfig
	var createdAt, updatedAt time.Time
	query := "SELECT id, backend, enabled, endpoint, region, bucket, prefix, force_path_style, access_key_env, secret_key_env, session_token_env, created_at, updated_at FROM backup_storage_configs WHERE enabled = TRUE LIMIT 1"
	err := d.QueryRow(query).Scan(&c.ID, &c.Backend, &c.Enabled, &c.Endpoint, &c.Region, &c.Bucket, &c.Prefix, &c.ForcePathStyle, &c.AccessKeyEnv, &c.SecretKeyEnv, &c.SessionTokenEnv, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("get active backup storage config: %w", err)
	}
	c.CreatedAt = createdAt.Format(time.RFC3339)
	c.UpdatedAt = updatedAt.Format(time.RFC3339)
	return &c, nil
}

// --- Backup Record CRUD ---
