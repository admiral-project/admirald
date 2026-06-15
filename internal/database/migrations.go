// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"fmt"
	"sort"
)

type Migration struct {
	Version int
	Name    string
	Up      func(*sql.DB) error
}

func RunMigrations(db *sql.DB) error {
	if err := ensureMigrationTable(db); err != nil {
		return err
	}

	applied, err := getAppliedMigrations(db)
	if err != nil {
		return err
	}

	migrations := getMigrations()
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	for _, m := range migrations {
		if !applied[m.Version] {
			fmt.Printf("Applying migration %04d_%s\n", m.Version, m.Name)
			if err := m.Up(db); err != nil {
				return fmt.Errorf("migration %04d_%s failed: %w", m.Version, m.Name, err)
			}
			if err := recordMigration(db, m.Version); err != nil {
				return err
			}
		}
	}

	return nil
}

func ensureMigrationTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version BIGINT PRIMARY KEY,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	_, err := db.Exec(query)
	return err
}

func getAppliedMigrations(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query("SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, nil
}

func recordMigration(db *sql.DB, version int) error {
	_, err := db.Exec("INSERT INTO schema_migrations (version) VALUES ($1)", version)
	return err
}

func getMigrations() []Migration {
	return []Migration{
		{
			Version: 1,
			Name:    "initial_schema",
			Up: func(db *sql.DB) error {
				_, err := db.Exec(initialSchema)
				return err
			},
		},
		{
			Version: 2,
			Name:    "add_app_catalog_fields",
			Up: func(db *sql.DB) error {
				queries := []string{
					"ALTER TABLE app_definitions ADD COLUMN IF NOT EXISTS availability TEXT NOT NULL DEFAULT 'available'",
					"ALTER TABLE app_definitions ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 0",
					"ALTER TABLE app_definitions ADD COLUMN IF NOT EXISTS checksum TEXT NOT NULL DEFAULT ''",
				}
				for _, q := range queries {
					if _, err := db.Exec(q); err != nil {
						return fmt.Errorf("migration 2 failed: %w", err)
					}
				}
				return nil
			},
		},
		{
			Version: 3,
			Name:    "add_availability_reason",
			Up: func(db *sql.DB) error {
				_, err := db.Exec("ALTER TABLE app_definitions ADD COLUMN IF NOT EXISTS last_availability_reason TEXT NOT NULL DEFAULT ''")
				return err
			},
		},
		{
			Version: 4,
			Name:    "add_is_free_to_tiers",
			Up: func(db *sql.DB) error {
				_, err := db.Exec("ALTER TABLE app_tiers ADD COLUMN IF NOT EXISTS is_free BOOLEAN NOT NULL DEFAULT FALSE")
				return err
			},
		},
		{
			Version: 5,
			Name:    "add_multinode_fields",
			Up: func(db *sql.DB) error {
				queries := []string{
					"ALTER TABLE nodes ADD COLUMN IF NOT EXISTS wireguard_ip TEXT NOT NULL DEFAULT ''",
					"ALTER TABLE nodes ADD COLUMN IF NOT EXISTS node_role TEXT NOT NULL DEFAULT 'worker'",
					"ALTER TABLE nodes ADD COLUMN IF NOT EXISTS public_ip TEXT NOT NULL DEFAULT ''",
				}
				for _, q := range queries {
					if _, err := db.Exec(q); err != nil {
						return fmt.Errorf("migration 5 failed: %w", err)
					}
				}
				return nil
			},
		},
		{
			Version: 6,
			Name:    "add_logical_instance_id",
			Up: func(db *sql.DB) error {
				queries := []string{
					"ALTER TABLE customer_apps ADD COLUMN IF NOT EXISTS logical_instance_id TEXT NOT NULL DEFAULT ''",
					"UPDATE customer_apps SET logical_instance_id = id WHERE logical_instance_id = ''",
				}
				for _, q := range queries {
					if _, err := db.Exec(q); err != nil {
						return fmt.Errorf("migration 6 failed: %w", err)
					}
				}
				return nil
			},
		},
	}
}

const initialSchema = `
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    ip TEXT NOT NULL,
    wireguard_ip TEXT NOT NULL DEFAULT '',
    node_role TEXT NOT NULL DEFAULT 'worker',
    public_ip TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL,
    podman_version TEXT NOT NULL,
    status TEXT NOT NULL,
    last_heartbeat TIMESTAMPTZ,
    fleet_version TEXT NOT NULL DEFAULT '',
    disk_total_bytes BIGINT NOT NULL DEFAULT 0,
    disk_used_bytes BIGINT NOT NULL DEFAULT 0,
    pods_active INTEGER NOT NULL DEFAULT 0,
    pods_paused INTEGER NOT NULL DEFAULT 0,
    pods_failed INTEGER NOT NULL DEFAULT 0,
    storage_state TEXT NOT NULL DEFAULT '',
    storage_message TEXT NOT NULL DEFAULT '',
    manual_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    health_status TEXT NOT NULL DEFAULT '',
    health_reason_codes TEXT NOT NULL DEFAULT '',
    available_for_provisioning BOOLEAN NOT NULL DEFAULT TRUE,
    unavailable_reason_codes TEXT NOT NULL DEFAULT '',
    ram_total_bytes BIGINT NOT NULL DEFAULT 0,
    ram_used_bytes BIGINT NOT NULL DEFAULT 0,
    ram_commit_limit_bytes BIGINT NOT NULL DEFAULT 0,
    disk_commit_limit_bytes BIGINT NOT NULL DEFAULT 0,
    committed_ram_bytes BIGINT NOT NULL DEFAULT 0,
    committed_disk_bytes BIGINT NOT NULL DEFAULT 0,
    last_metrics_at TIMESTAMPTZ,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_definitions (
    name TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    raw_yaml TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_tiers (
    app_name TEXT REFERENCES app_definitions(name) ON DELETE CASCADE,
    name TEXT NOT NULL,
    cpu DOUBLE PRECISION NOT NULL,
    memory TEXT NOT NULL,
    storage TEXT NOT NULL,
    price_monthly NUMERIC(10, 2) NOT NULL,
    is_free BOOLEAN NOT NULL DEFAULT FALSE,
    environment_json TEXT NOT NULL DEFAULT '',
    backup_policy_json TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (app_name, name)
);

CREATE TABLE IF NOT EXISTS customer_apps (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL,
    app_definition_name TEXT REFERENCES app_definitions(name),
    tier_name TEXT NOT NULL,
    node_id TEXT REFERENCES nodes(id),
    commercial_status TEXT NOT NULL,
    technical_status TEXT NOT NULL,
    tier_snapshot_json TEXT NOT NULL DEFAULT '',
    health_status TEXT NOT NULL DEFAULT '',
    health_message TEXT NOT NULL DEFAULT '',
    last_health_checked_at TIMESTAMP,
    storage_limit_bytes BIGINT NOT NULL DEFAULT 0,
    storage_used_bytes BIGINT NOT NULL DEFAULT 0,
    storage_used_percent REAL NOT NULL DEFAULT 0,
    storage_state TEXT NOT NULL DEFAULT 'unknown',
    storage_message TEXT NOT NULL DEFAULT '',
    storage_checked_at TIMESTAMP,
    storage_exceeded BOOLEAN NOT NULL DEFAULT FALSE,
    grace_period_starts_at TIMESTAMP,
    grace_period_ends_at TIMESTAMP,
    emergency_limit_bytes BIGINT NOT NULL DEFAULT 0,
    logical_instance_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    instance_id TEXT REFERENCES customer_apps(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    node_id TEXT NOT NULL DEFAULT '',
    task_id TEXT NOT NULL DEFAULT '',
    admin_user TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS instance_secrets (
    instance_id TEXT REFERENCES customer_apps(id) ON DELETE CASCADE,
    service_name TEXT NOT NULL,
    env_name TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    expose_to_customer BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (instance_id, service_name, env_name)
);

CREATE TABLE IF NOT EXISTS backups (
    id TEXT PRIMARY KEY,
    instance_id TEXT REFERENCES customer_apps(id) ON DELETE CASCADE,
    node_id TEXT REFERENCES nodes(id),
    status TEXT NOT NULL,
    filepath TEXT,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES admin_users(username) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS backup_storage_configs (
    id TEXT PRIMARY KEY,
    backend TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    endpoint TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    bucket TEXT NOT NULL DEFAULT '',
    prefix TEXT NOT NULL DEFAULT '',
    force_path_style BOOLEAN NOT NULL DEFAULT FALSE,
    access_key_env TEXT NOT NULL DEFAULT '',
    secret_key_env TEXT NOT NULL DEFAULT '',
    session_token_env TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS backup_records (
    id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES customer_apps(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL,
    tier_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    backup_type TEXT NOT NULL,
    database_type TEXT NOT NULL,
    status TEXT NOT NULL,
    storage_backend TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    storage_uri_admin TEXT NOT NULL DEFAULT '',
    size_bytes BIGINT NOT NULL DEFAULT 0,
    checksum_sha256 TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    expires_at TIMESTAMP,
    triggered_by TEXT NOT NULL,
    retention_policy_snapshot_json TEXT NOT NULL DEFAULT '',
    tier_snapshot_json TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS task_outbox (
    id TEXT PRIMARY KEY,
    task_json TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 10,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS public_routes (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    public_id TEXT NOT NULL,
    app_instance_id TEXT REFERENCES customer_apps(id) ON DELETE CASCADE,
    app_template_code TEXT NOT NULL,
    node_id TEXT REFERENCES nodes(id),
    service_name TEXT NOT NULL,
    target_scheme TEXT NOT NULL,
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL DEFAULT 0,
    target_url TEXT NOT NULL DEFAULT '',
    route_kind TEXT NOT NULL,
    tls_mode TEXT NOT NULL DEFAULT 'auto',
    status TEXT NOT NULL,
    last_error TEXT NOT NULL DEFAULT '',
    last_health_status TEXT NOT NULL DEFAULT '',
    last_health_checked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`
