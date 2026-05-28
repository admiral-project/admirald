package database

import (
	"database/sql"
	"fmt"
)

const schema = `
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    ip TEXT NOT NULL,
    os TEXT NOT NULL,
    podman_version TEXT NOT NULL,
    status TEXT NOT NULL,
    last_heartbeat TIMESTAMP,
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
    cpu INTEGER NOT NULL,
    memory TEXT NOT NULL,
    storage TEXT NOT NULL,
    price_monthly NUMERIC(10, 2) NOT NULL,
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    instance_id TEXT REFERENCES customer_apps(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES admin_users(username) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    last_activity_at TIMESTAMP NOT NULL,
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

func RunMigrations(db *sql.DB) error {
	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("run schema migrations: %w", err)
	}

	// Exec optional alters to be backwards compatible if tables already exist
	_, _ = db.Exec("ALTER TABLE app_tiers ADD COLUMN backup_policy_json TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE customer_apps ADD COLUMN tier_snapshot_json TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE public_routes ADD COLUMN target_url TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE public_routes ADD COLUMN last_health_checked_at TIMESTAMP")

	return nil
}
