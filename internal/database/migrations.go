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
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_definitions (
    name TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    raw_yaml TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_tiers (
    app_name TEXT REFERENCES app_definitions(name) ON DELETE CASCADE,
    name TEXT NOT NULL,
    cpu INTEGER NOT NULL,
    memory TEXT NOT NULL,
    storage TEXT NOT NULL,
    price_monthly NUMERIC(10, 2) NOT NULL,
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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    instance_id TEXT REFERENCES customer_apps(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS instance_secrets (
    instance_id TEXT REFERENCES customer_apps(id) ON DELETE CASCADE,
    service_name TEXT NOT NULL,
    env_name TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    expose_to_customer BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (instance_id, service_name, env_name)
);

CREATE TABLE IF NOT EXISTS backups (
    id TEXT PRIMARY KEY,
    instance_id TEXT REFERENCES customer_apps(id) ON DELETE CASCADE,
    node_id TEXT REFERENCES nodes(id),
    status TEXT NOT NULL,
    filepath TEXT,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
`

func RunMigrations(db *sql.DB) error {
	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("run schema migrations: %w", err)
	}
	return nil
}
