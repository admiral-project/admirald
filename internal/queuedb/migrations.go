// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package queuedb

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
		if applied[m.Version] {
			continue
		}
		if err := m.Up(db); err != nil {
			return fmt.Errorf("queue migration %04d_%s failed: %w", m.Version, m.Name, err)
		}
		if err := recordMigration(db, m.Version); err != nil {
			return err
		}
	}

	return nil
}

func ensureMigrationTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version BIGINT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
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
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
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
			Name:    "create_fleet_commands",
			Up: func(db *sql.DB) error {
				_, err := db.Exec(`
					CREATE TABLE IF NOT EXISTS fleet_commands (
						id UUID PRIMARY KEY,
						operation_id UUID NOT NULL,
						operation_public_id TEXT NOT NULL,
						task_public_id TEXT NOT NULL UNIQUE,
						instance_id TEXT NOT NULL,
						node_id TEXT NOT NULL,
						pod_id TEXT NULL,
						command_type TEXT NOT NULL,
						payload JSONB NOT NULL,
						status TEXT NOT NULL,
						priority INTEGER NOT NULL DEFAULT 100,
						available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
						leased_until TIMESTAMPTZ NULL,
						leased_by TEXT NULL,
						attempt_count INTEGER NOT NULL DEFAULT 0,
						max_attempts INTEGER NOT NULL DEFAULT 5,
						idempotency_key TEXT NOT NULL UNIQUE,
						created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
						started_at TIMESTAMPTZ NULL,
						completed_at TIMESTAMPTZ NULL,
						last_error TEXT NULL,
						result JSONB NULL
					);
					CREATE INDEX IF NOT EXISTS idx_fleet_commands_pickup
						ON fleet_commands (node_id, status, available_at, priority, created_at);
					CREATE INDEX IF NOT EXISTS idx_fleet_commands_operation
						ON fleet_commands (operation_public_id);
					CREATE INDEX IF NOT EXISTS idx_fleet_commands_status
						ON fleet_commands (status);
					CREATE INDEX IF NOT EXISTS idx_fleet_commands_leased_until
						ON fleet_commands (leased_until);
				`)
				return err
			},
		},
		{
			Version: 2,
			Name:    "add_task_signature",
			Up: func(db *sql.DB) error {
				queries := []string{
					"ALTER TABLE fleet_commands ADD COLUMN IF NOT EXISTS task_signature TEXT",
					"ALTER TABLE fleet_commands ADD COLUMN IF NOT EXISTS signed_at BIGINT DEFAULT 0",
				}
				for _, q := range queries {
					if _, err := db.Exec(q); err != nil {
						return fmt.Errorf("migration 2 failed: %w", err)
					}
				}
				return nil
			},
		},
	}
}
