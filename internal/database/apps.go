// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type AppDefinition struct {
	Name         string    `json:"name"`
	DisplayName  string    `json:"display_name"`
	Description  string    `json:"description"`
	RawYAML      string    `json:"raw_yaml"`
	Status       string    `json:"status"`
	Availability string    `json:"availability"`
	Revision     int       `json:"revision"`
	Checksum     string    `json:"checksum"`
	CreatedAt    time.Time `json:"created_at"`
}

type AppTier struct {
	AppName          string            `json:"app_name"`
	Name             string            `json:"name"`
	CPU              float64           `json:"cpu"`
	Memory           string            `json:"memory"`
	Storage          string            `json:"storage"`
	PriceMonthly     float64           `json:"price_monthly"`
	Free             bool              `json:"free"`
	Environment      map[string]string `json:"environment,omitempty"`
	BackupPolicyJSON string            `json:"backup_policy_json,omitempty"`
}

func (d *DB) SaveAppDefinition(name, displayName, description, rawYAML string, tiers []AppTier) error {
	tx, err := d.Begin()
	if err != nil {
		return fmt.Errorf("start transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	queryApp := `
		INSERT INTO app_definitions (name, display_name, description, raw_yaml, status)
		VALUES ($1, $2, $3, $4, 'active')
		ON CONFLICT (name) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			description = EXCLUDED.description,
			raw_yaml = EXCLUDED.raw_yaml,
			status = app_definitions.status
	`
	if _, err := tx.Exec(queryApp, name, displayName, description, rawYAML); err != nil {
		return fmt.Errorf("insert app definition: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM app_tiers WHERE app_name = $1", name); err != nil {
		return fmt.Errorf("clear old tiers: %w", err)
	}

	queryTier := `
		INSERT INTO app_tiers (app_name, name, cpu, memory, storage, price_monthly, is_free, environment_json, backup_policy_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	for _, tier := range tiers {
		envJSON := ""
		if len(tier.Environment) > 0 {
			data, err := json.Marshal(tier.Environment)
			if err != nil {
				return fmt.Errorf("marshal tier %q environment: %w", tier.Name, err)
			}
			envJSON = string(data)
		}
		if _, err := tx.Exec(queryTier, name, tier.Name, tier.CPU, tier.Memory, tier.Storage, tier.PriceMonthly, tier.Free, envJSON, tier.BackupPolicyJSON); err != nil {
			return fmt.Errorf("insert tier %q: %w", tier.Name, err)
		}
	}

	return tx.Commit()
}

func (d *DB) UpdateAppDefinitionStatus(name, status string) error {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "active", "inactive":
	default:
		return fmt.Errorf("invalid app definition status %q", status)
	}

	res, err := d.Exec("UPDATE app_definitions SET status = $2 WHERE name = $1", name, status)
	if err != nil {
		return fmt.Errorf("update app definition %q status: %w", name, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update app definition %q status rows affected: %w", name, err)
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (d *DB) UpdateAppAvailability(name, availability, reason string) error {
	availability = strings.ToLower(strings.TrimSpace(availability))
	switch availability {
	case "available", "unavailable":
	default:
		return fmt.Errorf("invalid app availability %q", availability)
	}

	res, err := d.Exec("UPDATE app_definitions SET availability = $2, last_availability_reason = $3 WHERE name = $1", name, availability, reason)
	if err != nil {
		return fmt.Errorf("update app %q availability: %w", name, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update app %q availability rows affected: %w", name, err)
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (d *DB) GetAppDefinitions() ([]AppDefinition, error) {
	rows, err := d.Query("SELECT name, display_name, description, raw_yaml, status, availability, revision, checksum, created_at FROM app_definitions ORDER BY name ASC")
	if err != nil {
		return nil, fmt.Errorf("query app definitions: %w", err)
	}
	defer rows.Close()

	var apps []AppDefinition
	for rows.Next() {
		var a AppDefinition
		if err := rows.Scan(&a.Name, &a.DisplayName, &a.Description, &a.RawYAML, &a.Status, &a.Availability, &a.Revision, &a.Checksum, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan app row: %w", err)
		}
		apps = append(apps, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate app definitions: %w", err)
	}
	return apps, nil
}

func (d *DB) GetAppDefinition(name string) (*AppDefinition, error) {
	var a AppDefinition
	query := "SELECT name, display_name, description, raw_yaml, status, availability, revision, checksum, created_at FROM app_definitions WHERE name = $1"
	err := d.QueryRow(query, name).Scan(&a.Name, &a.DisplayName, &a.Description, &a.RawYAML, &a.Status, &a.Availability, &a.Revision, &a.Checksum, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("query app %q: %w", name, err)
	}
	return &a, nil
}

func (d *DB) GetAppTiers(appName string) ([]AppTier, error) {
	rows, err := d.Query("SELECT app_name, name, cpu, memory, storage, price_monthly, is_free, environment_json, backup_policy_json FROM app_tiers WHERE app_name = $1", appName)
	if err != nil {
		return nil, fmt.Errorf("query app tiers: %w", err)
	}
	defer rows.Close()

	var tiers []AppTier
	for rows.Next() {
		var t AppTier
		var envJSON string
		if err := rows.Scan(&t.AppName, &t.Name, &t.CPU, &t.Memory, &t.Storage, &t.PriceMonthly, &t.Free, &envJSON, &t.BackupPolicyJSON); err != nil {
			return nil, fmt.Errorf("scan tier row: %w", err)
		}
		if envJSON != "" {
			if err := json.Unmarshal([]byte(envJSON), &t.Environment); err != nil {
				return nil, fmt.Errorf("unmarshal tier %q environment: %w", t.Name, err)
			}
		}
		tiers = append(tiers, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate app tiers: %w", err)
	}
	return tiers, nil
}

// --- Customer Apps CRUD ---
