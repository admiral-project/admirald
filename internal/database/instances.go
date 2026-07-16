// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"fmt"
	"time"
)

type CustomerApp struct {
	ID                  string     `json:"id"`
	CustomerID          string     `json:"customer_id"`
	AppDefinitionName   string     `json:"app_definition_name"`
	TierName            string     `json:"tier_name"`
	NodeID              *string    `json:"node_id"`
	CommercialStatus    string     `json:"commercial_status"`
	TechnicalStatus     string     `json:"technical_status"`
	TierSnapshotJSON    string     `json:"tier_snapshot_json"`
	CreatedAt           time.Time  `json:"created_at"`
	HealthStatus        string     `json:"health_status"`
	HealthMessage       string     `json:"health_message,omitempty"`
	LastHealthChecked   *time.Time `json:"last_health_checked_at,omitempty"`
	StorageLimitBytes   int64      `json:"storage_limit_bytes"`
	StorageUsedBytes    int64      `json:"storage_used_bytes"`
	StorageUsedPct      float64    `json:"storage_used_percent"`
	StorageState        string     `json:"storage_state"`
	StorageMessage      string     `json:"storage_message,omitempty"`
	StorageCheckedAt    *time.Time `json:"storage_checked_at,omitempty"`
	StorageExceeded     bool       `json:"storage_exceeded"`
	GracePeriodStartsAt *time.Time `json:"grace_period_starts_at,omitempty"`
	GracePeriodEndsAt   *time.Time `json:"grace_period_ends_at,omitempty"`
	EmergencyLimitBytes int64      `json:"emergency_limit_bytes"`
	Hostname            string     `json:"hostname"`
	LogicalInstanceID   string     `json:"logical_instance_id"`
	InspectData         string     `json:"inspect_data,omitempty"`
	SetupCompleted      bool       `json:"setup_completed"`
	SetupTimeoutSeconds int        `json:"setup_timeout_seconds,omitempty"`
}

func (d *DB) CreateCustomerApp(id, customerID, appName, tierName, nodeID, tierSnapshotJSON string) error {
	query := `
		INSERT INTO customer_apps (id, customer_id, app_definition_name, tier_name, node_id, commercial_status, technical_status, tier_snapshot_json, logical_instance_id)
		VALUES ($1, $2, $3, $4, $5, 'active', 'pending_provision', $6, $1)
	`
	var nID interface{}
	if nodeID != "" {
		nID = nodeID
	} else {
		nID = nil
	}
	_, err := d.Exec(query, id, customerID, appName, tierName, nID, tierSnapshotJSON)
	if err != nil {
		return fmt.Errorf("create customer app: %w", err)
	}
	return nil
}

func (d *DB) ReserveNodeCapacityAndCreateApp(id, customerID, appName, tierName, nodeID, tierSnapshotJSON, logicalInstanceID string, ramDelta, diskDelta int64) error {
	tx, err := d.Begin()
	if err != nil {
		return fmt.Errorf("begin reserve node capacity tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := reserveNodeCapacityTx(tx, nodeID, ramDelta, diskDelta); err != nil {
		return err
	}
	query := `
		INSERT INTO customer_apps (id, customer_id, app_definition_name, tier_name, node_id, commercial_status, technical_status, tier_snapshot_json, logical_instance_id)
		VALUES ($1, $2, $3, $4, $5, 'active', 'pending_provision', $6, $7)
	`
	lid := logicalInstanceID
	if lid == "" {
		lid = id
	}
	if _, err := tx.Exec(query, id, customerID, appName, tierName, nodeID, tierSnapshotJSON, lid); err != nil {
		return fmt.Errorf("create customer app in reserve tx: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit reserve node capacity tx: %w", err)
	}
	return nil
}

func (d *DB) ReserveNodeCapacity(nodeID string, ramDelta, diskDelta int64) error {
	tx, err := d.Begin()
	if err != nil {
		return fmt.Errorf("begin reserve node capacity tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := reserveNodeCapacityTx(tx, nodeID, ramDelta, diskDelta); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit reserve node capacity tx: %w", err)
	}
	return nil
}

func (d *DB) UpdateCustomerAppNode(id, nodeID string) error {
	_, err := d.Exec("UPDATE customer_apps SET node_id = $1 WHERE id = $2", nodeID, id)
	if err != nil {
		return fmt.Errorf("update customer app node: %w", err)
	}
	return nil
}

func (d *DB) UpdateCustomerAppStatus(id, commStatus, techStatus string) error {
	query := `
		UPDATE customer_apps
		SET commercial_status = COALESCE(NULLIF($1, ''), commercial_status),
		    technical_status = COALESCE(NULLIF($2, ''), technical_status)
		WHERE id = $3
	`
	_, err := d.Exec(query, commStatus, techStatus, id)
	if err != nil {
		return fmt.Errorf("update customer app status: %w", err)
	}
	return nil
}

func (d *DB) UpdateCustomerAppInspectData(id, inspectData string) error {
	_, err := d.Exec("UPDATE customer_apps SET inspect_data = $1 WHERE id = $2", inspectData, id)
	if err != nil {
		return fmt.Errorf("update customer app inspect data: %w", err)
	}
	return nil
}

// SetSetupCompleted marks the setup_command phase as completed for the
// given instance. Called after a successful setup_command execution
// during the provision callback.
func (d *DB) SetSetupCompleted(id string) error {
	_, err := d.Exec("UPDATE customer_apps SET setup_completed = TRUE WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("set setup_completed for instance %q: %w", id, err)
	}
	return nil
}

func (d *DB) UpdateCustomerAppTier(id, tierName, tierSnapshotJSON string) error {
	_, err := d.Exec(`
		UPDATE customer_apps
		SET tier_name = $1, tier_snapshot_json = $2
		WHERE id = $3
	`, tierName, tierSnapshotJSON, id)
	if err != nil {
		return fmt.Errorf("update customer app tier: %w", err)
	}
	return nil
}

func (d *DB) GetCustomerApps(customerID string) ([]CustomerApp, error) {
	apps, _, err := d.GetCustomerAppsPage(1000, 0, customerID)
	return apps, err
}

func (d *DB) GetCustomerAppsPage(limit, offset int, customerID string) ([]CustomerApp, int, error) {
	var total int
	if customerID != "" {
		if err := d.QueryRow("SELECT COUNT(*) FROM customer_apps WHERE customer_id = $1", customerID).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("count customer apps: %w", err)
		}
	} else {
		if err := d.QueryRow("SELECT COUNT(*) FROM customer_apps").Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("count customer apps: %w", err)
		}
	}

	var rows *sql.Rows
	var err error
	if customerID != "" {
		rows, err = d.Query(`SELECT ca.id, ca.customer_id, ca.app_definition_name, ca.tier_name, ca.node_id,
			ca.commercial_status, ca.technical_status, ca.tier_snapshot_json, ca.created_at,
			COALESCE(ca.health_status, ''), COALESCE(ca.health_message, ''),
			ca.last_health_checked_at,
			COALESCE(ca.storage_limit_bytes, 0), COALESCE(ca.storage_used_bytes, 0),
			COALESCE(ca.storage_used_percent, 0), COALESCE(ca.storage_state, 'unknown'),
			COALESCE(ca.storage_message, ''), ca.storage_checked_at,
			COALESCE(ca.storage_exceeded, FALSE),
			COALESCE(pr.hostname, ''),
			COALESCE(ca.logical_instance_id, ''),
			COALESCE(ca.setup_completed, FALSE)
			FROM customer_apps ca
			LEFT JOIN public_routes pr ON pr.app_instance_id = ca.id AND pr.route_kind = 'app_instance'
			WHERE ca.customer_id = $3 ORDER BY ca.created_at DESC, ca.id DESC LIMIT $1 OFFSET $2`, limit, offset, customerID)
	} else {
		rows, err = d.Query(`SELECT ca.id, ca.customer_id, ca.app_definition_name, ca.tier_name, ca.node_id,
			ca.commercial_status, ca.technical_status, ca.tier_snapshot_json, ca.created_at,
			COALESCE(ca.health_status, ''), COALESCE(ca.health_message, ''),
			ca.last_health_checked_at,
			COALESCE(ca.storage_limit_bytes, 0), COALESCE(ca.storage_used_bytes, 0),
			COALESCE(ca.storage_used_percent, 0), COALESCE(ca.storage_state, 'unknown'),
			COALESCE(ca.storage_message, ''), ca.storage_checked_at,
			COALESCE(ca.storage_exceeded, FALSE),
			COALESCE(pr.hostname, ''),
			COALESCE(ca.logical_instance_id, ''),
			COALESCE(ca.setup_completed, FALSE)
			FROM customer_apps ca
			LEFT JOIN public_routes pr ON pr.app_instance_id = ca.id AND pr.route_kind = 'app_instance'
			ORDER BY ca.created_at DESC, ca.id DESC LIMIT $1 OFFSET $2`, limit, offset)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("query customer apps: %w", err)
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
			&a.Hostname,
			&a.LogicalInstanceID,
			&a.SetupCompleted,
		); err != nil {
			return nil, 0, fmt.Errorf("scan customer app row: %w", err)
		}
		apps = append(apps, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate customer apps: %w", err)
	}
	return apps, total, nil
}

func (d *DB) GetCustomerApp(id string) (*CustomerApp, error) {
	var a CustomerApp
	query := `SELECT ca.id, ca.customer_id, ca.app_definition_name, ca.tier_name, ca.node_id,
		ca.commercial_status, ca.technical_status, ca.tier_snapshot_json, ca.created_at,
		COALESCE(ca.health_status, ''), COALESCE(ca.health_message, ''),
		ca.last_health_checked_at,
		COALESCE(ca.storage_limit_bytes, 0), COALESCE(ca.storage_used_bytes, 0),
		COALESCE(ca.storage_used_percent, 0), COALESCE(ca.storage_state, 'unknown'),
		COALESCE(ca.storage_message, ''), ca.storage_checked_at,
		COALESCE(ca.storage_exceeded, FALSE),
		COALESCE(pr.hostname, ''),
		COALESCE(ca.logical_instance_id, ''),
		COALESCE(ca.setup_completed, FALSE)
		FROM customer_apps ca
		LEFT JOIN public_routes pr ON pr.app_instance_id = ca.id AND pr.route_kind = 'app_instance'
		WHERE ca.id = $1`
	err := d.QueryRow(query, id).Scan(&a.ID, &a.CustomerID, &a.AppDefinitionName, &a.TierName, &a.NodeID,
		&a.CommercialStatus, &a.TechnicalStatus, &a.TierSnapshotJSON, &a.CreatedAt,
		&a.HealthStatus, &a.HealthMessage, &a.LastHealthChecked,
		&a.StorageLimitBytes, &a.StorageUsedBytes, &a.StorageUsedPct,
		&a.StorageState, &a.StorageMessage, &a.StorageCheckedAt,
		&a.StorageExceeded,
		&a.Hostname,
		&a.LogicalInstanceID,
		&a.SetupCompleted,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("query customer app %q: %w", id, err)
	}
	return &a, nil
}

// --- Operations CRUD ---
