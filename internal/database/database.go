// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	_ "github.com/lib/pq"
)



type DB struct {
	*sql.DB
}

var ErrNodeCapacityPolicyBlocked = errors.New("node cannot receive new workload under current policy")



func Connect(dbURL string) (*DB, error) {
	driver := "postgres"

	db, err := sql.Open(driver, dbURL)
	if err != nil {
		return nil, fmt.Errorf("open %s db: %w", driver, err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	var pingErr error
	for i := 0; i < 30; i++ {
		if pingErr = db.Ping(); pingErr == nil {
			return &DB{db}, nil
		}
		if i < 29 {
			time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("ping %s db after retries: %w", driver, pingErr)
}

// TruncateTables removes data from all tables for test isolation.
func (d *DB) TruncateTables() error {
	tables := []string{
		"public_routes",
		"task_outbox",
		"backup_records",
		"backup_storage_configs",
		"admin_sessions",
		"admin_users",
		"instance_secrets",
		"operations",
		"customer_apps",
		"app_tiers",
		"app_definitions",
		"nodes",
	}
	for _, t := range tables {
		if _, err := d.Exec(fmt.Sprintf("DELETE FROM %s", t)); err != nil {
			return fmt.Errorf("truncate %s: %w", t, err)
		}
	}
	return nil
}

// --- Nodes CRUD ---



func scanNode(scanner interface{ Scan(...interface{}) error }, n *Node) error {
	return scanner.Scan(&n.ID, &n.Hostname, &n.IP, &n.WireguardIP, &n.NodeRole, &n.PublicIP, &n.OS, &n.PodmanVersion, &n.FleetVersion, &n.Status, &n.LastHeartbeat, &n.DiskTotal, &n.DiskUsed, &n.PodsActive, &n.PodsPaused, &n.PodsFailed, &n.StorageState, &n.StorageMsg, &n.ManualDisabled, &n.HealthStatus, &n.HealthReasonCodes, &n.AvailableForProvisioning, &n.UnavailableReasonCodes, &n.RAMTotal, &n.RAMUsed, &n.RAMCommitLimit, &n.DiskCommitLimit, &n.CommittedRAM, &n.CommittedDisk, &n.LastMetricsAt, &n.TokenType, &n.TokenStatus, &n.TokenIdentifier, &n.TokenHash, &n.TokenExpiresAt, &n.ClaimID, &n.TokenValueEncrypted)
}























func reserveNodeCapacityTx(tx *sql.Tx, nodeID string, ramDelta, diskDelta int64) error {
	res, err := tx.Exec(`
		UPDATE nodes
		SET committed_ram_bytes = committed_ram_bytes + $1,
		    committed_disk_bytes = committed_disk_bytes + $2
		WHERE id = $3
		  AND status = 'active'
		  AND health_status = 'healthy'
		  AND available_for_provisioning = TRUE
		  AND COALESCE(ram_commit_limit_bytes, 0) > 0
		  AND COALESCE(disk_commit_limit_bytes, 0) > 0
		  AND committed_ram_bytes + $1 <= ram_commit_limit_bytes
		  AND committed_disk_bytes + $2 <= disk_commit_limit_bytes
	`, ramDelta, diskDelta, nodeID)
	if err != nil {
		return fmt.Errorf("reserve node %q capacity: %w", nodeID, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count reserve node %q rows affected: %w", nodeID, err)
	}
	if rows == 0 {
		return ErrNodeCapacityPolicyBlocked
	}
	return nil
}















func instanceIDArg(instanceID string) interface{} {
	if instanceID == "" {
		return nil
	}
	return instanceID
}















func scanOperationRow(rows *sql.Rows) (*Operation, error) {
	var o Operation
	var instID sql.NullString
	var metaJSON sql.NullString
	if err := rows.Scan(&o.ID, &instID, &o.NodeID, &o.TaskID, &o.Action, &o.Status, &o.ErrorMessage, &o.AdminUser, &o.CreatedAt, &o.UpdatedAt, &metaJSON); err != nil {
		return nil, err
	}
	o.InstanceID = instID.String
	if metaJSON.Valid && metaJSON.String != "" && metaJSON.String != "{}" {
		var meta OperationMetadata
		if err := json.Unmarshal([]byte(metaJSON.String), &meta); err == nil {
			o.Metadata = &meta
		}
	}
	return &o, nil
}

func scanOperationRowSingle(row *sql.Row) (*Operation, error) {
	var o Operation
	var instID sql.NullString
	var metaJSON sql.NullString
	if err := row.Scan(&o.ID, &instID, &o.NodeID, &o.TaskID, &o.Action, &o.Status, &o.ErrorMessage, &o.AdminUser, &o.CreatedAt, &o.UpdatedAt, &metaJSON); err != nil {
		return nil, err
	}
	o.InstanceID = instID.String
	if metaJSON.Valid && metaJSON.String != "" && metaJSON.String != "{}" {
		var meta OperationMetadata
		if err := json.Unmarshal([]byte(metaJSON.String), &meta); err == nil {
			o.Metadata = &meta
		}
	}
	return &o, nil
}

// --- Instance Secrets CRUD ---



































