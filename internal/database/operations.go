// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type OperationMetadata struct {
	TargetNodeID      string   `json:"target_node_id,omitempty"`
	SourceNodeID      string   `json:"source_node_id,omitempty"`
	LogicalInstanceID string   `json:"logical_instance_id,omitempty"`
	MigrationStep     string   `json:"migration_step,omitempty"`
	BackupRecordIDs   []string `json:"backup_record_ids,omitempty"`
	NewInstanceID     string   `json:"new_instance_id,omitempty"`
	SourceAction      string   `json:"source_action,omitempty"`
}

type Operation struct {
	ID           string             `json:"id"`
	InstanceID   string             `json:"instance_id"`
	NodeID       string             `json:"node_id,omitempty"`
	TaskID       string             `json:"task_id,omitempty"`
	Action       string             `json:"action"`
	Status       string             `json:"status"`
	ErrorMessage *string            `json:"error_message"`
	AdminUser    string             `json:"admin_user"`
	Metadata     *OperationMetadata `json:"metadata,omitempty"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`
}

func (d *DB) CreateOperation(id, instanceID, nodeID, action, status, adminUser string) error {
	query := `
		INSERT INTO operations (id, instance_id, node_id, action, status, admin_user)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := d.Exec(query, id, instanceIDArg(instanceID), nodeID, action, status, adminUser)
	if err != nil {
		return fmt.Errorf("create operation: %w", err)
	}
	return nil
}

func (d *DB) CreateOperationWithMetadata(id, instanceID, nodeID, action, status, adminUser string, metadata *OperationMetadata) error {
	var metaJSON interface{}
	if metadata != nil {
		b, err := json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("marshal operation metadata: %w", err)
		}
		metaJSON = string(b)
	} else {
		metaJSON = "{}"
	}
	query := `
		INSERT INTO operations (id, instance_id, node_id, action, status, admin_user, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := d.Exec(query, id, instanceIDArg(instanceID), nodeID, action, status, adminUser, metaJSON)
	if err != nil {
		return fmt.Errorf("create operation with metadata: %w", err)
	}
	return nil
}

func (d *DB) UpdateOperationMetadata(id string, metadata *OperationMetadata) error {
	b, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal operation metadata: %w", err)
	}
	_, err = d.Exec("UPDATE operations SET metadata = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", string(b), id)
	if err != nil {
		return fmt.Errorf("update operation metadata: %w", err)
	}
	return nil
}

func (d *DB) UpdateOperationTaskID(id, taskID string) error {
	_, err := d.Exec("UPDATE operations SET task_id = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", taskID, id)
	if err != nil {
		return fmt.Errorf("update operation task_id: %w", err)
	}
	return nil
}

func (d *DB) UpdateOperation(id, status, errMsg string) error {
	query := `
		UPDATE operations
		SET status = $1, error_message = NULLIF($2, ''), updated_at = CURRENT_TIMESTAMP
		WHERE id = $3
	`
	_, err := d.Exec(query, status, errMsg, id)
	if err != nil {
		return fmt.Errorf("update operation: %w", err)
	}
	return nil
}

func (d *DB) GetOperations() ([]Operation, error) {
	ops, _, err := d.GetOperationsPage(1000, 0)
	return ops, err
}

func (d *DB) GetOperationsPage(limit, offset int) ([]Operation, int, error) {
	var total int
	if err := d.QueryRow("SELECT COUNT(*) FROM operations").Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count operations: %w", err)
	}

	rows, err := d.Query("SELECT id, instance_id, node_id, task_id, action, status, error_message, admin_user, created_at, updated_at, metadata FROM operations ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2", limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("query operations: %w", err)
	}
	defer rows.Close()

	var ops []Operation
	for rows.Next() {
		o, err := scanOperationRow(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan operation row: %w", err)
		}
		ops = append(ops, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate operations: %w", err)
	}
	return ops, total, nil
}

func (d *DB) GetOperation(id string) (*Operation, error) {
	query := "SELECT id, instance_id, node_id, task_id, action, status, error_message, admin_user, created_at, updated_at, metadata FROM operations WHERE id = $1"
	row := d.QueryRow(query, id)
	o, err := scanOperationRowSingle(row)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("query operation %q: %w", id, err)
	}
	return o, nil
}

func (d *DB) GetRunningOperationsByInstance(instanceID string) ([]Operation, error) {
	query := "SELECT id, instance_id, node_id, task_id, action, status, error_message, admin_user, created_at, updated_at, metadata FROM operations WHERE instance_id = $1 AND status = 'running'"
	rows, err := d.Query(query, instanceID)
	if err != nil {
		return nil, fmt.Errorf("query operations by instance: %w", err)
	}
	defer rows.Close()
	var ops []Operation
	for rows.Next() {
		o, err := scanOperationRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan operation: %w", err)
		}
		ops = append(ops, *o)
	}
	return ops, rows.Err()
}
