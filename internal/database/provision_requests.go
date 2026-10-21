// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"errors"
	"fmt"
)

var ErrProvisionIdempotencyConflict = errors.New("idempotency key was already used for a different provision request")

type ProvisionRequestRecord struct {
	CustomerID     string
	KeyHash        string
	RequestHash    string
	InstanceID     string
	OperationID    string
	TaskID         string
	ResponseStatus int
	ResponseJSON   []byte
}

// ReserveIdempotentProvision atomically claims the caller's idempotency key,
// reserves node capacity, creates the instance and operation, and records the
// stable task ID. A duplicate key never creates a second reservation or row.
func (d *DB) ReserveIdempotentProvision(
	customerID, keyHash, requestHash, instanceID, operationID, taskID,
	appName, tierName, nodeID, tierSnapshotJSON, logicalInstanceID, adminUser string,
	ramDelta, diskDelta int64,
) (bool, *ProvisionRequestRecord, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, nil, fmt.Errorf("begin idempotent provision transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var insertedHash string
	err = tx.QueryRow(`
		INSERT INTO provision_requests (
			customer_id, idempotency_key_hash, request_hash, instance_id, operation_id, task_id
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (customer_id, idempotency_key_hash) DO NOTHING
		RETURNING request_hash
	`, customerID, keyHash, requestHash, instanceID, operationID, taskID).Scan(&insertedHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, nil, fmt.Errorf("claim provision idempotency key: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			return false, nil, fmt.Errorf("release duplicate provision transaction: %w", err)
		}
		existing, err := d.GetProvisionRequest(customerID, keyHash)
		if err != nil {
			return false, nil, err
		}
		if existing == nil {
			return false, nil, errors.New("provision idempotency record disappeared after conflict")
		}
		if existing.RequestHash != requestHash {
			return false, existing, ErrProvisionIdempotencyConflict
		}
		return false, existing, nil
	}
	if insertedHash != requestHash {
		return false, nil, errors.New("claimed provision idempotency hash changed unexpectedly")
	}

	if err := reserveNodeCapacityTx(tx, nodeID, ramDelta, diskDelta); err != nil {
		return false, nil, err
	}
	lid := logicalInstanceID
	if lid == "" {
		lid = instanceID
	}
	if _, err := tx.Exec(`
		INSERT INTO customer_apps (
			id, customer_id, app_definition_name, tier_name, node_id,
			commercial_status, technical_status, tier_snapshot_json, logical_instance_id
		) VALUES ($1, $2, $3, $4, $5, 'active', 'pending_provision', $6, $7)
	`, instanceID, customerID, appName, tierName, nodeID, tierSnapshotJSON, lid); err != nil {
		return false, nil, fmt.Errorf("create idempotent customer app: %w", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO operations (id, instance_id, node_id, task_id, action, status, admin_user)
		VALUES ($1, $2, $3, $4, 'provision_app', 'pending_dispatch', $5)
	`, operationID, instanceID, nodeID, taskID, adminUser); err != nil {
		return false, nil, fmt.Errorf("create idempotent provision operation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, nil, fmt.Errorf("commit idempotent provision transaction: %w", err)
	}
	return true, &ProvisionRequestRecord{
		CustomerID: customerID, KeyHash: keyHash, RequestHash: requestHash,
		InstanceID: instanceID, OperationID: operationID, TaskID: taskID,
	}, nil
}

func (d *DB) GetProvisionRequest(customerID, keyHash string) (*ProvisionRequestRecord, error) {
	var record ProvisionRequestRecord
	err := d.QueryRow(`
		SELECT customer_id, idempotency_key_hash, request_hash, instance_id,
			operation_id, task_id, response_status, response_json
		FROM provision_requests
		WHERE customer_id = $1 AND idempotency_key_hash = $2
	`, customerID, keyHash).Scan(
		&record.CustomerID, &record.KeyHash, &record.RequestHash,
		&record.InstanceID, &record.OperationID, &record.TaskID,
		&record.ResponseStatus, &record.ResponseJSON,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get provision idempotency record: %w", err)
	}
	return &record, nil
}

func (d *DB) CompleteProvisionRequest(customerID, keyHash string, status int, responseJSON []byte) error {
	result, err := d.Exec(`
		UPDATE provision_requests
		SET response_status = $3, response_json = $4::jsonb, updated_at = CURRENT_TIMESTAMP
		WHERE customer_id = $1 AND idempotency_key_hash = $2 AND response_status = 0
	`, customerID, keyHash, status, string(responseJSON))
	if err != nil {
		return fmt.Errorf("complete provision idempotency record: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check completed provision idempotency record: %w", err)
	}
	if rows == 1 {
		return nil
	}
	var exists bool
	if err := d.QueryRow(`SELECT EXISTS(SELECT 1 FROM provision_requests WHERE customer_id=$1 AND idempotency_key_hash=$2 AND response_status=$3 AND response_json=$4::jsonb)`, customerID, keyHash, status, string(responseJSON)).Scan(&exists); err != nil {
		return fmt.Errorf("verify completed provision idempotency record: %w", err)
	}
	if !exists {
		return errors.New("provision idempotency record was completed with a different response")
	}
	return nil
}
