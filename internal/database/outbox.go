// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"fmt"
	"time"
)

type OutboxEntry struct {
	ID          string    `json:"id"`
	TaskJSON    string    `json:"task_json"`
	OperationID string    `json:"operation_id"`
	InstanceID  string    `json:"instance_id"`
	NodeID      string    `json:"node_id"`
	Action      string    `json:"action"`
	Status      string    `json:"status"`
	RetryCount  int       `json:"retry_count"`
	MaxRetries  int       `json:"max_retries"`
	LastError   string    `json:"last_error"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (d *DB) CreateOutboxEntry(id, taskJSON, operationID, instanceID, nodeID, action string) error {
	query := `
		INSERT INTO task_outbox (id, task_json, operation_id, instance_id, node_id, action)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := d.Exec(query, id, taskJSON, operationID, instanceID, nodeID, action)
	if err != nil {
		return fmt.Errorf("create outbox entry: %w", err)
	}
	return nil
}

func (d *DB) GetPendingOutboxEntries(limit int) ([]OutboxEntry, error) {
	query := `
		SELECT id, task_json, operation_id, instance_id, node_id, action,
		       status, retry_count, max_retries, last_error, created_at, updated_at
		FROM task_outbox
		WHERE status = 'pending' AND retry_count < max_retries
		ORDER BY created_at ASC
		LIMIT $1
	`
	rows, err := d.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("query pending outbox entries: %w", err)
	}
	defer rows.Close()

	var entries []OutboxEntry
	for rows.Next() {
		var e OutboxEntry
		if err := rows.Scan(&e.ID, &e.TaskJSON, &e.OperationID, &e.InstanceID, &e.NodeID,
			&e.Action, &e.Status, &e.RetryCount, &e.MaxRetries, &e.LastError,
			&e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan outbox entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (d *DB) UpdateOutboxEntryRetry(id, lastError string, retryCount int) error {
	status := "pending"
	if retryCount >= 10 {
		status = "failed"
	}
	query := `
		UPDATE task_outbox
		SET status = $1, last_error = $2, retry_count = $3, updated_at = CURRENT_TIMESTAMP
		WHERE id = $4
	`
	_, err := d.Exec(query, status, lastError, retryCount, id)
	if err != nil {
		return fmt.Errorf("update outbox entry: %w", err)
	}
	return nil
}

func (d *DB) DeleteOutboxEntry(id string) error {
	_, err := d.Exec("DELETE FROM task_outbox WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete outbox entry: %w", err)
	}
	return nil
}
