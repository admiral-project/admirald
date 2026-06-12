// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package admiral

import "time"

type FleetCommandStatus string

const (
	CommandPending    FleetCommandStatus = "pending"
	CommandLeased     FleetCommandStatus = "leased"
	CommandRunning    FleetCommandStatus = "running"
	CommandSucceeded  FleetCommandStatus = "succeeded"
	CommandFailed     FleetCommandStatus = "failed"
	CommandDeadLetter FleetCommandStatus = "dead_letter"
	CommandCancelled  FleetCommandStatus = "cancelled"
)

type FleetCommand struct {
	ID                string             `json:"id"`
	OperationID       string             `json:"operation_id"`
	OperationPublicID string             `json:"operation_public_id"`
	NodeID            string             `json:"node_id"`
	PodID             *string            `json:"pod_id,omitempty"`
	CommandType       TaskAction         `json:"command_type"`
	Payload           FleetTask          `json:"payload"`
	Status            FleetCommandStatus `json:"status"`
	Priority          int                `json:"priority"`
	AvailableAt       time.Time          `json:"available_at"`
	LeasedUntil       *time.Time         `json:"leased_until,omitempty"`
	LeasedBy          *string            `json:"leased_by,omitempty"`
	AttemptCount      int                `json:"attempt_count"`
	MaxAttempts       int                `json:"max_attempts"`
	IdempotencyKey    string             `json:"idempotency_key"`
	TaskPublicID      string             `json:"task_public_id"`
	InstanceID        string             `json:"instance_id"`
	CreatedAt         time.Time          `json:"created_at"`
	StartedAt         *time.Time         `json:"started_at,omitempty"`
	CompletedAt       *time.Time         `json:"completed_at,omitempty"`
	LastError         *string            `json:"last_error,omitempty"`
	Result            *string            `json:"result,omitempty"`
}
