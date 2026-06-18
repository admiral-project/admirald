// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"fmt"
	"time"
)

type NodeMetrics struct {
	NodeID        string         `json:"node_id"`
	Hostname      string         `json:"hostname"`
	IP            string         `json:"ip"`
	Status        string         `json:"status"`
	PodmanVersion string         `json:"podman_version"`
	FleetVersion  string         `json:"fleet_version"`
	LastHeartbeat *time.Time     `json:"last_heartbeat"`
	DiskTotal     int64          `json:"disk_total_bytes"`
	DiskUsed      int64          `json:"disk_used_bytes"`
	PodsActive    int            `json:"pods_active"`
	PodsPaused    int            `json:"pods_paused"`
	PodsFailed    int            `json:"pods_failed"`
	Instances     InstanceCounts `json:"instances"`
	Storage       StorageSummary `json:"storage"`
}

type InstanceCounts struct {
	Running      int `json:"running"`
	Stopped      int `json:"stopped"`
	Failed       int `json:"failed"`
	Provisioning int `json:"provisioning"`
	Total        int `json:"total"`
}

type StorageSummary struct {
	TotalInstances int   `json:"total_instances"`
	TotalLimit     int64 `json:"total_limit_bytes"`
	TotalUsed      int64 `json:"total_used_bytes"`
	TotalExceeded  int   `json:"total_exceeded"`
}

func (d *DB) GetNodeMetrics(nodeID string) (*NodeMetrics, error) {
	node, err := d.GetNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("get node for metrics: %w", err)
	}
	if node == nil {
		return nil, nil
	}

	metrics := &NodeMetrics{
		NodeID:        node.ID,
		Hostname:      node.Hostname,
		IP:            node.IP,
		Status:        node.Status,
		PodmanVersion: node.PodmanVersion,
		FleetVersion:  node.FleetVersion,
		LastHeartbeat: node.LastHeartbeat,
		DiskTotal:     node.DiskTotal,
		DiskUsed:      node.DiskUsed,
		PodsActive:    node.PodsActive,
		PodsPaused:    node.PodsPaused,
		PodsFailed:    node.PodsFailed,
	}

	// Aggregate instance counts for this node
	row := d.QueryRow(`
		SELECT
			COALESCE(SUM(CASE WHEN technical_status = 'running' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN technical_status = 'stopped' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN technical_status = 'failed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN technical_status = 'provisioning' OR technical_status = 'pending_provision' THEN 1 ELSE 0 END), 0),
			COUNT(*)
		FROM customer_apps WHERE node_id = $1`, nodeID)
	var running, stopped, failed, provisioning, total int
	if err := row.Scan(&running, &stopped, &failed, &provisioning, &total); err == nil {
		metrics.Instances = InstanceCounts{
			Running:      running,
			Stopped:      stopped,
			Failed:       failed,
			Provisioning: provisioning,
			Total:        total,
		}
	}

	// Aggregate storage summary
	sRow := d.QueryRow(`
		SELECT
			COUNT(*),
			COALESCE(SUM(storage_limit_bytes), 0),
			COALESCE(SUM(storage_used_bytes), 0),
			COALESCE(SUM(CASE WHEN storage_exceeded = TRUE THEN 1 ELSE 0 END), 0)
		FROM customer_apps WHERE node_id = $1`, nodeID)
	var stTotal int
	var stLimit, stUsed int64
	var stExceeded int
	if err := sRow.Scan(&stTotal, &stLimit, &stUsed, &stExceeded); err == nil {
		metrics.Storage = StorageSummary{
			TotalInstances: stTotal,
			TotalLimit:     stLimit,
			TotalUsed:      stUsed,
			TotalExceeded:  stExceeded,
		}
	}

	return metrics, nil
}
