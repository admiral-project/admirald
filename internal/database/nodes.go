// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"fmt"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"time"
)

type Node struct {
	ID                       string     `json:"id"`
	Hostname                 string     `json:"hostname"`
	IP                       string     `json:"ip"`
	WireguardIP              string     `json:"wireguard_ip"`
	NodeRole                 string     `json:"node_role"`
	PublicIP                 string     `json:"public_ip"`
	OS                       string     `json:"os"`
	PodmanVersion            string     `json:"podman_version"`
	FleetVersion             string     `json:"fleet_version"`
	Status                   string     `json:"status"`
	LastHeartbeat            *time.Time `json:"last_heartbeat"`
	DiskTotal                int64      `json:"disk_total_bytes"`
	DiskUsed                 int64      `json:"disk_used_bytes"`
	PodsActive               int        `json:"pods_active"`
	PodsPaused               int        `json:"pods_paused"`
	PodsFailed               int        `json:"pods_failed"`
	StorageState             string     `json:"storage_state"`
	StorageMsg               string     `json:"storage_message,omitempty"`
	ManualDisabled           bool       `json:"manual_disabled"`
	HealthStatus             string     `json:"health_status"`
	HealthReasonCodes        string     `json:"health_reason_codes,omitempty"`
	AvailableForProvisioning bool       `json:"available_for_provisioning"`
	UnavailableReasonCodes   string     `json:"unavailable_reason_codes,omitempty"`
	RAMTotal                 int64      `json:"ram_total_bytes"`
	RAMUsed                  int64      `json:"ram_used_bytes"`
	RAMCommitLimit           int64      `json:"ram_commit_limit_bytes"`
	DiskCommitLimit          int64      `json:"disk_commit_limit_bytes"`
	CommittedRAM             int64      `json:"committed_ram_bytes"`
	CommittedDisk            int64      `json:"committed_disk_bytes"`
	LastMetricsAt            *time.Time `json:"last_metrics_at,omitempty"`
	TokenType                string     `json:"-"`
	TokenStatus              string     `json:"-"`
	TokenIdentifier          string     `json:"-"`
	TokenHash                string     `json:"-"`
	TokenExpiresAt           *time.Time `json:"-"`
	ClaimID                  string     `json:"-"`
	TokenValueEncrypted      string     `json:"-"`
}

var nodeColumns = "id, hostname, ip, COALESCE(wireguard_ip, ''), COALESCE(node_role, 'worker'), COALESCE(public_ip, ''), os, podman_version, COALESCE(fleet_version, ''), status, last_heartbeat, COALESCE(disk_total_bytes, 0), COALESCE(disk_used_bytes, 0), COALESCE(pods_active, 0), COALESCE(pods_paused, 0), COALESCE(pods_failed, 0), COALESCE(storage_state, ''), COALESCE(storage_message, ''), COALESCE(manual_disabled, FALSE), COALESCE(health_status, ''), COALESCE(health_reason_codes, ''), COALESCE(available_for_provisioning, TRUE), COALESCE(unavailable_reason_codes, ''), COALESCE(ram_total_bytes, 0), COALESCE(ram_used_bytes, 0), COALESCE(ram_commit_limit_bytes, 0), COALESCE(disk_commit_limit_bytes, 0), COALESCE(committed_ram_bytes, 0), COALESCE(committed_disk_bytes, 0), last_metrics_at, COALESCE(token_type, 'worker'), COALESCE(token_status, 'pending'), COALESCE(token_identifier, ''), COALESCE(token_hash, ''), token_expires_at, COALESCE(claim_id::text, ''), COALESCE(token_value_encrypted, '')"

func (d *DB) RegisterNode(id, hostname, ip, wireguardIP, nodeRole, publicIP, os, podmanV string) error {
	query := `
		INSERT INTO nodes (id, hostname, ip, wireguard_ip, node_role, public_ip, os, podman_version, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'registered')
		ON CONFLICT (id) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			ip = EXCLUDED.ip,
			wireguard_ip = EXCLUDED.wireguard_ip,
			node_role = EXCLUDED.node_role,
			public_ip = EXCLUDED.public_ip,
			os = EXCLUDED.os,
			podman_version = EXCLUDED.podman_version,
			status = 'active',
			last_heartbeat = CURRENT_TIMESTAMP
	`
	_, err := d.Exec(query, id, hostname, ip, wireguardIP, nodeRole, publicIP, os, podmanV)
	if err != nil {
		return fmt.Errorf("register node: %w", err)
	}
	return nil
}

func (d *DB) GetNodes() ([]Node, error) {
	query := "SELECT " + nodeColumns + " FROM nodes ORDER BY created_at ASC"
	rows, err := d.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query nodes: %w", err)
	}
	defer rows.Close()

	var nodes []Node
	for rows.Next() {
		var n Node
		if err := scanNode(rows, &n); err != nil {
			return nil, fmt.Errorf("scan node row: %w", err)
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

func (d *DB) GetNode(id string) (*Node, error) {
	var n Node
	query := "SELECT " + nodeColumns + " FROM nodes WHERE id = $1"
	err := scanNode(d.QueryRow(query, id), &n)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("query node %q: %w", id, err)
	}
	return &n, nil
}

func (d *DB) UpdateNodeStatus(id, status string) error {
	_, err := d.Exec("UPDATE nodes SET status = $1 WHERE id = $2", status, id)
	if err != nil {
		return fmt.Errorf("update node %q status: %w", id, err)
	}
	return nil
}

func (d *DB) MarkNodesOffline(timeout time.Duration) ([]string, error) {
	rows, err := d.Query(`
		UPDATE nodes SET
			status = 'offline',
			health_status = 'degraded',
			available_for_provisioning = FALSE,
			unavailable_reason_codes = 'heartbeat_timeout'
		WHERE status NOT IN ('offline', 'disabled')
		  AND last_heartbeat < CURRENT_TIMESTAMP - $1::interval
		RETURNING id
	`, fmt.Sprintf("%d microseconds", timeout.Microseconds()))
	if err != nil {
		return nil, fmt.Errorf("mark nodes offline: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan offline node id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (d *DB) SetNodeManualDisabled(id string, disabled bool) error {
	_, err := d.Exec("UPDATE nodes SET manual_disabled = $1 WHERE id = $2", disabled, id)
	if err != nil {
		return fmt.Errorf("set node %q manual_disabled=%t: %w", id, disabled, err)
	}
	return nil
}

func (d *DB) UpdateNodeHeartbeat(id string, req *admiral.HeartbeatRequest) error {
	query := `
		UPDATE nodes SET
			last_heartbeat = CURRENT_TIMESTAMP,
			last_metrics_at = CURRENT_TIMESTAMP,
			status = 'active',
			hostname = COALESCE(NULLIF($2, ''), hostname),
			ip = COALESCE(NULLIF($3, ''), ip),
			wireguard_ip = COALESCE(NULLIF($4, ''), wireguard_ip),
			public_ip = COALESCE(NULLIF($5, ''), public_ip),
			podman_version = COALESCE(NULLIF($6, ''), podman_version),
			fleet_version = COALESCE(NULLIF($7, ''), fleet_version),
			disk_total_bytes = $8,
			disk_used_bytes = $9,
			ram_total_bytes = $10,
			ram_used_bytes = $11,
			pods_active = $12,
			pods_paused = $13,
			pods_failed = $14
		WHERE id = $1
	`
	_, err := d.Exec(query, id, req.Hostname, req.IP, req.WireguardIP, req.PublicIP, req.PodmanVersion, req.FleetVersion,
		req.DiskTotal, req.DiskUsed, req.RAMTotal, req.RAMUsed,
		req.PodsActive, req.PodsPaused, req.PodsFailed)
	if err != nil {
		return fmt.Errorf("update node heartbeat: %w", err)
	}
	return nil
}

func (d *DB) UpsertNodeToken(nodeID, tokenIdentifier, tokenHash, tokenType, tokenStatus, tokenValueEncrypted string, expiresAt *time.Time, claimID string) error {
	query := `
		UPDATE nodes SET
			token_type = COALESCE(NULLIF($2, ''), token_type),
			token_status = $3,
			token_identifier = $4,
			token_hash = $5,
			token_expires_at = $6,
			claim_id = $7::uuid,
			token_value_encrypted = $8
		WHERE id = $1
	`
	claimIDVal := interface{}(nil)
	if claimID != "" {
		claimIDVal = claimID
	}
	_, err := d.Exec(query, nodeID, tokenType, tokenStatus, tokenIdentifier, tokenHash, expiresAt, claimIDVal, tokenValueEncrypted)
	if err != nil {
		return fmt.Errorf("upsert node token: %w", err)
	}
	return nil
}

func (d *DB) GetNodeByTokenIdentifier(identifier string) (*Node, error) {
	query := "SELECT " + nodeColumns + " FROM nodes WHERE token_identifier = $1"
	var n Node
	err := scanNode(d.QueryRow(query, identifier), &n)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("query node by token identifier: %w", err)
	}
	return &n, nil
}

func (d *DB) RemoveNode(id string, force bool) error {
	tx, err := d.Begin()
	if err != nil {
		return fmt.Errorf("remove node %q: begin tx: %w", id, err)
	}
	defer tx.Rollback()

	if !force {
		var count int
		err := tx.QueryRow("SELECT COUNT(*) FROM customer_apps WHERE node_id = $1", id).Scan(&count)
		if err != nil {
			return fmt.Errorf("remove node %q: check instances: %w", id, err)
		}
		if count > 0 {
			return fmt.Errorf("remove node %q: node has %d active instance(s); use --force to override", id, count)
		}
	}

	_, err = tx.Exec("DELETE FROM public_routes WHERE node_id = $1", id)
	if err != nil {
		return fmt.Errorf("remove node %q: delete public_routes: %w", id, err)
	}
	_, err = tx.Exec("DELETE FROM backups WHERE node_id = $1", id)
	if err != nil {
		return fmt.Errorf("remove node %q: delete backups: %w", id, err)
	}
	_, err = tx.Exec("DELETE FROM customer_apps WHERE node_id = $1", id)
	if err != nil {
		return fmt.Errorf("remove node %q: delete customer_apps: %w", id, err)
	}
	result, err := tx.Exec("DELETE FROM nodes WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("remove node %q: delete node: %w", id, err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("remove node %q: node not found", id)
	}
	return tx.Commit()
}

func (d *DB) DeleteExpiredPendingNodes() ([]string, error) {
	rows, err := d.Query(`
		DELETE FROM nodes
		WHERE token_status IN ('available', 'pending')
		  AND token_expires_at < NOW()
		RETURNING id
	`)
	if err != nil {
		return nil, fmt.Errorf("delete expired pending nodes: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan expired node id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (d *DB) ReapExpiredNodeTokens() (int64, error) {
	res, err := d.Exec(`
		DELETE FROM nodes
		WHERE token_status = 'available'
		  AND token_expires_at < NOW()
	`)
	if err != nil {
		return 0, fmt.Errorf("reap expired node tokens: %w", err)
	}
	count, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("reap expired node tokens: count rows: %w", err)
	}
	return count, nil
}

func (d *DB) UpdateNodeTokenStatus(nodeID, status string) error {
	_, err := d.Exec("UPDATE nodes SET token_status = $1 WHERE id = $2", status, nodeID)
	if err != nil {
		return fmt.Errorf("update node token status: %w", err)
	}
	return nil
}

// --- App Definitions CRUD ---
