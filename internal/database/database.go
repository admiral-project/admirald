// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"strings"
	"time"
	_ "github.com/lib/pq"
)



type DB struct {
	*sql.DB
}

var ErrNodeCapacityPolicyBlocked = errors.New("node cannot receive new workload under current policy")

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
}

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

type AdminUserRecord struct {
	Username           string    `json:"username"`
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
}



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



var nodeColumns = "id, hostname, ip, COALESCE(wireguard_ip, ''), COALESCE(node_role, 'worker'), COALESCE(public_ip, ''), os, podman_version, COALESCE(fleet_version, ''), status, last_heartbeat, COALESCE(disk_total_bytes, 0), COALESCE(disk_used_bytes, 0), COALESCE(pods_active, 0), COALESCE(pods_paused, 0), COALESCE(pods_failed, 0), COALESCE(storage_state, ''), COALESCE(storage_message, ''), COALESCE(manual_disabled, FALSE), COALESCE(health_status, ''), COALESCE(health_reason_codes, ''), COALESCE(available_for_provisioning, TRUE), COALESCE(unavailable_reason_codes, ''), COALESCE(ram_total_bytes, 0), COALESCE(ram_used_bytes, 0), COALESCE(ram_commit_limit_bytes, 0), COALESCE(disk_commit_limit_bytes, 0), COALESCE(committed_ram_bytes, 0), COALESCE(committed_disk_bytes, 0), last_metrics_at, COALESCE(token_type, 'worker'), COALESCE(token_status, 'pending'), COALESCE(token_identifier, ''), COALESCE(token_hash, ''), token_expires_at, COALESCE(claim_id::text, ''), COALESCE(token_value_encrypted, '')"

func scanNode(scanner interface{ Scan(...interface{}) error }, n *Node) error {
	return scanner.Scan(&n.ID, &n.Hostname, &n.IP, &n.WireguardIP, &n.NodeRole, &n.PublicIP, &n.OS, &n.PodmanVersion, &n.FleetVersion, &n.Status, &n.LastHeartbeat, &n.DiskTotal, &n.DiskUsed, &n.PodsActive, &n.PodsPaused, &n.PodsFailed, &n.StorageState, &n.StorageMsg, &n.ManualDisabled, &n.HealthStatus, &n.HealthReasonCodes, &n.AvailableForProvisioning, &n.UnavailableReasonCodes, &n.RAMTotal, &n.RAMUsed, &n.RAMCommitLimit, &n.DiskCommitLimit, &n.CommittedRAM, &n.CommittedDisk, &n.LastMetricsAt, &n.TokenType, &n.TokenStatus, &n.TokenIdentifier, &n.TokenHash, &n.TokenExpiresAt, &n.ClaimID, &n.TokenValueEncrypted)
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
	return tiers, nil
}

// --- Customer Apps CRUD ---

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
			COALESCE(ca.logical_instance_id, '')
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
			COALESCE(ca.logical_instance_id, '')
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
		); err != nil {
			return nil, 0, fmt.Errorf("scan customer app row: %w", err)
		}
		apps = append(apps, a)
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
		COALESCE(ca.logical_instance_id, '')
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
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("query customer app %q: %w", id, err)
	}
	return &a, nil
}

// --- Operations CRUD ---

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

func instanceIDArg(instanceID string) interface{} {
	if instanceID == "" {
		return nil
	}
	return instanceID
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

























func (d *DB) CreateAdminUser(username, passwordHash string, mustChangePassword bool) error {
	query := `
		INSERT INTO admin_users (username, password_hash, must_change_password)
		VALUES ($1, $2, $3)
		ON CONFLICT (username) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			must_change_password = EXCLUDED.must_change_password
	`
	_, err := d.Exec(query, username, passwordHash, mustChangePassword)
	if err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}
	return nil
}

func (d *DB) GetAdminUser(username string) (string, bool, error) {
	var passwordHash string
	var mustChange bool
	query := "SELECT password_hash, must_change_password FROM admin_users WHERE username = $1"
	err := d.QueryRow(query, username).Scan(&passwordHash, &mustChange)
	if err == sql.ErrNoRows {
		return "", false, nil
	} else if err != nil {
		return "", false, fmt.Errorf("get admin user: %w", err)
	}
	return passwordHash, mustChange, nil
}

func (d *DB) GetAdminUserCreatedAt(username string) (time.Time, error) {
	var createdAt time.Time
	query := "SELECT created_at FROM admin_users WHERE username = $1"
	err := d.QueryRow(query, username).Scan(&createdAt)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	} else if err != nil {
		return time.Time{}, fmt.Errorf("get admin user created at: %w", err)
	}
	return createdAt, nil
}

func (d *DB) UpdateAdminPassword(username, passwordHash string) error {
	query := "UPDATE admin_users SET password_hash = $1, must_change_password = FALSE WHERE username = $2"
	_, err := d.Exec(query, passwordHash, username)
	if err != nil {
		return fmt.Errorf("update admin password: %w", err)
	}
	return nil
}

func (d *DB) ListAdminUsers() ([]AdminUserRecord, error) {
	rows, err := d.Query(`
		SELECT username, must_change_password, created_at
		FROM admin_users
		ORDER BY username ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list admin users: %w", err)
	}
	defer rows.Close()

	var users []AdminUserRecord
	for rows.Next() {
		var user AdminUserRecord
		if err := rows.Scan(&user.Username, &user.MustChangePassword, &user.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan admin user: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin users: %w", err)
	}
	return users, nil
}

func (d *DB) HasAnyAdminUser() (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM admin_users)"
	if err := d.QueryRow(query).Scan(&exists); err != nil {
		return false, fmt.Errorf("check admin users: %w", err)
	}
	return exists, nil
}

// --- Admin Sessions CRUD ---







