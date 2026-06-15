// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
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

type PublicRoute struct {
	ID                  string     `json:"id"`
	Hostname            string     `json:"hostname"`
	PublicID            string     `json:"public_id"`
	AppInstanceID       string     `json:"app_instance_id"`
	AppTemplateCode     string     `json:"app_template_code"`
	NodeID              *string    `json:"node_id"`
	ServiceName         string     `json:"service_name"`
	TargetScheme        string     `json:"target_scheme"`
	TargetHost          string     `json:"target_host"`
	TargetPort          int        `json:"target_port"`
	TargetURL           string     `json:"target_url"`
	RouteKind           string     `json:"route_kind"`
	TLSMode             string     `json:"tls_mode"`
	Status              string     `json:"status"`
	LastError           string     `json:"last_error"`
	LastHealthStatus    string     `json:"last_health_status"`
	LastHealthCheckedAt *time.Time `json:"last_health_checked_at"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type InstanceSecret struct {
	InstanceID       string    `json:"instance_id"`
	ServiceName      string    `json:"service_name"`
	EnvName          string    `json:"env_name"`
	EncryptedValue   string    `json:"-"`
	ExposeToCustomer bool      `json:"expose_to_customer"`
	CreatedAt        time.Time `json:"created_at"`
}

func Connect(dbURL string) (*DB, error) {
	driver := "postgres"
	if strings.HasPrefix(dbURL, "sqlite://") {
		driver = "sqlite3"
		dbURL = strings.TrimPrefix(dbURL, "sqlite://")
	}

	db, err := sql.Open(driver, dbURL)
	if err != nil {
		return nil, fmt.Errorf("open %s db: %w", driver, err)
	}

	if driver == "postgres" {
		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(5 * time.Minute)
	}

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

func (d *DB) DeleteExpiredAdminSessions() error {
	_, err := d.Exec("DELETE FROM admin_sessions WHERE expires_at < CURRENT_TIMESTAMP OR last_activity_at < $1", time.Now().Add(-30*time.Minute))
	if err != nil {
		return fmt.Errorf("delete expired admin sessions: %w", err)
	}
	return nil
}

var nodeColumns = "id, hostname, ip, COALESCE(wireguard_ip, ''), COALESCE(node_role, 'worker'), COALESCE(public_ip, ''), os, podman_version, COALESCE(fleet_version, ''), status, last_heartbeat, COALESCE(disk_total_bytes, 0), COALESCE(disk_used_bytes, 0), COALESCE(pods_active, 0), COALESCE(pods_paused, 0), COALESCE(pods_failed, 0), COALESCE(storage_state, ''), COALESCE(storage_message, ''), COALESCE(manual_disabled, FALSE), COALESCE(health_status, ''), COALESCE(health_reason_codes, ''), COALESCE(available_for_provisioning, TRUE), COALESCE(unavailable_reason_codes, ''), COALESCE(ram_total_bytes, 0), COALESCE(ram_used_bytes, 0), COALESCE(ram_commit_limit_bytes, 0), COALESCE(disk_commit_limit_bytes, 0), COALESCE(committed_ram_bytes, 0), COALESCE(committed_disk_bytes, 0), last_metrics_at"

func scanNode(scanner interface{ Scan(...interface{}) error }, n *Node) error {
	return scanner.Scan(&n.ID, &n.Hostname, &n.IP, &n.WireguardIP, &n.NodeRole, &n.PublicIP, &n.OS, &n.PodmanVersion, &n.FleetVersion, &n.Status, &n.LastHeartbeat, &n.DiskTotal, &n.DiskUsed, &n.PodsActive, &n.PodsPaused, &n.PodsFailed, &n.StorageState, &n.StorageMsg, &n.ManualDisabled, &n.HealthStatus, &n.HealthReasonCodes, &n.AvailableForProvisioning, &n.UnavailableReasonCodes, &n.RAMTotal, &n.RAMUsed, &n.RAMCommitLimit, &n.DiskCommitLimit, &n.CommittedRAM, &n.CommittedDisk, &n.LastMetricsAt)
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

// --- App Definitions CRUD ---

func (d *DB) SaveAppDefinition(name, displayName, description, rawYAML string, tiers []AppTier) error {
	tx, err := d.Begin()
	if err != nil {
		return fmt.Errorf("start transaction: %w", err)
	}
	defer tx.Rollback()

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
	defer tx.Rollback()

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
	defer tx.Rollback()

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

func (d *DB) SaveInstanceSecret(instanceID, serviceName, envName, encryptedValue string, expose bool) error {
	query := `
		INSERT INTO instance_secrets (instance_id, service_name, env_name, encrypted_value, expose_to_customer)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (instance_id, service_name, env_name) DO UPDATE SET
			encrypted_value = EXCLUDED.encrypted_value,
			expose_to_customer = EXCLUDED.expose_to_customer
	`
	_, err := d.Exec(query, instanceID, serviceName, envName, encryptedValue, expose)
	if err != nil {
		return fmt.Errorf("save instance secret: %w", err)
	}
	return nil
}

func (d *DB) GetInstanceSecrets(instanceID string) ([]InstanceSecret, error) {
	rows, err := d.Query("SELECT instance_id, service_name, env_name, encrypted_value, expose_to_customer, created_at FROM instance_secrets WHERE instance_id = $1 ORDER BY service_name, env_name", instanceID)
	if err != nil {
		return nil, fmt.Errorf("query instance secrets: %w", err)
	}
	defer rows.Close()

	var secrets []InstanceSecret
	for rows.Next() {
		var s InstanceSecret
		if err := rows.Scan(&s.InstanceID, &s.ServiceName, &s.EnvName, &s.EncryptedValue, &s.ExposeToCustomer, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan instance secret row: %w", err)
		}
		secrets = append(secrets, s)
	}
	return secrets, nil
}

func (d *DB) GetExposedInstanceSecrets(instanceID string) ([]InstanceSecret, error) {
	rows, err := d.Query("SELECT instance_id, service_name, env_name, encrypted_value, expose_to_customer, created_at FROM instance_secrets WHERE instance_id = $1 AND expose_to_customer = TRUE ORDER BY service_name, env_name", instanceID)
	if err != nil {
		return nil, fmt.Errorf("query exposed instance secrets: %w", err)
	}
	defer rows.Close()

	var secrets []InstanceSecret
	for rows.Next() {
		var s InstanceSecret
		if err := rows.Scan(&s.InstanceID, &s.ServiceName, &s.EnvName, &s.EncryptedValue, &s.ExposeToCustomer, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan exposed instance secret row: %w", err)
		}
		secrets = append(secrets, s)
	}
	return secrets, nil
}

// --- Public Routes CRUD ---

func (d *DB) CreatePublicRoute(route PublicRoute) error {
	query := `
		INSERT INTO public_routes (
			id, hostname, public_id, app_instance_id, app_template_code, node_id,
			service_name, target_scheme, target_host, target_port, target_url,
			route_kind, tls_mode, status, last_error, last_health_status, last_health_checked_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (hostname) DO UPDATE SET
			public_id = EXCLUDED.public_id,
			app_instance_id = EXCLUDED.app_instance_id,
			app_template_code = EXCLUDED.app_template_code,
			node_id = EXCLUDED.node_id,
			service_name = EXCLUDED.service_name,
			target_scheme = EXCLUDED.target_scheme,
			target_host = EXCLUDED.target_host,
			target_port = EXCLUDED.target_port,
			target_url = EXCLUDED.target_url,
			route_kind = EXCLUDED.route_kind,
			tls_mode = EXCLUDED.tls_mode,
			status = EXCLUDED.status,
			last_error = EXCLUDED.last_error,
			last_health_status = EXCLUDED.last_health_status,
			last_health_checked_at = EXCLUDED.last_health_checked_at,
			updated_at = CURRENT_TIMESTAMP
	`
	var nodeID interface{}
	if route.NodeID != nil && *route.NodeID != "" {
		nodeID = *route.NodeID
	}
	var appInstanceID interface{}
	if route.AppInstanceID != "" {
		appInstanceID = route.AppInstanceID
	}
	var lastHealthCheckedAt interface{}
	if route.LastHealthCheckedAt != nil {
		lastHealthCheckedAt = *route.LastHealthCheckedAt
	}
	_, err := d.Exec(
		query,
		route.ID,
		route.Hostname,
		route.PublicID,
		appInstanceID,
		route.AppTemplateCode,
		nodeID,
		route.ServiceName,
		route.TargetScheme,
		route.TargetHost,
		route.TargetPort,
		route.TargetURL,
		route.RouteKind,
		route.TLSMode,
		route.Status,
		route.LastError,
		route.LastHealthStatus,
		lastHealthCheckedAt,
	)
	if err != nil {
		return fmt.Errorf("create public route %q: %w", route.Hostname, err)
	}
	return nil
}

func (d *DB) GetPublicRoutes() ([]PublicRoute, error) {
	rows, err := d.Query(`
		SELECT id, hostname, public_id, app_instance_id, app_template_code, node_id,
		       service_name, target_scheme, target_host, target_port, target_url,
		       route_kind, tls_mode, status, last_error, last_health_status,
		       last_health_checked_at, created_at, updated_at
		FROM public_routes
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query public routes: %w", err)
	}
	defer rows.Close()

	var routes []PublicRoute
	for rows.Next() {
		var r PublicRoute
		var appInstanceID sql.NullString
		var nodeID sql.NullString
		var lastHealthCheckedAt sql.NullTime
		if err := rows.Scan(
			&r.ID, &r.Hostname, &r.PublicID, &appInstanceID, &r.AppTemplateCode, &nodeID,
			&r.ServiceName, &r.TargetScheme, &r.TargetHost, &r.TargetPort, &r.TargetURL,
			&r.RouteKind, &r.TLSMode, &r.Status, &r.LastError, &r.LastHealthStatus,
			&lastHealthCheckedAt, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan public route row: %w", err)
		}
		if appInstanceID.Valid {
			r.AppInstanceID = appInstanceID.String
		}
		if nodeID.Valid {
			n := nodeID.String
			r.NodeID = &n
		}
		if lastHealthCheckedAt.Valid {
			t := lastHealthCheckedAt.Time
			r.LastHealthCheckedAt = &t
		}
		routes = append(routes, r)
	}
	return routes, nil
}

func (d *DB) GetPublicRoute(hostname string) (*PublicRoute, error) {
	var r PublicRoute
	var appInstanceID sql.NullString
	var nodeID sql.NullString
	var lastHealthCheckedAt sql.NullTime
	query := `
		SELECT id, hostname, public_id, app_instance_id, app_template_code, node_id,
		       service_name, target_scheme, target_host, target_port, target_url,
		       route_kind, tls_mode, status, last_error, last_health_status,
		       last_health_checked_at, created_at, updated_at
		FROM public_routes
		WHERE hostname = $1
	`
	err := d.QueryRow(query, hostname).Scan(
		&r.ID, &r.Hostname, &r.PublicID, &appInstanceID, &r.AppTemplateCode, &nodeID,
		&r.ServiceName, &r.TargetScheme, &r.TargetHost, &r.TargetPort, &r.TargetURL,
		&r.RouteKind, &r.TLSMode, &r.Status, &r.LastError, &r.LastHealthStatus,
		&lastHealthCheckedAt, &r.CreatedAt, &r.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("query public route %q: %w", hostname, err)
	}
	if appInstanceID.Valid {
		r.AppInstanceID = appInstanceID.String
	}
	if nodeID.Valid {
		n := nodeID.String
		r.NodeID = &n
	}
	if lastHealthCheckedAt.Valid {
		t := lastHealthCheckedAt.Time
		r.LastHealthCheckedAt = &t
	}
	return &r, nil
}

func (d *DB) UpdatePublicRoute(route *PublicRoute) error {
	if route == nil {
		return fmt.Errorf("public route is nil")
	}
	query := `
		UPDATE public_routes
		SET hostname = $1,
		    public_id = $2,
		    app_instance_id = $3,
		    app_template_code = $4,
		    node_id = $5,
		    service_name = $6,
		    target_scheme = $7,
		    target_host = $8,
		    target_port = $9,
		    target_url = $10,
		    route_kind = $11,
		    tls_mode = $12,
		    status = $13,
		    last_error = $14,
		    last_health_status = $15,
		    last_health_checked_at = $16,
		    updated_at = CURRENT_TIMESTAMP
		WHERE hostname = $1
	`
	var nodeID interface{}
	if route.NodeID != nil && *route.NodeID != "" {
		nodeID = *route.NodeID
	}
	var appInstanceID interface{}
	if route.AppInstanceID != "" {
		appInstanceID = route.AppInstanceID
	}
	var lastHealthCheckedAt interface{}
	if route.LastHealthCheckedAt != nil {
		lastHealthCheckedAt = *route.LastHealthCheckedAt
	}
	res, err := d.Exec(
		query,
		route.Hostname,
		route.PublicID,
		appInstanceID,
		route.AppTemplateCode,
		nodeID,
		route.ServiceName,
		route.TargetScheme,
		route.TargetHost,
		route.TargetPort,
		route.TargetURL,
		route.RouteKind,
		route.TLSMode,
		route.Status,
		route.LastError,
		route.LastHealthStatus,
		lastHealthCheckedAt,
	)
	if err != nil {
		return fmt.Errorf("update public route %q: %w", route.Hostname, err)
	}
	if rows, rerr := res.RowsAffected(); rerr == nil && rows == 0 {
		return fmt.Errorf("update public route %q: no rows affected", route.Hostname)
	}
	return nil
}

func (d *DB) DeletePublicRoute(hostname string) error {
	_, err := d.Exec("DELETE FROM public_routes WHERE hostname = $1", hostname)
	if err != nil {
		return fmt.Errorf("delete public route %q: %w", hostname, err)
	}
	return nil
}

func (d *DB) DeletePublicRouteByKind(kind string) error {
	_, err := d.Exec("DELETE FROM public_routes WHERE route_kind = $1", kind)
	if err != nil {
		return fmt.Errorf("delete public routes by kind %q: %w", kind, err)
	}
	return nil
}

func (d *DB) DeletePublicRouteByKindAndNotHostname(kind, hostname string) error {
	_, err := d.Exec("DELETE FROM public_routes WHERE route_kind = $1 AND hostname != $2", kind, hostname)
	if err != nil {
		return fmt.Errorf("delete public routes by kind %q except %q: %w", kind, hostname, err)
	}
	return nil
}

func (d *DB) UpdatePublicRouteStatus(hostname, status, lastError, lastHealth string, checkedAt *time.Time) error {
	query := `
		UPDATE public_routes
		SET status = $2,
		    last_error = $3,
		    last_health_status = $4,
		    last_health_checked_at = $5,
		    updated_at = CURRENT_TIMESTAMP
		WHERE hostname = $1
	`
	var checked interface{}
	if checkedAt != nil {
		checked = *checkedAt
	}
	_, err := d.Exec(query, hostname, status, lastError, lastHealth, checked)
	if err != nil {
		return fmt.Errorf("update public route %q status: %w", hostname, err)
	}
	return nil
}

// --- Admin Users CRUD ---

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

func (d *DB) CreateAdminSession(tokenHash, username string, expiresAt, lastActivityAt time.Time) error {
	query := `
		INSERT INTO admin_sessions (token_hash, username, expires_at, last_activity_at)
		VALUES ($1, $2, $3, $4)
	`
	_, err := d.Exec(query, tokenHash, username, expiresAt, lastActivityAt)
	if err != nil {
		return fmt.Errorf("create admin session: %w", err)
	}
	return nil
}

func (d *DB) GetAdminSession(tokenHash string) (string, time.Time, time.Time, error) {
	var username string
	var expiresAt, lastActivityAt time.Time
	query := "SELECT username, expires_at, last_activity_at FROM admin_sessions WHERE token_hash = $1"
	err := d.QueryRow(query, tokenHash).Scan(&username, &expiresAt, &lastActivityAt)
	if err == sql.ErrNoRows {
		return "", time.Time{}, time.Time{}, nil
	} else if err != nil {
		return "", time.Time{}, time.Time{}, fmt.Errorf("get admin session: %w", err)
	}
	return username, expiresAt, lastActivityAt, nil
}

func (d *DB) UpdateAdminSessionActivity(tokenHash string, lastActivity time.Time) error {
	_, err := d.Exec("UPDATE admin_sessions SET last_activity_at = $1 WHERE token_hash = $2", lastActivity, tokenHash)
	if err != nil {
		return fmt.Errorf("update admin session activity: %w", err)
	}
	return nil
}

func (d *DB) DeleteAdminSession(tokenHash string) error {
	_, err := d.Exec("DELETE FROM admin_sessions WHERE token_hash = $1", tokenHash)
	if err != nil {
		return fmt.Errorf("delete admin session: %w", err)
	}
	return nil
}

// --- Backup Storage Config CRUD ---

func (d *DB) SaveBackupStorageConfig(cfg *admiral.BackupStorageConfig) error {
	query := `
		INSERT INTO backup_storage_configs (id, backend, enabled, endpoint, region, bucket, prefix, force_path_style, access_key_env, secret_key_env, session_token_env, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO UPDATE SET
			backend = EXCLUDED.backend,
			enabled = EXCLUDED.enabled,
			endpoint = EXCLUDED.endpoint,
			region = EXCLUDED.region,
			bucket = EXCLUDED.bucket,
			prefix = EXCLUDED.prefix,
			force_path_style = EXCLUDED.force_path_style,
			access_key_env = EXCLUDED.access_key_env,
			secret_key_env = EXCLUDED.secret_key_env,
			session_token_env = EXCLUDED.session_token_env,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := d.Exec(query, cfg.ID, cfg.Backend, cfg.Enabled, cfg.Endpoint, cfg.Region, cfg.Bucket, cfg.Prefix, cfg.ForcePathStyle, cfg.AccessKeyEnv, cfg.SecretKeyEnv, cfg.SessionTokenEnv)
	if err != nil {
		return fmt.Errorf("save backup storage config: %w", err)
	}
	return nil
}

func (d *DB) GetBackupStorageConfig(id string) (*admiral.BackupStorageConfig, error) {
	var c admiral.BackupStorageConfig
	var createdAt, updatedAt time.Time
	query := "SELECT id, backend, enabled, endpoint, region, bucket, prefix, force_path_style, access_key_env, secret_key_env, session_token_env, created_at, updated_at FROM backup_storage_configs WHERE id = $1"
	err := d.QueryRow(query, id).Scan(&c.ID, &c.Backend, &c.Enabled, &c.Endpoint, &c.Region, &c.Bucket, &c.Prefix, &c.ForcePathStyle, &c.AccessKeyEnv, &c.SecretKeyEnv, &c.SessionTokenEnv, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("get backup storage config: %w", err)
	}
	c.CreatedAt = createdAt.Format(time.RFC3339)
	c.UpdatedAt = updatedAt.Format(time.RFC3339)
	return &c, nil
}

func (d *DB) GetActiveBackupStorageConfig() (*admiral.BackupStorageConfig, error) {
	var c admiral.BackupStorageConfig
	var createdAt, updatedAt time.Time
	query := "SELECT id, backend, enabled, endpoint, region, bucket, prefix, force_path_style, access_key_env, secret_key_env, session_token_env, created_at, updated_at FROM backup_storage_configs WHERE enabled = TRUE LIMIT 1"
	err := d.QueryRow(query).Scan(&c.ID, &c.Backend, &c.Enabled, &c.Endpoint, &c.Region, &c.Bucket, &c.Prefix, &c.ForcePathStyle, &c.AccessKeyEnv, &c.SecretKeyEnv, &c.SessionTokenEnv, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("get active backup storage config: %w", err)
	}
	c.CreatedAt = createdAt.Format(time.RFC3339)
	c.UpdatedAt = updatedAt.Format(time.RFC3339)
	return &c, nil
}

// --- Backup Record CRUD ---

func (d *DB) CreateBackupRecord(rec *admiral.BackupRecord) error {
	query := `
		INSERT INTO backup_records (id, instance_id, app_id, tier_id, node_id, backup_type, database_type, status, storage_backend, storage_key, storage_uri_admin, size_bytes, checksum_sha256, triggered_by, retention_policy_snapshot_json, tier_snapshot_json, error_message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`
	_, err := d.Exec(query, rec.ID, rec.InstanceID, rec.AppID, rec.TierID, rec.NodeID, rec.BackupType, rec.DatabaseType, rec.Status, rec.StorageBackend, rec.StorageKey, rec.StorageURIAdmin, rec.SizeBytes, rec.ChecksumSHA256, rec.TriggeredBy, rec.RetentionPolicySnapshotJSON, rec.TierSnapshotJSON, rec.ErrorMessage)
	if err != nil {
		return fmt.Errorf("create backup record: %w", err)
	}
	return nil
}

func (d *DB) UpdateBackupRecord(rec *admiral.BackupRecord) error {
	query := `
		UPDATE backup_records
		SET status = $1, storage_backend = $2, storage_key = $3, storage_uri_admin = $4, size_bytes = $5, checksum_sha256 = $6, completed_at = CURRENT_TIMESTAMP, expires_at = $7, error_message = $8
		WHERE id = $9
	`
	var expiresVal interface{}
	if rec.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, rec.ExpiresAt)
		if err == nil {
			expiresVal = parsed
		} else {
			expiresVal = nil
		}
	} else {
		expiresVal = nil
	}

	_, err := d.Exec(query, rec.Status, rec.StorageBackend, rec.StorageKey, rec.StorageURIAdmin, rec.SizeBytes, rec.ChecksumSHA256, expiresVal, rec.ErrorMessage, rec.ID)
	if err != nil {
		return fmt.Errorf("update backup record: %w", err)
	}
	return nil
}

func (d *DB) GetBackupRecords(instanceID string) ([]admiral.BackupRecord, error) {
	records, _, err := d.GetBackupRecordsPage(instanceID, 1000, 0)
	return records, err
}

func (d *DB) GetBackupRecordsPage(instanceID string, limit, offset int) ([]admiral.BackupRecord, int, error) {
	var total int
	var countErr error
	if instanceID != "" {
		countErr = d.QueryRow("SELECT COUNT(*) FROM backup_records WHERE instance_id = $1", instanceID).Scan(&total)
	} else {
		countErr = d.QueryRow("SELECT COUNT(*) FROM backup_records").Scan(&total)
	}
	if countErr != nil {
		return nil, 0, fmt.Errorf("count backup records: %w", countErr)
	}

	var rows *sql.Rows
	var err error
	if instanceID != "" {
		rows, err = d.Query("SELECT id, instance_id, app_id, tier_id, node_id, backup_type, database_type, status, storage_backend, storage_key, storage_uri_admin, size_bytes, checksum_sha256, created_at, completed_at, expires_at, triggered_by, retention_policy_snapshot_json, tier_snapshot_json, error_message FROM backup_records WHERE instance_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3", instanceID, limit, offset)
	} else {
		rows, err = d.Query("SELECT id, instance_id, app_id, tier_id, node_id, backup_type, database_type, status, storage_backend, storage_key, storage_uri_admin, size_bytes, checksum_sha256, created_at, completed_at, expires_at, triggered_by, retention_policy_snapshot_json, tier_snapshot_json, error_message FROM backup_records ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2", limit, offset)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("query backup records: %w", err)
	}
	defer rows.Close()

	var records []admiral.BackupRecord
	for rows.Next() {
		var r admiral.BackupRecord
		var createdAt time.Time
		var completedAt, expiresAt sql.NullTime
		err := rows.Scan(
			&r.ID, &r.InstanceID, &r.AppID, &r.TierID, &r.NodeID,
			&r.BackupType, &r.DatabaseType, &r.Status, &r.StorageBackend,
			&r.StorageKey, &r.StorageURIAdmin, &r.SizeBytes, &r.ChecksumSHA256,
			&createdAt, &completedAt, &expiresAt, &r.TriggeredBy,
			&r.RetentionPolicySnapshotJSON, &r.TierSnapshotJSON, &r.ErrorMessage,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan backup record row: %w", err)
		}
		r.CreatedAt = createdAt.Format(time.RFC3339)
		if completedAt.Valid {
			r.CompletedAt = completedAt.Time.Format(time.RFC3339)
		}
		if expiresAt.Valid {
			r.ExpiresAt = expiresAt.Time.Format(time.RFC3339)
		}
		records = append(records, r)
	}
	return records, total, nil
}

func (d *DB) GetBackupRecord(id string) (*admiral.BackupRecord, error) {
	var r admiral.BackupRecord
	var createdAt time.Time
	var completedAt, expiresAt sql.NullTime
	query := "SELECT id, instance_id, app_id, tier_id, node_id, backup_type, database_type, status, storage_backend, storage_key, storage_uri_admin, size_bytes, checksum_sha256, created_at, completed_at, expires_at, triggered_by, retention_policy_snapshot_json, tier_snapshot_json, error_message FROM backup_records WHERE id = $1"
	err := d.QueryRow(query, id).Scan(
		&r.ID, &r.InstanceID, &r.AppID, &r.TierID, &r.NodeID,
		&r.BackupType, &r.DatabaseType, &r.Status, &r.StorageBackend,
		&r.StorageKey, &r.StorageURIAdmin, &r.SizeBytes, &r.ChecksumSHA256,
		&createdAt, &completedAt, &expiresAt, &r.TriggeredBy,
		&r.RetentionPolicySnapshotJSON, &r.TierSnapshotJSON, &r.ErrorMessage,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("get backup record: %w", err)
	}
	r.CreatedAt = createdAt.Format(time.RFC3339)
	if completedAt.Valid {
		r.CompletedAt = completedAt.Time.Format(time.RFC3339)
	}
	if expiresAt.Valid {
		r.ExpiresAt = expiresAt.Time.Format(time.RFC3339)
	}
	return &r, nil
}

// --- Task Outbox ---

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

func (d *DB) UpdateInstanceHealth(instanceID, healthStatus, message string) error {
	_, err := d.Exec("UPDATE customer_apps SET health_status = $1, health_message = $2, last_health_checked_at = CURRENT_TIMESTAMP WHERE id = $3",
		healthStatus, message, instanceID)
	return err
}

func (d *DB) UpdateInstanceHealthAndTechStatus(instanceID, healthStatus, techStatus, message string) error {
	_, err := d.Exec("UPDATE customer_apps SET health_status = $1, health_message = $2, technical_status = $3, last_health_checked_at = CURRENT_TIMESTAMP WHERE id = $4",
		healthStatus, message, techStatus, instanceID)
	return err
}

func (d *DB) UpdateInstanceStorage(instanceID, storageState, storageMessage string, limitBytes, usedBytes int64, usedPct float64, exceeded bool) error {
	_, err := d.Exec(`UPDATE customer_apps SET
		storage_limit_bytes = $1, storage_used_bytes = $2, storage_used_percent = $3,
		storage_state = $4, storage_message = $5, storage_checked_at = CURRENT_TIMESTAMP,
		storage_exceeded = $6 WHERE id = $7`,
		limitBytes, usedBytes, usedPct, storageState, storageMessage, exceeded, instanceID)
	return err
}

func (d *DB) SetGracePeriod(instanceID string, endsAt time.Time) error {
	_, err := d.Exec(`UPDATE customer_apps SET
		grace_period_starts_at = CURRENT_TIMESTAMP,
		grace_period_ends_at = $1
		WHERE id = $2`, endsAt, instanceID)
	return err
}

func (d *DB) ClearGracePeriod(instanceID string) error {
	_, err := d.Exec(`UPDATE customer_apps SET
		grace_period_starts_at = NULL,
		grace_period_ends_at = NULL
		WHERE id = $1`, instanceID)
	return err
}

func (d *DB) GetExpiredGracePeriodApps() ([]CustomerApp, error) {
	rows, err := d.Query(`SELECT id, customer_id, app_definition_name, tier_name, node_id,
		commercial_status, technical_status, tier_snapshot_json, created_at,
		COALESCE(health_status, ''), COALESCE(health_message, ''),
		last_health_checked_at,
		COALESCE(storage_limit_bytes, 0), COALESCE(storage_used_bytes, 0),
		COALESCE(storage_used_percent, 0), COALESCE(storage_state, 'unknown'),
		COALESCE(storage_message, ''), storage_checked_at,
		COALESCE(storage_exceeded, FALSE),
		COALESCE(logical_instance_id, '')
		FROM customer_apps
		WHERE grace_period_ends_at IS NOT NULL
		AND grace_period_ends_at < CURRENT_TIMESTAMP
		AND storage_state = 'over_quota'
		AND technical_status NOT IN ('stopped', 'paused_for_storage')
		ORDER BY grace_period_ends_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("query expired grace period apps: %w", err)
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
			&a.LogicalInstanceID,
		); err != nil {
			return nil, fmt.Errorf("scan expired grace period app: %w", err)
		}
		apps = append(apps, a)
	}
	return apps, nil
}

func (d *DB) UpdateNodeStorageState(nodeID, storageState, storageMsg string) error {
	_, err := d.Exec("UPDATE nodes SET storage_state = $1, storage_message = $2 WHERE id = $3",
		storageState, storageMsg, nodeID)
	return err
}

const (
	RAMCommitRatio          = 0.80
	DiskSafeNodeRatio       = 0.80
	DiskEmergencyMultiplier = 1.20
	RAMHealthCriticalRatio  = 0.90
	DiskHealthCriticalRatio = 0.90
	MetricsStaleAfterSec    = 180
)

func ParseSizeBytes(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	lower := strings.ToLower(value)
	mult := int64(1)
	switch {
	case strings.HasSuffix(lower, "tb"), strings.HasSuffix(lower, "t"):
		mult = 1 << 40
		value = strings.TrimRight(value, "tbTB")
	case strings.HasSuffix(lower, "gb"), strings.HasSuffix(lower, "g"):
		mult = 1 << 30
		value = strings.TrimRight(value, "gbGB")
	case strings.HasSuffix(lower, "mb"), strings.HasSuffix(lower, "m"):
		mult = 1 << 20
		value = strings.TrimRight(value, "mbMB")
	case strings.HasSuffix(lower, "kb"), strings.HasSuffix(lower, "k"):
		mult = 1 << 10
		value = strings.TrimRight(value, "kbKB")
	}
	num, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || num <= 0 {
		return 0
	}
	return int64(num * float64(mult))
}

func CalculateRAMCommitLimit(totalRAM int64) int64 {
	return int64(float64(totalRAM) * RAMCommitRatio)
}

func CalculateDiskCommitLimit(totalDisk int64) int64 {
	return int64((float64(totalDisk) * DiskSafeNodeRatio) / DiskEmergencyMultiplier)
}

func (d *DB) UpdateNodeHealth(nodeID, healthStatus, healthReasons string, available bool, unavailableReasons string) error {
	_, err := d.Exec(`UPDATE nodes SET
		health_status = $1, health_reason_codes = $2,
		available_for_provisioning = $3, unavailable_reason_codes = $4
		WHERE id = $5`, healthStatus, healthReasons, available, unavailableReasons, nodeID)
	return err
}

func (d *DB) UpdateNodeCommitLimits(nodeID string, ramCommitLimit, diskCommitLimit int64) error {
	_, err := d.Exec("UPDATE nodes SET ram_commit_limit_bytes = $1, disk_commit_limit_bytes = $2 WHERE id = $3",
		ramCommitLimit, diskCommitLimit, nodeID)
	return err
}

func (d *DB) AddNodeCommitment(nodeID string, ramDelta, diskDelta int64) error {
	_, err := d.Exec("UPDATE nodes SET committed_ram_bytes = committed_ram_bytes + $1, committed_disk_bytes = committed_disk_bytes + $2 WHERE id = $3",
		ramDelta, diskDelta, nodeID)
	return err
}

func (d *DB) ReleaseNodeCommitment(nodeID string, ramDelta, diskDelta int64) error {
	_, err := d.Exec("UPDATE nodes SET committed_ram_bytes = GREATEST(committed_ram_bytes - $1, 0), committed_disk_bytes = GREATEST(committed_disk_bytes - $2, 0) WHERE id = $3",
		ramDelta, diskDelta, nodeID)
	return err
}

func (d *DB) GetCommittedResources(nodeID string) (ram, disk int64, err error) {
	err = d.QueryRow("SELECT COALESCE(committed_ram_bytes, 0), COALESCE(committed_disk_bytes, 0) FROM nodes WHERE id = $1", nodeID).Scan(&ram, &disk)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return
}

func NodeStorageState(diskTotal, diskUsed int64) (string, string) {
	if diskTotal <= 0 {
		return "", ""
	}
	pct := float64(diskUsed) / float64(diskTotal) * 100
	switch {
	case pct >= 95:
		return "critical", fmt.Sprintf("node disk usage at %.1f%%", pct)
	case pct >= 90:
		return "degraded", fmt.Sprintf("node disk usage at %.1f%%", pct)
	case pct >= 80:
		return "warning", fmt.Sprintf("node disk usage at %.1f%%", pct)
	default:
		return "", ""
	}
}

func (d *DB) DeleteOutboxEntry(id string) error {
	_, err := d.Exec("DELETE FROM task_outbox WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete outbox entry: %w", err)
	}
	return nil
}

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
