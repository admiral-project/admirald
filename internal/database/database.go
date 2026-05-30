package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
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

type Node struct {
	ID            string     `json:"id"`
	Hostname      string     `json:"hostname"`
	IP            string     `json:"ip"`
	OS            string     `json:"os"`
	PodmanVersion string     `json:"podman_version"`
	Status        string     `json:"status"`
	LastHeartbeat *time.Time `json:"last_heartbeat"`
}

type AppDefinition struct {
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Description string    `json:"description"`
	RawYAML     string    `json:"raw_yaml"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type AppTier struct {
	AppName          string            `json:"app_name"`
	Name             string            `json:"name"`
	CPU              float64           `json:"cpu"`
	Memory           string            `json:"memory"`
	Storage          string            `json:"storage"`
	PriceMonthly     float64           `json:"price_monthly"`
	Environment      map[string]string `json:"environment,omitempty"`
	BackupPolicyJSON string            `json:"backup_policy_json,omitempty"`
}

type CustomerApp struct {
	ID                string     `json:"id"`
	CustomerID        string     `json:"customer_id"`
	AppDefinitionName string     `json:"app_definition_name"`
	TierName          string     `json:"tier_name"`
	NodeID            *string    `json:"node_id"`
	CommercialStatus  string     `json:"commercial_status"`
	TechnicalStatus   string     `json:"technical_status"`
	TierSnapshotJSON  string     `json:"tier_snapshot_json"`
	CreatedAt         time.Time  `json:"created_at"`
	HealthStatus      string     `json:"health_status"`
	HealthMessage     string     `json:"health_message,omitempty"`
	LastHealthChecked *time.Time `json:"last_health_checked_at,omitempty"`
	StorageLimitBytes int64      `json:"storage_limit_bytes"`
	StorageUsedBytes  int64      `json:"storage_used_bytes"`
	StorageUsedPct    float64    `json:"storage_used_percent"`
	StorageState      string     `json:"storage_state"`
	StorageMessage    string     `json:"storage_message,omitempty"`
	StorageCheckedAt  *time.Time `json:"storage_checked_at,omitempty"`
	StorageExceeded   bool       `json:"storage_exceeded"`
}

type Operation struct {
	ID           string    `json:"id"`
	InstanceID   string    `json:"instance_id"`
	Action       string    `json:"action"`
	Status       string    `json:"status"`
	ErrorMessage *string   `json:"error_message"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Backup struct {
	ID         string    `json:"id"`
	InstanceID string    `json:"instance_id"`
	NodeID     string    `json:"node_id"`
	Status     string    `json:"status"`
	Filepath   *string   `json:"filepath"`
	SizeBytes  int64     `json:"size_bytes"`
	CreatedAt  time.Time `json:"created_at"`
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
	driver, dsn := driverAndDSN(dbURL)
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s db: %w", driver, err)
	}

	if driver == "sqlite3" {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(5 * time.Minute)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping %s db: %w", driver, err)
	}

	return &DB{db}, nil
}

func driverAndDSN(dbURL string) (string, string) {
	switch {
	case strings.HasPrefix(dbURL, "sqlite://"):
		return "sqlite3", strings.TrimPrefix(dbURL, "sqlite://")
	case strings.HasPrefix(dbURL, "file:"):
		return "sqlite3", dbURL
	default:
		return "postgres", dbURL
	}
}

// --- Nodes CRUD ---

func (d *DB) RegisterNode(id, hostname, ip, os, podmanV string) error {
	query := `
		INSERT INTO nodes (id, hostname, ip, os, podman_version, status)
		VALUES ($1, $2, $3, $4, $5, 'registered')
		ON CONFLICT (id) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			ip = EXCLUDED.ip,
			os = EXCLUDED.os,
			podman_version = EXCLUDED.podman_version,
			status = 'active',
			last_heartbeat = CURRENT_TIMESTAMP
	`
	_, err := d.Exec(query, id, hostname, ip, os, podmanV)
	if err != nil {
		return fmt.Errorf("register node: %w", err)
	}
	return nil
}

func (d *DB) GetNodes() ([]Node, error) {
	rows, err := d.Query("SELECT id, hostname, ip, os, podman_version, status, last_heartbeat FROM nodes ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("query nodes: %w", err)
	}
	defer rows.Close()

	var nodes []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Hostname, &n.IP, &n.OS, &n.PodmanVersion, &n.Status, &n.LastHeartbeat); err != nil {
			return nil, fmt.Errorf("scan node row: %w", err)
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

func (d *DB) GetNode(id string) (*Node, error) {
	var n Node
	query := "SELECT id, hostname, ip, os, podman_version, status, last_heartbeat FROM nodes WHERE id = $1"
	err := d.QueryRow(query, id).Scan(&n.ID, &n.Hostname, &n.IP, &n.OS, &n.PodmanVersion, &n.Status, &n.LastHeartbeat)
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

func (d *DB) UpdateNodeHeartbeat(id string) error {
	_, err := d.Exec("UPDATE nodes SET last_heartbeat = CURRENT_TIMESTAMP, status = 'active' WHERE id = $1", id)
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
			raw_yaml = EXCLUDED.raw_yaml
	`
	if _, err := tx.Exec(queryApp, name, displayName, description, rawYAML); err != nil {
		return fmt.Errorf("insert app definition: %w", err)
	}

	if _, err := tx.Exec("DELETE FROM app_tiers WHERE app_name = $1", name); err != nil {
		return fmt.Errorf("clear old tiers: %w", err)
	}

	queryTier := `
		INSERT INTO app_tiers (app_name, name, cpu, memory, storage, price_monthly, environment_json, backup_policy_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
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
		if _, err := tx.Exec(queryTier, name, tier.Name, tier.CPU, tier.Memory, tier.Storage, tier.PriceMonthly, envJSON, tier.BackupPolicyJSON); err != nil {
			return fmt.Errorf("insert tier %q: %w", tier.Name, err)
		}
	}

	return tx.Commit()
}

func (d *DB) GetAppDefinitions() ([]AppDefinition, error) {
	rows, err := d.Query("SELECT name, display_name, description, raw_yaml, status, created_at FROM app_definitions ORDER BY name ASC")
	if err != nil {
		return nil, fmt.Errorf("query app definitions: %w", err)
	}
	defer rows.Close()

	var apps []AppDefinition
	for rows.Next() {
		var a AppDefinition
		if err := rows.Scan(&a.Name, &a.DisplayName, &a.Description, &a.RawYAML, &a.Status, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan app row: %w", err)
		}
		apps = append(apps, a)
	}
	return apps, nil
}

func (d *DB) GetAppDefinition(name string) (*AppDefinition, error) {
	var a AppDefinition
	query := "SELECT name, display_name, description, raw_yaml, status, created_at FROM app_definitions WHERE name = $1"
	err := d.QueryRow(query, name).Scan(&a.Name, &a.DisplayName, &a.Description, &a.RawYAML, &a.Status, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("query app %q: %w", name, err)
	}
	return &a, nil
}

func (d *DB) GetAppTiers(appName string) ([]AppTier, error) {
	rows, err := d.Query("SELECT app_name, name, cpu, memory, storage, price_monthly, environment_json, backup_policy_json FROM app_tiers WHERE app_name = $1", appName)
	if err != nil {
		return nil, fmt.Errorf("query app tiers: %w", err)
	}
	defer rows.Close()

	var tiers []AppTier
	for rows.Next() {
		var t AppTier
		var envJSON string
		if err := rows.Scan(&t.AppName, &t.Name, &t.CPU, &t.Memory, &t.Storage, &t.PriceMonthly, &envJSON, &t.BackupPolicyJSON); err != nil {
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
		INSERT INTO customer_apps (id, customer_id, app_definition_name, tier_name, node_id, commercial_status, technical_status, tier_snapshot_json)
		VALUES ($1, $2, $3, $4, $5, 'active', 'pending_provision', $6)
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

func (d *DB) GetCustomerApps() ([]CustomerApp, error) {
	rows, err := d.Query(`SELECT id, customer_id, app_definition_name, tier_name, node_id,
		commercial_status, technical_status, tier_snapshot_json, created_at,
		COALESCE(health_status, ''), COALESCE(health_message, ''),
		last_health_checked_at,
		COALESCE(storage_limit_bytes, 0), COALESCE(storage_used_bytes, 0),
		COALESCE(storage_used_percent, 0), COALESCE(storage_state, 'unknown'),
		COALESCE(storage_message, ''), storage_checked_at,
		COALESCE(storage_exceeded, FALSE)
		FROM customer_apps ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("query customer apps: %w", err)
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
		); err != nil {
			return nil, fmt.Errorf("scan customer app row: %w", err)
		}
		apps = append(apps, a)
	}
	return apps, nil
}

func (d *DB) GetCustomerApp(id string) (*CustomerApp, error) {
	var a CustomerApp
	query := `SELECT id, customer_id, app_definition_name, tier_name, node_id,
		commercial_status, technical_status, tier_snapshot_json, created_at,
		COALESCE(health_status, ''), COALESCE(health_message, ''),
		last_health_checked_at,
		COALESCE(storage_limit_bytes, 0), COALESCE(storage_used_bytes, 0),
		COALESCE(storage_used_percent, 0), COALESCE(storage_state, 'unknown'),
		COALESCE(storage_message, ''), storage_checked_at,
		COALESCE(storage_exceeded, FALSE)
		FROM customer_apps WHERE id = $1`
	err := d.QueryRow(query, id).Scan(&a.ID, &a.CustomerID, &a.AppDefinitionName, &a.TierName, &a.NodeID,
		&a.CommercialStatus, &a.TechnicalStatus, &a.TierSnapshotJSON, &a.CreatedAt,
		&a.HealthStatus, &a.HealthMessage, &a.LastHealthChecked,
		&a.StorageLimitBytes, &a.StorageUsedBytes, &a.StorageUsedPct,
		&a.StorageState, &a.StorageMessage, &a.StorageCheckedAt,
		&a.StorageExceeded,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("query customer app %q: %w", id, err)
	}
	return &a, nil
}

// --- Operations CRUD ---

func (d *DB) CreateOperation(id, instanceID, action, status string) error {
	query := `
		INSERT INTO operations (id, instance_id, action, status)
		VALUES ($1, $2, $3, $4)
	`
	_, err := d.Exec(query, id, instanceID, action, status)
	if err != nil {
		return fmt.Errorf("create operation: %w", err)
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
	rows, err := d.Query("SELECT id, instance_id, action, status, error_message, created_at, updated_at FROM operations ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("query operations: %w", err)
	}
	defer rows.Close()

	var ops []Operation
	for rows.Next() {
		var o Operation
		if err := rows.Scan(&o.ID, &o.InstanceID, &o.Action, &o.Status, &o.ErrorMessage, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan operation row: %w", err)
		}
		ops = append(ops, o)
	}
	return ops, nil
}

func (d *DB) GetOperation(id string) (*Operation, error) {
	var o Operation
	query := "SELECT id, instance_id, action, status, error_message, created_at, updated_at FROM operations WHERE id = $1"
	err := d.QueryRow(query, id).Scan(&o.ID, &o.InstanceID, &o.Action, &o.Status, &o.ErrorMessage, &o.CreatedAt, &o.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("query operation %q: %w", id, err)
	}
	return &o, nil
}

// --- Backups CRUD ---

func (d *DB) CreateBackup(id, instanceID, nodeID, status string) error {
	query := `
		INSERT INTO backups (id, instance_id, node_id, status, size_bytes)
		VALUES ($1, $2, $3, $4, 0)
	`
	_, err := d.Exec(query, id, instanceID, nodeID, status)
	if err != nil {
		return fmt.Errorf("create backup: %w", err)
	}
	return nil
}

func (d *DB) UpdateBackup(id, status, filepath string, sizeBytes int64) error {
	query := `
		UPDATE backups
		SET status = $1, filepath = NULLIF($2, ''), size_bytes = $3
		WHERE id = $4
	`
	_, err := d.Exec(query, status, filepath, sizeBytes, id)
	if err != nil {
		return fmt.Errorf("update backup: %w", err)
	}
	return nil
}

func (d *DB) GetBackups() ([]Backup, error) {
	rows, err := d.Query("SELECT id, instance_id, node_id, status, filepath, size_bytes, created_at FROM backups ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("query backups: %w", err)
	}
	defer rows.Close()

	var backups []Backup
	for rows.Next() {
		var b Backup
		if err := rows.Scan(&b.ID, &b.InstanceID, &b.NodeID, &b.Status, &b.Filepath, &b.SizeBytes, &b.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan backup row: %w", err)
		}
		backups = append(backups, b)
	}
	return backups, nil
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
		SET public_id = $2,
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
	_, err := d.Exec(
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
	return nil
}

func (d *DB) DeletePublicRoute(hostname string) error {
	_, err := d.Exec("DELETE FROM public_routes WHERE hostname = $1", hostname)
	if err != nil {
		return fmt.Errorf("delete public route %q: %w", hostname, err)
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

func (d *DB) CreateAdminUser(username, passwordHash string) error {
	query := `
		INSERT INTO admin_users (username, password_hash)
		VALUES ($1, $2)
		ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
	`
	_, err := d.Exec(query, username, passwordHash)
	if err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}
	return nil
}

func (d *DB) GetAdminUser(username string) (string, error) {
	var passwordHash string
	query := "SELECT password_hash FROM admin_users WHERE username = $1"
	err := d.QueryRow(query, username).Scan(&passwordHash)
	if err == sql.ErrNoRows {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("get admin user: %w", err)
	}
	return passwordHash, nil
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
	var rows *sql.Rows
	var err error
	if instanceID != "" {
		rows, err = d.Query("SELECT id, instance_id, app_id, tier_id, node_id, backup_type, database_type, status, storage_backend, storage_key, storage_uri_admin, size_bytes, checksum_sha256, created_at, completed_at, expires_at, triggered_by, retention_policy_snapshot_json, tier_snapshot_json, error_message FROM backup_records WHERE instance_id = $1 ORDER BY created_at DESC", instanceID)
	} else {
		rows, err = d.Query("SELECT id, instance_id, app_id, tier_id, node_id, backup_type, database_type, status, storage_backend, storage_key, storage_uri_admin, size_bytes, checksum_sha256, created_at, completed_at, expires_at, triggered_by, retention_policy_snapshot_json, tier_snapshot_json, error_message FROM backup_records ORDER BY created_at DESC")
	}
	if err != nil {
		return nil, fmt.Errorf("query backup records: %w", err)
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
			return nil, fmt.Errorf("scan backup record row: %w", err)
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
	return records, nil
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

func (d *DB) UpdateInstanceStorage(instanceID, storageState, storageMessage string, limitBytes, usedBytes int64, usedPct float64, exceeded bool) error {
	_, err := d.Exec(`UPDATE customer_apps SET
		storage_limit_bytes = $1, storage_used_bytes = $2, storage_used_percent = $3,
		storage_state = $4, storage_message = $5, storage_checked_at = CURRENT_TIMESTAMP,
		storage_exceeded = $6 WHERE id = $7`,
		limitBytes, usedBytes, usedPct, storageState, storageMessage, exceeded, instanceID)
	return err
}

func (d *DB) DeleteOutboxEntry(id string) error {
	_, err := d.Exec("DELETE FROM task_outbox WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete outbox entry: %w", err)
	}
	return nil
}
