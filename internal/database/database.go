package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

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
	AppName      string  `json:"app_name"`
	Name         string  `json:"name"`
	CPU          int     `json:"cpu"`
	Memory       string  `json:"memory"`
	Storage      string  `json:"storage"`
	PriceMonthly float64 `json:"price_monthly"`
}

type CustomerApp struct {
	ID                string    `json:"id"`
	CustomerID        string    `json:"customer_id"`
	AppDefinitionName string    `json:"app_definition_name"`
	TierName          string    `json:"tier_name"`
	NodeID            *string   `json:"node_id"`
	CommercialStatus  string    `json:"commercial_status"`
	TechnicalStatus   string    `json:"technical_status"`
	CreatedAt         time.Time `json:"created_at"`
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
		INSERT INTO app_tiers (app_name, name, cpu, memory, storage, price_monthly)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	for _, tier := range tiers {
		if _, err := tx.Exec(queryTier, name, tier.Name, tier.CPU, tier.Memory, tier.Storage, tier.PriceMonthly); err != nil {
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
	rows, err := d.Query("SELECT app_name, name, cpu, memory, storage, price_monthly FROM app_tiers WHERE app_name = $1", appName)
	if err != nil {
		return nil, fmt.Errorf("query app tiers: %w", err)
	}
	defer rows.Close()

	var tiers []AppTier
	for rows.Next() {
		var t AppTier
		if err := rows.Scan(&t.AppName, &t.Name, &t.CPU, &t.Memory, &t.Storage, &t.PriceMonthly); err != nil {
			return nil, fmt.Errorf("scan tier row: %w", err)
		}
		tiers = append(tiers, t)
	}
	return tiers, nil
}

// --- Customer Apps CRUD ---

func (d *DB) CreateCustomerApp(id, customerID, appName, tierName, nodeID string) error {
	query := `
		INSERT INTO customer_apps (id, customer_id, app_definition_name, tier_name, node_id, commercial_status, technical_status)
		VALUES ($1, $2, $3, $4, $5, 'active', 'pending_provision')
	`
	var nID interface{}
	if nodeID != "" {
		nID = nodeID
	} else {
		nID = nil
	}
	_, err := d.Exec(query, id, customerID, appName, tierName, nID)
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
	rows, err := d.Query("SELECT id, customer_id, app_definition_name, tier_name, node_id, commercial_status, technical_status, created_at FROM customer_apps ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("query customer apps: %w", err)
	}
	defer rows.Close()

	var apps []CustomerApp
	for rows.Next() {
		var a CustomerApp
		if err := rows.Scan(&a.ID, &a.CustomerID, &a.AppDefinitionName, &a.TierName, &a.NodeID, &a.CommercialStatus, &a.TechnicalStatus, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan customer app row: %w", err)
		}
		apps = append(apps, a)
	}
	return apps, nil
}

func (d *DB) GetCustomerApp(id string) (*CustomerApp, error) {
	var a CustomerApp
	query := "SELECT id, customer_id, app_definition_name, tier_name, node_id, commercial_status, technical_status, created_at FROM customer_apps WHERE id = $1"
	err := d.QueryRow(query, id).Scan(&a.ID, &a.CustomerID, &a.AppDefinitionName, &a.TierName, &a.NodeID, &a.CommercialStatus, &a.TechnicalStatus, &a.CreatedAt)
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
