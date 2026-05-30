package admiral

type RegisterNodeRequest struct {
	NodeID   string `json:"node_id"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	OS       string `json:"os"`
	PodmanV  string `json:"podman_version"`
}

type RegisterNodeResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token"`
}

type HeartbeatRequest struct {
	NodeID      string   `json:"node_id"`
	Status      string   `json:"status"`
	CPUUsage    float64  `json:"cpu_usage"`
	MemoryUsage float64  `json:"memory_usage"`
	DiskUsage   float64  `json:"disk_usage"`
	RunningPods []string `json:"running_pods"`
}

// AppDefinitionPayload is the parsed YAML structure for an Admiral app definition.
// It declares services, tiers, and backup sources for an application.
type AppDefinitionPayload struct {
	Name        string                 `yaml:"name" json:"name"`
	DisplayName string                 `yaml:"display_name" json:"display_name"`
	Description string                 `yaml:"description" json:"description"`
	Services    map[string]YAMLService `yaml:"services" json:"services"`
	Tiers       map[string]YAMLTier    `yaml:"tiers" json:"tiers"`
	Backup      *YAMLBackup            `yaml:"backup,omitempty" json:"backup,omitempty"`
}

// YAMLService describes a single container service within an app.
// A service with a Volume gets a persistent Podman volume mounted at a
// default target path determined by the image type (see defaultVolumeTarget).
type YAMLService struct {
	Image       string                `yaml:"image" json:"image"`
	Port        int                   `yaml:"port,omitempty" json:"port,omitempty"`
	Public      bool                  `yaml:"public,omitempty" json:"public,omitempty"`
	Volume      string                `yaml:"volume,omitempty" json:"volume,omitempty"`
	Env         map[string]string     `yaml:"env,omitempty" json:"env,omitempty"`
	Secrets     map[string]YAMLSecret `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	HealthCheck *YAMLHealthCheck      `yaml:"healthcheck,omitempty" json:"healthcheck,omitempty"`
}

type YAMLSecret struct {
	Generate string `yaml:"generate,omitempty" json:"generate,omitempty"`
	Value    string `yaml:"value,omitempty" json:"value,omitempty"`
	Expose   bool   `yaml:"expose,omitempty" json:"expose,omitempty"`
}

// YAMLBackup defines the backup source for an app.
//
// For type "database", Service must be the database container and all env
// references (DatabaseEnv, UsernameEnv, PasswordEnv) must point to valid
// env vars or secrets defined in that service.
//
// For type "volume", Service must be a container that declares a Volume.
// Volume backups are also independently activatable via the tier-level
// backup_policy.backup_volumes flag, which auto-discovers all services
// with volumes.
//
// The recommended pattern for apps with both databases and file data
// (e.g., WordPress) is:
//
//	backup:
//	  type: database         # logical DB dump config
//	  engine: mariadb
//	  service: db
//	  database_env: MARIADB_DATABASE
//	  username_env: MARIADB_USER
//	  password_env: MARIADB_PASSWORD
//
//	tiers:
//	  small:
//	    backups:
//	      backup_database: true  # enables scheduled DB dumps
//	      backup_volumes: true   # enables volume backups of wp-content, etc.
type YAMLBackup struct {
	Type        string `yaml:"type" json:"type"`
	Engine      string `yaml:"engine,omitempty" json:"engine,omitempty"`
	Service     string `yaml:"service" json:"service"`
	DatabaseEnv string `yaml:"database_env,omitempty" json:"database_env,omitempty"`
	UsernameEnv string `yaml:"username_env,omitempty" json:"username_env,omitempty"`
	PasswordEnv string `yaml:"password_env,omitempty" json:"password_env,omitempty"`
}

type YAMLHealthCheck struct {
	Type             string   `yaml:"type" json:"type"`
	Port             int      `yaml:"port,omitempty" json:"port,omitempty"`
	Path             string   `yaml:"path,omitempty" json:"path,omitempty"`
	ExpectedStatus   int      `yaml:"expected_status,omitempty" json:"expected_status,omitempty"`
	Command          []string `yaml:"command,omitempty" json:"command,omitempty"`
	TimeoutSeconds   int      `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
	IntervalSeconds  int      `yaml:"interval_seconds,omitempty" json:"interval_seconds,omitempty"`
	FailureThreshold int      `yaml:"failure_threshold,omitempty" json:"failure_threshold,omitempty"`
}

type YAMLTier struct {
	CPU          float64           `yaml:"cpu" json:"cpu"`
	Memory       string            `yaml:"memory" json:"memory"`
	Storage      string            `yaml:"storage" json:"storage"`
	PriceMonthly float64           `yaml:"price_monthly" json:"price_monthly"`
	Environment  map[string]string `yaml:"environment,omitempty" json:"environment,omitempty"`
	Backups      *BackupPolicy     `yaml:"backups,omitempty" json:"backups,omitempty"`
}

type BackupPolicy struct {
	Enabled        bool            `yaml:"enabled" json:"enabled"`
	Schedule       string          `yaml:"schedule" json:"schedule"`                   // disabled, daily, weekly
	Weekday        string          `yaml:"weekday,omitempty" json:"weekday,omitempty"` // e.g. sunday
	Time           string          `yaml:"time" json:"time"`
	Timezone       string          `yaml:"timezone" json:"timezone"`
	Retention      RetentionPolicy `yaml:"retention" json:"retention"`
	ManualBackups  bool            `yaml:"manual_backups" json:"manual_backups"`
	BackupDatabase bool            `yaml:"backup_database" json:"backup_database"`
	BackupVolumes  bool            `yaml:"backup_volumes" json:"backup_volumes"`
	RestoreAllowed bool            `yaml:"restore_allowed" json:"restore_allowed"`
}

type RetentionPolicy struct {
	Count int `yaml:"count" json:"count"`
	Days  int `yaml:"days" json:"days"`
}

type AdminLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AdminLoginResponse struct {
	Token                  string `json:"token,omitempty"`
	ExpiresAt              string `json:"expires_at,omitempty"`
	PasswordChangeRequired bool   `json:"password_change_required,omitempty"`
	Username               string `json:"username,omitempty"`
}

type AdminMeResponse struct {
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
}

type BackupStorageConfig struct {
	ID              string `json:"id"`
	Backend         string `json:"backend"` // local | s3
	Enabled         bool   `json:"enabled"`
	Endpoint        string `json:"endpoint"`
	Region          string `json:"region"`
	Bucket          string `json:"bucket"`
	Prefix          string `json:"prefix"`
	ForcePathStyle  bool   `json:"force_path_style"`
	AccessKeyEnv    string `json:"access_key_env"`
	SecretKeyEnv    string `json:"secret_key_env"`
	SessionTokenEnv string `json:"session_token_env,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

type BackupRecord struct {
	ID                          string `json:"id"`
	InstanceID                  string `json:"instance_id"`
	AppID                       string `json:"app_id"`
	TierID                      string `json:"tier_id"`
	NodeID                      string `json:"node_id"`
	BackupType                  string `json:"backup_type"`     // database | volume
	DatabaseType                string `json:"database_type"`   // postgresql | mysql | mariadb | none
	Status                      string `json:"status"`          // pending | running | succeeded | failed | deleted
	StorageBackend              string `json:"storage_backend"` // local | s3
	StorageKey                  string `json:"storage_key"`
	StorageURIAdmin             string `json:"storage_uri_admin,omitempty"`
	SizeBytes                   int64  `json:"size_bytes"`
	ChecksumSHA256              string `json:"checksum_sha256"`
	CreatedAt                   string `json:"created_at"`
	CompletedAt                 string `json:"completed_at,omitempty"`
	ExpiresAt                   string `json:"expires_at,omitempty"`
	TriggeredBy                 string `json:"triggered_by"` // scheduled | manual | system
	RetentionPolicySnapshotJSON string `json:"retention_policy_snapshot_json"`
	TierSnapshotJSON            string `json:"tier_snapshot_json"`
	ErrorMessage                string `json:"error_message,omitempty"`
}

type ProvisionRequest struct {
	AppDefinitionName string `json:"app_definition_name"`
	TierName          string `json:"tier_name"`
	CustomerID        string `json:"customer_id"`
}

type OperationResponse struct {
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
}

type ProvisionResponse struct {
	OperationID string       `json:"operation_id"`
	Status      string       `json:"status"`
	Credentials []Credential `json:"credentials,omitempty"`
}

type Credential struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	Value   string `json:"value"`
}

type BackupRestoreSource struct {
	Type           string `json:"type"`
	URI            string `json:"uri"`
	CredentialsRef string `json:"credentials_ref,omitempty"`
	Checksum       string `json:"checksum,omitempty"`
	SizeBytes      int64  `json:"size_bytes,omitempty"`
}

type RouteKind string

const (
	RouteKindAdmin     RouteKind = "admin"
	RouteKindPortal    RouteKind = "portal"
	RouteKindAppsRoot  RouteKind = "apps_root"
	RouteKindInstance  RouteKind = "app_instance"
	RouteKindFlagship  RouteKind = "flagship"
	RouteKindCockpit   RouteKind = "cockpit"
)

type RouteStatus string

const (
	RouteStatusPending  RouteStatus = "pending"
	RouteStatusActive   RouteStatus = "active"
	RouteStatusFailed   RouteStatus = "failed"
	RouteStatusDisabled RouteStatus = "disabled"
	RouteStatusDeleting RouteStatus = "deleting"
	RouteStatusDeleted  RouteStatus = "deleted"
)

type HealthStatus string

const (
	HealthHealthy   HealthStatus = "healthy"
	HealthUnhealthy HealthStatus = "unhealthy"
	HealthUnknown   HealthStatus = "unknown"
	HealthStarting  HealthStatus = "starting"
	HealthStopped   HealthStatus = "stopped"
)

type HealthReport struct {
	InstanceID   string       `json:"instance_id"`
	NodeID       string       `json:"node_id"`
	HealthStatus HealthStatus `json:"health_status"`
	Message      string       `json:"message,omitempty"`
	CheckedAt    string       `json:"checked_at"`
}

type StorageState string

const (
	StorageOK       StorageState = "ok"
	StorageWarning  StorageState = "warning"
	StorageCritical StorageState = "critical"
	StorageExceeded StorageState = "exceeded"
	StorageUnknown  StorageState = "unknown"
)

type StorageReport struct {
	InstanceID        string       `json:"instance_id"`
	NodeID            string       `json:"node_id"`
	StorageLimitBytes int64        `json:"storage_limit_bytes"`
	StorageUsedBytes  int64        `json:"storage_used_bytes"`
	StorageUsedPct    float64      `json:"storage_used_percent"`
	StorageState      StorageState `json:"storage_state"`
	StorageMessage    string       `json:"storage_message,omitempty"`
	CheckedAt         string       `json:"checked_at"`
}

type PublicRoute struct {
	ID                  string      `json:"id"`
	Hostname            string      `json:"hostname"`
	PublicID            string      `json:"public_id"`
	AppInstanceID       string      `json:"app_instance_id,omitempty"`
	AppTemplateCode     string      `json:"app_template_code,omitempty"`
	NodeID              string      `json:"node_id,omitempty"`
	ServiceName         string      `json:"service_name,omitempty"`
	TargetScheme        string      `json:"target_scheme,omitempty"`
	TargetHost          string      `json:"target_host,omitempty"`
	TargetPort          int         `json:"target_port,omitempty"`
	TargetURL           string      `json:"target_url,omitempty"`
	RouteKind           RouteKind   `json:"route_kind"`
	TLSMode             string      `json:"tls_mode,omitempty"`
	Status              RouteStatus `json:"status"`
	LastError           string      `json:"last_error,omitempty"`
	LastHealthStatus    string      `json:"last_health_status,omitempty"`
	LastHealthCheckedAt string      `json:"last_health_checked_at,omitempty"`
	CreatedAt           string      `json:"created_at,omitempty"`
	UpdatedAt           string      `json:"updated_at,omitempty"`
}

type PublicRouteRequest struct {
	Hostname string `json:"hostname"`
}

type RestoreBackupRequest struct {
	BackupID       string              `json:"backup_id"`
	TargetAppID    string              `json:"target_app_id"`
	TargetNodeID   string              `json:"target_node_id,omitempty"`
	Source         BackupRestoreSource `json:"source"`
	RestoreMode    string              `json:"restore_mode"`
	VerifyChecksum bool                `json:"verify_checksum"`
}

type RestoreBackupResponse struct {
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
}
