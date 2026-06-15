// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package admiral

type RegisterNodeRequest struct {
	NodeID      string `json:"node_id"`
	Hostname    string `json:"hostname"`
	IP          string `json:"ip"`
	WireguardIP string `json:"wireguard_ip,omitempty"`
	NodeRole    string `json:"node_role,omitempty"`
	PublicIP    string `json:"public_ip,omitempty"`
	OS          string `json:"os"`
	PodmanV     string `json:"podman_version"`
}

type RegisterNodeResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token"`
}

type HeartbeatRequest struct {
	NodeID        string `json:"node_id"`
	Hostname      string `json:"hostname,omitempty"`
	IP            string `json:"ip,omitempty"`
	WireguardIP   string `json:"wireguard_ip,omitempty"`
	PublicIP      string `json:"public_ip,omitempty"`
	PodmanVersion string `json:"podman_version,omitempty"`
	FleetVersion  string `json:"fleet_version,omitempty"`
	Status        string `json:"status"`
	DiskTotal     int64  `json:"disk_total_bytes,omitempty"`
	DiskUsed      int64  `json:"disk_used_bytes,omitempty"`
	RAMTotal      int64  `json:"ram_total_bytes,omitempty"`
	RAMUsed       int64  `json:"ram_used_bytes,omitempty"`
	RAMAvailable  int64  `json:"ram_available_bytes,omitempty"`
	PodsActive    int    `json:"pods_active,omitempty"`
	PodsPaused    int    `json:"pods_paused,omitempty"`
	PodsFailed    int    `json:"pods_failed,omitempty"`
}

// AppDefinitionPayload is the parsed YAML structure for an Admiral app definition.
// It declares services, tiers, and backup sources for an application.
type AppDefinitionPayload struct {
	Name        string                 `yaml:"name" json:"name"`
	DisplayName string                 `yaml:"display_name" json:"display_name"`
	Description string                 `yaml:"description" json:"description"`
	Services    map[string]YAMLService `yaml:"services" json:"services"`
	Secrets     map[string]YAMLSecret  `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Tiers       map[string]YAMLTier    `yaml:"tiers" json:"tiers"`
}

// YAMLService describes a single container service within an app.
// A service with a Volume gets a persistent Podman volume mounted at a
// default target path determined by the image type (see defaultVolumeTarget).
// If the image is in a private registry, the Registry field provides
// authentication credentials for podman login.
type YAMLService struct {
	Image       string                `yaml:"image" json:"image"`
	Port        int                   `yaml:"port,omitempty" json:"port,omitempty"`
	Public      bool                  `yaml:"public,omitempty" json:"public,omitempty"`
	Volume      string                `yaml:"volume,omitempty" json:"volume,omitempty"`
	Command     string                `yaml:"command,omitempty" json:"command,omitempty"`
	Env         map[string]string     `yaml:"env,omitempty" json:"env,omitempty"`
	Secrets     map[string]YAMLSecret `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	HealthCheck *YAMLHealthCheck      `yaml:"healthcheck,omitempty" json:"healthcheck,omitempty"`
	Backup      *YAMLServiceBackup    `yaml:"backup" json:"backup"`
	Registry    *YAMLRegistry         `yaml:"registry,omitempty" json:"registry,omitempty"`
}

// YAMLRegistry configures authentication for a private container registry.
type YAMLRegistry struct {
	Server   string `yaml:"server" json:"server"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

type YAMLSecret struct {
	Generate string `yaml:"generate,omitempty" json:"generate,omitempty"`
	Value    string `yaml:"value,omitempty" json:"value,omitempty"`
	Expose   bool   `yaml:"expose,omitempty" json:"expose,omitempty"`
	Persist  bool   `yaml:"persist,omitempty" json:"persist,omitempty"`
}

// YAMLServiceBackup defines the backup contract for a single service.
// Each service must explicitly declare one backup type:
//   - "database" for logical database dumps
//   - "volume" for persistent filesystem content
//   - "none" when the service does not require backup
type YAMLServiceBackup struct {
	Type        string `yaml:"type" json:"type"`
	Engine      string `yaml:"engine,omitempty" json:"engine,omitempty"`
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
	Free         bool              `yaml:"free,omitempty" json:"free,omitempty"`
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

type AdminChangePasswordRequest struct {
	Username        string `json:"username,omitempty"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type AdminChangePasswordResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
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
	NodeID            string `json:"node_id,omitempty"`
}

type OperationResponse struct {
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
}

type InstanceActionRequest struct {
	InstanceID string `json:"instance_id"`
	Action     string `json:"action"`
	Tier       string `json:"tier,omitempty"`
	Service    string `json:"service,omitempty"`
	NodeID     string `json:"node_id,omitempty"`
}

type ProvisionResponse struct {
	OperationID string       `json:"operation_id"`
	Status      string       `json:"status"`
	Hostname    string       `json:"hostname,omitempty"`
	Credentials []Credential `json:"credentials,omitempty"`
}

type NodeProvisioningEvaluation struct {
	NodeID                            string   `json:"node_id"`
	Eligible                          bool     `json:"eligible"`
	RejectionReasons                  []string `json:"rejection_reasons,omitempty"`
	RemainingRAMAfterAllocationBytes  int64    `json:"remaining_ram_after_allocation_bytes,omitempty"`
	RemainingDiskAfterAllocationBytes int64    `json:"remaining_disk_after_allocation_bytes,omitempty"`
}

type ProvisioningRejectedResponse struct {
	Code            string                       `json:"code"`
	Message         string                       `json:"message"`
	Error           string                       `json:"error"`
	Detail          string                       `json:"detail,omitempty"`
	OperationID     string                       `json:"operation_id"`
	TaskID          string                       `json:"task_id,omitempty"`
	RequestedNodeID string                       `json:"requested_node_id,omitempty"`
	NodeEvaluations []NodeProvisioningEvaluation `json:"node_evaluations,omitempty"`
}

type Credential struct {
	Service  string `json:"service"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Generate string `json:"generate,omitempty"`
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
	RouteKindAdmin    RouteKind = "admin"
	RouteKindPortal   RouteKind = "portal"
	RouteKindAppsRoot RouteKind = "apps_root"
	RouteKindInstance RouteKind = "app_instance"
	RouteKindFlagship RouteKind = "flagship"
	RouteKindCockpit  RouteKind = "cockpit"
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
	InstanceID   string         `json:"instance_id"`
	NodeID       string         `json:"node_id"`
	HealthStatus HealthStatus   `json:"health_status"`
	Message      string         `json:"message,omitempty"`
	HostPorts    map[string]int `json:"host_ports,omitempty"`
	CheckedAt    string         `json:"checked_at"`
}

type StorageState string

const (
	StorageOK          StorageState = "ok"
	StorageWarning     StorageState = "warning"
	StorageCritical    StorageState = "critical"
	StorageOverQuota   StorageState = "over_quota"
	StorageGracePeriod StorageState = "grace_period"
	StorageSuspended   StorageState = "suspended"
	StorageUnknown     StorageState = "unknown"
)

type StorageReport struct {
	InstanceID            string       `json:"instance_id"`
	NodeID                string       `json:"node_id"`
	StorageLimitBytes     int64        `json:"storage_limit_bytes"`
	StorageUsedBytes      int64        `json:"storage_used_bytes"`
	StorageUsedPct        float64      `json:"storage_used_percent"`
	StorageState          StorageState `json:"storage_state"`
	StorageMessage        string       `json:"storage_message,omitempty"`
	StorageEmergencyBytes int64        `json:"storage_emergency_bytes,omitempty"`
	StorageGraceStartedAt string       `json:"storage_grace_started_at,omitempty"`
	StorageGraceExpiresAt string       `json:"storage_grace_expires_at,omitempty"`
	StoragePausedReason   string       `json:"storage_paused_reason,omitempty"`
	CheckedAt             string       `json:"checked_at"`
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
	Service        string              `json:"service"`
	TargetNodeID   string              `json:"target_node_id,omitempty"`
	Source         BackupRestoreSource `json:"source"`
	RestoreMode    string              `json:"restore_mode"`
	VerifyChecksum bool                `json:"verify_checksum"`
}

type RestoreBackupResponse struct {
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
}

// Catalog API types for harbor synchronization

// AvailabilityRequest is the payload for PATCH /api/v1/apps/{id}/availability
type AvailabilityRequest struct {
	Availability string `json:"availability"`
	Reason       string `json:"reason"`
}

// ValidateProvisioningRequest is the payload for POST /api/v1/apps/{id}/validate-provisioning
type ValidateProvisioningRequest struct {
	TierID           string `json:"tier_id"`
	ExpectedRevision int    `json:"expected_revision,omitempty"`
	ExpectedChecksum string `json:"expected_checksum,omitempty"`
}

// ValidateProvisioningResponse is the response for validation
type ValidateProvisioningResponse struct {
	Valid    bool   `json:"valid"`
	AppID    string `json:"app_id,omitempty"`
	TierID   string `json:"tier_id,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Revision int    `json:"revision,omitempty"`
	Checksum string `json:"checksum,omitempty"`
}
