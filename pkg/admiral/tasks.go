// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package admiral

type TaskAction string

const (
	ActionProvisionApp            TaskAction = "provision_app"
	ActionProvisionPolicyRejected TaskAction = "provision_policy_rejected"
	ActionStartApp                TaskAction = "start_app"
	ActionStopApp                 TaskAction = "stop_app"
	ActionPauseApp                TaskAction = "pause_app"
	ActionResumeApp               TaskAction = "resume_app"
	ActionResizeApp               TaskAction = "resize_app"
	ActionResizePolicyRejected    TaskAction = "resize_policy_rejected"
	ActionDeprovisionApp          TaskAction = "deprovision_app"
	ActionBackupDatabase          TaskAction = "backup_database"
	ActionBackupVolumes           TaskAction = "backup_volumes"
	ActionInspectApp              TaskAction = "inspect_app"
	ActionDeleteBackup            TaskAction = "delete_backup"
	ActionTestStorage             TaskAction = "test_backup_storage"
	ActionRestoreBackup           TaskAction = "restore_backup"
	ActionPauseAppStorage         TaskAction = "pause_app_storage"
	ActionReactivateApp           TaskAction = "reactivate_app"
)

type FleetTask struct {
	TaskID         string             `json:"task_id"`
	OperationID    string             `json:"operation_id"`
	NodeID         string             `json:"node_id"`
	Action         TaskAction         `json:"action"`
	InstanceID     string             `json:"instance_id"`
	App            AppInfo            `json:"app"`
	Tier           TierInfo           `json:"tier"`
	Services       []ServiceInfo      `json:"services"`
	SharedVolumes  []SharedVolumeInfo `json:"shared_volumes,omitempty"`
	Backup         *BackupInfo        `json:"backup,omitempty"`
	Restore        *RestoreInfo       `json:"restore,omitempty"`
	Storage        *StorageConfig     `json:"storage,omitempty"`
	SetupCompleted bool               `json:"setup_completed,omitempty"`
}

type StorageConfig struct {
	Backend         string `json:"backend"`
	Key             string `json:"key"`
	BackupID        string `json:"backup_id,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	Region          string `json:"region,omitempty"`
	Bucket          string `json:"bucket,omitempty"`
	Prefix          string `json:"prefix,omitempty"`
	ForcePathStyle  bool   `json:"force_path_style,omitempty"`
	AccessKeyEnv    string `json:"access_key_env,omitempty"`
	SecretKeyEnv    string `json:"secret_key_env,omitempty"`
	SessionTokenEnv string `json:"session_token_env,omitempty"`
}

type AppInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type TierInfo struct {
	Name        string            `json:"name"`
	CPU         float64           `json:"cpu"`
	Memory      string            `json:"memory"`
	Storage     string            `json:"storage"`
	Environment map[string]string `json:"environment,omitempty"`
}

type ServiceInfo struct {
	Name                string                     `json:"name"`
	Image               string                     `json:"image"`
	Port                int                        `json:"port,omitempty"`
	Volume              string                     `json:"volume,omitempty"`
	DependsOn           []string                   `json:"depends_on,omitempty"`
	Requires            []string                   `json:"requires,omitempty"`
	SharedVolumes       []ServiceSharedVolumeMount `json:"shared_volumes,omitempty"`
	Command             string                     `json:"command,omitempty"`
	SetupCommand        string                     `json:"setup_command,omitempty"`
	NotifyOnSetup       []YAMLSetupNotice          `json:"notify_on_setup,omitempty"`
	Env                 map[string]string          `json:"env,omitempty"`
	Secrets             map[string]string          `json:"secrets,omitempty"`
	HealthCheck         *YAMLHealthCheck           `json:"healthcheck,omitempty"`
	HealthCheckWaitSecs int                        `json:"healthcheck_wait_timeout,omitempty"`
	Registry            *RegistryConfig            `json:"registry,omitempty"`
	User                string                     `json:"user,omitempty"`
}

type SharedVolumeInfo struct {
	Name     string   `json:"name"`
	Mount    string   `json:"mount"`
	Services []string `json:"services"`
	UID      int      `json:"uid,omitempty"`
	GID      int      `json:"gid,omitempty"`
}

type ServiceSharedVolumeMount struct {
	Name  string `json:"name"`
	Mount string `json:"mount"`
	UID   int    `json:"uid,omitempty"`
	GID   int    `json:"gid,omitempty"`
}

// RegistryConfig carries credentials for authenticating to a private
// container registry. Fleet uses this to run podman login before
// pulling images during provisioning.
type RegistryConfig struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type BackupInfo struct {
	Type         string `json:"type"`
	Engine       string `json:"engine,omitempty"`
	Service      string `json:"service"`
	DatabaseType string `json:"database_type,omitempty"`
	DatabaseEnv  string `json:"database_env"`
	UsernameEnv  string `json:"username_env"`
	PasswordEnv  string `json:"password_env"`
}

type RestoreInfo struct {
	BackupID       string `json:"backup_id"`
	StorageBackend string `json:"storage_backend"`
	StorageKey     string `json:"storage_key"`
	BackupType     string `json:"backup_type"`
	DatabaseType   string `json:"database_type"`
	Service        string `json:"service"`
	ChecksumSHA256 string `json:"checksum_sha256,omitempty"`
	VerifyChecksum bool   `json:"verify_checksum,omitempty"`
}

type TaskResult struct {
	TaskID      string `json:"task_id"`
	OperationID string `json:"operation_id"`
	NodeID      string `json:"node_id"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
	Logs        string `json:"logs,omitempty"`
	Metadata    string `json:"metadata,omitempty"`
}
