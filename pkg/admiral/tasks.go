package admiral

type TaskAction string

const (
	ActionProvisionApp   TaskAction = "provision_app"
	ActionStartApp       TaskAction = "start_app"
	ActionStopApp        TaskAction = "stop_app"
	ActionPauseApp       TaskAction = "pause_app"
	ActionResumeApp      TaskAction = "resume_app"
	ActionResizeApp      TaskAction = "resize_app"
	ActionDeprovisionApp TaskAction = "deprovision_app"
	ActionBackupDatabase TaskAction = "backup_database"
	ActionBackupVolumes  TaskAction = "backup_volumes"
	ActionInspectApp     TaskAction = "inspect_app"
	ActionDeleteBackup   TaskAction = "delete_backup"
	ActionTestStorage    TaskAction = "test_backup_storage"
	ActionRestoreBackup  TaskAction = "restore_backup"
)

type FleetTask struct {
	TaskID      string         `json:"task_id"`
	OperationID string         `json:"operation_id"`
	NodeID      string         `json:"node_id"`
	Action      TaskAction     `json:"action"`
	InstanceID  string         `json:"instance_id"`
	App         AppInfo        `json:"app"`
	Tier        TierInfo       `json:"tier"`
	Services    []ServiceInfo  `json:"services"`
	Backup      *BackupInfo    `json:"backup,omitempty"`
	Restore     *RestoreInfo   `json:"restore,omitempty"`
	Storage     *StorageConfig `json:"storage,omitempty"`
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
	Name    string `json:"name"`
	CPU     int    `json:"cpu"`
	Memory  string `json:"memory"`
	Storage string `json:"storage"`
}

type ServiceInfo struct {
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	Port    int               `json:"port,omitempty"`
	Volume  string            `json:"volume,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
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
