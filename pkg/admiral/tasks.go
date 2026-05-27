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
)

type FleetTask struct {
	TaskID      string        `json:"task_id"`
	OperationID string        `json:"operation_id"`
	NodeID      string        `json:"node_id"`
	Action      TaskAction    `json:"action"`
	InstanceID  string        `json:"instance_id"`
	App         AppInfo       `json:"app"`
	Tier        TierInfo      `json:"tier"`
	Services    []ServiceInfo `json:"services"`
	Backup      *BackupInfo   `json:"backup,omitempty"`
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
	Type        string `json:"type"`
	Service     string `json:"service"`
	DatabaseEnv string `json:"database_env"`
	UsernameEnv string `json:"username_env"`
	PasswordEnv string `json:"password_env"`
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
