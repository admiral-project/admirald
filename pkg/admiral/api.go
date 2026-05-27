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

type AppDefinitionPayload struct {
	Name        string                 `yaml:"name" json:"name"`
	DisplayName string                 `yaml:"display_name" json:"display_name"`
	Description string                 `yaml:"description" json:"description"`
	Services    map[string]YAMLService `yaml:"services" json:"services"`
	Tiers       map[string]YAMLTier    `yaml:"tiers" json:"tiers"`
	Backup      *YAMLBackup            `yaml:"backup,omitempty" json:"backup,omitempty"`
}

type YAMLService struct {
	Image   string                `yaml:"image" json:"image"`
	Port    int                   `yaml:"port,omitempty" json:"port,omitempty"`
	Volume  string                `yaml:"volume,omitempty" json:"volume,omitempty"`
	Env     map[string]string     `yaml:"env,omitempty" json:"env,omitempty"`
	Secrets map[string]YAMLSecret `yaml:"secrets,omitempty" json:"secrets,omitempty"`
}

type YAMLSecret struct {
	Generate string `yaml:"generate,omitempty" json:"generate,omitempty"`
	Value    string `yaml:"value,omitempty" json:"value,omitempty"`
	Expose   bool   `yaml:"expose,omitempty" json:"expose,omitempty"`
}

type YAMLBackup struct {
	Type        string `yaml:"type" json:"type"`
	Service     string `yaml:"service" json:"service"`
	DatabaseEnv string `yaml:"database_env" json:"database_env"`
	UsernameEnv string `yaml:"username_env" json:"username_env"`
	PasswordEnv string `yaml:"password_env" json:"password_env"`
}

type YAMLTier struct {
	CPU          int     `yaml:"cpu" json:"cpu"`
	Memory       string  `yaml:"memory" json:"memory"`
	Storage      string  `yaml:"storage" json:"storage"`
	PriceMonthly float64 `yaml:"price_monthly" json:"price_monthly"`
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
