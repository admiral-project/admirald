package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/networking"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

type TaskPublisher interface {
	PublishTask(task *admiral.FleetTask) error
}

type APIHandlers struct {
	db         *database.DB
	log        *logging.Logger
	publisher  TaskPublisher
	secrets    *secrets.Manager
	networking *networking.Manager
}

func NewHandlers(db *database.DB, log *logging.Logger, pub TaskPublisher, secretManager *secrets.Manager, networkingManager *networking.Manager) *APIHandlers {
	return &APIHandlers{
		db:         db,
		log:        log,
		publisher:  pub,
		secrets:    secretManager,
		networking: networkingManager,
	}
}

func generateID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%x", prefix, b)
}

func generateSecretValue(kind string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	value := hex.EncodeToString(b)
	if kind == "username" {
		return "usr_" + value[:12]
	}
	return value
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// writeJSON encoding error
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *APIHandlers) HandleNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		nodes, err := h.db.GetNodes()
		if err != nil {
			h.log.Error("Get nodes failed", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to fetch nodes")
			return
		}
		writeJSON(w, http.StatusOK, nodes)

	case http.MethodPost:
		var req admiral.RegisterNodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}

		if req.NodeID == "" || req.Hostname == "" || req.IP == "" {
			writeError(w, http.StatusBadRequest, "node_id, hostname, and ip are required")
			return
		}

		if err := h.db.RegisterNode(req.NodeID, req.Hostname, req.IP, req.OS, req.PodmanV); err != nil {
			h.log.Error("Register node failed", err, map[string]interface{}{"node_id": req.NodeID})
			writeError(w, http.StatusInternalServerError, "Failed to register node")
			return
		}

		h.log.Info("Node registered successfully", map[string]interface{}{"node_id": req.NodeID, "hostname": req.Hostname})
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *APIHandlers) HandleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req admiral.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, "node_id is required")
		return
	}

	node, err := h.db.GetNode(req.NodeID)
	if err != nil {
		h.log.Error("Get node failed on heartbeat", err, map[string]interface{}{"node_id": req.NodeID})
		writeError(w, http.StatusInternalServerError, "Failed checking node registration")
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not registered")
		return
	}

	if err := h.db.UpdateNodeHeartbeat(req.NodeID); err != nil {
		h.log.Error("Update heartbeat failed", err, map[string]interface{}{"node_id": req.NodeID})
		writeError(w, http.StatusInternalServerError, "Failed updating heartbeat")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (h *APIHandlers) HandleApps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		apps, err := h.db.GetAppDefinitions()
		if err != nil {
			h.log.Error("Get apps failed", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to fetch applications")
			return
		}
		writeJSON(w, http.StatusOK, apps)

	case http.MethodPost:
		yamlContent, err := readAppDefinitionBody(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		var payload admiral.AppDefinitionPayload
		if err := yaml.Unmarshal([]byte(yamlContent), &payload); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("YAML parsing failed: %v", err))
			return
		}

		if err := admiral.ValidateAppDefinition(payload); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("application definition validation failed: %v", err))
			return
		}

		var dbTiers []database.AppTier
		for name, t := range payload.Tiers {
			var backupPolicyJSON string
			if t.Backups != nil {
				bBytes, err := json.Marshal(t.Backups)
				if err != nil {
					h.log.Error("Failed to marshal backup policy", err, map[string]interface{}{"tier": name})
				}
				backupPolicyJSON = string(bBytes)
			}
			dbTiers = append(dbTiers, database.AppTier{
				AppName:          payload.Name,
				Name:             name,
				CPU:              t.CPU,
				Memory:           t.Memory,
				Storage:          t.Storage,
				PriceMonthly:     t.PriceMonthly,
				BackupPolicyJSON: backupPolicyJSON,
			})
		}

		if err := h.db.SaveAppDefinition(payload.Name, payload.DisplayName, payload.Description, yamlContent, dbTiers); err != nil {
			h.log.Error("Save app definition failed", err, map[string]interface{}{"app_name": payload.Name})
			writeError(w, http.StatusInternalServerError, "Failed to save application definition")
			return
		}

		h.log.Info("App definition applied successfully", map[string]interface{}{"app_name": payload.Name})
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "name": payload.Name})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func readAppDefinitionBody(r *http.Request) (string, error) {
	if strings.Contains(r.Header.Get("Content-Type"), "yaml") || strings.Contains(r.Header.Get("Content-Type"), "text") {
		bodyBytes, err := io.ReadAll(r.Body)
		if cerr := r.Body.Close(); cerr != nil {
			return "", fmt.Errorf("failed to close request body")
		}
		if err != nil {
			return "", fmt.Errorf("failed to read body")
		}
		if len(bodyBytes) == 0 {
			return "", fmt.Errorf("YAML content is empty")
		}
		return string(bodyBytes), nil
	}

	var req struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "", fmt.Errorf("Invalid JSON payload (must include 'yaml' field or be application/x-yaml)")
	}
	if req.YAML == "" {
		return "", fmt.Errorf("YAML content is empty")
	}
	return req.YAML, nil
}

func (h *APIHandlers) HandleCustomerApps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		apps, err := h.db.GetCustomerApps()
		if err != nil {
			h.log.Error("Get customer apps failed", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to fetch customer applications")
			return
		}
		writeJSON(w, http.StatusOK, apps)

	case http.MethodPost:
		var req admiral.ProvisionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}

		if req.AppDefinitionName == "" || req.TierName == "" || req.CustomerID == "" {
			writeError(w, http.StatusBadRequest, "app_definition_name, tier_name, and customer_id are required")
			return
		}

		appDef, err := h.db.GetAppDefinition(req.AppDefinitionName)
		if err != nil {
			h.log.Error("Get app definition failed on provision", err, map[string]interface{}{"app_name": req.AppDefinitionName})
			writeError(w, http.StatusInternalServerError, "Database error validating app")
			return
		}
		if appDef == nil {
			writeError(w, http.StatusNotFound, "App definition not found")
			return
		}

		var payload admiral.AppDefinitionPayload
		if err := yaml.Unmarshal([]byte(appDef.RawYAML), &payload); err != nil {
			writeError(w, http.StatusInternalServerError, "Stored application definition is invalid")
			return
		}

		tiers, err := h.db.GetAppTiers(req.AppDefinitionName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Database error validating tiers")
			return
		}
		var matchedTier *database.AppTier
		for _, t := range tiers {
			if t.Name == req.TierName {
				tierCopy := t
				matchedTier = &tierCopy
				break
			}
		}
		if matchedTier == nil {
			writeError(w, http.StatusNotFound, "Tier not found for this app definition")
			return
		}

		nodeID, err := h.firstActiveNodeID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Database error selecting node")
			return
		}
		if nodeID == "" {
			writeError(w, http.StatusServiceUnavailable, "No active worker nodes available to provision application")
			return
		}

		instanceID := generateID("inst")
		operationID := generateID("op")

		tierBytes, err := json.Marshal(matchedTier)
		if err != nil {
			h.log.Error("Failed to marshal tier snapshot", err, map[string]interface{}{"tier": req.TierName})
		}
		tierSnapshotJSON := string(tierBytes)
		if err := h.db.CreateCustomerApp(instanceID, req.CustomerID, req.AppDefinitionName, req.TierName, nodeID, tierSnapshotJSON); err != nil {
			h.log.Error("Create customer app record failed", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to create app record")
			return
		}

		credentials, err := h.createInstanceSecrets(instanceID, payload)
		if err != nil {
			h.log.Error("Create instance secrets failed", err, map[string]interface{}{"instance_id": instanceID})
			if uerr := h.db.UpdateCustomerAppStatus(instanceID, "", "failed"); uerr != nil {
				h.log.Error("Failed to mark instance as failed after secrets error", uerr, map[string]interface{}{"instance_id": instanceID})
			}
			writeError(w, http.StatusInternalServerError, "Failed to create instance secrets")
			return
		}

		if err := h.db.CreateOperation(operationID, instanceID, string(admiral.ActionProvisionApp), "queued"); err != nil {
			h.log.Error("Create operation record failed", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to create operation record")
			return
		}

		if h.networking != nil {
			if _, err := h.networking.CreateInstanceRoutes(instanceID, payload, nodeID); err != nil {
				h.log.Error("Create public routes failed", err, map[string]interface{}{"instance_id": instanceID})
				if uerr := h.db.UpdateCustomerAppStatus(instanceID, "", "failed"); uerr != nil {
					h.log.Error("Failed to mark instance as failed after routes error", uerr, map[string]interface{}{"instance_id": instanceID})
				}
				if uerr := h.db.UpdateOperation(operationID, "failed", err.Error()); uerr != nil {
					h.log.Error("Failed to mark operation as failed after routes error", uerr, map[string]interface{}{"operation_id": operationID})
				}
				writeError(w, http.StatusInternalServerError, "Failed to create public routes")
				return
			}
		}

		h.enqueueTask(operationID, instanceID, nodeID, appDef.RawYAML, *matchedTier, admiral.ActionProvisionApp)

		writeJSON(w, http.StatusAccepted, admiral.ProvisionResponse{
			OperationID: operationID,
			Status:      "queued",
			Credentials: credentials,
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *APIHandlers) firstActiveNodeID() (string, error) {
	nodes, err := h.db.GetNodes()
	if err != nil {
		return "", err
	}
	for _, n := range nodes {
		if n.Status == "active" {
			return n.ID, nil
		}
	}
	return "", nil
}

func (h *APIHandlers) createInstanceSecrets(instanceID string, payload admiral.AppDefinitionPayload) ([]admiral.Credential, error) {
	// First pass: generate all secrets for all services
	allPlain := make(map[string]map[string]string) // serviceName -> envName -> plaintext
	for serviceName, svc := range payload.Services {
		allPlain[serviceName] = make(map[string]string)
		for envName, secretDef := range svc.Secrets {
			plain := secretDef.Value
			if secretDef.Generate != "" {
				plain = generateSecretValue(secretDef.Generate)
			}
			allPlain[serviceName][envName] = plain
		}
	}

	// Second pass: normalize credentials that must match across services
	normalizeInstanceSecrets(allPlain, payload)

	// Encrypt and save
	var credentials []admiral.Credential
	for serviceName, svc := range payload.Services {
		for envName, secretDef := range svc.Secrets {
			plain := allPlain[serviceName][envName]

			encrypted, err := h.secrets.Encrypt(plain)
			if err != nil {
				return nil, err
			}
			if err := h.db.SaveInstanceSecret(instanceID, serviceName, envName, encrypted, secretDef.Expose); err != nil {
				return nil, err
			}
			if secretDef.Expose {
				credentials = append(credentials, admiral.Credential{Service: serviceName, Name: envName, Value: plain})
			}
		}
	}
	return credentials, nil
}

// normalizeInstanceSecrets propagates database credentials from the database
// service to any client service (e.g., WORDPRESS_DB_USER gets MARIADB_USER's value).
func normalizeInstanceSecrets(all map[string]map[string]string, payload admiral.AppDefinitionPayload) {
	// Identify the database service — the one with a volume or DB-like image
	dbService := ""
	for name, svc := range payload.Services {
		if svc.Volume != "" {
			dbService = name
			break
		}
		img := strings.ToLower(svc.Image)
		if strings.Contains(img, "postgres") || strings.Contains(img, "mysql") || strings.Contains(img, "mariadb") {
			dbService = name
			break
		}
	}
	if dbService == "" {
		return
	}

	dbSecrets := all[dbService]
	if dbSecrets == nil {
		return
	}

	// Find the DB user, password, and database env var names.
	// When both ROOT and non-root credentials exist, prefer the non-root variant.
	var dbUser, dbPass, dbRootPass, dbName string
	for envName := range dbSecrets {
		upper := strings.ToUpper(envName)
		if strings.HasSuffix(upper, "_USER") && (strings.HasPrefix(upper, "POSTGRES_") || strings.HasPrefix(upper, "MYSQL_") || strings.HasPrefix(upper, "MARIADB_")) {
			dbUser = envName
		}
		if strings.HasSuffix(upper, "_PASSWORD") && (strings.HasPrefix(upper, "POSTGRES_") || strings.HasPrefix(upper, "MYSQL_") || strings.HasPrefix(upper, "MARIADB_")) {
			if strings.Contains(upper, "_ROOT_") || strings.HasSuffix(upper, "_ROOT_PASSWORD") {
				dbRootPass = envName
			} else {
				dbPass = envName
			}
		}
		if strings.HasSuffix(upper, "_DATABASE") && (strings.HasPrefix(upper, "POSTGRES_") || strings.HasPrefix(upper, "MYSQL_") || strings.HasPrefix(upper, "MARIADB_")) {
			dbName = envName
		}
	}
	if dbPass == "" && dbRootPass != "" {
		dbPass = dbRootPass
	}

	// Propagate to client services
	for svcName, secrets := range all {
		if svcName == dbService {
			continue
		}
		for envName, _ := range secrets {
			if dbUser != "" && strings.HasSuffix(strings.ToUpper(envName), "_DB_USER") {
				all[svcName][envName] = dbSecrets[dbUser]
			}
			if dbPass != "" && strings.HasSuffix(strings.ToUpper(envName), "_DB_PASSWORD") {
				all[svcName][envName] = dbSecrets[dbPass]
			}
			if dbName != "" && strings.HasSuffix(strings.ToUpper(envName), "_DB_NAME") {
				all[svcName][envName] = dbSecrets[dbName]
			}
		}
	}
}

func (h *APIHandlers) HandleCustomerAppAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		InstanceID string `json:"instance_id"`
		Action     string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	if req.InstanceID == "" || req.Action == "" {
		writeError(w, http.StatusBadRequest, "instance_id and action are required")
		return
	}

	inst, err := h.db.GetCustomerApp(req.InstanceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error validating instance")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Customer application instance not found")
		return
	}

	if inst.NodeID == nil || *inst.NodeID == "" {
		writeError(w, http.StatusServiceUnavailable, "Application is not scheduled on any active node")
		return
	}

	appDef, err := h.db.GetAppDefinition(inst.AppDefinitionName)
	if err != nil || appDef == nil {
		writeError(w, http.StatusInternalServerError, "Failed retrieving application details")
		return
	}

	tiers, err := h.db.GetAppTiers(inst.AppDefinitionName)
	if err != nil {
		h.log.Error("Failed to get app tiers", err, map[string]interface{}{"app_name": inst.AppDefinitionName})
	}
	var matchedTier database.AppTier
	for _, t := range tiers {
		if t.Name == inst.TierName {
			matchedTier = t
			break
		}
	}

	var action admiral.TaskAction
	var nextTechStatus string

	switch req.Action {
	case "pause":
		action = admiral.ActionPauseApp
		nextTechStatus = "stopped"
	case "resume":
		action = admiral.ActionResumeApp
		nextTechStatus = "running"
	case "start":
		action = admiral.ActionStartApp
		nextTechStatus = "running"
	case "stop":
		action = admiral.ActionStopApp
		nextTechStatus = "stopped"
	case "backup":
		action = admiral.ActionBackupDatabase
		nextTechStatus = "backup_running"
	case "deprovision":
		action = admiral.ActionDeprovisionApp
		nextTechStatus = "deprovisioning"
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Unsupported action %q", req.Action))
		return
	}

	operationID := generateID("op")
	if uerr := h.db.UpdateCustomerAppStatus(req.InstanceID, "", nextTechStatus); uerr != nil {
		h.log.Error("Failed to update instance status before action", uerr, map[string]interface{}{"instance_id": req.InstanceID})
	}

	if err := h.db.CreateOperation(operationID, req.InstanceID, string(action), "queued"); err != nil {
		h.log.Error("Create action operation failed", err, nil)
		writeError(w, http.StatusInternalServerError, "Failed recording operation")
		return
	}

	h.enqueueTask(operationID, req.InstanceID, *inst.NodeID, appDef.RawYAML, matchedTier, action)

	writeJSON(w, http.StatusAccepted, admiral.OperationResponse{
		OperationID: operationID,
		Status:      "queued",
	})
}

func (h *APIHandlers) enqueueTask(opID, instID, nodeID, rawYAML string, tier database.AppTier, action admiral.TaskAction) {
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &payload); err != nil {
		h.log.Error("Failed to parse app definition for task dispatch", err, map[string]interface{}{"operation_id": opID})
		if uerr := h.db.UpdateOperation(opID, "failed", "invalid stored app definition"); uerr != nil {
			h.log.Error("Failed to update operation as failed", uerr, map[string]interface{}{"operation_id": opID})
		}
		if uerr := h.db.UpdateCustomerAppStatus(instID, "", "failed"); uerr != nil {
			h.log.Error("Failed to update instance status as failed", uerr, map[string]interface{}{"instance_id": instID})
		}
		return
	}

	var secretValues map[string]map[string]string
	if actionRequiresSecrets(action) {
		allSecretValues, err := h.decryptedSecretMap(instID)
		if err != nil {
			h.log.Error("Failed to decrypt task secrets", err, map[string]interface{}{"operation_id": opID, "instance_id": instID})
			if uerr := h.db.UpdateOperation(opID, "failed", "failed to prepare task secrets"); uerr != nil {
				h.log.Error("Failed to update operation as failed", uerr, map[string]interface{}{"operation_id": opID})
			}
			if uerr := h.db.UpdateCustomerAppStatus(instID, "", "failed"); uerr != nil {
				h.log.Error("Failed to update instance status as failed", uerr, map[string]interface{}{"instance_id": instID})
			}
			return
		}
		secretValues = scopeTaskSecrets(action, payload, allSecretValues)
	}

	var services []admiral.ServiceInfo
	for name, s := range payload.Services {
		services = append(services, admiral.ServiceInfo{
			Name:    name,
			Image:   s.Image,
			Port:    s.Port,
			Volume:  s.Volume,
			Env:     s.Env,
			Secrets: secretValues[name],
		})
	}

	task := &admiral.FleetTask{
		TaskID:      generateID("task"),
		OperationID: opID,
		NodeID:      nodeID,
		Action:      action,
		InstanceID:  instID,
		App: admiral.AppInfo{
			Name:    payload.Name,
			Version: "latest",
		},
		Tier: admiral.TierInfo{
			Name:    tier.Name,
			CPU:     tier.CPU,
			Memory:  tier.Memory,
			Storage: tier.Storage,
		},
		Services: services,
	}

	if payload.Backup != nil {
		task.Backup = &admiral.BackupInfo{
			Type:         payload.Backup.Type,
			Engine:       payload.Backup.Engine,
			Service:      payload.Backup.Service,
			DatabaseType: payload.Backup.Engine,
			DatabaseEnv:  payload.Backup.DatabaseEnv,
			UsernameEnv:  payload.Backup.UsernameEnv,
			PasswordEnv:  payload.Backup.PasswordEnv,
		}
	}

	h.log.Info("Enqueuing fleet task to outbox", map[string]interface{}{
		"task_id":      task.TaskID,
		"operation_id": opID,
		"node_id":      nodeID,
		"action":       action,
	})

	taskJSON, err := json.Marshal(task)
	if err != nil {
		h.log.Error("Failed to serialize task", err, map[string]interface{}{"task_id": task.TaskID, "operation_id": opID})
		if uerr := h.db.UpdateOperation(opID, "failed", "serialize error"); uerr != nil {
			h.log.Error("Failed to update operation as failed", uerr, map[string]interface{}{"operation_id": opID})
		}
		if uerr := h.db.UpdateCustomerAppStatus(instID, "", "failed"); uerr != nil {
			h.log.Error("Failed to update instance status as failed", uerr, map[string]interface{}{"instance_id": instID})
		}
		return
	}

	outboxID := generateID("out")
	if uerr := h.db.CreateOutboxEntry(outboxID, string(taskJSON), opID, instID, nodeID, string(action)); uerr != nil {
		h.log.Error("Failed to persist task to outbox", uerr, map[string]interface{}{"task_id": task.TaskID, "operation_id": opID})
	}
}

func (h *APIHandlers) dispatchTask(opID, instID, nodeID, rawYAML string, tier database.AppTier, action admiral.TaskAction) {
	h.enqueueTask(opID, instID, nodeID, rawYAML, tier, action)
}

func (h *APIHandlers) enqueueRawTask(task *admiral.FleetTask) {
	taskJSON, err := json.Marshal(task)
	if err != nil {
		h.log.Error("Failed to serialize task for outbox", err, map[string]interface{}{"task_id": task.TaskID, "operation_id": task.OperationID})
		return
	}
	outboxID := generateID("out")
	if uerr := h.db.CreateOutboxEntry(outboxID, string(taskJSON), task.OperationID, task.InstanceID, task.NodeID, string(task.Action)); uerr != nil {
		h.log.Error("Failed to persist task to outbox", uerr, map[string]interface{}{"task_id": task.TaskID, "operation_id": task.OperationID})
	}
}

func (h *APIHandlers) decryptedSecretMap(instanceID string) (map[string]map[string]string, error) {
	rows, err := h.db.GetInstanceSecrets(instanceID)
	if err != nil {
		return nil, err
	}
	result := make(map[string]map[string]string)
	for _, row := range rows {
		plain, err := h.secrets.Decrypt(row.EncryptedValue)
		if err != nil {
			return nil, err
		}
		if result[row.ServiceName] == nil {
			result[row.ServiceName] = make(map[string]string)
		}
		result[row.ServiceName][row.EnvName] = plain
	}
	return result, nil
}

func actionRequiresSecrets(action admiral.TaskAction) bool {
	switch action {
	case admiral.ActionProvisionApp, admiral.ActionBackupDatabase, admiral.ActionRestoreBackup:
		return true
	default:
		return false
	}
}

func scopeTaskSecrets(action admiral.TaskAction, payload admiral.AppDefinitionPayload, all map[string]map[string]string) map[string]map[string]string {
	switch action {
	case admiral.ActionProvisionApp, admiral.ActionRestoreBackup:
		return cloneSecretMap(all)
	case admiral.ActionBackupDatabase:
		return scopeBackupSecrets(payload, all)
	default:
		return map[string]map[string]string{}
	}
}

func scopeBackupSecrets(payload admiral.AppDefinitionPayload, all map[string]map[string]string) map[string]map[string]string {
	if payload.Backup == nil {
		return map[string]map[string]string{}
	}

	serviceSecrets := all[payload.Backup.Service]
	if len(serviceSecrets) == 0 {
		return map[string]map[string]string{}
	}

	required := map[string]struct{}{
		payload.Backup.DatabaseEnv: {},
		payload.Backup.UsernameEnv: {},
		payload.Backup.PasswordEnv: {},
	}

	filtered := make(map[string]string)
	for name, value := range serviceSecrets {
		if _, ok := required[name]; ok {
			filtered[name] = value
		}
	}
	if len(filtered) == 0 {
		return map[string]map[string]string{}
	}
	return map[string]map[string]string{payload.Backup.Service: filtered}
}

func cloneSecretMap(all map[string]map[string]string) map[string]map[string]string {
	cloned := make(map[string]map[string]string, len(all))
	for serviceName, serviceSecrets := range all {
		inner := make(map[string]string, len(serviceSecrets))
		for envName, value := range serviceSecrets {
			inner[envName] = value
		}
		cloned[serviceName] = inner
	}
	return cloned
}

func (h *APIHandlers) HandleOperations(w http.ResponseWriter, r *http.Request) {
	opID := r.URL.Query().Get("id")
	if opID != "" {
		op, err := h.db.GetOperation(opID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Database error retrieving operation")
			return
		}
		if op == nil {
			writeError(w, http.StatusNotFound, "Operation not found")
			return
		}
		writeJSON(w, http.StatusOK, op)
		return
	}

	ops, err := h.db.GetOperations()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error retrieving operations list")
		return
	}
	writeJSON(w, http.StatusOK, ops)
}

func (h *APIHandlers) HandleFleetCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var res admiral.TaskResult
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	h.log.Info("Received fleet task callback", map[string]interface{}{
		"operation_id": res.OperationID,
		"task_id":      res.TaskID,
		"success":      res.Success,
	})

	op, err := h.db.GetOperation(res.OperationID)
	if err != nil {
		h.log.Error("Failed to get operation from callback", err, map[string]interface{}{"operation_id": res.OperationID})
	}
	if op == nil {
		writeError(w, http.StatusNotFound, "Operation not found for callback")
		return
	}

	status := "succeeded"
	if !res.Success {
		status = "failed"
	}

	if uerr := h.db.UpdateOperation(res.OperationID, status, res.Error); uerr != nil {
		h.log.Error("Failed to update operation from callback", uerr, map[string]interface{}{"operation_id": res.OperationID})
	}

	var nextTechStatus string
	if res.Success {
		switch op.Action {
		case string(admiral.ActionProvisionApp), string(admiral.ActionStartApp), string(admiral.ActionResumeApp):
			nextTechStatus = "running"
			if op.Action == string(admiral.ActionProvisionApp) && h.networking != nil {
				hostPorts := parseHostPortsFromMetadata(res.Metadata)
				if err := h.networking.ActivateInstanceRoutes(context.Background(), op.InstanceID, hostPorts); err != nil {
					h.log.Error("Activate public routes failed", err, map[string]interface{}{"instance_id": op.InstanceID})
				}
			}
		case string(admiral.ActionStopApp), string(admiral.ActionPauseApp):
			nextTechStatus = "stopped"
		case string(admiral.ActionDeprovisionApp):
			nextTechStatus = "deprovisioned"
			if uerr := h.db.UpdateCustomerAppStatus(op.InstanceID, "cancelled", "deprovisioned"); uerr != nil {
				h.log.Error("Failed to update instance as deprovisioned", uerr, map[string]interface{}{"instance_id": op.InstanceID})
			}
			if h.networking != nil {
				if err := h.networking.DeleteInstanceRoutes(context.Background(), op.InstanceID); err != nil {
					h.log.Error("Delete public routes failed", err, map[string]interface{}{"instance_id": op.InstanceID})
				}
			}
		case string(admiral.ActionRestoreBackup):
			nextTechStatus = "running"
		case string(admiral.ActionBackupDatabase), "backup_volumes":
			nextTechStatus = "running"

			// Parse metadata from fleet task result
			var cbData struct {
				Backup struct {
					BackupID       string `json:"backup_id"`
					StorageBackend string `json:"storage_backend"`
					StorageKey     string `json:"storage_key"`
					SizeBytes      int64  `json:"size_bytes"`
					ChecksumSHA256 string `json:"checksum_sha256"`
					CompletedAt    string `json:"completed_at"`
				} `json:"backup"`
			}
			if uerr := json.Unmarshal([]byte(res.Metadata), &cbData); uerr != nil {
				h.log.Error("Failed to parse backup metadata from callback", uerr, map[string]interface{}{"operation_id": res.OperationID})
			}

			bkID := cbData.Backup.BackupID
			if bkID == "" {
				// Fallback search in backup records by instance
				recs, err := h.db.GetBackupRecords(op.InstanceID)
				if err != nil {
					h.log.Error("Failed to get backup records for fallback", err, map[string]interface{}{"instance_id": op.InstanceID})
				}
				for _, r := range recs {
					if r.Status == "pending" {
						bkID = r.ID
						break
					}
				}
			}

			if bkID != "" {
				rec, err := h.db.GetBackupRecord(bkID)
				if err != nil {
					h.log.Error("Failed to get backup record", err, map[string]interface{}{"backup_id": bkID})
				}
				if rec != nil {
					rec.Status = "succeeded"
					rec.SizeBytes = cbData.Backup.SizeBytes
					rec.ChecksumSHA256 = cbData.Backup.ChecksumSHA256
					if cbData.Backup.StorageBackend != "" {
						rec.StorageBackend = cbData.Backup.StorageBackend
					}
					if cbData.Backup.StorageKey != "" {
						rec.StorageKey = cbData.Backup.StorageKey
					}
					rec.CompletedAt = time.Now().Format(time.RFC3339)
					rec.ExpiresAt = time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
					if uerr := h.db.UpdateBackupRecord(rec); uerr != nil {
						h.log.Error("Failed to update backup record", uerr, map[string]interface{}{"backup_id": bkID})
					}
				}
			}

			// Keep existing backups legacy creation for compatibility
			backupID := generateID("bk")
			if uerr := h.db.CreateBackup(backupID, op.InstanceID, res.NodeID, "succeeded"); uerr != nil {
				h.log.Error("Failed to create backup record", uerr, map[string]interface{}{"backup_id": backupID})
			}
			if uerr := h.db.UpdateBackup(backupID, "succeeded", res.Metadata, 1024*1024); uerr != nil {
				h.log.Error("Failed to update backup metadata", uerr, map[string]interface{}{"backup_id": backupID})
			}
		}
	} else {
		nextTechStatus = "failed"
		if h.networking != nil && op.Action == string(admiral.ActionProvisionApp) {
			routes, err := h.db.GetPublicRoutes()
			if err == nil {
				for _, route := range routes {
					if route.AppInstanceID != op.InstanceID {
						continue
					}
					route.Status = string(admiral.RouteStatusFailed)
					route.LastError = res.Error
					now := time.Now().UTC()
					route.LastHealthCheckedAt = &now
					route.LastHealthStatus = "unhealthy"
					if uerr := h.db.UpdatePublicRoute(&route); uerr != nil {
						h.log.Error("Failed to update route status", uerr, map[string]interface{}{"hostname": route.Hostname})
					}
				}
				if uerr := h.networking.Sync(context.Background()); uerr != nil {
					h.log.Error("Failed to sync routes after failure", uerr, nil)
				}
			}
		}
	}

	if nextTechStatus != "" && op.Action != string(admiral.ActionDeprovisionApp) {
		if uerr := h.db.UpdateCustomerAppStatus(op.InstanceID, "", nextTechStatus); uerr != nil {
			h.log.Error("Failed to update instance status after callback", uerr, map[string]interface{}{"instance_id": op.InstanceID})
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (h *APIHandlers) HandleRoutes(w http.ResponseWriter, r *http.Request) {
	if h.networking == nil {
		writeError(w, http.StatusServiceUnavailable, "networking manager unavailable")
		return
	}

	trimmed := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(trimmed, "/")

	if len(parts) == 3 {
		switch r.Method {
		case http.MethodGet:
			routes, err := h.db.GetPublicRoutes()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Failed to fetch routes")
				return
			}
			writeJSON(w, http.StatusOK, routes)
		case http.MethodPost:
			if err := h.networking.Sync(context.Background()); err != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	if len(parts) < 4 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	hostname := parts[3]
	if hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}

	if len(parts) == 4 {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		route, err := h.db.GetPublicRoute(hostname)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to fetch route")
			return
		}
		if route == nil {
			writeError(w, http.StatusNotFound, "Route not found")
			return
		}
		writeJSON(w, http.StatusOK, route)
		return
	}

	switch parts[4] {
	case "enable":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := h.networking.EnableRoute(context.Background(), hostname); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	case "disable":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := h.networking.DisableRoute(context.Background(), hostname); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	case "sync":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := h.networking.Sync(context.Background()); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	case "delete":
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := h.networking.DeleteRoute(context.Background(), hostname); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func parseHostPortsFromMetadata(metadata string) map[string]int {
	var data struct {
		HostPorts map[string]int `json:"host_ports"`
	}
	if err := json.Unmarshal([]byte(metadata), &data); err != nil {
		return nil
	}
	return data.HostPorts
}
