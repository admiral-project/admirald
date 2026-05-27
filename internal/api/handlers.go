package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

type TaskPublisher interface {
	PublishTask(task *admiral.FleetTask) error
}

type APIHandlers struct {
	db        *database.DB
	log       *logging.Logger
	publisher TaskPublisher
	secrets   *secrets.Manager
}

func NewHandlers(db *database.DB, log *logging.Logger, pub TaskPublisher, secretManager *secrets.Manager) *APIHandlers {
	return &APIHandlers{
		db:        db,
		log:       log,
		publisher: pub,
		secrets:   secretManager,
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
	_ = json.NewEncoder(w).Encode(data)
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
			dbTiers = append(dbTiers, database.AppTier{
				AppName:      payload.Name,
				Name:         name,
				CPU:          t.CPU,
				Memory:       t.Memory,
				Storage:      t.Storage,
				PriceMonthly: t.PriceMonthly,
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
		_ = r.Body.Close()
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

		if err := h.db.CreateCustomerApp(instanceID, req.CustomerID, req.AppDefinitionName, req.TierName, nodeID); err != nil {
			h.log.Error("Create customer app record failed", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to create app record")
			return
		}

		credentials, err := h.createInstanceSecrets(instanceID, payload)
		if err != nil {
			h.log.Error("Create instance secrets failed", err, map[string]interface{}{"instance_id": instanceID})
			_ = h.db.UpdateCustomerAppStatus(instanceID, "", "failed")
			writeError(w, http.StatusInternalServerError, "Failed to create instance secrets")
			return
		}

		if err := h.db.CreateOperation(operationID, instanceID, string(admiral.ActionProvisionApp), "queued"); err != nil {
			h.log.Error("Create operation record failed", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to create operation record")
			return
		}

		go h.dispatchTask(operationID, instanceID, nodeID, appDef.RawYAML, *matchedTier, admiral.ActionProvisionApp)

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
	var credentials []admiral.Credential
	for serviceName, svc := range payload.Services {
		for envName, secretDef := range svc.Secrets {
			plain := secretDef.Value
			if secretDef.Generate != "" {
				plain = generateSecretValue(secretDef.Generate)
			}

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

	tiers, _ := h.db.GetAppTiers(inst.AppDefinitionName)
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
	_ = h.db.UpdateCustomerAppStatus(req.InstanceID, "", nextTechStatus)

	if err := h.db.CreateOperation(operationID, req.InstanceID, string(action), "queued"); err != nil {
		h.log.Error("Create action operation failed", err, nil)
		writeError(w, http.StatusInternalServerError, "Failed recording operation")
		return
	}

	go h.dispatchTask(operationID, req.InstanceID, *inst.NodeID, appDef.RawYAML, matchedTier, action)

	writeJSON(w, http.StatusAccepted, admiral.OperationResponse{
		OperationID: operationID,
		Status:      "queued",
	})
}

func (h *APIHandlers) dispatchTask(opID, instID, nodeID, rawYAML string, tier database.AppTier, action admiral.TaskAction) {
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &payload); err != nil {
		h.log.Error("Failed to parse app definition for task dispatch", err, map[string]interface{}{"operation_id": opID})
		_ = h.db.UpdateOperation(opID, "failed", "invalid stored app definition")
		_ = h.db.UpdateCustomerAppStatus(instID, "", "failed")
		return
	}

	var secretValues map[string]map[string]string
	if actionRequiresSecrets(action) {
		allSecretValues, err := h.decryptedSecretMap(instID)
		if err != nil {
			h.log.Error("Failed to decrypt task secrets", err, map[string]interface{}{"operation_id": opID, "instance_id": instID})
			_ = h.db.UpdateOperation(opID, "failed", "failed to prepare task secrets")
			_ = h.db.UpdateCustomerAppStatus(instID, "", "failed")
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
			Type:        payload.Backup.Type,
			Service:     payload.Backup.Service,
			DatabaseEnv: payload.Backup.DatabaseEnv,
			UsernameEnv: payload.Backup.UsernameEnv,
			PasswordEnv: payload.Backup.PasswordEnv,
		}
	}

	h.log.Info("Dispatching fleet task", map[string]interface{}{
		"task_id":      task.TaskID,
		"operation_id": opID,
		"node_id":      nodeID,
		"action":       action,
	})

	_ = h.db.UpdateOperation(opID, "running", "")
	if err := h.publisher.PublishTask(task); err != nil {
		h.log.Error("Failed to publish task to worker", err, map[string]interface{}{"task_id": task.TaskID})
		_ = h.db.UpdateOperation(opID, "failed", err.Error())
		_ = h.db.UpdateCustomerAppStatus(instID, "", "failed")
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
	case admiral.ActionProvisionApp, admiral.ActionBackupDatabase:
		return true
	default:
		return false
	}
}

func scopeTaskSecrets(action admiral.TaskAction, payload admiral.AppDefinitionPayload, all map[string]map[string]string) map[string]map[string]string {
	switch action {
	case admiral.ActionProvisionApp:
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

	op, _ := h.db.GetOperation(res.OperationID)
	if op == nil {
		writeError(w, http.StatusNotFound, "Operation not found for callback")
		return
	}

	status := "succeeded"
	if !res.Success {
		status = "failed"
	}

	_ = h.db.UpdateOperation(res.OperationID, status, res.Error)

	var nextTechStatus string
	if res.Success {
		switch op.Action {
		case string(admiral.ActionProvisionApp), string(admiral.ActionStartApp), string(admiral.ActionResumeApp):
			nextTechStatus = "running"
		case string(admiral.ActionStopApp), string(admiral.ActionPauseApp):
			nextTechStatus = "stopped"
		case string(admiral.ActionDeprovisionApp):
			nextTechStatus = "deprovisioned"
			_ = h.db.UpdateCustomerAppStatus(op.InstanceID, "cancelled", "deprovisioned")
		case string(admiral.ActionBackupDatabase):
			nextTechStatus = "running"
			backupID := generateID("bk")
			_ = h.db.CreateBackup(backupID, op.InstanceID, res.NodeID, "succeeded")
			_ = h.db.UpdateBackup(backupID, "succeeded", res.Metadata, 1024*1024)
		}
	} else {
		nextTechStatus = "failed"
	}

	if nextTechStatus != "" && op.Action != string(admiral.ActionDeprovisionApp) {
		_ = h.db.UpdateCustomerAppStatus(op.InstanceID, "", nextTechStatus)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}
