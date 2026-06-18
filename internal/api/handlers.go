// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/networking"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
)

type TaskPublisher interface {
	PublishTask(task *admiral.FleetTask) error
	PublishRejectedTask(task *admiral.FleetTask, reason, result string) error
}

type APIHandlers struct {
	db                *database.DB
	log               *logging.Logger
	publisher         TaskPublisher
	secrets           *secrets.Manager
	networking        *networking.Manager
	hmacKey           string
	tokenPepper       string
	configTokenTTL    int
	loginLimiter      *RateLimiter
	knowHostPath      string
	taskEncryptionKey string // shared AES-256-GCM key served to authenticated worker nodes
}

func (h *APIHandlers) auditEvent(eventType string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["event_type"] = eventType
	h.log.Info(eventType, fields)
}

const (
	provisioningBlockedCode    = "no_node_available_for_requested_tier"
	provisioningBlockedMessage = "No hay nodos disponibles con capacidad suficiente para este tier."
)

type nodeSelectionResult struct {
	NodeID      string
	Evaluations []admiral.NodeProvisioningEvaluation
}

type blockedProvisioningAuditDetail struct {
	Code                   string                               `json:"code"`
	Message                string                               `json:"message"`
	Detail                 string                               `json:"detail"`
	Action                 string                               `json:"action"`
	RequestedAppDefinition string                               `json:"requested_app_definition"`
	RequestedTier          string                               `json:"requested_tier"`
	RequestedNodeID        string                               `json:"requested_node_id,omitempty"`
	CustomerID             string                               `json:"customer_id"`
	Operator               string                               `json:"operator"`
	NodeEvaluations        []admiral.NodeProvisioningEvaluation `json:"node_evaluations,omitempty"`
}

func NewHandlers(db *database.DB, log *logging.Logger, pub TaskPublisher, secretManager *secrets.Manager, networkingManager *networking.Manager, hmacKey, tokenPepper string, tokenTTL int, taskEncryptionKey string) *APIHandlers {
	return &APIHandlers{
		db:                db,
		log:               log,
		publisher:         pub,
		secrets:           secretManager,
		networking:        networkingManager,
		hmacKey:           hmacKey,
		tokenPepper:       tokenPepper,
		configTokenTTL:    tokenTTL,
		loginLimiter:      NewRateLimiter(),
		knowHostPath:      "/var/lib/admiral/know_host.yaml",
		taskEncryptionKey: taskEncryptionKey,
	}
}

type knownHostInventory struct {
	Version     int                          `yaml:"version"`
	GeneratedAt string                       `yaml:"generated_at"`
	Next        knownHostNextAssignments     `yaml:"next"`
	Nodes       map[string]knownHostNodeSpec `yaml:"nodes"`
}

type knownHostNextAssignments struct {
	Worker knownHostBootstrapAssignment `yaml:"worker"`
	Portal knownHostBootstrapAssignment `yaml:"portal"`
}

type knownHostBootstrapAssignment struct {
	NodeID      string `yaml:"node_id"`
	WireguardIP string `yaml:"wireguard_ip"`
}

type knownHostNodeSpec struct {
	NodeID      string `yaml:"node_id"`
	Hostname    string `yaml:"hostname,omitempty"`
	NodeRole    string `yaml:"node_role"`
	PublicIP    string `yaml:"public_ip,omitempty"`
	WireguardIP string `yaml:"wireguard_ip,omitempty"`
	Status      string `yaml:"status,omitempty"`
}

func nextKnownHostAssignment(nodes []database.Node, role string) knownHostBootstrapAssignment {
	startOctet := 2
	if role == "portal" {
		startOctet = 100
	}
	maxSuffix := 0
	usedOctets := map[int]bool{}
	prefix := role + "-"
	for _, node := range nodes {
		if node.NodeRole != role {
			continue
		}
		if strings.HasPrefix(node.ID, prefix) {
			if suffix, err := strconv.Atoi(strings.TrimPrefix(node.ID, prefix)); err == nil && suffix > maxSuffix {
				maxSuffix = suffix
			}
		}
		if octet := wireguardLastOctet(node.WireguardIP); octet >= startOctet {
			usedOctets[octet] = true
		}
	}

	nextOctet := startOctet
	for usedOctets[nextOctet] {
		nextOctet++
	}
	return knownHostBootstrapAssignment{
		NodeID:      fmt.Sprintf("%s-%03d", role, maxSuffix+1),
		WireguardIP: fmt.Sprintf("10.99.0.%d", nextOctet),
	}
}

func wireguardLastOctet(ip string) int {
	parts := strings.Split(strings.TrimSpace(ip), ".")
	if len(parts) != 4 {
		return 0
	}
	last, err := strconv.Atoi(parts[3])
	if err != nil {
		return 0
	}
	return last
}

func (h *APIHandlers) syncKnownHostInventory() error {
	nodes, err := h.db.GetNodes()
	if err != nil {
		return fmt.Errorf("get nodes for know_host inventory: %w", err)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})

	inv := knownHostInventory{
		Version:     1,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Next: knownHostNextAssignments{
			Worker: nextKnownHostAssignment(nodes, "worker"),
			Portal: nextKnownHostAssignment(nodes, "portal"),
		},
		Nodes: map[string]knownHostNodeSpec{},
	}
	for _, node := range nodes {
		inv.Nodes[node.ID] = knownHostNodeSpec{
			NodeID:      node.ID,
			Hostname:    node.Hostname,
			NodeRole:    node.NodeRole,
			PublicIP:    node.PublicIP,
			WireguardIP: node.WireguardIP,
			Status:      node.Status,
		}
	}

	content, err := yaml.Marshal(inv)
	if err != nil {
		return fmt.Errorf("marshal know_host inventory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(h.knowHostPath), 0750); err != nil {
		return fmt.Errorf("mkdir know_host path: %w", err)
	}
	tmpPath := h.knowHostPath + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0600); err != nil {
		return fmt.Errorf("write know_host temp file: %w", err)
	}
	if err := os.Rename(tmpPath, h.knowHostPath); err != nil {
		return fmt.Errorf("rename know_host inventory: %w", err)
	}
	return nil
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

func generateSecretKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func operatorFromRequest(r *http.Request) string {
	if op := r.Header.Get("X-Admiral-Admin-User"); op != "" {
		return op
	}
	return r.Header.Get("X-Admiral-Operator")
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func encryptTokenValue(rawToken, pepper string) (string, error) {
	key := sha256Key(pepper)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(rawToken), nil)
	return hex.EncodeToString(ciphertext), nil
}

func sha256Key(pepper string) []byte {
	h := sha256.Sum256([]byte(pepper))
	return h[:]
}

func generateNodeToken(pepper string, ttlMinutes int) (rawToken, identifier, hash, encryptedValue, claimID string, expiresAt time.Time, err error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		err = fmt.Errorf("generate random token: %w", e)
		return
	}
	rawToken = hex.EncodeToString(b)
	identifier = nodeTokenIdentifier(rawToken, pepper)
	hash, err = bcryptHash(rawToken)
	if err != nil {
		return
	}
	encryptedValue, err = encryptTokenValue(rawToken, pepper)
	if err != nil {
		return
	}
	claimID = generateID("claim")
	expiresAt = time.Now().UTC().Add(time.Duration(ttlMinutes) * time.Minute)
	return
}

func bcryptHash(raw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash: %w", err)
	}
	return string(b), nil
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

		if err := h.db.RegisterNode(req.NodeID, req.Hostname, req.IP, req.WireguardIP, req.NodeRole, req.PublicIP, req.OS, req.PodmanV); err != nil {
			h.log.Error("Register node failed", err, map[string]interface{}{"node_id": req.NodeID})
			writeError(w, http.StatusInternalServerError, "Failed to register node")
			return
		}

		resp := admiral.RegisterNodeResponse{Success: true}

		if req.Token != "" {
			// Single-node mode: pre-generated token
			identifier := nodeTokenIdentifier(req.Token, h.tokenPepper)
			hash, err := bcryptHash(req.Token)
			if err != nil {
				h.log.Error("Failed to hash pre-generated token", err, map[string]interface{}{"node_id": req.NodeID})
				writeError(w, http.StatusInternalServerError, "Failed to process node token")
				return
			}
			encryptedValue, err := encryptTokenValue(req.Token, h.tokenPepper)
			if err != nil {
				h.log.Error("Failed to encrypt pre-generated token", err, map[string]interface{}{"node_id": req.NodeID})
				writeError(w, http.StatusInternalServerError, "Failed to process node token")
				return
			}
			tokenType := req.TokenType
			if tokenType == "" {
				tokenType = "worker"
			}
			if err := h.db.UpsertNodeToken(req.NodeID, identifier, hash, tokenType, "active", encryptedValue, nil, ""); err != nil {
				h.log.Error("Failed to store node token", err, map[string]interface{}{"node_id": req.NodeID})
				writeError(w, http.StatusInternalServerError, "Failed to store node token")
				return
			}
		} else {
			// Multi-node mode: server-generated token
			tokenType := req.TokenType
			if tokenType == "" {
				tokenType = "worker"
			}
			rawToken, identifier, hash, encryptedValue, claimID, expiresAt, err := generateNodeToken(h.tokenPepper, h.configTokenTTL)
			if err != nil {
				h.log.Error("Failed to generate node token", err, map[string]interface{}{"node_id": req.NodeID})
				writeError(w, http.StatusInternalServerError, "Failed to generate node token")
				return
			}
			if err := h.db.UpsertNodeToken(req.NodeID, identifier, hash, tokenType, "available", encryptedValue, &expiresAt, claimID); err != nil {
				h.log.Error("Failed to store generated node token", err, map[string]interface{}{"node_id": req.NodeID})
				writeError(w, http.StatusInternalServerError, "Failed to store node token")
				return
			}
			resp.Token = rawToken
			resp.ClaimID = claimID
		}

		if err := h.recomputeNodePolicy(req.NodeID); err != nil {
			h.log.Error("Recompute node policy failed after register", err, map[string]interface{}{"node_id": req.NodeID})
		}
		if err := h.syncKnownHostInventory(); err != nil {
			h.log.Error("Sync know_host inventory failed after register", err, map[string]interface{}{"node_id": req.NodeID})
		}

		h.log.Info("Node registered successfully", map[string]interface{}{"node_id": req.NodeID, "hostname": req.Hostname})
		writeJSON(w, http.StatusOK, resp)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// HandleTaskEncryptionKey serves the shared AES-256-GCM task encryption key
// to authenticated worker nodes. The key is used to decrypt task payloads
// from the queue. Only nodes authenticated via per-node token and matching
// their registered WireGuard IP may retrieve it.
func (h *APIHandlers) HandleTaskEncryptionKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	nodeID, ok := NodeIDFromContext(r.Context())
	if !ok || nodeID == "" {
		writeError(w, http.StatusUnauthorized, "node authentication required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"task_encryption_key": h.taskEncryptionKey})
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

	if err := h.db.UpdateNodeHeartbeat(req.NodeID, &req); err != nil {
		h.log.Error("Update heartbeat failed", err, map[string]interface{}{"node_id": req.NodeID})
		writeError(w, http.StatusInternalServerError, "Failed updating heartbeat")
		return
	}

	state, msg := database.NodeStorageState(req.DiskTotal, req.DiskUsed)
	if state != "" {
		if err := h.db.UpdateNodeStorageState(req.NodeID, state, msg); err != nil {
			h.log.Error("Failed to update node storage state", err, map[string]interface{}{"node_id": req.NodeID})
		}
	}

	// Evaluate and persist node health, capacity limits, and provisioning availability.
	if err := h.recomputeNodePolicy(req.NodeID); err != nil {
		h.log.Error("Recompute node policy failed after heartbeat", err, map[string]interface{}{"node_id": req.NodeID})
	}
	if err := h.syncKnownHostInventory(); err != nil {
		h.log.Error("Sync know_host inventory failed after heartbeat", err, map[string]interface{}{"node_id": req.NodeID})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

func (h *APIHandlers) HandleNodeByID(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		writeError(w, http.StatusBadRequest, "node_id is required")
		return
	}
	nodeID := parts[3]

	if len(parts) >= 5 && parts[4] == "metrics" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		metrics, err := h.db.GetNodeMetrics(nodeID)
		if err != nil {
			h.log.Error("Get node metrics failed", err, map[string]interface{}{"node_id": nodeID})
			writeError(w, http.StatusInternalServerError, "Failed to fetch node metrics")
			return
		}
		if metrics == nil {
			writeError(w, http.StatusNotFound, "Node not found")
			return
		}
		writeJSON(w, http.StatusOK, metrics)
		return
	}

	if len(parts) == 4 {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		node, err := h.db.GetNode(nodeID)
		if err != nil {
			h.log.Error("Get node failed", err, map[string]interface{}{"node_id": nodeID})
			writeError(w, http.StatusInternalServerError, "Database error")
			return
		}
		if node == nil {
			writeError(w, http.StatusNotFound, "Node not found")
			return
		}
		writeJSON(w, http.StatusOK, node)
		return
	}

	if len(parts) != 5 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	node, err := h.db.GetNode(nodeID)
	if err != nil {
		h.log.Error("Get node failed", err, map[string]interface{}{"node_id": nodeID})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not found")
		return
	}

	var disabled bool
	switch parts[4] {
	case "enable":
		disabled = false
	case "disable":
		disabled = true
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if err := h.db.SetNodeManualDisabled(nodeID, disabled); err != nil {
		h.log.Error("Set node manual disabled failed", err, map[string]interface{}{"node_id": nodeID, "manual_disabled": disabled})
		writeError(w, http.StatusInternalServerError, "Failed updating node state")
		return
	}
	h.auditEvent(map[bool]string{true: "node_manually_disabled", false: "node_manually_enabled"}[disabled], map[string]interface{}{
		"node_id":    nodeID,
		"actor_type": "operator",
		"actor_id":   operatorFromRequest(r),
		"new_value":  disabled,
	})
	if err := h.recomputeNodePolicy(nodeID); err != nil {
		h.log.Error("Recompute node policy failed", err, map[string]interface{}{"node_id": nodeID, "manual_disabled": disabled})
		writeError(w, http.StatusInternalServerError, "Failed recomputing node policy")
		return
	}
	updatedNode, err := h.db.GetNode(nodeID)
	if err != nil {
		h.log.Error("Reload node after toggle failed", err, map[string]interface{}{"node_id": nodeID})
		writeError(w, http.StatusInternalServerError, "Failed reloading node")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"node":    updatedNode,
	})
}

func (h *APIHandlers) HandleApps(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var appID string
	if len(parts) >= 4 {
		appID = parts[3]
	}

	// Dispatch to sub-resource handlers
	if len(parts) >= 5 && appID != "" {
		switch parts[4] {
		case "availability":
			h.HandleAppAvailability(w, r)
			return
		case "validate-provisioning":
			h.HandleAppValidateProvisioning(w, r)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		if appID != "" {
			app, err := h.db.GetAppDefinition(appID)
			if err != nil {
				h.log.Error("Get app failed", err, map[string]interface{}{"app_name": appID})
				writeError(w, http.StatusInternalServerError, "Failed to fetch application")
				return
			}
			if app == nil {
				writeError(w, http.StatusNotFound, "App definition not found")
				return
			}
			writeJSON(w, http.StatusOK, app)
			return
		}

		apps, err := h.db.GetAppDefinitions()
		if err != nil {
			h.log.Error("Get apps failed", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to fetch applications")
			return
		}
		writeJSON(w, http.StatusOK, apps)

	case http.MethodPost:
		yamlContent, err := readAppDefinitionBody(w, r)
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
				Free:             t.Free,
				Environment:      t.Environment,
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

	case http.MethodPatch, http.MethodPut:
		if appID == "" || len(parts) < 5 || parts[4] != "status" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}
		status := strings.ToLower(strings.TrimSpace(req.Status))
		if status != "active" && status != "inactive" {
			writeError(w, http.StatusBadRequest, "status must be active or inactive")
			return
		}
		if err := h.db.UpdateAppDefinitionStatus(appID, status); err != nil {
			if err == sql.ErrNoRows {
				writeError(w, http.StatusNotFound, "App definition not found")
				return
			}
			h.log.Error("Update app definition status failed", err, map[string]interface{}{"app_name": appID, "status": status})
			writeError(w, http.StatusInternalServerError, "Failed to update application status")
			return
		}
		h.log.Info("App definition status updated", map[string]interface{}{"app_name": appID, "status": status})
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "name": appID, "status": status})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func readAppDefinitionBody(w http.ResponseWriter, r *http.Request) (string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

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
		return "", fmt.Errorf("invalid JSON payload (must include 'yaml' field or be application/x-yaml)")
	}
	if req.YAML == "" {
		return "", fmt.Errorf("YAML content is empty")
	}
	return req.YAML, nil
}

func (h *APIHandlers) HandleCustomerApps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		customerID := r.URL.Query().Get("customer_id")
		apps, err := h.db.GetCustomerApps(customerID)
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
		if strings.ToLower(strings.TrimSpace(appDef.Status)) != "active" {
			writeError(w, http.StatusConflict, "App definition is inactive and cannot be provisioned")
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
		if req.NodeID != "" {
			node, err := h.db.GetNode(req.NodeID)
			if err != nil {
				h.log.Error("Get requested node failed on provision", err, map[string]interface{}{"node_id": req.NodeID})
				writeError(w, http.StatusInternalServerError, "Database error validating requested node")
				return
			}
			if node == nil {
				writeError(w, http.StatusNotFound, "Requested node not found")
				return
			}
		}

		selection, err := h.selectNodeForTier(*matchedTier, req.NodeID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Database error selecting node")
			return
		}
		if selection.NodeID == "" {
			if err := h.recordBlockedWorkloadAttempt(w, r, admiral.ActionProvisionApp, "", req.AppDefinitionName, req.CustomerID, req.NodeID, *matchedTier, selection.Evaluations); err != nil {
				h.log.Error("Record blocked provisioning attempt failed", err, map[string]interface{}{"app_name": req.AppDefinitionName, "tier_name": req.TierName, "requested_node_id": req.NodeID})
				writeError(w, http.StatusInternalServerError, "Failed recording blocked provisioning attempt")
			}
			return
		}

		instanceID := generateID("inst")
		operationID := generateID("op")
		nodeID := selection.NodeID

		tierBytes, err := json.Marshal(matchedTier)
		if err != nil {
			h.log.Error("Failed to marshal tier snapshot", err, map[string]interface{}{"tier": req.TierName})
		}
		tierSnapshotJSON := string(tierBytes)

		lid := req.LogicalInstanceID
		ramBytes := database.ParseSizeBytes(matchedTier.Memory)
		diskBytes := database.ParseSizeBytes(matchedTier.Storage)
		if err := h.db.ReserveNodeCapacityAndCreateApp(instanceID, req.CustomerID, req.AppDefinitionName, req.TierName, nodeID, tierSnapshotJSON, lid, ramBytes, diskBytes); err != nil {
			if err == database.ErrNodeCapacityPolicyBlocked {
				evaluations := h.refreshNodeEvaluationsForTier(*matchedTier, nodeID)
				if recErr := h.recordBlockedWorkloadAttempt(w, r, admiral.ActionProvisionApp, "", req.AppDefinitionName, req.CustomerID, nodeID, *matchedTier, evaluations); recErr != nil {
					h.log.Error("Record blocked provisioning attempt after reserve race failed", recErr, map[string]interface{}{"app_name": req.AppDefinitionName, "tier_name": req.TierName, "requested_node_id": nodeID})
					writeError(w, http.StatusInternalServerError, "Failed recording blocked provisioning attempt")
				}
				return
			}
			h.log.Error("Create customer app with capacity reservation failed", err, map[string]interface{}{"node_id": nodeID, "instance_id": instanceID})
			writeError(w, http.StatusInternalServerError, "Failed to create app record")
			return
		}
		h.auditCapacityEvent("node_capacity_reserved", nodeID, instanceID, operationID, admiral.ActionProvisionApp, ramBytes, diskBytes)
		if err := h.recomputeNodePolicy(nodeID); err != nil {
			h.log.Error("Failed to recompute node policy after reservation", err, map[string]interface{}{"node_id": nodeID, "instance_id": instanceID})
		}

		releaseCapacity := func() {
			if ramBytes > 0 && diskBytes > 0 {
				if uerr := h.db.ReleaseNodeCommitment(nodeID, ramBytes, diskBytes); uerr != nil {
					h.log.Error("Failed to release capacity after rollback", uerr, map[string]interface{}{"node_id": nodeID, "instance_id": instanceID})
				} else if uerr := h.recomputeNodePolicy(nodeID); uerr != nil {
					h.log.Error("Failed to recompute node policy after rollback", uerr, map[string]interface{}{"node_id": nodeID, "instance_id": instanceID})
				} else {
					h.auditCapacityEvent("node_capacity_released", nodeID, instanceID, operationID, admiral.ActionProvisionApp, ramBytes, diskBytes)
				}
			}
		}

		credentials, err := h.createInstanceSecrets(instanceID, payload)
		if err != nil {
			h.log.Error("Create instance secrets failed", err, map[string]interface{}{"instance_id": instanceID})
			if uerr := h.db.UpdateCustomerAppStatus(instanceID, "", "failed"); uerr != nil {
				h.log.Error("Failed to mark instance as failed after secrets error", uerr, map[string]interface{}{"instance_id": instanceID})
			}
			releaseCapacity()
			writeError(w, http.StatusInternalServerError, "Failed to create instance secrets")
			return
		}

		if err := h.db.CreateOperation(operationID, instanceID, nodeID, string(admiral.ActionProvisionApp), "pending_dispatch", operatorFromRequest(r)); err != nil {
			h.log.Error("Create operation record failed", err, nil)
			releaseCapacity()
			writeError(w, http.StatusInternalServerError, "Failed to create operation record")
			return
		}

		var hostname string
		var routes []database.PublicRoute
		if h.networking != nil {
			routes, err = h.networking.CreateInstanceRoutes(instanceID, payload, nodeID)
			if err != nil {
				h.log.Error("Create public routes failed", err, map[string]interface{}{"instance_id": instanceID})
				if uerr := h.db.UpdateCustomerAppStatus(instanceID, "", "failed"); uerr != nil {
					h.log.Error("Failed to mark instance as failed after routes error", uerr, map[string]interface{}{"instance_id": instanceID})
				}
				if uerr := h.db.UpdateOperation(operationID, "failed", err.Error()); uerr != nil {
					h.log.Error("Failed to mark operation as failed after routes error", uerr, map[string]interface{}{"operation_id": operationID})
				}
				releaseCapacity()
				writeError(w, http.StatusInternalServerError, "Failed to create public routes")
				return
			}
		}

		if len(routes) > 0 {
			hostname = routes[0].Hostname
		}

		h.enqueueTask(operationID, instanceID, nodeID, req.CustomerID, appDef.RawYAML, *matchedTier, admiral.ActionProvisionApp, "", "")

		writeJSON(w, http.StatusAccepted, admiral.ProvisionResponse{
			OperationID: operationID,
			Status:      "queued",
			Hostname:    hostname,
			Credentials: credentials,
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *APIHandlers) HandleCustomerAppByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		writeError(w, http.StatusBadRequest, "instance_id is required")
		return
	}
	instanceID := parts[3]

	// /api/v1/customer-apps/{id}/credentials
	if len(parts) >= 5 && parts[4] == "credentials" {
		h.handleCredentials(w, r, instanceID)
		return
	}

	inst, err := h.db.GetCustomerApp(instanceID)
	if err != nil {
		h.log.Error("Get customer app failed", err, map[string]interface{}{"instance_id": instanceID})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	writeJSON(w, http.StatusOK, inst)
}

func (h *APIHandlers) handleCredentials(w http.ResponseWriter, r *http.Request, instanceID string) {
	secrets, err := h.db.GetExposedInstanceSecrets(instanceID)
	if err != nil {
		h.log.Error("Get exposed secrets failed", err, map[string]interface{}{"instance_id": instanceID})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}

	credentials := make([]admiral.Credential, 0, len(secrets))
	for _, s := range secrets {
		plain, err := h.secrets.Decrypt(s.EncryptedValue)
		if err != nil {
			h.log.Error("Decrypt secret failed", err, nil)
			continue
		}
		credentials = append(credentials, admiral.Credential{
			Service: s.ServiceName,
			Name:    s.EnvName,
			Value:   plain,
		})
	}

	writeJSON(w, http.StatusOK, credentials)
}

// POST /api/v1/apps/{id}/validate-provisioning — verify app+tier before provisioning
