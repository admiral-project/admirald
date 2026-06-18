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

func isMetricsFresh(lastMetricsAt *time.Time) bool {
	if lastMetricsAt == nil {
		return false
	}
	return time.Since(lastMetricsAt.UTC()) <= time.Duration(database.MetricsStaleAfterSec)*time.Second
}

func hasValidNodeMetrics(node database.Node) bool {
	if node.RAMTotal <= 0 || node.DiskTotal <= 0 {
		return false
	}
	if node.RAMUsed < 0 || node.DiskUsed < 0 {
		return false
	}
	if node.RAMUsed > node.RAMTotal || node.DiskUsed > node.DiskTotal {
		return false
	}
	return true
}

func appendUniqueReason(reasons []string, reason string) []string {
	if reason == "" {
		return reasons
	}
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

func normalizeReasons(reasons []string) []string {
	if len(reasons) == 0 {
		return nil
	}
	sort.Strings(reasons)
	out := reasons[:0]
	for _, reason := range reasons {
		if len(out) == 0 || out[len(out)-1] != reason {
			out = append(out, reason)
		}
	}
	return out
}

func joinReasons(reasons []string) string {
	reasons = normalizeReasons(reasons)
	if len(reasons) == 0 {
		return ""
	}
	return strings.Join(reasons, ",")
}

func (h *APIHandlers) recomputeNodePolicy(nodeID string) error {
	node, err := h.db.GetNode(nodeID)
	if err != nil {
		return fmt.Errorf("get node %q for policy recompute: %w", nodeID, err)
	}
	if node == nil {
		return fmt.Errorf("node %q not found for policy recompute", nodeID)
	}

	ramCommitLimit := database.CalculateRAMCommitLimit(node.RAMTotal)
	diskCommitLimit := database.CalculateDiskCommitLimit(node.DiskTotal)
	if err := h.db.UpdateNodeCommitLimits(nodeID, ramCommitLimit, diskCommitLimit); err != nil {
		return fmt.Errorf("update commit limits for node %q: %w", nodeID, err)
	}

	metricsFresh := isMetricsFresh(node.LastMetricsAt)
	metricsValid := hasValidNodeMetrics(*node) && ramCommitLimit > 0 && diskCommitLimit > 0

	healthReasons := []string{}
	availabilityReasons := []string{}

	if node.Status != "active" {
		healthReasons = appendUniqueReason(healthReasons, "fleet_offline")
		availabilityReasons = appendUniqueReason(availabilityReasons, "fleet_offline")
	}
	if node.ManualDisabled {
		healthReasons = appendUniqueReason(healthReasons, "manual_disabled")
		availabilityReasons = appendUniqueReason(availabilityReasons, "manual_disabled")
	}
	if !metricsFresh {
		healthReasons = appendUniqueReason(healthReasons, "metrics_stale")
		availabilityReasons = appendUniqueReason(availabilityReasons, "metrics_stale")
	}
	if !metricsValid {
		healthReasons = appendUniqueReason(healthReasons, "invalid_metrics")
		availabilityReasons = appendUniqueReason(availabilityReasons, "invalid_metrics")
	}
	if metricsValid {
		ramRatio := float64(node.RAMUsed) / float64(node.RAMTotal)
		if ramRatio >= database.RAMHealthCriticalRatio {
			healthReasons = appendUniqueReason(healthReasons, "ram_usage_critical")
			availabilityReasons = appendUniqueReason(availabilityReasons, "ram_usage_critical")
		}
		diskRatio := float64(node.DiskUsed) / float64(node.DiskTotal)
		if diskRatio >= database.DiskHealthCriticalRatio {
			healthReasons = appendUniqueReason(healthReasons, "disk_usage_critical")
			availabilityReasons = appendUniqueReason(availabilityReasons, "disk_usage_critical")
		}
	}
	if ramCommitLimit <= 0 || node.CommittedRAM >= ramCommitLimit {
		availabilityReasons = appendUniqueReason(availabilityReasons, "insufficient_ram_commit_capacity")
	}
	if diskCommitLimit <= 0 || node.CommittedDisk >= diskCommitLimit {
		availabilityReasons = appendUniqueReason(availabilityReasons, "insufficient_disk_commit_capacity")
	}

	healthStatus := "healthy"
	if len(healthReasons) > 0 {
		healthStatus = "unhealthy"
	}
	available := len(availabilityReasons) == 0

	if err := h.db.UpdateNodeHealth(nodeID, healthStatus, joinReasons(healthReasons), available, joinReasons(availabilityReasons)); err != nil {
		return fmt.Errorf("update node %q health: %w", nodeID, err)
	}
	newHealthReasons := joinReasons(healthReasons)
	newAvailabilityReasons := joinReasons(availabilityReasons)
	if node.HealthStatus != healthStatus || node.HealthReasonCodes != newHealthReasons {
		h.auditEvent("node_health_changed", map[string]interface{}{
			"node_id":        nodeID,
			"actor_type":     "system",
			"actor_id":       "admirald",
			"previous_value": node.HealthStatus,
			"new_value":      healthStatus,
			"reason_codes":   newHealthReasons,
		})
	}
	if node.AvailableForProvisioning != available || node.UnavailableReasonCodes != newAvailabilityReasons {
		h.auditEvent("node_provisioning_availability_changed", map[string]interface{}{
			"node_id":        nodeID,
			"actor_type":     "system",
			"actor_id":       "admirald",
			"previous_value": node.AvailableForProvisioning,
			"new_value":      available,
			"reason_codes":   newAvailabilityReasons,
		})
	}
	return nil
}

func (h *APIHandlers) evaluateNodeForTier(node database.Node, requestedRAM, requestedDisk int64) admiral.NodeProvisioningEvaluation {
	evaluation := admiral.NodeProvisioningEvaluation{NodeID: node.ID}
	reasons := []string{}

	if node.NodeRole == "admin" || node.NodeRole == "portal" {
		reasons = appendUniqueReason(reasons, "not_a_worker_node")
	}
	if node.Status != "active" || node.HealthStatus != "healthy" {
		reasons = appendUniqueReason(reasons, "node_unhealthy")
	}
	if node.ManualDisabled {
		reasons = appendUniqueReason(reasons, "manual_disabled")
	}
	if !isMetricsFresh(node.LastMetricsAt) {
		reasons = appendUniqueReason(reasons, "metrics_stale")
	}
	if !hasValidNodeMetrics(node) {
		reasons = appendUniqueReason(reasons, "invalid_metrics")
	}

	ramCommitLimit := node.RAMCommitLimit
	if ramCommitLimit <= 0 {
		ramCommitLimit = database.CalculateRAMCommitLimit(node.RAMTotal)
	}
	diskCommitLimit := node.DiskCommitLimit
	if diskCommitLimit <= 0 {
		diskCommitLimit = database.CalculateDiskCommitLimit(node.DiskTotal)
	}

	if ramCommitLimit <= 0 || node.CommittedRAM+requestedRAM > ramCommitLimit {
		reasons = appendUniqueReason(reasons, "insufficient_ram_commit_capacity")
	}
	if diskCommitLimit <= 0 || node.CommittedDisk+requestedDisk > diskCommitLimit {
		reasons = appendUniqueReason(reasons, "insufficient_disk_commit_capacity")
	}

	reasons = normalizeReasons(reasons)
	evaluation.RejectionReasons = reasons
	evaluation.Eligible = len(reasons) == 0
	if evaluation.Eligible {
		evaluation.RemainingRAMAfterAllocationBytes = ramCommitLimit - (node.CommittedRAM + requestedRAM)
		evaluation.RemainingDiskAfterAllocationBytes = diskCommitLimit - (node.CommittedDisk + requestedDisk)
	}
	return evaluation
}

func (h *APIHandlers) selectNodeForTier(tier database.AppTier, requestedNodeID string) (nodeSelectionResult, error) {
	nodes, err := h.db.GetNodes()
	if err != nil {
		return nodeSelectionResult{}, err
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})

	requestedRAM := database.ParseSizeBytes(tier.Memory)
	requestedDisk := database.ParseSizeBytes(tier.Storage)
	if requestedRAM <= 0 || requestedDisk <= 0 {
		return nodeSelectionResult{}, fmt.Errorf("tier %q has invalid resource definition", tier.Name)
	}

	result := nodeSelectionResult{}
	for _, node := range nodes {
		if requestedNodeID != "" && node.ID != requestedNodeID {
			continue
		}
		evaluation := h.evaluateNodeForTier(node, requestedRAM, requestedDisk)
		result.Evaluations = append(result.Evaluations, evaluation)
		if !evaluation.Eligible {
			continue
		}
		if result.NodeID == "" {
			result.NodeID = node.ID
			continue
		}
		best := result.Evaluations[0]
		for _, candidate := range result.Evaluations {
			if candidate.NodeID == result.NodeID {
				best = candidate
				break
			}
		}
		if evaluation.RemainingRAMAfterAllocationBytes > best.RemainingRAMAfterAllocationBytes ||
			(evaluation.RemainingRAMAfterAllocationBytes == best.RemainingRAMAfterAllocationBytes && evaluation.RemainingDiskAfterAllocationBytes > best.RemainingDiskAfterAllocationBytes) ||
			(evaluation.RemainingRAMAfterAllocationBytes == best.RemainingRAMAfterAllocationBytes && evaluation.RemainingDiskAfterAllocationBytes == best.RemainingDiskAfterAllocationBytes && node.ID < result.NodeID) {
			result.NodeID = node.ID
		}
	}
	return result, nil
}

func policyRejectedAction(action admiral.TaskAction) admiral.TaskAction {
	switch action {
	case admiral.ActionResizeApp:
		return admiral.ActionResizePolicyRejected
	default:
		return admiral.ActionProvisionPolicyRejected
	}
}

func (h *APIHandlers) refreshNodeEvaluationsForTier(tier database.AppTier, requestedNodeID string) []admiral.NodeProvisioningEvaluation {
	selection, err := h.selectNodeForTier(tier, requestedNodeID)
	if err != nil {
		h.log.Error("Refresh node evaluations failed", err, map[string]interface{}{"requested_node_id": requestedNodeID, "tier": tier.Name})
		return nil
	}
	return selection.Evaluations
}

func (h *APIHandlers) persistRejectedTask(operationID, instanceID, nodeID string, taskAction admiral.TaskAction, tier database.AppTier, detail blockedProvisioningAuditDetail) (string, error) {
	if h.publisher == nil {
		return "", nil
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		return "", fmt.Errorf("marshal rejected task payload: %w", err)
	}
	task := &admiral.FleetTask{
		TaskID:      generateID("task"),
		OperationID: operationID,
		NodeID:      nodeID,
		Action:      taskAction,
		InstanceID:  instanceID,
		Tier: admiral.TierInfo{
			Name:        tier.Name,
			CPU:         tier.CPU,
			Memory:      tier.Memory,
			Storage:     tier.Storage,
			Environment: tier.Environment,
		},
		App: admiral.AppInfo{Name: detail.RequestedAppDefinition, Version: "policy-rejected"},
	}
	if err := h.db.UpdateOperationTaskID(operationID, task.TaskID); err != nil {
		return "", fmt.Errorf("persist rejected task id on operation: %w", err)
	}
	if err := h.publisher.PublishRejectedTask(task, detail.Detail, string(payload)); err != nil {
		return "", fmt.Errorf("persist rejected queue task: %w", err)
	}
	return task.TaskID, nil
}

func (h *APIHandlers) auditCapacityEvent(eventType, nodeID, instanceID, operationID string, action admiral.TaskAction, ramBytes, diskBytes int64) {
	h.auditEvent(eventType, map[string]interface{}{
		"node_id":        nodeID,
		"related_app_id": instanceID,
		"operation_id":   operationID,
		"action":         string(action),
		"ram_bytes":      ramBytes,
		"disk_bytes":     diskBytes,
		"actor_type":     "system",
		"actor_id":       "admirald",
	})
}

func (h *APIHandlers) recordBlockedWorkloadAttempt(w http.ResponseWriter, r *http.Request, action admiral.TaskAction, instanceID, appDefinitionName, customerID, requestedNodeID string, tier database.AppTier, evaluations []admiral.NodeProvisioningEvaluation) error {
	operationID := generateID("op")
	operator := operatorFromRequest(r)
	if err := h.db.CreateOperation(operationID, instanceID, requestedNodeID, string(action), "failed", operator); err != nil {
		return fmt.Errorf("create blocked workload operation: %w", err)
	}

	detail := blockedProvisioningAuditDetail{
		Code:                   provisioningBlockedCode,
		Message:                provisioningBlockedMessage,
		Detail:                 provisioningBlockedMessage + " La politica de capacidad impide asignar mas workloads al nodo evaluado.",
		Action:                 string(action),
		RequestedAppDefinition: appDefinitionName,
		RequestedTier:          tier.Name,
		RequestedNodeID:        requestedNodeID,
		CustomerID:             customerID,
		Operator:               operator,
		NodeEvaluations:        evaluations,
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("marshal blocked workload detail: %w", err)
	}
	if err := h.db.UpdateOperation(operationID, "failed", string(payload)); err != nil {
		return fmt.Errorf("update blocked workload operation: %w", err)
	}
	taskID, err := h.persistRejectedTask(operationID, instanceID, requestedNodeID, policyRejectedAction(action), tier, detail)
	if err != nil {
		return err
	}
	h.auditEvent("node_provisioning_rejected_no_capacity", map[string]interface{}{
		"node_id":          requestedNodeID,
		"operation_id":     operationID,
		"task_id":          taskID,
		"related_app_id":   instanceID,
		"related_tier_id":  tier.Name,
		"app_definition":   appDefinitionName,
		"customer_id":      customerID,
		"reason_codes":     provisioningBlockedCode,
		"node_evaluations": evaluations,
		"actor_type":       "operator",
		"actor_id":         operator,
	})

	writeJSON(w, http.StatusServiceUnavailable, admiral.ProvisioningRejectedResponse{
		Code:            provisioningBlockedCode,
		Message:         provisioningBlockedMessage,
		Error:           provisioningBlockedMessage,
		Detail:          detail.Detail,
		OperationID:     operationID,
		TaskID:          taskID,
		RequestedNodeID: requestedNodeID,
		NodeEvaluations: evaluations,
	})
	return nil
}

func (h *APIHandlers) createInstanceSecrets(instanceID string, payload admiral.AppDefinitionPayload) ([]admiral.Credential, error) {
	// Load any existing secrets so persistent ones are reused.
	existingPlain := h.loadExistingPlainSecrets(instanceID)

	// First pass: generate all secrets for all services
	allPlain := make(map[string]map[string]string) // serviceName -> envName -> plaintext
	for serviceName, svc := range payload.Services {
		allPlain[serviceName] = make(map[string]string)
		for envName, secretDef := range svc.Secrets {
			var plain string
			switch {
			case secretDef.Persist:
				if existing, ok := existingPlain[serviceName][envName]; ok {
					plain = existing
				} else {
					plain = generateSecretKey()
				}
			case secretDef.Value != "":
				plain = secretDef.Value
			default:
				plain = generateSecretValue(secretDef.Generate)
			}
			allPlain[serviceName][envName] = plain
		}
	}

	// Generate top-level secrets (shared across services)
	allPlain["__global__"] = make(map[string]string)
	for envName, secretDef := range payload.Secrets {
		var plain string
		switch {
		case secretDef.Persist:
			if existing, ok := existingPlain["__global__"][envName]; ok {
				plain = existing
			} else {
				plain = generateSecretKey()
			}
		case secretDef.Value != "":
			plain = secretDef.Value
		default:
			plain = generateSecretValue(secretDef.Generate)
		}
		allPlain["__global__"][envName] = plain
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
				credentials = append(credentials, admiral.Credential{Service: serviceName, Name: envName, Value: plain, Generate: secretDef.Generate})
			}
		}
	}
	// Save top-level secrets
	for envName, secretDef := range payload.Secrets {
		plain := allPlain["__global__"][envName]
		encrypted, err := h.secrets.Encrypt(plain)
		if err != nil {
			return nil, err
		}
		if err := h.db.SaveInstanceSecret(instanceID, "__global__", envName, encrypted, secretDef.Expose); err != nil {
			return nil, err
		}
		if secretDef.Expose {
			credentials = append(credentials, admiral.Credential{Service: "__global__", Name: envName, Value: plain, Generate: secretDef.Generate})
		}
	}
	return credentials, nil
}

func (h *APIHandlers) loadExistingPlainSecrets(instanceID string) map[string]map[string]string {
	rows, err := h.db.GetInstanceSecrets(instanceID)
	if err != nil || len(rows) == 0 {
		return nil
	}
	result := make(map[string]map[string]string)
	for _, row := range rows {
		plain, err := h.secrets.Decrypt(row.EncryptedValue)
		if err != nil {
			continue
		}
		if result[row.ServiceName] == nil {
			result[row.ServiceName] = make(map[string]string)
		}
		result[row.ServiceName][row.EnvName] = plain
	}
	return result
}

// normalizeInstanceSecrets propagates database credentials from the database
// service to any client service (e.g., WORDPRESS_DB_USER gets MARIADB_USER's value).
func normalizeInstanceSecrets(all map[string]map[string]string, payload admiral.AppDefinitionPayload) {
	// Identify the database service — check for a DB image first, then fall back to volume.
	dbService := ""
	for name, svc := range payload.Services {
		img := strings.ToLower(svc.Image)
		if strings.Contains(img, "postgres") || strings.Contains(img, "mysql") || strings.Contains(img, "mariadb") {
			dbService = name
			break
		}
	}
	if dbService == "" {
		for name, svc := range payload.Services {
			if svc.Volume != "" {
				dbService = name
				break
			}
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
		for envName := range secrets {
			upper := strings.ToUpper(envName)
			if dbUser != "" && isDBUserEnv(upper) {
				all[svcName][envName] = dbSecrets[dbUser]
			}
			if dbPass != "" && isDBPasswordEnv(upper) {
				all[svcName][envName] = dbSecrets[dbPass]
			}
			if dbName != "" && isDBNameEnv(upper) {
				all[svcName][envName] = dbSecrets[dbName]
			}
		}
	}
}

// isDBUserEnv returns true if env name looks like it expects a database username.
func isDBUserEnv(upper string) bool {
	if strings.HasSuffix(upper, "_DB_USER") {
		return true
	}
	// Gitea-style: GITEA__DATABASE__USER
	return strings.Contains(upper, "__DATABASE__") && strings.HasSuffix(upper, "_USER")
}

// isDBPasswordEnv returns true if env name looks like it expects a database password.
func isDBPasswordEnv(upper string) bool {
	if strings.HasSuffix(upper, "_DB_PASSWORD") {
		return true
	}
	// Gitea-style: GITEA__DATABASE__PASSWD
	return strings.Contains(upper, "__DATABASE__") && (strings.HasSuffix(upper, "_PASSWORD") || strings.HasSuffix(upper, "_PASSWD"))
}

// isDBNameEnv returns true if env name looks like it expects a database name.
func isDBNameEnv(upper string) bool {
	if strings.HasSuffix(upper, "_DB_NAME") {
		return true
	}
	return strings.Contains(upper, "__DATABASE__") && strings.HasSuffix(upper, "_NAME")
}

func (h *APIHandlers) HandleCustomerAppAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req admiral.InstanceActionRequest
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
	if req.NodeID != "" && req.NodeID != *inst.NodeID {
		writeError(w, http.StatusConflict, fmt.Sprintf("Instance is assigned to node %q and cannot execute this action on node %q", *inst.NodeID, req.NodeID))
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
	var currentTier database.AppTier
	var resizeReservedRAM int64
	var resizeReservedDisk int64

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
		nextTechStatus = "backup_running"
		payload := parseAppPayload(appDef.RawYAML)
		if payload == nil {
			writeError(w, http.StatusInternalServerError, "Stored application definition is invalid")
			return
		}
		target, err := resolveBackupTarget(*payload, req.Service)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if target.Backup.Type == "volume" {
			action = admiral.ActionBackupVolumes
		} else {
			action = admiral.ActionBackupDatabase
		}
	case "deprovision":
		action = admiral.ActionDeprovisionApp
		nextTechStatus = "deprovisioning"
	case "reactivate":
		action = admiral.ActionReactivateApp
		nextTechStatus = "running"
	case "resize":
		tierName := req.Tier
		if tierName == "" {
			writeError(w, http.StatusBadRequest, "tier is required for resize")
			return
		}
		currentTier = matchedTier
		if currentTier.Name == "" && strings.TrimSpace(inst.TierSnapshotJSON) != "" {
			_ = json.Unmarshal([]byte(inst.TierSnapshotJSON), &currentTier)
		}
		matchedTier = database.AppTier{}
		for _, t := range tiers {
			if t.Name == tierName {
				matchedTier = t
				break
			}
		}
		if matchedTier.Name == "" {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("tier %q not found", tierName))
			return
		}
		currentRAM := database.ParseSizeBytes(currentTier.Memory)
		currentDisk := database.ParseSizeBytes(currentTier.Storage)
		targetRAM := database.ParseSizeBytes(matchedTier.Memory)
		targetDisk := database.ParseSizeBytes(matchedTier.Storage)
		if targetRAM <= 0 || targetDisk <= 0 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("tier %q has invalid resource definition", tierName))
			return
		}
		if targetRAM > currentRAM {
			resizeReservedRAM = targetRAM - currentRAM
		}
		if targetDisk > currentDisk {
			resizeReservedDisk = targetDisk - currentDisk
		}
		if resizeReservedRAM > 0 || resizeReservedDisk > 0 {
			node, nerr := h.db.GetNode(*inst.NodeID)
			if nerr != nil {
				writeError(w, http.StatusInternalServerError, "Database error validating node capacity")
				return
			}
			if node == nil {
				writeError(w, http.StatusNotFound, "Assigned node not found")
				return
			}
			evaluation := h.evaluateNodeForTier(*node, resizeReservedRAM, resizeReservedDisk)
			if !evaluation.Eligible {
				if err := h.recordBlockedWorkloadAttempt(w, r, admiral.ActionResizeApp, req.InstanceID, inst.AppDefinitionName, inst.CustomerID, *inst.NodeID, matchedTier, []admiral.NodeProvisioningEvaluation{evaluation}); err != nil {
					h.log.Error("Record blocked resize attempt failed", err, map[string]interface{}{"instance_id": req.InstanceID, "requested_node_id": *inst.NodeID, "tier_name": tierName})
					writeError(w, http.StatusInternalServerError, "Failed recording blocked resize attempt")
				}
				return
			}
		}
		action = admiral.ActionResizeApp
		nextTechStatus = "running"
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Unsupported action %q", req.Action))
		return
	}

	operationID := generateID("op")

	// Create a backup_record before dispatching so HandleFleetCallback can find it.
	var backupID string
	if action == admiral.ActionBackupDatabase || action == admiral.ActionBackupVolumes {
		backupID = generateID("bk")
		backupType := "database"
		backupPrefix := "database"
		if action == admiral.ActionBackupVolumes {
			backupType = "volume"
			backupPrefix = "volumes"
		}
		storageCfg, _ := h.db.GetActiveBackupStorageConfig()
		var backend, key string
		if storageCfg != nil {
			backend = storageCfg.Backend
			key = fmt.Sprintf("%s/%s/%s/%s-%s-%s", storageCfg.Prefix, *inst.NodeID, req.InstanceID, req.Service, backupPrefix, operationID)
		} else {
			backend = "local"
			key = fmt.Sprintf("/var/lib/admiral/backups/%s/%s-%s", req.InstanceID, req.Service, operationID)
		}
		bkRec := &admiral.BackupRecord{
			ID:                          backupID,
			InstanceID:                  req.InstanceID,
			AppID:                       inst.AppDefinitionName,
			TierID:                      inst.TierName,
			NodeID:                      *inst.NodeID,
			BackupType:                  backupType,
			Status:                      "pending",
			StorageBackend:              backend,
			StorageKey:                  key,
			TriggeredBy:                 "manual",
			TierSnapshotJSON:            inst.TierSnapshotJSON,
			RetentionPolicySnapshotJSON: `{"count":7,"days":30}`,
		}
		if action == admiral.ActionBackupDatabase {
			payload := parseAppPayload(appDef.RawYAML)
			if payload == nil {
				writeError(w, http.StatusInternalServerError, "Stored application definition is invalid")
				return
			}
			target, err := resolveBackupTarget(*payload, req.Service)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			bkRec.DatabaseType = target.Backup.Engine
		} else {
			bkRec.DatabaseType = "none"
		}
		_ = h.db.CreateBackupRecord(bkRec)
	}

	if uerr := h.db.UpdateCustomerAppStatus(req.InstanceID, "", nextTechStatus); uerr != nil {
		h.log.Error("Failed to update instance status before action", uerr, map[string]interface{}{"instance_id": req.InstanceID})
	}

	nodeID := ""
	if inst.NodeID != nil {
		nodeID = *inst.NodeID
	}
	if action == admiral.ActionResizeApp && (resizeReservedRAM > 0 || resizeReservedDisk > 0) {
		if err := h.db.ReserveNodeCapacity(nodeID, resizeReservedRAM, resizeReservedDisk); err != nil {
			if err == database.ErrNodeCapacityPolicyBlocked {
				evaluations := h.refreshNodeEvaluationsForTier(matchedTier, nodeID)
				if recErr := h.recordBlockedWorkloadAttempt(w, r, admiral.ActionResizeApp, req.InstanceID, inst.AppDefinitionName, inst.CustomerID, nodeID, matchedTier, evaluations); recErr != nil {
					h.log.Error("Record blocked resize attempt after reserve race failed", recErr, map[string]interface{}{"instance_id": req.InstanceID, "requested_node_id": nodeID, "tier_name": matchedTier.Name})
					writeError(w, http.StatusInternalServerError, "Failed recording blocked resize attempt")
				}
				return
			}
			h.log.Error("Reserve node capacity for resize failed", err, map[string]interface{}{"instance_id": req.InstanceID, "node_id": nodeID, "tier_name": matchedTier.Name})
			writeError(w, http.StatusInternalServerError, "Failed reserving node capacity for resize")
			return
		}
		h.auditCapacityEvent("node_capacity_reserved", nodeID, req.InstanceID, operationID, admiral.ActionResizeApp, resizeReservedRAM, resizeReservedDisk)
		if err := h.recomputeNodePolicy(nodeID); err != nil {
			h.log.Error("Failed to recompute node policy after resize reservation", err, map[string]interface{}{"instance_id": req.InstanceID, "node_id": nodeID})
		}
	}
	if err := h.db.CreateOperation(operationID, req.InstanceID, nodeID, string(action), "pending_dispatch", operatorFromRequest(r)); err != nil {
		h.log.Error("Create action operation failed", err, nil)
		if action == admiral.ActionResizeApp && (resizeReservedRAM > 0 || resizeReservedDisk > 0) {
			if uerr := h.db.ReleaseNodeCommitment(nodeID, resizeReservedRAM, resizeReservedDisk); uerr != nil {
				h.log.Error("Failed to release reserved resize capacity after operation create error", uerr, map[string]interface{}{"instance_id": req.InstanceID, "node_id": nodeID})
			} else if uerr := h.recomputeNodePolicy(nodeID); uerr != nil {
				h.log.Error("Failed to recompute node policy after resize rollback", uerr, map[string]interface{}{"instance_id": req.InstanceID, "node_id": nodeID})
			} else {
				h.auditCapacityEvent("node_capacity_released", nodeID, req.InstanceID, operationID, admiral.ActionResizeApp, resizeReservedRAM, resizeReservedDisk)
			}
		}
		writeError(w, http.StatusInternalServerError, "Failed recording operation")
		return
	}

	h.enqueueTask(operationID, req.InstanceID, *inst.NodeID, inst.CustomerID, appDef.RawYAML, matchedTier, action, backupID, req.Service)

	// Clear grace period on reactivate
	if req.Action == "reactivate" {
		if err := h.db.ClearGracePeriod(req.InstanceID); err != nil {
			h.log.Error("Failed to clear grace period on reactivate", err, map[string]interface{}{"instance_id": req.InstanceID})
		} else {
			h.log.Info("Grace period cleared on reactivate", map[string]interface{}{"instance_id": req.InstanceID})
		}
	}

	writeJSON(w, http.StatusAccepted, admiral.OperationResponse{
		OperationID: operationID,
		Status:      "queued",
	})
}

func (h *APIHandlers) enqueueTask(opID, instID, nodeID, tenantID, rawYAML string, tier database.AppTier, action admiral.TaskAction, backupID, backupService string) {
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &payload); err != nil { //nolint:gosec // rawYAML from stored appDef.RawYAML (trusted DB data)
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
		secretValues = scopeTaskSecrets(action, payload, allSecretValues, backupService)
	}

	services := buildServiceInfos(payload, tier, instID, tenantID, secretValues)

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
			Name:        tier.Name,
			CPU:         tier.CPU,
			Memory:      tier.Memory,
			Storage:     tier.Storage,
			Environment: tier.Environment,
		},
		Services: services,
	}

	if action == admiral.ActionBackupDatabase || action == admiral.ActionBackupVolumes {
		target, err := resolveBackupTarget(payload, backupService)
		if err != nil {
			h.log.Error("Failed to resolve backup target", err, map[string]interface{}{"operation_id": opID, "service": backupService})
			if uerr := h.db.UpdateOperation(opID, "failed", err.Error()); uerr != nil {
				h.log.Error("Failed to update operation as failed", uerr, map[string]interface{}{"operation_id": opID})
			}
			if uerr := h.db.UpdateCustomerAppStatus(instID, "", "failed"); uerr != nil {
				h.log.Error("Failed to update instance status as failed", uerr, map[string]interface{}{"instance_id": instID})
			}
			return
		}
		task.Backup = buildTaskBackupInfo(target)
	}

	if backupID != "" {
		storageCfg, _ := h.db.GetActiveBackupStorageConfig()
		backend := "local"
		key := fmt.Sprintf("/var/lib/admiral/backups/%s/%s", instID, opID)
		if storageCfg != nil {
			backend = storageCfg.Backend
			backupPrefix := "database"
			if action == admiral.ActionBackupVolumes {
				backupPrefix = "volumes"
			}
			key = fmt.Sprintf("%s/%s/%s/%s-%s-%s", storageCfg.Prefix, nodeID, instID, backupService, backupPrefix, opID)
		}
		task.Storage = &admiral.StorageConfig{
			Backend:  backend,
			Key:      key,
			BackupID: backupID,
		}
		if storageCfg != nil {
			task.Storage.Endpoint = storageCfg.Endpoint
			task.Storage.Region = storageCfg.Region
			task.Storage.Bucket = storageCfg.Bucket
			task.Storage.Prefix = storageCfg.Prefix
			task.Storage.ForcePathStyle = storageCfg.ForcePathStyle
			task.Storage.AccessKeyEnv = storageCfg.AccessKeyEnv
			task.Storage.SecretKeyEnv = storageCfg.SecretKeyEnv
			task.Storage.SessionTokenEnv = storageCfg.SessionTokenEnv
		}
	}

	h.log.Info("Persisting fleet task to queue", map[string]interface{}{
		"task_id":      task.TaskID,
		"operation_id": opID,
		"node_id":      nodeID,
		"action":       action,
	})

	if uerr := h.db.UpdateOperationTaskID(opID, task.TaskID); uerr != nil {
		h.log.Error("Failed to persist task_id on operation", uerr, map[string]interface{}{"task_id": task.TaskID, "operation_id": opID})
	}
	if err := h.publisher.PublishTask(task); err != nil {
		h.log.Error("Failed to persist task to queue database", err, map[string]interface{}{"task_id": task.TaskID, "operation_id": opID})
		if uerr := h.db.UpdateOperation(opID, "failed", err.Error()); uerr != nil {
			h.log.Error("Failed to update operation as failed", uerr, map[string]interface{}{"operation_id": opID})
		}
		if uerr := h.db.UpdateCustomerAppStatus(instID, "", "failed"); uerr != nil {
			h.log.Error("Failed to update instance status as failed", uerr, map[string]interface{}{"instance_id": instID})
		}
		return
	}
	if uerr := h.db.UpdateOperation(opID, "queued", ""); uerr != nil {
		h.log.Error("Failed to update operation as queued", uerr, map[string]interface{}{"operation_id": opID})
	}
}

func (h *APIHandlers) dispatchTask(opID, instID, nodeID, tenantID, rawYAML string, tier database.AppTier, action admiral.TaskAction) {
	h.enqueueTask(opID, instID, nodeID, tenantID, rawYAML, tier, action, "", "")
}

func (h *APIHandlers) enqueueRawTask(task *admiral.FleetTask) {
	_ = h.enqueueRawTaskWithErr(task)
}

func (h *APIHandlers) enqueueRestoreTask(opID, instID, nodeID, rawYAML string, tier database.AppTier, bk *admiral.BackupRecord) {
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &payload); err != nil { //nolint:gosec // rawYAML from stored appDef.RawYAML (trusted DB data)
		h.log.Error("Failed to parse app definition for restore", err, map[string]interface{}{"operation_id": opID})
		_ = h.db.UpdateOperation(opID, "failed", "invalid stored app definition")
		return
	}

	allSecretValues, err := h.decryptedSecretMap(instID)
	if err != nil {
		h.log.Error("Failed to decrypt secrets for restore", err, map[string]interface{}{"operation_id": opID})
		_ = h.db.UpdateOperation(opID, "failed", "failed to prepare restore secrets")
		return
	}

	services := buildServiceInfos(payload, tier, instID, "", allSecretValues)

	srcType := strings.ToLower(strings.TrimSpace(bk.StorageBackend))
	srcURI := bk.StorageKey
	if srcType == "" || srcType == "local" {
		srcType = "local_path"
	}

	target, err := resolveRestoreTarget(payload, bk.BackupType, "")
	if err != nil {
		h.log.Error("Failed to resolve restore target", err, map[string]interface{}{"operation_id": opID})
		_ = h.db.UpdateOperation(opID, "failed", err.Error())
		return
	}

	task := &admiral.FleetTask{
		TaskID:      generateID("task"),
		OperationID: opID,
		NodeID:      nodeID,
		Action:      admiral.ActionRestoreBackup,
		InstanceID:  instID,
		App:         admiral.AppInfo{Name: payload.Name, Version: "latest"},
		Tier:        admiral.TierInfo{Name: tier.Name, CPU: tier.CPU, Memory: tier.Memory, Storage: tier.Storage, Environment: tier.Environment},
		Services:    services,
		Backup:      buildTaskBackupInfo(target),
		Restore: &admiral.RestoreInfo{
			BackupID:       bk.ID,
			StorageBackend: srcType,
			StorageKey:     srcURI,
			BackupType:     bk.BackupType,
			DatabaseType:   bk.DatabaseType,
			Service:        target.ServiceName,
			ChecksumSHA256: bk.ChecksumSHA256,
		},
	}

	if srcType == "s3" {
		storageCfg, _ := h.db.GetActiveBackupStorageConfig()
		if storageCfg != nil && storageCfg.Backend == "s3" {
			task.Storage = &admiral.StorageConfig{
				Backend:        storageCfg.Backend,
				Endpoint:       storageCfg.Endpoint,
				Region:         storageCfg.Region,
				Bucket:         storageCfg.Bucket,
				Prefix:         storageCfg.Prefix,
				ForcePathStyle: storageCfg.ForcePathStyle,
				AccessKeyEnv:   storageCfg.AccessKeyEnv,
				SecretKeyEnv:   storageCfg.SecretKeyEnv,
			}
		}
	}

	h.enqueueRawTask(task)
	_ = h.db.UpdateOperationTaskID(opID, task.TaskID)
	_ = h.db.UpdateOperation(opID, "queued", "")
}

func (h *APIHandlers) enqueueRawTaskWithErr(task *admiral.FleetTask) error {
	if uerr := h.db.UpdateOperationTaskID(task.OperationID, task.TaskID); uerr != nil {
		h.log.Error("Failed to persist task_id on operation from raw task", uerr, map[string]interface{}{"task_id": task.TaskID, "operation_id": task.OperationID})
		return fmt.Errorf("persist task id for operation %q: %w", task.OperationID, uerr)
	}
	if err := h.publisher.PublishTask(task); err != nil {
		h.log.Error("Failed to persist raw task to queue database", err, map[string]interface{}{"task_id": task.TaskID, "operation_id": task.OperationID})
		if uerr := h.db.UpdateOperation(task.OperationID, "failed", err.Error()); uerr != nil {
			h.log.Error("Failed to update operation as failed", uerr, map[string]interface{}{"operation_id": task.OperationID})
		}
		return fmt.Errorf("publish raw task %q: %w", task.TaskID, err)
	}
	if uerr := h.db.UpdateOperation(task.OperationID, "queued", ""); uerr != nil {
		h.log.Error("Failed to update operation as queued", uerr, map[string]interface{}{"operation_id": task.OperationID})
		return fmt.Errorf("mark operation %q queued: %w", task.OperationID, uerr)
	}
	return nil
}

func parseAppPayload(rawYAML string) *admiral.AppDefinitionPayload {
	var p admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &p); err != nil {
		return nil
	}
	return &p
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
	case admiral.ActionProvisionApp, admiral.ActionRestoreBackup,
		admiral.ActionStartApp, admiral.ActionResumeApp,
		admiral.ActionBackupDatabase:
		return true
	default:
		return false
	}
}

func retryableAction(action admiral.TaskAction) (admiral.TaskAction, string, bool) {
	switch action {
	case admiral.ActionProvisionApp:
		return admiral.ActionProvisionApp, "provisioning", true
	case admiral.ActionStartApp, admiral.ActionResumeApp, admiral.ActionReactivateApp:
		return action, "running", true
	case admiral.ActionStopApp, admiral.ActionPauseApp:
		return action, "stopped", true
	case admiral.ActionResizeApp:
		return admiral.ActionResizeApp, "running", true
	case admiral.ActionDeprovisionApp:
		return admiral.ActionDeprovisionApp, "deprovisioning", true
	default:
		return "", "", false
	}
}

func scopeTaskSecrets(action admiral.TaskAction, payload admiral.AppDefinitionPayload, all map[string]map[string]string, serviceName string) map[string]map[string]string {
	switch action {
	case admiral.ActionProvisionApp, admiral.ActionRestoreBackup,
		admiral.ActionStartApp, admiral.ActionResumeApp:
		return cloneSecretMap(all)
	case admiral.ActionBackupDatabase:
		return scopeBackupSecrets(payload, all, serviceName)
	default:
		return map[string]map[string]string{}
	}
}

func scopeBackupSecrets(payload admiral.AppDefinitionPayload, all map[string]map[string]string, serviceName string) map[string]map[string]string {
	target, err := resolveBackupTarget(payload, serviceName)
	if err != nil || target.Backup.Type != "database" {
		return map[string]map[string]string{}
	}

	serviceSecrets := all[target.ServiceName]
	if len(serviceSecrets) == 0 {
		return map[string]map[string]string{}
	}

	required := map[string]struct{}{
		target.Backup.DatabaseEnv: {},
		target.Backup.UsernameEnv: {},
		target.Backup.PasswordEnv: {},
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
	return map[string]map[string]string{target.ServiceName: filtered}
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

// POST /api/v1/apps/{id}/validate-provisioning — verify app+tier before provisioning
