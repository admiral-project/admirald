// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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

// POST /api/v1/apps/{id}/validate-provisioning — verify app+tier before provisioning
