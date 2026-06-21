package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
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
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
)

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
	claimID = generateUUID()
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
				tokenType = req.NodeRole
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
				tokenType = req.NodeRole
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

	if len(parts) >= 5 && parts[4] == "ready" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.handleNodeReady(w, nodeID)
		return
	}

	if len(parts) == 4 {
		if r.Method == http.MethodDelete {
			force := r.URL.Query().Get("force") == "true"
			if err := h.db.RemoveNode(nodeID, force); err != nil {
				if strings.Contains(err.Error(), "has active instance") {
					writeError(w, http.StatusConflict, err.Error())
				} else if strings.Contains(err.Error(), "node not found") {
					writeError(w, http.StatusNotFound, "Node not found")
				} else {
					h.log.Error("Remove node failed", err, map[string]interface{}{"node_id": nodeID})
					writeError(w, http.StatusInternalServerError, "Failed to remove node")
				}
				return
			}
			if err := h.syncKnownHostInventory(); err != nil {
				h.log.Error("Sync know_host inventory failed after remove", err, map[string]interface{}{"node_id": nodeID})
			}
			h.auditEvent("node_removed", map[string]interface{}{
				"node_id":    nodeID,
				"force":      force,
				"actor_type": "operator",
				"actor_id":   operatorFromRequest(r),
			})
			writeJSON(w, http.StatusOK, map[string]bool{"success": true})
			return
		}
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

func (h *APIHandlers) handleNodeReady(w http.ResponseWriter, nodeID string) {
	node, err := h.db.GetNode(nodeID)
	if err != nil {
		h.log.Error("Get node failed for ready check", err, map[string]interface{}{"node_id": nodeID})
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if node == nil {
		writeError(w, http.StatusNotFound, "Node not found")
		return
	}

	addr := node.PublicIP
	if addr == "" {
		addr = node.IP
	}
	if addr == "" {
		addr = node.WireguardIP
	}
	if addr == "" {
		writeError(w, http.StatusBadRequest, "Node has no reachable address")
		return
	}

	var readyURL string
	client := &http.Client{Timeout: 10 * time.Second}

	switch node.NodeRole {
	case "worker":
		readyURL = fmt.Sprintf("http://%s:9099/ready", addr)
	case "portal":
		readyURL = fmt.Sprintf("https://%s:5001/ready", addr)
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Unsupported node role: %s", node.NodeRole))
		return
	}

	resp, err := client.Get(readyURL)
	if err != nil {
		h.log.Warn("Node ready check failed", map[string]interface{}{"node_id": nodeID, "url": readyURL, "error": err.Error()})
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"node_id": nodeID,
			"role":    node.NodeRole,
			"status":  "unreachable",
			"error":   err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	var result json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		writeJSON(w, resp.StatusCode, map[string]interface{}{
			"node_id": nodeID,
			"role":    node.NodeRole,
			"status":  "error",
			"error":   "invalid response from node",
		})
		return
	}

	writeJSON(w, resp.StatusCode, map[string]interface{}{
		"node_id": nodeID,
		"role":    node.NodeRole,
		"detail":  result,
	})
}

// POST /api/v1/apps/{id}/validate-provisioning — verify app+tier before provisioning
