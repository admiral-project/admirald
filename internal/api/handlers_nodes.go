package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
	"gopkg.in/yaml.v2"
)

func nextKnownHostAssignment(nodes []database.Node, role, subnet, hubIP string) (knownHostBootstrapAssignment, error) {
	if strings.TrimSpace(subnet) == "" {
		subnet = "10.99.0.0/24"
	}
	if strings.TrimSpace(hubIP) == "" {
		hubIP = "10.99.0.1"
	}
	network, err := netip.ParsePrefix(strings.TrimSpace(subnet))
	if err != nil || !network.Addr().Is4() {
		return knownHostBootstrapAssignment{}, fmt.Errorf("invalid WireGuard IPv4 subnet %q", subnet)
	}
	network = network.Masked()
	hub, err := netip.ParseAddr(strings.TrimSpace(hubIP))
	if err != nil || !hub.Is4() || !network.Contains(hub) {
		return knownHostBootstrapAssignment{}, fmt.Errorf("invalid WireGuard hub address %q for subnet %q", hubIP, network)
	}

	maxSuffix := 0
	usedAddresses := map[uint32]bool{}
	rolePrefix := role + "-"
	for _, node := range nodes {
		if node.NodeRole == role && strings.HasPrefix(node.ID, rolePrefix) {
			if suffix, err := strconv.Atoi(strings.TrimPrefix(node.ID, rolePrefix)); err == nil && suffix > maxSuffix {
				maxSuffix = suffix
			}
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(node.WireguardIP))
		if err == nil && addr.Is4() && network.Contains(addr) {
			usedAddresses[ipv4Uint32(addr)] = true
		}
	}

	base := ipv4Uint32(network.Addr())
	hubValue := ipv4Uint32(hub)
	if network.Bits() == 32 {
		return knownHostBootstrapAssignment{}, fmt.Errorf("WireGuard subnet %q has no peer address", network)
	}
	hostCount := uint64(1) << uint(32-network.Bits())
	firstOffset := uint64(1)
	lastOffset := hostCount - 2
	if network.Bits() == 31 {
		firstOffset = 0
		lastOffset = 1
	}
	preferredOffset := uint64(2)
	if role == "portal" {
		preferredOffset = 100
	}
	if preferredOffset < firstOffset || preferredOffset > lastOffset {
		preferredOffset = firstOffset
	}
	addressValue, found := findAvailableWireguardAddress(base, firstOffset, lastOffset, preferredOffset, hubValue, usedAddresses)
	if !found {
		return knownHostBootstrapAssignment{}, fmt.Errorf("no WireGuard addresses remain in subnet %q", network)
	}
	return knownHostBootstrapAssignment{
		NodeID:      fmt.Sprintf("%s-%03d", role, maxSuffix+1),
		WireguardIP: ipv4FromUint32(addressValue).String(),
	}, nil
}

func nextKnownHostAssignments(nodes []database.Node, subnet, hubIP string) (knownHostBootstrapAssignment, knownHostBootstrapAssignment, error) {
	worker, err := nextKnownHostAssignment(nodes, "worker", subnet, hubIP)
	if err != nil {
		return knownHostBootstrapAssignment{}, knownHostBootstrapAssignment{}, fmt.Errorf("allocate next worker address: %w", err)
	}

	// Reserve the worker address while computing the portal assignment so a
	// small custom subnet cannot advertise the same address for both roles.
	nodesWithWorkerReservation := append(append([]database.Node(nil), nodes...), database.Node{
		WireguardIP: worker.WireguardIP,
	})
	portal, err := nextKnownHostAssignment(nodesWithWorkerReservation, "portal", subnet, hubIP)
	if err != nil {
		return knownHostBootstrapAssignment{}, knownHostBootstrapAssignment{}, fmt.Errorf("allocate next portal address: %w", err)
	}
	return worker, portal, nil
}

func ipv4Uint32(addr netip.Addr) uint32 {
	bytes := addr.As4()
	return binary.BigEndian.Uint32(bytes[:])
}

func ipv4FromUint32(value uint32) netip.Addr {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], value)
	return netip.AddrFrom4(bytes)
}

func findAvailableWireguardAddress(base uint32, first, last, preferred uint64, hub uint32, used map[uint32]bool) (uint32, bool) {
	for offset := preferred; offset <= last; offset++ {
		candidate := base + uint32(offset)
		if candidate != hub && !used[candidate] {
			return candidate, true
		}
	}
	for offset := first; offset < preferred; offset++ {
		candidate := base + uint32(offset)
		if candidate != hub && !used[candidate] {
			return candidate, true
		}
	}
	return 0, false
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
		Nodes:       map[string]knownHostNodeSpec{},
	}
	workerAssignment, portalAssignment, err := nextKnownHostAssignments(nodes, h.wireguardSubnet, h.wireguardHubIP)
	if err != nil {
		return err
	}
	inv.Next = knownHostNextAssignments{Worker: workerAssignment, Portal: portalAssignment}
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

// deriveEncryptionKey derives an AES-256-GCM key from pepper using HKDF with
// a distinct context label ("node-token-encryption-v1") so that the same
// pepper material is not shared between hashing (nodeTokenIdentifier) and
// encryption. This prevents one-use key exposure from compromising the other.
func deriveEncryptionKey(pepper string) ([]byte, error) {
	salt := []byte("admiral-node-tok-enc-v1")
	prk := hkdf.Extract(sha256.New, []byte(pepper), salt)
	r := hkdf.Expand(sha256.New, prk, []byte("node-token-encryption-key"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("derive node token encryption key: %w", err)
	}
	return key, nil
}

func encryptTokenValue(rawToken, pepper string) (string, error) {
	key, err := deriveEncryptionKey(pepper)
	if err != nil {
		return "", err
	}
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

func nodeRemovalErrorStatus(err error) int {
	switch {
	case errors.Is(err, database.ErrNodeHasActiveInstances):
		return http.StatusConflict
	case errors.Is(err, ErrWireGuardPeerRevocation):
		return http.StatusServiceUnavailable
	case strings.Contains(err.Error(), "node not found"):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
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
			// The generated token is returned once in this response. It is already
			// held by the enrolling operator/fleet, so it must be usable immediately.
			// "available" tokens are reserved for an unclaimed one-shot flow and
			// cannot authenticate through NodeAuthMiddleware.
			if err := h.db.UpsertNodeToken(req.NodeID, identifier, hash, tokenType, "active", encryptedValue, &expiresAt, claimID); err != nil {
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

	if req.NodeID == "" || strings.TrimSpace(req.BootID) == "" {
		writeError(w, http.StatusBadRequest, "node_id and boot_id are required")
		return
	}
	authenticatedNodeID, ok := NodeIDFromContext(r.Context())
	if !ok || authenticatedNodeID != req.NodeID {
		writeError(w, http.StatusForbidden, "node_id does not match authenticated node")
		return
	}

	node, err := h.db.GetNode(authenticatedNodeID)
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
			if !force {
				activeTasks, err := h.publisher.HasActiveTasksForNode(nodeID)
				if err != nil {
					h.log.Error("Check node tasks failed", err, map[string]interface{}{"node_id": nodeID})
					writeError(w, http.StatusInternalServerError, "Failed to check node tasks")
					return
				}
				if activeTasks {
					writeError(w, http.StatusConflict, "node has pending or running tasks; use force=true to override")
					return
				}
			}
			removalMarker := "node removal pending:" + generateUUID()
			coordinator, coordinated := h.publisher.(interface {
				CancelTasksForNode(string, string) error
				RestoreCancelledTasksForNode(string, string) error
				FinalizeCancelledTasksForNode(string, string) error
			})
			if coordinated {
				if err := coordinator.CancelTasksForNode(nodeID, removalMarker); err != nil {
					h.log.Error("Discard node tasks failed", err, map[string]interface{}{"node_id": nodeID})
					writeError(w, http.StatusInternalServerError, "Failed to discard node tasks")
					return
				}
			} else if reaper, ok := h.publisher.(interface{ DiscardTasksForNode(string) error }); ok {
				// Compatibility path for test and migration publishers that predate
				// the compensating coordinator.
				if err := reaper.DiscardTasksForNode(nodeID); err != nil {
					h.log.Error("Discard node tasks failed", err, map[string]interface{}{"node_id": nodeID})
					writeError(w, http.StatusInternalServerError, "Failed to discard node tasks")
					return
				}
			}
			if err := h.db.RemoveNodeWithHook(nodeID, force, func(node database.Node) (func(), error) {
				wireguardIP := strings.TrimSpace(node.WireguardIP)
				if wireguardIP == "" || wireguardIP == strings.TrimSpace(h.wireguardHubIP) {
					return nil, nil
				}
				if h.wireguardPeerRevoker == nil {
					return nil, fmt.Errorf("%w: local helper is unavailable", ErrWireGuardPeerRevocation)
				}
				release, err := h.wireguardPeerRevoker.RevokePeer(
					r.Context(), node.ID, node.NodeRole, wireguardIP,
				)
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrWireGuardPeerRevocation, err)
				}
				return release, nil
			}); err != nil {
				if coordinated {
					if restoreErr := coordinator.RestoreCancelledTasksForNode(nodeID, removalMarker); restoreErr != nil {
						h.log.Error("Restore node tasks after failed removal failed", restoreErr, map[string]interface{}{"node_id": nodeID})
					}
				}
				switch nodeRemovalErrorStatus(err) {
				case http.StatusConflict:
					writeError(w, http.StatusConflict, err.Error())
				case http.StatusNotFound:
					writeError(w, http.StatusNotFound, "Node not found")
				case http.StatusServiceUnavailable:
					writeError(w, http.StatusServiceUnavailable, "WireGuard peer revocation or spoke reconciliation failed; node and token were retained. Check the peer-revocation service and pinned spoke SSH access, then retry.")
				default:
					h.log.Error("Remove node failed", err, map[string]interface{}{"node_id": nodeID})
					writeError(w, http.StatusInternalServerError, "Failed to remove node")
				}
				return
			}
			if coordinated {
				if err := coordinator.FinalizeCancelledTasksForNode(nodeID, removalMarker); err != nil {
					h.log.Error("Finalize cancelled node tasks failed", err, map[string]interface{}{"node_id": nodeID})
				}
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

	addr := node.WireguardIP
	if h.server.singleNodeMode() {
		// Single-node and dev installs have no WireGuard interface; both
		// fleet and harbor bind to loopback, and nodes are registered with
		// a placeholder VPN address that must not be dialed.
		addr = "127.0.0.1"
	}
	if addr == "" {
		writeError(w, http.StatusBadRequest, "Node has no WireGuard address; refusing non-VPN readiness check")
		return
	}

	var readyURL string
	client := &http.Client{Timeout: 10 * time.Second}

	switch node.NodeRole {
	case "worker":
		readyURL = fmt.Sprintf("http://%s:9099/ready", addr)
	case "portal":
		scheme := "https"
		if h.server.devMode {
			scheme = "http"
		}
		readyURL = fmt.Sprintf("%s://%s:5001/ready", scheme, addr)
		if scheme == "https" {
			client, err = internalHTTPClient(10*time.Second, h.server.devMode)
			if err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("Configure internal TLS: %v", err))
				return
			}
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
