// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/networking"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

type TaskPublisher interface {
	PublishTask(task *admiral.FleetTask) error
	PublishRejectedTask(task *admiral.FleetTask, reason, result string) error
	ClaimTask(nodeID string) (*admiral.FleetTask, string, int, int, error)
	MarkRunning(commandID string) error
	RenewLease(commandID string) error
	DiscardCommand(commandID, reason string) error
	CompleteTask(taskPublicID string, success bool, errorMsg string) error
}

type APIHandlers struct {
	db                *database.DB
	log               *logging.Logger
	publisher         TaskPublisher
	secrets           *secrets.Manager
	networking        *networking.Manager
	server            *Server
	hmacKey           string
	tokenPepper       string
	configTokenTTL    int
	loginLimiter      Limiter
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
		loginLimiter:      NewDBRateLimiter(db),
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

func generateID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%x", prefix, b)
}

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
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
