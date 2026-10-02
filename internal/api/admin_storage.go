package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"github.com/admiral-project/admiral/admirald/pkg/admiral/storage"
)

const storageTestHeartbeatTimeout = 2 * time.Minute

func isEligibleStorageTestNode(node database.Node, now time.Time) bool {
	if node.NodeRole != "worker" || node.Status != "active" || node.ManualDisabled {
		return false
	}
	if node.TokenType != "worker" || (node.TokenStatus != "active" && node.TokenStatus != "consumed") {
		return false
	}
	return node.LastHeartbeat != nil && now.Sub(*node.LastHeartbeat) <= storageTestHeartbeatTimeout
}

func (h *APIHandlers) HandleAdminSettingsStorage(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	isTest := len(parts) >= 5 && parts[4] == "test"

	switch r.Method {
	case http.MethodGet:
		cfg, _ := h.db.GetBackupStorageConfig("global")
		if cfg == nil {
			cfg = &admiral.BackupStorageConfig{
				ID:      "global",
				Backend: "local",
				Enabled: true,
			}
		}
		// Mask secrets
		cfg.AccessKeyEnv = ""
		cfg.SecretKeyEnv = ""
		writeJSON(w, http.StatusOK, cfg)

	case http.MethodPut:
		var req admiral.BackupStorageConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}

		if req.Backend != "local" && req.Backend != "s3" {
			writeError(w, http.StatusBadRequest, "Invalid backend, must be local or s3")
			return
		}

		if req.Backend == "s3" {
			if err := storage.ValidateEndpoint(req.Endpoint); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}

		req.ID = "global"
		if err := h.db.SaveBackupStorageConfig(&req); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	case http.MethodPost:
		if !isTest {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		cfg, err := h.db.GetBackupStorageConfig("global")
		if err != nil {
			h.log.Error("Failed to load backup storage config", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to load backup storage configuration")
			return
		}
		if cfg == nil || !cfg.Enabled {
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "Local storage always active"})
			return
		}

		// A storage check needs a live Fleet executor; portal and stale nodes
		// cannot claim Fleet tasks.
		nodes, err := h.db.GetNodes()
		if err != nil {
			h.log.Error("Failed to list nodes for storage test", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to find a worker for the backup storage test")
			return
		}
		var activeNode string
		for _, node := range nodes {
			if isEligibleStorageTestNode(node, time.Now()) {
				activeNode = node.ID
				break
			}
		}
		if activeNode == "" {
			writeError(w, http.StatusServiceUnavailable, "No active Fleet worker is available for the backup storage test; register and enable a worker with a recent heartbeat, then retry")
			return
		}

		opID := generateID("op")
		if err := h.db.CreateOperation(opID, "", activeNode, "test_backup_storage", "pending_dispatch", operatorFromRequest(r)); err != nil {
			h.log.Error("Failed to create operation for storage test", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to create operation")
			return
		}

		task := &admiral.FleetTask{
			TaskID:      generateID("task"),
			OperationID: opID,
			NodeID:      activeNode,
			Action:      admiral.TaskAction("test_backup_storage"),
			Storage: &admiral.StorageConfig{
				Backend:        cfg.Backend,
				Endpoint:       cfg.Endpoint,
				Region:         cfg.Region,
				Bucket:         cfg.Bucket,
				Prefix:         cfg.Prefix,
				ForcePathStyle: cfg.ForcePathStyle,
				AccessKeyEnv:   cfg.AccessKeyEnv,
				SecretKeyEnv:   cfg.SecretKeyEnv,
			},
		}
		if err := h.enqueueRawTaskWithErr(task); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to queue backup storage test")
			return
		}

		writeJSON(w, http.StatusAccepted, map[string]interface{}{"success": true, "operation_id": opID})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
