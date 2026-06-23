package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

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

		if req.Backend == "s3" && !strings.HasPrefix(req.Endpoint, "https://") {
			if !strings.HasPrefix(req.Endpoint, "http://localhost") &&
				!strings.HasPrefix(req.Endpoint, "http://127.0.0.1") &&
				!strings.HasPrefix(req.Endpoint, "http://10.") {
				writeError(w, http.StatusBadRequest, "S3 endpoint must use HTTPS for non-localhost endpoints")
				return
			}
		}

		req.ID = "global"
		err := h.db.SaveBackupStorageConfig(&req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})

	case http.MethodPost:
		if isTest {
			// Trigger backup storage connectivity check
			cfg, _ := h.db.GetBackupStorageConfig("global")
			if cfg == nil || !cfg.Enabled {
				writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "Local storage always active"})
				return
			}
			// Dispatch test task
			nodes, _ := h.db.GetNodes()
			var activeNode string
			for _, n := range nodes {
				if n.Status == "active" {
					activeNode = n.ID
					break
				}
			}
			if activeNode == "" && len(nodes) > 0 {
				activeNode = nodes[0].ID
			}

			opID := generateID("op")
			if err := h.db.CreateOperation(opID, "", activeNode, "test_backup_storage", "pending_dispatch", operatorFromRequest(r)); err != nil {
				h.log.Error("Failed to create operation for storage test", err, nil)
				writeError(w, http.StatusInternalServerError, "Failed to create operation")
				return
			}

			if activeNode != "" {
				task := &admiral.FleetTask{
					TaskID:      generateID("task"),
					OperationID: opID,
					NodeID:      activeNode,
					Action:      admiral.TaskAction("test_backup_storage"),
					InstanceID:  "",
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
				h.enqueueRawTask(task)
			}

			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "operation_id": opID})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
