package api

import (
	"net/http"
	"strings"
)

// GET /api/admin/nodes & tasks
func (h *APIHandlers) HandleAdminNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var nodeID string
	if len(parts) >= 4 {
		nodeID = parts[3]
	}

	if nodeID != "" {
		if len(parts) >= 5 && parts[4] == "metrics" {
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
		node, _ := h.db.GetNode(nodeID)
		if node == nil {
			writeError(w, http.StatusNotFound, "Node not found")
			return
		}
		writeJSON(w, http.StatusOK, node)
		return
	}

	nodes, err := h.db.GetNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}
