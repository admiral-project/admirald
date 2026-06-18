package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func healthToTechStatus(h admiral.HealthStatus) string {
	switch h {
	case admiral.HealthHealthy:
		return "running"
	case admiral.HealthStopped:
		return "stopped"
	case admiral.HealthUnhealthy:
		return "failed"
	default:
		return ""
	}
}

// HandleMigrateInstance starts an offline migration of an instance to a target node.

func (h *APIHandlers) HandleStorageReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var report admiral.StorageReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	if report.InstanceID == "" || report.NodeID == "" || report.StorageState == "" {
		writeError(w, http.StatusBadRequest, "instance_id, node_id, and storage_state are required")
		return
	}

	inst, err := h.db.GetCustomerApp(report.InstanceID)
	if err != nil {
		h.log.Error("Failed to fetch customer app for storage report check", err, map[string]interface{}{"instance_id": report.InstanceID})
		writeError(w, http.StatusInternalServerError, "Failed to verify instance node ownership")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	if inst.NodeID != nil && *inst.NodeID != "" && *inst.NodeID != report.NodeID {
		h.log.Error("Storage report instance node_id mismatch", nil, map[string]interface{}{
			"instance_id":   report.InstanceID,
			"expected_node": *inst.NodeID,
			"received_node": report.NodeID,
		})
		writeError(w, http.StatusForbidden, "Instance does not belong to the reporting node")
		return
	}

	prevState := inst.StorageState

	exceeded := string(report.StorageState) == string(admiral.StorageOverQuota)
	if err := h.db.UpdateInstanceStorage(
		report.InstanceID,
		string(report.StorageState),
		report.StorageMessage,
		report.StorageLimitBytes,
		report.StorageUsedBytes,
		report.StorageUsedPct,
		exceeded,
	); err != nil {
		h.log.Error("Failed to update instance storage", err, map[string]interface{}{"instance_id": report.InstanceID})
		writeError(w, http.StatusInternalServerError, "Failed to update storage")
		return
	}

	newState := string(report.StorageState)
	if prevState != newState {
		h.log.Info("Storage state changed", map[string]interface{}{
			"instance_id":  report.InstanceID,
			"node_id":      report.NodeID,
			"prev_state":   prevState,
			"new_state":    newState,
			"used_bytes":   report.StorageUsedBytes,
			"used_percent": report.StorageUsedPct,
			"limit_bytes":  report.StorageLimitBytes,
		})
	}

	// Manage grace period based on storage state
	if inst != nil {
		isOverQuota := string(report.StorageState) == string(admiral.StorageOverQuota)
		inGrace := inst.GracePeriodEndsAt != nil && inst.GracePeriodEndsAt.After(time.Now())

		if isOverQuota && !inGrace && inst.GracePeriodStartsAt == nil {
			endsAt := time.Now().Add(5 * 24 * time.Hour)
			if err := h.db.SetGracePeriod(report.InstanceID, endsAt); err != nil {
				h.log.Error("Failed to set grace period", err, map[string]interface{}{"instance_id": report.InstanceID})
			} else {
				h.log.Info("Storage grace period started", map[string]interface{}{
					"instance_id": report.InstanceID,
					"ends_at":     endsAt.Format(time.RFC3339),
				})
			}
		} else if !isOverQuota && inst.GracePeriodStartsAt != nil {
			if err := h.db.ClearGracePeriod(report.InstanceID); err != nil {
				h.log.Error("Failed to clear grace period", err, map[string]interface{}{"instance_id": report.InstanceID})
			} else {
				h.log.Info("Storage grace period cleared - usage below quota", map[string]interface{}{
					"instance_id": report.InstanceID,
				})
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// healthToTechStatus maps instance health status to technical status for
// automatic reconciliation after node recovery.
// POST /api/admin/instances/{id}/migrate

func (h *APIHandlers) HandleAdminHealthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var report admiral.HealthReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}
	if report.InstanceID == "" || report.NodeID == "" || report.HealthStatus == "" {
		writeError(w, http.StatusBadRequest, "instance_id, node_id, and health_status are required")
		return
	}

	inst, err := h.db.GetCustomerApp(report.InstanceID)
	if err != nil {
		h.log.Error("Failed to fetch customer app for health report check", err, map[string]interface{}{"instance_id": report.InstanceID})
		writeError(w, http.StatusInternalServerError, "Failed to verify instance node ownership")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	if inst.NodeID != nil && *inst.NodeID != "" && *inst.NodeID != report.NodeID {
		h.log.Error("Health report instance node_id mismatch", nil, map[string]interface{}{
			"instance_id":   report.InstanceID,
			"expected_node": *inst.NodeID,
			"received_node": report.NodeID,
		})
		writeError(w, http.StatusForbidden, "Instance does not belong to the reporting node")
		return
	}

	techStatus := healthToTechStatus(report.HealthStatus)
	if err := h.db.UpdateInstanceHealthAndTechStatus(report.InstanceID, string(report.HealthStatus), techStatus, report.Message); err != nil {
		h.log.Error("Failed to update instance health", err, map[string]interface{}{"instance_id": report.InstanceID})
		writeError(w, http.StatusInternalServerError, "Failed to update health")
		return
	}

	if len(report.HostPorts) > 0 && h.networking != nil {
		if err := h.networking.ActivateInstanceRoutes(r.Context(), report.InstanceID, report.HostPorts); err != nil {
			h.log.Warn("Route reconciliation from health check failed", map[string]interface{}{
				"instance_id": report.InstanceID,
				"error":       err.Error(),
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}
