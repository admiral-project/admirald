package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func (h *APIHandlers) HandleOperations(w http.ResponseWriter, r *http.Request) {
	opID := r.URL.Query().Get("id")
	if opID != "" {
		op, err := h.db.GetOperation(opID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Database error retrieving operation")
			return
		}
		if op == nil {
			writeError(w, http.StatusNotFound, "Operation not found")
			return
		}
		writeJSON(w, http.StatusOK, op)
		return
	}

	ops, err := h.db.GetOperations()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error retrieving operations list")
		return
	}
	writeJSON(w, http.StatusOK, ops)
}

func (h *APIHandlers) HandleOperationByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(strings.Trim(r.URL.Path, "/"), "api/v1/operations/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "retry" {
		writeError(w, http.StatusNotFound, "Operation route not found")
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	op, err := h.db.GetOperation(parts[0])
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error retrieving operation")
		return
	}
	if op == nil {
		writeError(w, http.StatusNotFound, "Operation not found")
		return
	}
	if op.Status != "failed" {
		writeError(w, http.StatusConflict, "Only failed operations can be retried")
		return
	}

	retryAction, nextTechStatus, ok := retryableAction(admiral.TaskAction(op.Action))
	if !ok {
		writeError(w, http.StatusConflict, fmt.Sprintf("Operation action %q cannot be retried automatically", op.Action))
		return
	}

	inst, err := h.db.GetCustomerApp(op.InstanceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error retrieving instance")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Instance not found for operation retry")
		return
	}
	if inst.NodeID == nil || *inst.NodeID == "" {
		writeError(w, http.StatusConflict, "Operation retry requires an assigned node")
		return
	}

	appDef, err := h.db.GetAppDefinition(inst.AppDefinitionName)
	if err != nil || appDef == nil {
		writeError(w, http.StatusInternalServerError, "Stored application definition is unavailable")
		return
	}

	tiers, err := h.db.GetAppTiers(inst.AppDefinitionName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error retrieving app tiers")
		return
	}
	matchedTier := database.AppTier{Name: inst.TierName}
	for _, tier := range tiers {
		if tier.Name == inst.TierName {
			matchedTier = tier
			break
		}
	}
	if matchedTier.Name == "" {
		writeError(w, http.StatusConflict, fmt.Sprintf("Tier %q not found for retry", inst.TierName))
		return
	}

	retryOperationID := generateID("op")
	if err := h.db.CreateOperation(retryOperationID, inst.ID, *inst.NodeID, string(retryAction), "pending_dispatch", operatorFromRequest(r)); err != nil {
		h.log.Error("Create retry operation failed", err, map[string]interface{}{"operation_id": op.ID, "retry_operation_id": retryOperationID})
		writeError(w, http.StatusInternalServerError, "Failed recording retry operation")
		return
	}
	if nextTechStatus != "" {
		if err := h.db.UpdateCustomerAppStatus(inst.ID, "", nextTechStatus); err != nil {
			h.log.Error("Failed to update instance status before retry", err, map[string]interface{}{"instance_id": inst.ID, "retry_operation_id": retryOperationID})
		}
	}

	h.enqueueTask(retryOperationID, inst.ID, *inst.NodeID, inst.CustomerID, appDef.RawYAML, matchedTier, retryAction, "", "")

	writeJSON(w, http.StatusOK, admiral.OperationResponse{
		OperationID: retryOperationID,
		Status:      "queued",
	})
}
