package api

import (
	"net/http"
	"strings"
)

func (h *APIHandlers) HandleAdminTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var taskID string
	if len(parts) >= 4 {
		taskID = parts[3]
	}

	if taskID != "" {
		// Mock task fetch since tasks are durably queued, we can return details from operations
		op, _ := h.db.GetOperation(taskID)
		if op == nil {
			writeError(w, http.StatusNotFound, "Task not found")
			return
		}
		writeJSON(w, http.StatusOK, op)
		return
	}

	page, pageSize := parsePagination(r)
	ops, total, err := h.db.GetOperationsPage(pageSize, (page-1)*pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pagedResponse{
		Items:    ops,
		Page:     page,
		PageSize: pageSize,
		Total:    total,
	})
}
