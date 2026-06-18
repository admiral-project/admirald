package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func (h *APIHandlers) HandleAppValidateProvisioning(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[4] != "validate-provisioning" {
		writeError(w, http.StatusBadRequest, "Missing app ID or sub-route")
		return
	}
	appID := parts[3]

	var req admiral.ValidateProvisioningRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	app, err := h.db.GetAppDefinition(appID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if app == nil {
		writeJSON(w, http.StatusOK, admiral.ValidateProvisioningResponse{
			Valid:  false,
			Reason: "app_not_found",
		})
		return
	}

	if app.Availability != "available" {
		writeJSON(w, http.StatusOK, admiral.ValidateProvisioningResponse{
			Valid:    false,
			AppID:    appID,
			Reason:   "app_not_available",
			Revision: app.Revision,
			Checksum: app.Checksum,
		})
		return
	}

	tiers, err := h.db.GetAppTiers(appID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error fetching tiers")
		return
	}

	tierFound := false
	for _, t := range tiers {
		if t.Name == req.TierID {
			tierFound = true
			break
		}
	}
	if !tierFound {
		writeJSON(w, http.StatusOK, admiral.ValidateProvisioningResponse{
			Valid:    false,
			AppID:    appID,
			Reason:   "tier_not_found",
			Revision: app.Revision,
			Checksum: app.Checksum,
		})
		return
	}

	if req.ExpectedRevision > 0 && app.Revision != req.ExpectedRevision {
		writeJSON(w, http.StatusOK, admiral.ValidateProvisioningResponse{
			Valid:    false,
			AppID:    appID,
			TierID:   req.TierID,
			Reason:   "revision_mismatch",
			Revision: app.Revision,
			Checksum: app.Checksum,
		})
		return
	}

	if req.ExpectedChecksum != "" && app.Checksum != req.ExpectedChecksum {
		writeJSON(w, http.StatusOK, admiral.ValidateProvisioningResponse{
			Valid:    false,
			AppID:    appID,
			TierID:   req.TierID,
			Reason:   "checksum_mismatch",
			Revision: app.Revision,
			Checksum: app.Checksum,
		})
		return
	}

	writeJSON(w, http.StatusOK, admiral.ValidateProvisioningResponse{
		Valid:    true,
		AppID:    appID,
		TierID:   req.TierID,
		Revision: app.Revision,
		Checksum: app.Checksum,
	})
}

func (h *APIHandlers) HandleAppAvailability(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[4] != "availability" {
		writeError(w, http.StatusBadRequest, "Missing app ID or sub-route")
		return
	}
	appID := parts[3]

	var req admiral.AvailabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	app, err := h.db.GetAppDefinition(appID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "App not found")
		return
	}
	prevAvailability := app.Availability

	if err := h.db.UpdateAppAvailability(appID, req.Availability, req.Reason); err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "App not found")
			return
		}
		h.log.Error("Update app availability failed", err, map[string]interface{}{"app_name": appID})
		writeError(w, http.StatusInternalServerError, "Failed to update availability")
		return
	}

	h.auditEvent("app_availability_changed", map[string]interface{}{
		"app_id":                appID,
		"previous_availability": prevAvailability,
		"new_availability":      req.Availability,
		"reason":                req.Reason,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"app_id":       appID,
		"availability": req.Availability,
	})
}
