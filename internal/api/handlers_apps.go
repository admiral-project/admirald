package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
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

func (h *APIHandlers) HandleApps(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var appID string
	if len(parts) >= 4 {
		appID = parts[3]
	}

	// Dispatch to sub-resource handlers
	if len(parts) >= 5 && appID != "" {
		switch parts[4] {
		case "availability":
			h.HandleAppAvailability(w, r)
			return
		case "validate-provisioning":
			h.HandleAppValidateProvisioning(w, r)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		if appID != "" {
			app, err := h.db.GetAppDefinition(appID)
			if err != nil {
				h.log.Error("Get app failed", err, map[string]interface{}{"app_name": appID})
				writeError(w, http.StatusInternalServerError, "Failed to fetch application")
				return
			}
			if app == nil {
				writeError(w, http.StatusNotFound, "App definition not found")
				return
			}
			writeJSON(w, http.StatusOK, app)
			return
		}

		apps, err := h.db.GetAppDefinitions()
		if err != nil {
			h.log.Error("Get apps failed", err, nil)
			writeError(w, http.StatusInternalServerError, "Failed to fetch applications")
			return
		}
		writeJSON(w, http.StatusOK, apps)

	case http.MethodPost:
		yamlContent, err := readAppDefinitionBody(w, r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		var payload admiral.AppDefinitionPayload
		if err := yaml.Unmarshal([]byte(yamlContent), &payload); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("YAML parsing failed: %v", err))
			return
		}

		if err := admiral.ValidateAppDefinition(payload); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("application definition validation failed: %v", err))
			return
		}

		var dbTiers []database.AppTier
		for name, t := range payload.Tiers {
			var backupPolicyJSON string
			if t.Backups != nil {
				bBytes, err := json.Marshal(t.Backups)
				if err != nil {
					h.log.Error("Failed to marshal backup policy", err, map[string]interface{}{"tier": name})
				}
				backupPolicyJSON = string(bBytes)
			}
			dbTiers = append(dbTiers, database.AppTier{
				AppName:          payload.Name,
				Name:             name,
				CPU:              t.CPU,
				Memory:           t.Memory,
				Storage:          t.Storage,
				PriceMonthly:     t.PriceMonthly,
				Free:             t.Free,
				Environment:      t.Environment,
				BackupPolicyJSON: backupPolicyJSON,
			})
		}

		if err := h.db.SaveAppDefinition(payload.Name, payload.DisplayName, payload.Description, yamlContent, dbTiers); err != nil {
			h.log.Error("Save app definition failed", err, map[string]interface{}{"app_name": payload.Name})
			writeError(w, http.StatusInternalServerError, "Failed to save application definition")
			return
		}

		h.log.Info("App definition applied successfully", map[string]interface{}{"app_name": payload.Name})
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "name": payload.Name})

	case http.MethodPatch, http.MethodPut:
		if appID == "" || len(parts) < 5 || parts[4] != "status" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}
		status := strings.ToLower(strings.TrimSpace(req.Status))
		if status != "active" && status != "inactive" {
			writeError(w, http.StatusBadRequest, "status must be active or inactive")
			return
		}
		if err := h.db.UpdateAppDefinitionStatus(appID, status); err != nil {
			if err == sql.ErrNoRows {
				writeError(w, http.StatusNotFound, "App definition not found")
				return
			}
			h.log.Error("Update app definition status failed", err, map[string]interface{}{"app_name": appID, "status": status})
			writeError(w, http.StatusInternalServerError, "Failed to update application status")
			return
		}
		h.log.Info("App definition status updated", map[string]interface{}{"app_name": appID, "status": status})
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "name": appID, "status": status})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func readAppDefinitionBody(w http.ResponseWriter, r *http.Request) (string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	if strings.Contains(r.Header.Get("Content-Type"), "yaml") || strings.Contains(r.Header.Get("Content-Type"), "text") {
		bodyBytes, err := io.ReadAll(r.Body)
		if cerr := r.Body.Close(); cerr != nil {
			return "", fmt.Errorf("failed to close request body")
		}
		if err != nil {
			return "", fmt.Errorf("failed to read body")
		}
		if len(bodyBytes) == 0 {
			return "", fmt.Errorf("YAML content is empty")
		}
		return string(bodyBytes), nil
	}

	var req struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return "", fmt.Errorf("invalid JSON payload (must include 'yaml' field or be application/x-yaml)")
	}
	if req.YAML == "" {
		return "", fmt.Errorf("YAML content is empty")
	}
	return req.YAML, nil
}
