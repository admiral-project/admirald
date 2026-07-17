package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

// GET & POST & PUT /api/admin/apps
func (h *APIHandlers) HandleAdminApps(w http.ResponseWriter, r *http.Request) {
	// Extract app ID if present
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var appID string
	if len(parts) >= 4 {
		appID = parts[3]
	}

	switch r.Method {
	case http.MethodGet:
		if appID != "" {
			// Sub-routes logic
			if len(parts) >= 5 && parts[4] == "yaml" {
				app, _ := h.db.GetAppDefinition(appID)
				if app == nil {
					writeError(w, http.StatusNotFound, "App not found")
					return
				}
				redacted, err := redactAppDefinitionYAML(app.RawYAML)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "Failed to fetch app definition")
					return
				}
				w.Header().Set("Content-Type", "application/x-yaml")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(redacted))
				return
			}
			if len(parts) >= 5 && parts[4] == "versions" {
				writeJSON(w, http.StatusOK, []string{"latest"})
				return
			}
			if len(parts) >= 5 && parts[4] == "tiers" {
				tiers, _ := h.db.GetAppTiers(appID)
				writeJSON(w, http.StatusOK, tiers)
				return
			}

			app, _ := h.db.GetAppDefinition(appID)
			if app == nil {
				writeError(w, http.StatusNotFound, "App not found")
				return
			}
			redacted, err := redactAppDefinition(*app)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Failed to fetch app definition")
				return
			}
			writeJSON(w, http.StatusOK, redacted)
			return
		}

		apps, err := h.db.GetAppDefinitions()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		redacted, err := redactAppDefinitions(apps)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to fetch applications")
			return
		}
		writeJSON(w, http.StatusOK, redacted)

	case http.MethodPost, http.MethodPut:
		// Sub-routes logic for tiers
		if appID != "" && len(parts) >= 5 && parts[4] == "tiers" {
			h.HandleAdminAppTiers(w, r, appID)
			return
		}

		h.HandleApps(w, r) // Reuse existing validation and logic
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Handles App Tiers nested operations
func (h *APIHandlers) HandleAdminAppTiers(w http.ResponseWriter, r *http.Request, appID string) {
	app, _ := h.db.GetAppDefinition(appID)
	if app == nil {
		writeError(w, http.StatusNotFound, "App not found")
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var tierID string
	if len(parts) >= 6 {
		tierID = parts[5]
	}

	switch r.Method {
	case http.MethodGet:
		tiers, _ := h.db.GetAppTiers(appID)
		if tierID != "" {
			for _, t := range tiers {
				if t.Name == tierID {
					writeJSON(w, http.StatusOK, t)
					return
				}
			}
			writeError(w, http.StatusNotFound, "Tier not found")
			return
		}
		writeJSON(w, http.StatusOK, tiers)

	case http.MethodPost, http.MethodPut:
		var req struct {
			Name         string                `json:"name"`
			CPU          float64               `json:"cpu"`
			Memory       string                `json:"memory"`
			Storage      string                `json:"storage"`
			PriceMonthly float64               `json:"price_monthly"`
			Free         bool                  `json:"free"`
			Environment  map[string]string     `json:"environment,omitempty"`
			Backups      *admiral.BackupPolicy `json:"backups,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}

		if req.Name == "" || req.CPU <= 0 || req.Memory == "" || req.Storage == "" {
			writeError(w, http.StatusBadRequest, "Missing required tier fields")
			return
		}
		if err := admiral.ValidateTierEnvironment(req.Name, req.Environment); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		var backupPolicyJSON string
		if req.Backups != nil && req.Backups.Enabled {
			if req.Backups.Schedule != "disabled" && req.Backups.Schedule != "daily" && req.Backups.Schedule != "weekly" {
				writeError(w, http.StatusBadRequest, "Invalid backup schedule")
				return
			}
			if req.Backups.Retention.Count < 1 || req.Backups.Retention.Days < 1 {
				writeError(w, http.StatusBadRequest, "Invalid backup retention")
				return
			}
			bBytes, _ := json.Marshal(req.Backups)
			backupPolicyJSON = string(bBytes)
		}

		tiers, _ := h.db.GetAppTiers(appID)
		var updatedTiers []database.AppTier
		for _, t := range tiers {
			if t.Name != req.Name {
				updatedTiers = append(updatedTiers, t)
			}
		}
		updatedTiers = append(updatedTiers, database.AppTier{
			AppName:          appID,
			Name:             req.Name,
			CPU:              req.CPU,
			Memory:           req.Memory,
			Storage:          req.Storage,
			PriceMonthly:     req.PriceMonthly,
			Free:             req.Free,
			Environment:      req.Environment,
			BackupPolicyJSON: backupPolicyJSON,
		})

		var payload admiral.AppDefinitionPayload
		if err := yaml.Unmarshal([]byte(app.RawYAML), &payload); err != nil { //nolint:gosec // app.RawYAML from trusted DB data
			writeError(w, http.StatusInternalServerError, "Stored application definition is invalid")
			return
		}
		if payload.Tiers == nil {
			payload.Tiers = make(map[string]admiral.YAMLTier)
		}
		payload.Tiers[req.Name] = admiral.YAMLTier{
			CPU:          req.CPU,
			Memory:       req.Memory,
			Storage:      req.Storage,
			PriceMonthly: req.PriceMonthly,
			Environment:  req.Environment,
			Backups:      req.Backups,
		}
		updatedRawYAML, err := yaml.Marshal(payload)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed serializing updated application definition")
			return
		}

		if err := h.db.SaveAppDefinition(app.Name, app.DisplayName, app.Description, string(updatedRawYAML), updatedTiers); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	}
}
