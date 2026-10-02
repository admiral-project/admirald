// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

// customerBackupRecord deliberately omits node IDs and storage locations from
// the Harbor-facing response.
type customerBackupRecord struct {
	ID             string `json:"id"`
	InstanceID     string `json:"instance_id"`
	BackupType     string `json:"backup_type"`
	Service        string `json:"service"`
	DatabaseType   string `json:"database_type"`
	Status         string `json:"status"`
	SizeBytes      int64  `json:"size_bytes"`
	ChecksumSHA256 string `json:"checksum_sha256"`
	CreatedAt      string `json:"created_at"`
	CompletedAt    string `json:"completed_at,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	TriggeredBy    string `json:"triggered_by"`
}

func customerBackup(rec admiral.BackupRecord) customerBackupRecord {
	return customerBackupRecord{
		ID:             rec.ID,
		InstanceID:     rec.InstanceID,
		BackupType:     rec.BackupType,
		Service:        rec.Service,
		DatabaseType:   rec.DatabaseType,
		Status:         rec.Status,
		SizeBytes:      rec.SizeBytes,
		ChecksumSHA256: rec.ChecksumSHA256,
		CreatedAt:      rec.CreatedAt,
		CompletedAt:    rec.CompletedAt,
		ExpiresAt:      rec.ExpiresAt,
		TriggeredBy:    rec.TriggeredBy,
	}
}

func uploadedRestoreRecord(req admiral.RestoreBackupRequest, inst *database.CustomerApp, rawYAML string) (*admiral.BackupRecord, error) {
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &payload); err != nil {
		return nil, fmt.Errorf("stored application definition is invalid: %w", err)
	}
	target, err := resolveBackupTarget(payload, req.Service)
	if err != nil {
		return nil, err
	}
	databaseType := target.Backup.Engine
	if target.Backup.Type == "volume" && databaseType == "" {
		databaseType = "none"
	}
	return &admiral.BackupRecord{
		ID:             req.BackupID,
		InstanceID:     inst.ID,
		BackupType:     target.Backup.Type,
		Service:        target.ServiceName,
		DatabaseType:   databaseType,
		StorageBackend: "https",
		StorageKey:     strings.TrimSpace(req.Source.URI),
		ChecksumSHA256: strings.TrimSpace(req.Source.Checksum),
	}, nil
}

// HandleCustomerAppBackups serves backup metadata and restore requests for an
// instance after HandleCustomerAppByID has authenticated the Harbor token.
func (h *APIHandlers) HandleCustomerAppBackups(w http.ResponseWriter, r *http.Request, instanceID string, suffix []string) {
	inst, err := h.db.GetCustomerApp(instanceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Database error validating instance")
		return
	}
	if inst == nil {
		writeError(w, http.StatusNotFound, "Instance not found")
		return
	}
	if !requireCustomerOwnership(w, r, inst.CustomerID) {
		return
	}

	if len(suffix) == 0 {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed for customer backup list")
			return
		}
		records, err := h.db.GetBackupRecords(instanceID)
		if err != nil {
			h.log.Error("List customer backups failed", err, map[string]interface{}{"instance_id": instanceID})
			writeError(w, http.StatusInternalServerError, "Failed to fetch backups")
			return
		}
		response := make([]customerBackupRecord, 0, len(records))
		for _, record := range records {
			response = append(response, customerBackup(record))
		}
		writeJSON(w, http.StatusOK, response)
		return
	}

	if len(suffix) == 1 && suffix[0] == "restore" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "restore requires POST")
			return
		}
		var req admiral.RestoreBackupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON payload")
			return
		}
		if req.TargetAppID != "" && req.TargetAppID != instanceID {
			writeError(w, http.StatusBadRequest, "Target instance does not match the customer backup route")
			return
		}
		req.TargetAppID = instanceID
		if req.BackupID != "" {
			backup, err := h.db.GetBackupRecord(req.BackupID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Database error retrieving backup")
				return
			}
			if backup != nil {
				source, err := h.db.GetCustomerApp(backup.InstanceID)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "Database error validating backup ownership")
					return
				}
				if source == nil || source.CustomerID != inst.CustomerID {
					writeError(w, http.StatusNotFound, "Backup not found")
					return
				}
			} else if !strings.EqualFold(strings.TrimSpace(req.Source.Type), "https") || strings.TrimSpace(req.Source.URI) == "" {
				writeError(w, http.StatusNotFound, "Backup not found")
				return
			}
		}

		body, err := json.Marshal(req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to prepare restore request")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h.HandleAdminRestoreBackup(w, r)
		return
	}

	if len(suffix) == 1 && suffix[0] != "" {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed for customer backup")
			return
		}
		record, err := h.db.GetBackupRecord(suffix[0])
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Database error retrieving backup")
			return
		}
		if record == nil || record.InstanceID != instanceID {
			writeError(w, http.StatusNotFound, "Backup not found")
			return
		}
		writeJSON(w, http.StatusOK, customerBackup(*record))
		return
	}
	writeError(w, http.StatusNotFound, "customer backup endpoint not found")
}
