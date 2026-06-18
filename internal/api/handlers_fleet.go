package api

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func parseHostPortsFromMetadata(metadata string) map[string]int {
	var data struct {
		HostPorts map[string]int `json:"host_ports"`
	}
	if err := json.Unmarshal([]byte(metadata), &data); err != nil {
		return nil
	}
	return data.HostPorts
}

// PATCH /api/v1/apps/{id}/availability — change app availability

func handleBackupCallback(h *APIHandlers, op *database.Operation, res admiral.TaskResult, success bool) {
	if success {
		var cbData struct {
			Backup struct {
				BackupID       string `json:"backup_id"`
				StorageBackend string `json:"storage_backend"`
				StorageKey     string `json:"storage_key"`
				SizeBytes      int64  `json:"size_bytes"`
				ChecksumSHA256 string `json:"checksum_sha256"`
				CompletedAt    string `json:"completed_at"`
			} `json:"backup"`
		}
		if uerr := json.Unmarshal([]byte(res.Metadata), &cbData); uerr != nil {
			h.log.Error("Failed to parse backup metadata from callback", uerr, map[string]interface{}{"operation_id": res.OperationID})
		}

		bkID := cbData.Backup.BackupID
		if bkID == "" {
			recs, err := h.db.GetBackupRecords(op.InstanceID)
			if err != nil {
				h.log.Error("Failed to get backup records for fallback", err, map[string]interface{}{"instance_id": op.InstanceID})
			}
			for _, r := range recs {
				if r.Status == "pending" {
					bkID = r.ID
					break
				}
			}
		}

		if bkID != "" {
			rec, err := h.db.GetBackupRecord(bkID)
			if err != nil {
				h.log.Error("Failed to get backup record", err, map[string]interface{}{"backup_id": bkID})
			}
			if rec != nil {
				rec.Status = "succeeded"
				rec.SizeBytes = cbData.Backup.SizeBytes
				rec.ChecksumSHA256 = cbData.Backup.ChecksumSHA256
				if cbData.Backup.StorageBackend != "" {
					rec.StorageBackend = cbData.Backup.StorageBackend
				}
				if cbData.Backup.StorageKey != "" && cbData.Backup.StorageBackend == "local" {
					cleaned := filepath.Clean(cbData.Backup.StorageKey)
					if filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "..") {
						h.log.Error("Rejected local backup storage_key with path traversal", nil, map[string]interface{}{
							"operation_id": res.OperationID,
							"storage_key":  cbData.Backup.StorageKey,
						})
					} else {
						rec.StorageKey = cbData.Backup.StorageKey
					}
				}
				rec.CompletedAt = time.Now().Format(time.RFC3339)
				rec.ExpiresAt = time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
				if uerr := h.db.UpdateBackupRecord(rec); uerr != nil {
					h.log.Error("Failed to update backup record", uerr, map[string]interface{}{"backup_id": bkID})
				}
			}
		}
	} else {
		recs, err := h.db.GetBackupRecords(op.InstanceID)
		if err != nil {
			h.log.Error("Failed to get backup records for failure", err, map[string]interface{}{"instance_id": op.InstanceID})
			return
		}
		for _, r := range recs {
			if r.Status == "pending" {
				r.Status = "failed"
				if uerr := h.db.UpdateBackupRecord(&r); uerr != nil {
					h.log.Error("Failed to update backup record as failed", uerr, map[string]interface{}{"backup_id": r.ID})
				}
				break
			}
		}
	}
}
