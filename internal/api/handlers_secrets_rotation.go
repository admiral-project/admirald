package api

import (
	"net/http"

	"github.com/admiral-project/admiral/admirald/internal/database"
)

func (h *APIHandlers) HandleSecretRotation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rows, err := h.db.GetAllInstanceSecrets()
	if err != nil {
		h.log.Error("List instance secrets for rotation failed", err, nil)
		writeError(w, http.StatusInternalServerError, "Failed to prepare secret rotation")
		return
	}
	updates := make([]database.InstanceSecretUpdate, 0, len(rows))
	alreadyCurrent := 0
	for _, row := range rows {
		if h.secrets.IsCurrent(row.EncryptedValue) {
			alreadyCurrent++
			continue
		}
		rotated, err := h.secrets.Reencrypt(row.EncryptedValue)
		if err != nil {
			h.log.Error("Decrypt instance secret for rotation failed", err, map[string]interface{}{
				"instance_id": row.InstanceID, "service_name": row.ServiceName, "env_name": row.EnvName,
			})
			writeError(w, http.StatusConflict, "Secret rotation could not decrypt all stored values")
			return
		}
		updates = append(updates, database.InstanceSecretUpdate{
			InstanceID: row.InstanceID, ServiceName: row.ServiceName, EnvName: row.EnvName, EncryptedValue: rotated,
		})
	}
	if err := h.db.UpdateInstanceSecretCiphertexts(updates); err != nil {
		h.log.Error("Persist rotated instance secrets failed", err, nil)
		writeError(w, http.StatusInternalServerError, "Failed to persist secret rotation")
		return
	}
	h.auditEvent("instance_secrets_rotated", map[string]interface{}{
		"migrated": len(updates), "already_current": alreadyCurrent,
	})
	writeJSON(w, http.StatusOK, map[string]int{"migrated": len(updates), "already_current": alreadyCurrent, "total": len(rows)})
}
