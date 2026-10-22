package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func provisionIdempotencyKeyHash(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 255 {
		return "", errors.New("Idempotency-Key must contain 1 to 255 bytes")
	}
	for _, r := range key {
		if unicode.IsControl(r) {
			return "", errors.New("Idempotency-Key must not contain control characters")
		}
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:]), nil
}

func provisionRequestHash(req admiral.ProvisionRequest) (string, error) {
	canonical := struct {
		AppDefinitionName string `json:"app_definition_name"`
		TierName          string `json:"tier_name"`
		CustomerID        string `json:"customer_id"`
		NodeID            string `json:"node_id,omitempty"`
		LogicalInstanceID string `json:"logical_instance_id,omitempty"`
	}{req.AppDefinitionName, req.TierName, req.CustomerID, req.NodeID, req.LogicalInstanceID}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode provision request fingerprint: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func writeProvisionReplay(w http.ResponseWriter, record *database.ProvisionRequestRecord) {
	w.Header().Set("Idempotency-Replayed", "true")
	if record.ResponseStatus > 0 && len(record.ResponseJSON) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(record.ResponseStatus)
		_, _ = w.Write(record.ResponseJSON)
		return
	}
	w.Header().Set("Retry-After", "1")
	writeJSON(w, http.StatusAccepted, admiral.ProvisionResponse{
		InstanceID:  record.InstanceID,
		OperationID: record.OperationID,
		Status:      "processing",
	})
}

func (h *APIHandlers) replayProvisionIfPresent(w http.ResponseWriter, customerID, keyHash, requestHash string) (bool, error) {
	record, err := h.db.GetProvisionRequest(customerID, keyHash)
	if err != nil {
		return false, err
	}
	if record == nil {
		return false, nil
	}
	if record.RequestHash != requestHash {
		writeError(w, http.StatusConflict, "Idempotency-Key was already used for a different provision request")
		return true, nil
	}
	writeProvisionReplay(w, record)
	return true, nil
}

func (h *APIHandlers) handleProvisionWithoutCapacity(
	w http.ResponseWriter,
	r *http.Request,
	req admiral.ProvisionRequest,
	keyHash, requestHash string,
	tier database.AppTier,
	evaluations []admiral.NodeProvisioningEvaluation,
) error {
	replayed, err := h.replayProvisionIfPresent(w, req.CustomerID, keyHash, requestHash)
	if err != nil {
		return fmt.Errorf("recheck provision idempotency record after capacity selection: %w", err)
	}
	if replayed {
		return nil
	}
	return h.recordBlockedWorkloadAttempt(w, r, admiral.ActionProvisionApp, "", req.AppDefinitionName, req.CustomerID, req.NodeID, tier, evaluations)
}

func completeProvisionResponse(db *database.DB, customerID, keyHash string, status int, response interface{}) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("encode provision response for idempotency: %w", err)
	}
	if err := db.CompleteProvisionRequest(customerID, keyHash, status, encoded); err != nil {
		return fmt.Errorf("persist provision response for idempotency: %w", err)
	}
	return nil
}
