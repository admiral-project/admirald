package queue

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA1 used for UUIDv5 generation (non-crypto task IDs)
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/queuedb"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

const (
	defaultPriority    = 100
	defaultMaxAttempts = 5
)

type Publisher struct {
	db         *queuedb.DB
	log        *logging.Logger
	privateKey ed25519.PrivateKey
}

func NewPublisher(db *queuedb.DB, log *logging.Logger, seed []byte) *Publisher {
	var priv ed25519.PrivateKey
	if len(seed) == 32 {
		priv = ed25519.NewKeyFromSeed(seed)
	}
	return &Publisher{db: db, log: log, privateKey: priv}
}

func (p *Publisher) PublishTask(task *admiral.FleetTask) error {
	payload, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("serialize task payload: %w", err)
	}
	signedAt := time.Now().Unix()
	sig := p.signPayload(payload, signedAt)
	return p.persistTask(task, admiral.CommandPending, defaultMaxAttempts, "", "", sig, signedAt)
}

func (p *Publisher) PublishRejectedTask(task *admiral.FleetTask, reason, result string) error {
	payload, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("serialize task payload: %w", err)
	}
	signedAt := time.Now().Unix()
	sig := p.signPayload(payload, signedAt)
	return p.persistTask(task, admiral.CommandFailed, 0, reason, result, sig, signedAt)
}

func (p *Publisher) signPayload(payload []byte, timestamp int64) string {
	msg := append(payload, []byte(fmt.Sprintf("%d", timestamp))...)
	sig := ed25519.Sign(p.privateKey, msg)
	return hex.EncodeToString(sig)
}

func (p *Publisher) persistTask(task *admiral.FleetTask, status admiral.FleetCommandStatus, maxAttempts int, lastError, result, sig string, signedAt int64) error {
	payload, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("serialize task payload: %w", err)
	}

	commandID := newUUID()
	operationUUID := nameUUID(task.OperationID)
	idempotencyKey := task.TaskID
	availableAt := time.Now().UTC()
	var completedAt interface{}
	if status == admiral.CommandFailed || status == admiral.CommandSucceeded || status == admiral.CommandCancelled || status == admiral.CommandDeadLetter {
		completedAt = availableAt
	} else {
		completedAt = nil
	}
	var lastErrorValue interface{}
	if strings.TrimSpace(lastError) != "" {
		lastErrorValue = lastError
	}
	var sigValue interface{}
	if sig != "" {
		sigValue = sig
	}
	var signedAtValue interface{}
	if signedAt > 0 {
		signedAtValue = signedAt
	}
	_, err = p.db.Exec(`
		INSERT INTO fleet_commands (
			id,
			operation_id,
			operation_public_id,
			task_public_id,
			instance_id,
			node_id,
			command_type,
			payload,
			status,
			priority,
			available_at,
			attempt_count,
			max_attempts,
			idempotency_key,
			completed_at,
			last_error,
			result,
			task_signature,
			signed_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, 0, $12, $13, $14, $15, NULLIF($16, '')::jsonb, $17, $18
		)
	`, commandID, operationUUID, task.OperationID, task.TaskID, task.InstanceID, task.NodeID, string(task.Action), string(payload), string(status), defaultPriority, availableAt, maxAttempts, idempotencyKey, completedAt, lastErrorValue, result, sigValue, signedAtValue)
	if err != nil {
		return fmt.Errorf("insert fleet command: %w", err)
	}

	p.log.Info("Task persisted to queue database", map[string]interface{}{
		"task_id":        task.TaskID,
		"operation_id":   task.OperationID,
		"command_id":     commandID,
		"node_id":        task.NodeID,
		"command_type":   task.Action,
		"queue_status":   status,
		"idempotencyKey": idempotencyKey,
	})
	return nil
}

func (p *Publisher) Close() {}

func newUUID() string {
	return nameUUID(fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomHex(16)))
}

func nameUUID(seed string) string {
	sum := sha1.Sum([]byte(seed)) //nolint:gosec // SHA1 for UUIDv5 task IDs (non-crypto)
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return formatUUID(b)
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func formatUUID(b []byte) string {
	raw := hex.EncodeToString(b)
	parts := []string{
		raw[0:8],
		raw[8:12],
		raw[12:16],
		raw[16:20],
		raw[20:32],
	}
	return strings.Join(parts, "-")
}
