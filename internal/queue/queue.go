package queue

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA1 used for UUIDv5 generation (non-crypto task IDs)
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/queuedb"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

const (
	defaultPriority     = 100
	defaultMaxAttempts  = 5
	defaultLeaseSeconds = 300
)

var ErrNoCommandAvailable = errors.New("no command available")

type Publisher struct {
	db            *queuedb.DB
	log           *logging.Logger
	privateKey    ed25519.PrivateKey
	encryptionKey []byte
}

func NewPublisher(db *queuedb.DB, log *logging.Logger, seed []byte, encryptionKey []byte) *Publisher {
	var priv ed25519.PrivateKey
	if len(seed) == 32 {
		priv = ed25519.NewKeyFromSeed(seed)
	}
	return &Publisher{db: db, log: log, privateKey: priv, encryptionKey: encryptionKey}
}

func (p *Publisher) PublishTask(task *admiral.FleetTask) error {
	task.TaskSignature = ""
	task.SignedAt = 0

	payload, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("serialize task payload: %w", err)
	}
	signedAt := time.Now().Unix()
	sig := p.signPayload(payload, signedAt)

	task.TaskSignature = sig
	task.SignedAt = signedAt

	storePayload, err := p.sealPayload(payload)
	if err != nil {
		return fmt.Errorf("encrypt task payload: %w", err)
	}
	return p.persistTask(task, storePayload, admiral.CommandPending, defaultMaxAttempts, "", "", sig, signedAt)
}

func (p *Publisher) PublishRejectedTask(task *admiral.FleetTask, reason, result string) error {
	task.TaskSignature = ""
	task.SignedAt = 0

	payload, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("serialize task payload: %w", err)
	}
	signedAt := time.Now().Unix()
	sig := p.signPayload(payload, signedAt)

	task.TaskSignature = sig
	task.SignedAt = signedAt

	storePayload, err := p.sealPayload(payload)
	if err != nil {
		return fmt.Errorf("encrypt task payload: %w", err)
	}
	return p.persistTask(task, storePayload, admiral.CommandFailed, 0, reason, result, sig, signedAt)
}

func (p *Publisher) signPayload(payload []byte, timestamp int64) string {
	msg := append(payload, []byte(fmt.Sprintf("%d", timestamp))...)
	sig := ed25519.Sign(p.privateKey, msg)
	return hex.EncodeToString(sig)
}

func (p *Publisher) sealPayload(plaintext []byte) ([]byte, error) {
	if len(p.encryptionKey) == 0 {
		return plaintext, nil
	}
	block, err := aes.NewCipher(p.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	wrapper, _ := json.Marshal(map[string]string{"ct": base64.StdEncoding.EncodeToString(ciphertext)})
	return wrapper, nil
}

func (p *Publisher) persistTask(task *admiral.FleetTask, storePayload []byte, status admiral.FleetCommandStatus, maxAttempts int, lastError, result, sig string, signedAt int64) error {
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
	_, err := p.db.Exec(`
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
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 0, $12, $13, $14, $15, NULLIF($16, '')::jsonb, $17, $18
		)
	`, commandID, operationUUID, task.OperationID, task.TaskID, task.InstanceID, task.NodeID, string(task.Action), string(storePayload), string(status), defaultPriority, availableAt, maxAttempts, idempotencyKey, completedAt, lastErrorValue, result, sigValue, signedAtValue)
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

func (p *Publisher) ClaimTask(nodeID string) (*admiral.FleetTask, string, int, int, error) {
	return p.claimTask(context.Background(), nodeID)
}

func (p *Publisher) claimTask(ctx context.Context, nodeID string) (*admiral.FleetTask, string, int, int, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", 0, 0, fmt.Errorf("begin claim tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		UPDATE fleet_commands
		SET status = $1,
			leased_until = NULL,
			leased_by = NULL
		WHERE node_id = $2
		  AND status IN ($3, $4)
		  AND leased_until IS NOT NULL
		  AND leased_until < CURRENT_TIMESTAMP
	`, string(admiral.CommandPending), nodeID, string(admiral.CommandLeased), string(admiral.CommandRunning)); err != nil {
		return nil, "", 0, 0, fmt.Errorf("reset expired leases: %w", err)
	}

	consumerID := fmt.Sprintf("%s-%d", nodeID, time.Now().UnixNano())
	row := tx.QueryRowContext(ctx, `
		WITH next_command AS (
			SELECT id
			FROM fleet_commands
			WHERE node_id = $1
			  AND status = $2
			  AND available_at <= CURRENT_TIMESTAMP
			ORDER BY priority ASC, created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE fleet_commands fc
		SET status = $3,
			leased_by = $4,
			leased_until = CURRENT_TIMESTAMP + ($5 * INTERVAL '1 second'),
			attempt_count = attempt_count + 1
		FROM next_command
		WHERE fc.id = next_command.id
		RETURNING fc.id, fc.payload, fc.attempt_count, fc.max_attempts, fc.task_signature, fc.signed_at
	`, nodeID, string(admiral.CommandPending), string(admiral.CommandLeased), consumerID, defaultLeaseSeconds)

	var (
		commandID     string
		payload       []byte
		attemptCount  int
		maxAttempts   int
		taskSignature sql.NullString
		signedAt      sql.NullInt64
	)
	if err := row.Scan(&commandID, &payload, &attemptCount, &maxAttempts, &taskSignature, &signedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if err := tx.Commit(); err != nil {
				return nil, "", 0, 0, fmt.Errorf("commit empty claim tx: %w", err)
			}
			return nil, "", 0, 0, ErrNoCommandAvailable
		}
		return nil, "", 0, 0, fmt.Errorf("scan claimed command: %w", err)
	}

	var task admiral.FleetTask
	if err := json.Unmarshal(payload, &task); err != nil || task.TaskID == "" {
		var wrapper struct {
			Ct string `json:"ct"`
		}
		if uerr := json.Unmarshal(payload, &wrapper); uerr != nil || wrapper.Ct == "" {
			return nil, "", 0, 0, fmt.Errorf("decode command payload: %w", err)
		}
		plaintext, derr := p.openPayload(wrapper.Ct)
		if derr != nil {
			return nil, "", 0, 0, fmt.Errorf("decrypt command payload: %w", derr)
		}
		if uerr := json.Unmarshal(plaintext, &task); uerr != nil {
			return nil, "", 0, 0, fmt.Errorf("decode decrypted command payload: %w", uerr)
		}
	}

	if taskSignature.Valid {
		task.TaskSignature = taskSignature.String
	}
	if signedAt.Valid {
		task.SignedAt = signedAt.Int64
	}

	if err := tx.Commit(); err != nil {
		return nil, "", 0, 0, fmt.Errorf("commit claim tx: %w", err)
	}

	return &task, commandID, attemptCount, maxAttempts, nil
}

func (p *Publisher) MarkRunning(commandID string) error {
	_, err := p.db.Exec(`
		UPDATE fleet_commands
		SET status = $1,
			started_at = CURRENT_TIMESTAMP
		WHERE id = $2
	`, string(admiral.CommandRunning), commandID)
	if err != nil {
		return fmt.Errorf("mark running: %w", err)
	}
	return nil
}

func (p *Publisher) RenewLease(commandID string) error {
	_, err := p.db.Exec(`
		UPDATE fleet_commands
		SET leased_until = CURRENT_TIMESTAMP + ($1 * INTERVAL '1 second')
		WHERE id = $2
		  AND status = $3
	`, defaultLeaseSeconds, commandID, string(admiral.CommandRunning))
	if err != nil {
		return fmt.Errorf("renew lease: %w", err)
	}
	return nil
}

func (p *Publisher) DiscardCommand(commandID, reason string) error {
	_, err := p.db.Exec(`
		UPDATE fleet_commands
		SET status = $1,
			last_error = $2,
			completed_at = CURRENT_TIMESTAMP,
			leased_until = NULL
		WHERE id = $3
	`, string(admiral.CommandFailed), reason, commandID)
	if err != nil {
		return fmt.Errorf("discard command: %w", err)
	}
	return nil
}

func (p *Publisher) CompleteTask(taskPublicID string, success bool, errorMsg string) error {
	if success {
		_, err := p.db.Exec(`
			UPDATE fleet_commands
			SET status = $1,
				completed_at = CURRENT_TIMESTAMP,
				leased_until = NULL
			WHERE task_public_id = $2
		`, string(admiral.CommandSucceeded), taskPublicID)
		return err
	}

	var (
		attemptCount int
		maxAttempts  int
	)
	err := p.db.QueryRow(`
		SELECT attempt_count, max_attempts
		FROM fleet_commands
		WHERE task_public_id = $1
	`, taskPublicID).Scan(&attemptCount, &maxAttempts)
	if err != nil {
		return fmt.Errorf("query fleet_commands for retry: %w", err)
	}

	if attemptCount >= maxAttempts {
		_, err = p.db.Exec(`
			UPDATE fleet_commands
			SET status = $1,
				last_error = $2,
				completed_at = CURRENT_TIMESTAMP,
				leased_until = NULL
			WHERE task_public_id = $3
		`, string(admiral.CommandDeadLetter), errorMsg, taskPublicID)
		return err
	}

	availableAt := time.Now().UTC().Add(backoff(attemptCount))
	_, err = p.db.Exec(`
		UPDATE fleet_commands
		SET status = $1,
			last_error = $2,
			available_at = $3,
			leased_until = NULL,
			leased_by = NULL
		WHERE task_public_id = $4
	`, string(admiral.CommandPending), errorMsg, availableAt, taskPublicID)
	return err
}

func (p *Publisher) openPayload(b64Ciphertext string) ([]byte, error) {
	if len(p.encryptionKey) == 0 {
		return nil, fmt.Errorf("task is encrypted but no encryption key configured")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode base64 ciphertext: %w", err)
	}
	block, err := aes.NewCipher(p.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plaintext, nil
}

func backoff(attempt int) time.Duration {
	switch {
	case attempt <= 1:
		return 2 * time.Second
	case attempt == 2:
		return 5 * time.Second
	case attempt == 3:
		return 10 * time.Second
	default:
		return 30 * time.Second
	}
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
