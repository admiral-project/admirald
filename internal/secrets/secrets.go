// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	saltLen = 16
)

type Manager struct {
	currentKey []byte
	previous   [][]byte
}

func NewManager(masterKey string) *Manager {
	return NewManagerWithKeys(masterKey, nil)
}

// NewManagerWithKeys creates a manager with one active key and optional old
// keys kept during a rotation window. New ciphertext always uses the active
// key; old ciphertext remains decryptable while its key is configured.
func NewManagerWithKeys(current string, previous []string) *Manager {
	manager := &Manager{currentKey: []byte(current)}
	for _, key := range previous {
		if strings.TrimSpace(key) != "" {
			manager.previous = append(manager.previous, []byte(strings.TrimSpace(key)))
		}
	}
	return manager
}

func keyID(key []byte) string {
	digest := sha256.Sum256(key)
	return fmt.Sprintf("%x", digest[:8])
}

// deriveKey derives an AES-256 key from the master key using HKDF with a salt.
func deriveKey(masterKey, salt []byte) ([]byte, error) {
	prk := hkdf.Extract(sha256.New, masterKey, salt)
	r := hkdf.Expand(sha256.New, prk, []byte("admiral-secrets-key-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return key, nil
}

func (m *Manager) encryptWithKey(key []byte, plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(key)
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
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

func (m *Manager) decryptWithKey(key []byte, data []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}
	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(plaintext), nil
}

func (m *Manager) Encrypt(plaintext string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key, err := deriveKey(m.currentKey, salt)
	if err != nil {
		return "", err
	}
	ct, err := m.encryptWithKey(key, plaintext)
	if err != nil {
		return "", err
	}

	// Format: v2:<key-id>:<base64(salt || nonce || ciphertext)>. The key ID
	// lets rotation select the correct decryption key without trial-decrypting.
	out := make([]byte, 0, saltLen+len(ct))
	out = append(out, salt...)
	out = append(out, ct...)
	return "v2:" + keyID(m.currentKey) + ":" + base64.StdEncoding.EncodeToString(out), nil
}

func (m *Manager) Decrypt(encoded string) (string, error) {
	if strings.HasPrefix(encoded, "v2:") {
		parts := strings.SplitN(encoded, ":", 3)
		if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
			return "", fmt.Errorf("invalid versioned ciphertext")
		}
		keys := append([][]byte{m.currentKey}, m.previous...)
		for _, key := range keys {
			if keyID(key) != parts[1] {
				continue
			}
			return m.decryptPayload(parts[2], key)
		}
		return "", fmt.Errorf("ciphertext key %q is not configured", parts[1])
	}

	// Support the pre-rotation format during migration. New writes are always
	// versioned, so data is gradually upgraded as values are replaced.
	keys := append([][]byte{m.currentKey}, m.previous...)
	var lastErr error
	for _, key := range keys {
		plain, err := m.decryptPayload(encoded, key)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func (m *Manager) decryptPayload(encoded string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	if len(data) == 0 {
		return "", fmt.Errorf("ciphertext too short")
	}

	// New format (salt || nonce || ciphertext) — REQUIRED.
	// Legacy format (no salt, raw SHA256 key derivation) was removed
	// for security: silent fallback from AES-GCM to SHA256 allowed
	// ciphertext substitution attacks.
	if len(data) <= saltLen {
		return "", fmt.Errorf("ciphertext too short for current encryption format; " +
			"data may be from a removed legacy format")
	}

	salt := data[:saltLen]
	ct := data[saltLen:]
	derivedKey, err := deriveKey(key, salt)
	if err != nil {
		return "", err
	}
	return m.decryptWithKey(derivedKey, ct)
}
