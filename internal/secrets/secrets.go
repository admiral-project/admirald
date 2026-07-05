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

	"golang.org/x/crypto/hkdf"
)

const (
	saltLen = 16
)

type Manager struct {
	masterKey []byte
}

func NewManager(masterKey string) *Manager {
	return &Manager{masterKey: []byte(masterKey)}
}

// deriveKey derives an AES-256 key from the master key using HKDF with a salt.
func (m *Manager) deriveKey(salt []byte) []byte {
	prk := hkdf.Extract(sha256.New, m.masterKey, salt)
	r := hkdf.Expand(sha256.New, prk, []byte("admiral-secrets-key-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(fmt.Sprintf("hkdf key derivation failed: %v", err))
	}
	return key
}

// legacyKey derives the key using raw SHA256 (old format, no salt).
func (m *Manager) legacyKey() []byte {
	sum := sha256.Sum256(m.masterKey)
	return sum[:]
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

	key := m.deriveKey(salt)
	ct, err := m.encryptWithKey(key, plaintext)
	if err != nil {
		return "", err
	}

	// Format: salt(16) || nonce(12) || ciphertext
	out := make([]byte, 0, saltLen+len(ct))
	out = append(out, salt...)
	out = append(out, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

func (m *Manager) Decrypt(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	if len(data) == 0 {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Try new format (salt || nonce || ciphertext).
	if len(data) > saltLen {
		salt := data[:saltLen]
		ct := data[saltLen:]
		key := m.deriveKey(salt)
		plaintext, err := m.decryptWithKey(key, ct)
		if err == nil {
			return plaintext, nil
		}
	}

	// Fall back to old format (no salt, raw SHA256 key derivation).
	key := m.legacyKey()
	return m.decryptWithKey(key, data)
}
