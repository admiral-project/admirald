// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

func TestManagerEncryptDecrypt(t *testing.T) {
	manager := NewManager("test-master-key")
	ciphertext, err := manager.Encrypt("super-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ciphertext == "super-secret" {
		t.Fatal("ciphertext must not equal plaintext")
	}

	plaintext, err := manager.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plaintext != "super-secret" {
		t.Fatalf("unexpected plaintext %q", plaintext)
	}
}

func TestManagerDecryptRejectsInvalidCiphertext(t *testing.T) {
	manager := NewManager("test-master-key")
	if _, err := manager.Decrypt("not-base64"); err == nil {
		t.Fatal("expected invalid ciphertext to fail")
	}
}

func TestKeyRotationKeepsPreviousCiphertextReadable(t *testing.T) {
	oldManager := NewManager("old-master-key")
	ciphertext, err := oldManager.Encrypt("rotation-secret")
	if err != nil {
		t.Fatalf("encrypt with old key: %v", err)
	}

	rotated := NewManagerWithKeys("new-master-key", []string{"old-master-key"})
	plaintext, err := rotated.Decrypt(ciphertext)
	if err != nil || plaintext != "rotation-secret" {
		t.Fatalf("decrypt with previous key: plaintext=%q err=%v", plaintext, err)
	}

	newCiphertext, err := rotated.Encrypt("new-secret")
	if err != nil {
		t.Fatalf("encrypt with current key: %v", err)
	}
	if _, err := NewManager("old-master-key").Decrypt(newCiphertext); err == nil {
		t.Fatal("expected old key to reject ciphertext written after rotation")
	}
	if !rotated.IsCurrent(newCiphertext) || rotated.IsCurrent(ciphertext) {
		t.Fatal("expected current-key detection to be idempotent")
	}
	reencrypted, err := rotated.Reencrypt(ciphertext)
	if err != nil || !rotated.IsCurrent(reencrypted) {
		t.Fatalf("reencrypt old ciphertext: value=%q err=%v", reencrypted, err)
	}
}

func TestManagerDecryptEdgeCases(t *testing.T) {
	manager := NewManager("test-master-key")

	t.Run("invalid versioned ciphertext split", func(t *testing.T) {
		_, err := manager.Decrypt("v2:keyid")
		if err == nil {
			t.Fatal("expected error for malformed versioned ciphertext")
		}
	})

	t.Run("empty parts in versioned ciphertext", func(t *testing.T) {
		_, err := manager.Decrypt("v2::payload")
		if err == nil {
			t.Fatal("expected error for empty keyid part")
		}
		_, err = manager.Decrypt("v2:keyid:")
		if err == nil {
			t.Fatal("expected error for empty payload part")
		}
	})

	t.Run("unconfigured key id", func(t *testing.T) {
		_, err := manager.Decrypt("v2:wrongid:cGF5bG9hZA==")
		if err == nil {
			t.Fatal("expected error for unconfigured key ID")
		}
	})

	t.Run("invalid base64 decode of legacy payload", func(t *testing.T) {
		_, err := manager.Decrypt("not-base64-at-all!")
		if err == nil {
			t.Fatal("expected error for non-base64 payload")
		}
	})

	t.Run("ciphertext too short", func(t *testing.T) {
		// Base64 of empty string is empty, so length is 0
		_, err := manager.Decrypt("")
		if err == nil {
			t.Fatal("expected error for empty ciphertext")
		}

		// Base64 of 5 bytes (too short for saltLen = 16)
		// "abcde" encoded is "YWJjZGU="
		_, err = manager.Decrypt("YWJjZGU=")
		if err == nil {
			t.Fatal("expected error for legacy/short ciphertext")
		}
	})

	t.Run("NewManagerWithKeys skips empty previous keys", func(t *testing.T) {
		mgr := NewManagerWithKeys("curr", []string{"", "  ", "prev"})
		if len(mgr.previous) != 1 {
			t.Fatalf("expected 1 previous key, got %d", len(mgr.previous))
		}
		if string(mgr.previous[0]) != "prev" {
			t.Fatalf("expected 'prev', got %q", string(mgr.previous[0]))
		}
	})

	t.Run("Reencrypt on already current payload returns same payload", func(t *testing.T) {
		curr, err := manager.Encrypt("hello")
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		re, err := manager.Reencrypt(curr)
		if err != nil {
			t.Fatalf("reencrypt failed: %v", err)
		}
		if re != curr {
			t.Fatalf("expected unchanged payload, got %q", re)
		}
	})

	t.Run("Reencrypt error on invalid payload", func(t *testing.T) {
		_, err := manager.Reencrypt("invalid-payload")
		if err == nil {
			t.Fatal("expected error during re-encryption of invalid payload")
		}
	})

	t.Run("decrypt tampered payload", func(t *testing.T) {
		ciphertext, err := manager.Encrypt("my-secret")
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		// Tamper with the base64 part of the ciphertext
		parts := strings.Split(ciphertext, ":")
		if len(parts) == 3 {
			// Change last character of the payload base64 string
			b64 := parts[2]
			if len(b64) > 0 {
				lastChar := b64[len(b64)-1]
				newChar := byte('A')
				if lastChar == 'A' {
					newChar = 'B'
				}
				parts[2] = b64[:len(b64)-1] + string(newChar)
			}
			tampered := strings.Join(parts, ":")
			_, err = manager.Decrypt(tampered)
			if err == nil {
				t.Fatal("expected decryption of tampered ciphertext to fail")
			}
		}
	})

	t.Run("decrypt legacy format that fails decryption", func(t *testing.T) {
		// 20 bytes of dummy data encoded in base64.
		// It will pass the length check (> saltLen = 16) but fail decryption.
		dummyLegacy := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1"
		_, err := manager.Decrypt(dummyLegacy)
		if err == nil {
			t.Fatal("expected decryption of dummy legacy format to fail")
		}
	})
}
