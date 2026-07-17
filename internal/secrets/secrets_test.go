// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package secrets

import "testing"

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
}
