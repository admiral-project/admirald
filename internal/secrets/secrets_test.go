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
