// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("super-secret-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	ok, err := VerifyPassword("super-secret-password", hash)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if !ok {
		t.Fatal("expected password verification to succeed")
	}

	ok, err = VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("verify wrong password: %v", err)
	}
	if ok {
		t.Fatal("expected wrong password to fail")
	}
}

func TestValidateInitialAdminPassword(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{name: "valid", username: "admin", password: "correct-horse-battery", wantErr: false},
		{name: "empty", username: "admin", password: "", wantErr: true},
		{name: "short", username: "admin", password: "short", wantErr: true},
		{name: "secret", username: "admin", password: "secret", wantErr: true},
		{name: "admin", username: "admin", password: "admin", wantErr: true},
		{name: "same as user", username: "bootstrap", password: "bootstrap", wantErr: true},
		{name: "same as user long", username: "correct-horse-battery", password: "correct-horse-battery", wantErr: true},
		{name: "trimmed", username: "admin", password: "  surrounding-space  ", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInitialAdminPassword(tt.username, tt.password)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyPasswordEdgeAndErrorCases(t *testing.T) {
	t.Run("invalid argon2 hash format count", func(t *testing.T) {
		_, err := VerifyPassword("pw", "argon2id$v=19$m=65536,t=3,p=4$salt")
		if err == nil || err.Error() != "invalid argon2 hash format" {
			t.Fatalf("expected format error, got %v", err)
		}
	})

	t.Run("unsupported argon2 prefix", func(t *testing.T) {
		_, err := VerifyPassword("pw", "argon2i$v=19$m=65536,t=3,p=4$salt$hash")
		if err == nil || err.Error() != "unsupported argon2 hash format" {
			t.Fatalf("expected unsupported format error, got %v", err)
		}
	})

	t.Run("unsupported argon2 version", func(t *testing.T) {
		_, err := VerifyPassword("pw", "argon2id$v=18$m=65536,t=3,p=4$salt$hash")
		if err == nil || err.Error() != "unsupported argon2 hash format" {
			t.Fatalf("expected unsupported format error, got %v", err)
		}
	})

	t.Run("invalid argon2 parameters count", func(t *testing.T) {
		_, err := VerifyPassword("pw", "argon2id$v=19$m=65536,t=3$salt$hash")
		if err == nil || err.Error() != "invalid argon2 parameters" {
			t.Fatalf("expected invalid parameters error, got %v", err)
		}
	})

	t.Run("invalid prefix name in parameter", func(t *testing.T) {
		_, err := VerifyPassword("pw", "argon2id$v=19$x=65536,t=3,p=4$salt$hash")
		if err == nil {
			t.Fatal("expected error for wrong parameter prefix 'x'")
		}
	})

	t.Run("missing equals in parameter", func(t *testing.T) {
		_, err := VerifyPassword("pw", "argon2id$v=19$m65536,t=3,p=4$salt$hash")
		if err == nil {
			t.Fatal("expected error for missing equals")
		}
	})

	t.Run("non-integer parameter value", func(t *testing.T) {
		_, err := VerifyPassword("pw", "argon2id$v=19$m=abc,t=3,p=4$salt$hash")
		if err == nil {
			t.Fatal("expected error for non-integer value")
		}
	})

	t.Run("parameter value zero", func(t *testing.T) {
		_, err := VerifyPassword("pw", "argon2id$v=19$m=0,t=3,p=4$salt$hash")
		if err == nil {
			t.Fatal("expected error for value of zero")
		}
	})

	t.Run("invalid base64 decode of salt", func(t *testing.T) {
		_, err := VerifyPassword("pw", "argon2id$v=19$m=65536,t=3,p=4$invalid_salt!$hash")
		if err == nil {
			t.Fatal("expected error for invalid salt base64")
		}
	})

	t.Run("invalid base64 decode of hash", func(t *testing.T) {
		_, err := VerifyPassword("pw", "argon2id$v=19$m=65536,t=3,p=4$salt$invalid_hash!")
		if err == nil {
			t.Fatal("expected error for invalid hash base64")
		}
	})
}
