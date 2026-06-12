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
