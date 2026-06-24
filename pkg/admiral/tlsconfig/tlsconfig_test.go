// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package tlsconfig

import (
	"os"
	"testing"
)

func TestValidateURLScheme(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		allowed []string
		wantErr bool
	}{
		{name: "https accepted", raw: "https://admiral.example.com", allowed: []string{"https"}},
		{name: "amqps accepted", raw: "amqps://rabbitmq.example.com", allowed: []string{"amqps"}},
		{name: "http rejected", raw: "http://admiral.example.com", allowed: []string{"https"}, wantErr: true},
		{name: "amqp rejected", raw: "amqp://rabbitmq.example.com", allowed: []string{"amqps"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURLScheme(tt.raw, tt.allowed...)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestNewServerConfig(t *testing.T) {
	cfg := NewServerConfig()
	if cfg.MinVersion != 0 && cfg.MinVersion < 0x0303 {
		t.Fatalf("expected TLS 1.2 minimum, got %v", cfg.MinVersion)
	}
}

func TestNewClientConfig(t *testing.T) {
	t.Run("no CA file", func(t *testing.T) {
		cfg, err := NewClientConfig("")
		if err != nil {
			t.Fatalf("NewClientConfig failed: %v", err)
		}
		if cfg.RootCAs == nil {
			t.Error("expected RootCAs to be set")
		}
	})

	t.Run("missing CA file", func(t *testing.T) {
		_, err := NewClientConfig("non-existent-file.crt")
		if err == nil {
			t.Error("expected error for missing CA file, got nil")
		}
	})

	t.Run("invalid CA file", func(t *testing.T) {
		f, err := os.CreateTemp("", "invalid-ca-*.crt")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		if _, err := f.WriteString("not a certificate"); err != nil {
			t.Fatal(err)
		}
		f.Close()

		_, err = NewClientConfig(f.Name())
		if err == nil {
			t.Error("expected error for invalid CA file, got nil")
		}
	})
}
