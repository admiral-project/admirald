// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigPathUsesSystemdCredential(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/admirald.service")

	want := "/run/credentials/admirald.service/admirald.ini"
	if got := configPath(); got != want {
		t.Fatalf("configPath() = %q, want %q", got, want)
	}
}

func TestLoadRequiresAdminToken(t *testing.T) {
	setEnv(t, "ADMIRAL_ADMIN_TOKEN", "")
	setEnv(t, "ADMIRAL_SECRETS_KEY", "")
	setEnv(t, "ADMIRAL_ENV", "development") // Use dev to avoid failing on SecretsKey first
	setEnv(t, "ADMIRAL_FLAGSHIP_ADMIN_USER", "")
	setEnv(t, "ADMIRAL_FLAGSHIP_ADMIN_PSWD", "")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", "")
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", "")

	_, err := load("/tmp/does-not-exist.ini")
	if err == nil {
		t.Fatal("expected error when shared token is missing")
	}
}

func TestLoadRequiresSecretsKeyInProduction(t *testing.T) {
	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")

	setEnv(t, "ADMIRAL_ENV", "production")
	setEnv(t, "ADMIRAL_ADMIN_TOKEN", "dev-token")
	setEnv(t, "ADMIRAL_TOKEN_PEPPER", "dev-pepper")
	setEnv(t, "ADMIRAL_SECRETS_KEY", "")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", certFile)
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", keyFile)
	setEnv(t, "ADMIRAL_DATABASE_URL", "postgres://user:pass@localhost:5432/admiral_core?sslmode=require")
	setEnv(t, "ADMIRAL_QUEUE_DATABASE_URL", "postgres://queue:pass@localhost:5432/admiral_queue?sslmode=require")

	_, err := load("/tmp/does-not-exist.ini")
	if err == nil {
		t.Fatal("expected error when secrets key is missing in production")
	}
}

func TestLoadAllowsEphemeralSecretsKeyInDevelopment(t *testing.T) {
	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")

	setEnv(t, "ADMIRAL_ENV", "development")
	setEnv(t, "ADMIRAL_ADMIN_TOKEN", "dev-token")
	setEnv(t, "ADMIRAL_TOKEN_PEPPER", "dev-pepper")
	setEnv(t, "ADMIRAL_SECRETS_KEY", "")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", certFile)
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", keyFile)
	setEnv(t, "ADMIRAL_DATABASE_URL", "postgres://user:pass@localhost:5432/admiral_core?sslmode=require")
	setEnv(t, "ADMIRAL_QUEUE_DATABASE_URL", "postgres://queue:pass@localhost:5432/admiral_queue?sslmode=require")

	cfg, err := load("/tmp/does-not-exist.ini")
	if err != nil {
		t.Fatalf("load returned error: %v", err)
	}
	if cfg.SecretsKey != "dev-ephemeral-key-change-me" {
		t.Fatalf("expected ephemeral secrets key, got %q", cfg.SecretsKey)
	}
}

func TestLoadAllowsMissingFlagshipAdminCredentials(t *testing.T) {
	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")

	setEnv(t, "ADMIRAL_ENV", "development")
	setEnv(t, "ADMIRAL_ADMIN_TOKEN", "dev-token")
	setEnv(t, "ADMIRAL_TOKEN_PEPPER", "dev-pepper")
	setEnv(t, "ADMIRAL_SECRETS_KEY", "")
	setEnv(t, "ADMIRAL_FLAGSHIP_ADMIN_USER", "")
	setEnv(t, "ADMIRAL_FLAGSHIP_ADMIN_PSWD", "")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", certFile)
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", keyFile)
	setEnv(t, "ADMIRAL_DATABASE_URL", "postgres://user:pass@localhost:5432/admiral_core?sslmode=require")
	setEnv(t, "ADMIRAL_QUEUE_DATABASE_URL", "postgres://queue:pass@localhost:5432/admiral_queue?sslmode=require")

	cfg, err := load("/tmp/does-not-exist.ini")
	if err != nil {
		t.Fatalf("load returned error: %v", err)
	}
	if cfg.FlagshipAdminUser != "" {
		t.Fatalf("expected flagship admin user to remain empty, got %q", cfg.FlagshipAdminUser)
	}
	if cfg.FlagshipAdminPassword != "" {
		t.Fatalf("expected flagship admin password to remain empty, got %q", cfg.FlagshipAdminPassword)
	}
}

func TestLoadAcceptsQueueDatabaseURL(t *testing.T) {
	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")

	setEnv(t, "ADMIRAL_ENV", "development")
	setEnv(t, "ADMIRAL_ADMIN_TOKEN", "dev-token")
	setEnv(t, "ADMIRAL_TOKEN_PEPPER", "dev-pepper")
	setEnv(t, "ADMIRAL_FLAGSHIP_ADMIN_USER", "")
	setEnv(t, "ADMIRAL_FLAGSHIP_ADMIN_PSWD", "")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", certFile)
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", keyFile)
	setEnv(t, "ADMIRAL_DATABASE_URL", "postgres://user:pass@localhost:5432/admiral_core?sslmode=require")
	setEnv(t, "ADMIRAL_QUEUE_DATABASE_URL", "postgres://queue:pass@localhost:5432/admiral_queue?sslmode=require")

	_, err := load("/tmp/does-not-exist.ini")
	if err != nil {
		t.Fatalf("load returned error: %v", err)
	}
}

func TestLoadDerivesNetworkingHostsFromBaseDomain(t *testing.T) {
	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")

	setEnv(t, "ADMIRAL_ENV", "development")
	setEnv(t, "ADMIRAL_ADMIN_TOKEN", "dev-token")
	setEnv(t, "ADMIRAL_TOKEN_PEPPER", "dev-pepper")
	setEnv(t, "ADMIRAL_FLAGSHIP_ADMIN_USER", "")
	setEnv(t, "ADMIRAL_FLAGSHIP_ADMIN_PSWD", "")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", certFile)
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", keyFile)
	setEnv(t, "ADMIRAL_DATABASE_URL", "postgres://user:pass@localhost:5432/admiral_core?sslmode=require")
	setEnv(t, "ADMIRAL_QUEUE_DATABASE_URL", "postgres://queue:pass@localhost:5432/admiral_queue?sslmode=require")
	setEnv(t, "ADMIRAL_NETWORKING_BASE_DOMAIN", "cloud.example.com")
	setEnv(t, "ADMIRAL_NETWORKING_APPS_REDIRECT_TO", "portal.cloud.example.com")

	cfg, err := load("/tmp/does-not-exist.ini")
	if err != nil {
		t.Fatalf("load returned error: %v", err)
	}
	if cfg.NetworkingAdminHost != "admin.cloud.example.com" {
		t.Fatalf("unexpected admin host %q", cfg.NetworkingAdminHost)
	}
	if cfg.NetworkingPortalHost != "portal.cloud.example.com" {
		t.Fatalf("unexpected portal host %q", cfg.NetworkingPortalHost)
	}
	if cfg.NetworkingAppsDomain != "apps.cloud.example.com" {
		t.Fatalf("unexpected apps domain %q", cfg.NetworkingAppsDomain)
	}
	if cfg.NetworkingAppsRedirect != "portal.cloud.example.com" {
		t.Fatalf("unexpected redirect target %q", cfg.NetworkingAppsRedirect)
	}
}

func TestRedactURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"postgres://user:pass@db.example.com:5432/admiral?sslmode=disable", "postgres://REDACTED:REDACTED@db.example.com:5432/admiral?sslmode=disable"},
		{"postgres://user@db.example.com:5432/admiral", "postgres://REDACTED@db.example.com:5432/admiral"},
		{"postgres://:pass@db.example.com:5432/admiral", "postgres://:REDACTED@db.example.com:5432/admiral"},
		{"postgres://db.example.com:5432/admiral", "postgres://db.example.com:5432/admiral"},
		{"not-a-url", "not-a-url"},
	}
	for _, tt := range tests {
		got := RedactURL(tt.input)
		if got != tt.want {
			t.Errorf("RedactURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestLoadRejectsSameLogicalDatabase(t *testing.T) {
	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")

	setEnv(t, "ADMIRAL_ENV", "development")
	setEnv(t, "ADMIRAL_ADMIN_TOKEN", "dev-token")
	setEnv(t, "ADMIRAL_TOKEN_PEPPER", "dev-pepper")
	setEnv(t, "ADMIRAL_SECRETS_KEY", "")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", certFile)
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", keyFile)
	setEnv(t, "ADMIRAL_DATABASE_URL", "postgres://user:pass@localhost:5432/admiral?sslmode=require")
	setEnv(t, "ADMIRAL_QUEUE_DATABASE_URL", "postgres://queue:pass@localhost:5432/admiral?sslmode=require")

	_, err := load("/tmp/does-not-exist.ini")
	if err == nil {
		t.Fatal("expected error when core and queue DBs are the same")
	}
}

func TestLoadINI(t *testing.T) {
	tempDir := t.TempDir()
	iniFile := filepath.Join(tempDir, "admirald.ini")
	content := `
port = 9090
listen_address = 0.0.0.0
# Comment
; Another comment
invalid_line
database_url = postgres://localhost/admiral
`
	if err := os.WriteFile(iniFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	values := map[string]string{
		"port":           "8080",
		"listen_address": "127.0.0.1",
		"database_url":   "",
	}
	loadINI(iniFile, values)

	if values["port"] != "9090" {
		t.Errorf("expected port 9090, got %s", values["port"])
	}
	if values["listen_address"] != "0.0.0.0" {
		t.Errorf("expected listen_address 0.0.0.0, got %s", values["listen_address"])
	}
	if values["database_url"] != "postgres://localhost/admiral" {
		t.Errorf("expected database_url postgres://localhost/admiral, got %s", values["database_url"])
	}
}

func TestLoadWithTrustedProxies(t *testing.T) {
	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")

	setEnv(t, "ADMIRAL_ENV", "development")
	setEnv(t, "ADMIRAL_ADMIN_TOKEN", "dev-token")
	setEnv(t, "ADMIRAL_TOKEN_PEPPER", "dev-pepper")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", certFile)
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", keyFile)
	setEnv(t, "ADMIRAL_DATABASE_URL", "postgres://user:pass@localhost:5432/admiral_core?sslmode=require")
	setEnv(t, "ADMIRAL_QUEUE_DATABASE_URL", "postgres://queue:pass@localhost:5432/admiral_queue?sslmode=require")
	setEnv(t, "ADMIRAL_TRUSTED_PROXIES", "10.0.0.1, 10.0.0.2")

	cfg, err := load("/tmp/does-not-exist.ini")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[0] != "10.0.0.1" || cfg.TrustedProxies[1] != "10.0.0.2" {
		t.Errorf("unexpected trusted proxies: %v", cfg.TrustedProxies)
	}
}

func TestLoadWithTokenTTL(t *testing.T) {
	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")

	setEnv(t, "ADMIRAL_ENV", "development")
	setEnv(t, "ADMIRAL_ADMIN_TOKEN", "dev-token")
	setEnv(t, "ADMIRAL_TOKEN_PEPPER", "dev-pepper")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", certFile)
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", keyFile)
	setEnv(t, "ADMIRAL_DATABASE_URL", "postgres://user:pass@localhost:5432/admiral_core?sslmode=require")
	setEnv(t, "ADMIRAL_QUEUE_DATABASE_URL", "postgres://queue:pass@localhost:5432/admiral_queue?sslmode=require")

	t.Run("default TTL", func(t *testing.T) {
		cfg, err := load("/tmp/does-not-exist.ini")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.TokenTTLMinutes != 5 {
			t.Errorf("expected default TTL 5, got %d", cfg.TokenTTLMinutes)
		}
	})

	t.Run("INI TTL", func(t *testing.T) {
		iniFile := filepath.Join(tempDir, "ttl.ini")
		content := "token_ttl_minutes = 15\n"
		if err := os.WriteFile(iniFile, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := load(iniFile)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.TokenTTLMinutes != 15 {
			t.Errorf("expected INI TTL 15, got %d", cfg.TokenTTLMinutes)
		}
	})
}

func setEnv(t *testing.T, key, value string) {
	t.Helper()

	original, ok := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}

	t.Cleanup(func() {
		var err error
		if ok {
			err = os.Setenv(key, original)
		} else {
			err = os.Unsetenv(key)
		}
		if err != nil {
			t.Fatalf("restore %s: %v", key, err)
		}
	})
}

func writeTempFile(t *testing.T, dir, name string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}
