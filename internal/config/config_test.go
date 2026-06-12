// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRequiresSharedToken(t *testing.T) {
	setEnv(t, "ADMIRAL_SHARED_TOKEN", "")
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
	setEnv(t, "ADMIRAL_SHARED_TOKEN", "dev-token")
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
	setEnv(t, "ADMIRAL_SHARED_TOKEN", "dev-token")
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
	setEnv(t, "ADMIRAL_SHARED_TOKEN", "dev-token")
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
	setEnv(t, "ADMIRAL_SHARED_TOKEN", "dev-token")
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
	setEnv(t, "ADMIRAL_SHARED_TOKEN", "dev-token")
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
	got := RedactURL("postgres://user:pass@db.example.com:5432/admiral?sslmode=disable")
	want := "postgres://REDACTED:REDACTED@db.example.com:5432/admiral?sslmode=disable"
	if got != want {
		t.Fatalf("expected redacted URL %q, got %q", want, got)
	}
}

func TestLoadRejectsSameLogicalDatabase(t *testing.T) {
	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")

	setEnv(t, "ADMIRAL_ENV", "development")
	setEnv(t, "ADMIRAL_SHARED_TOKEN", "dev-token")
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
