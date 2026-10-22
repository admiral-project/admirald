// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigPathUsesSystemdCredential(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/admirald.service")

	want := "/run/credentials/admirald.service/admirald.ini"
	if got := configPath(); got != want {
		t.Fatalf("configPath() = %q, want %q", got, want)
	}
}

func TestLoadRejectsTemplatePlaceholdersInConfig(t *testing.T) {
	envNames := []string{
		"ADMIRAL_ENV", "ADMIRAL_PORT", "ADMIRAL_LISTEN_ADDRESS", "DATABASE_URL", "ADMIRAL_DATABASE_URL",
		"ADMIRAL_QUEUE_DATABASE_URL", "ADMIRAL_ADMIN_TOKEN", "ADMIRAL_HARBOR_API_TOKEN", "ADMIRAL_TOKEN_PEPPER",
		"ADMIRAL_SECRETS_KEY", "ADMIRAL_SECRETS_KEY_PREVIOUS", "ADMIRAL_ED25519_PRIVATE_KEY",
		"ADMIRAL_TASK_ENCRYPTION_KEY", "ADMIRAL_FLEET_CALLBACK_KEY", "ADMIRAL_SESSION_HMAC_KEY",
		"ADMIRAL_FLAGSHIP_ADMIN_USER", "ADMIRAL_FLAGSHIP_ADMIN_PSWD", "ADMIRAL_TLS_CERT_FILE", "ADMIRAL_TLS_KEY_FILE",
		"ADMIRAL_NETWORKING_BASE_DOMAIN", "ADMIRAL_NETWORKING_ADMIN_HOSTNAME", "ADMIRAL_NETWORKING_ADMIN_TARGET",
		"ADMIRAL_NETWORKING_PORTAL_HOSTNAME", "ADMIRAL_NETWORKING_PORTAL_TARGET", "ADMIRAL_NETWORKING_APPS_DOMAIN",
		"ADMIRAL_NETWORKING_APPS_REDIRECT_TO", "ADMIRAL_NETWORKING_TLS_PROVIDER", "ADMIRAL_NETWORKING_TLS_EMAIL",
		"ADMIRAL_NETWORKING_TLS_CERT_FILE", "ADMIRAL_NETWORKING_TLS_KEY_FILE", "ADMIRAL_NETWORKING_FLAGSHIP_HOST",
		"ADMIRAL_NETWORKING_FLAGSHIP_TARGET", "ADMIRAL_NETWORKING_COCKPIT_HOST", "ADMIRAL_NETWORKING_COCKPIT_TARGET",
		"ADMIRAL_CADDY_ADMIN_URL", "ADMIRAL_TRUSTED_PROXIES", "ADMIRAL_WIREGUARD_SUBNET", "ADMIRAL_WIREGUARD_HUB_IP",
	}
	for _, name := range envNames {
		t.Setenv(name, "")
	}
	t.Setenv("ADMIRAL_ENV", "production")

	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")
	baseConfig := []string{
		"database_url=postgres://user:pass@localhost:5432/admiral_core?sslmode=require",
		"queue_database_url=postgres://queue:pass@localhost:5432/admiral_queue?sslmode=require",
		"admin_token=valid-admin-token",
		"harbor_api_token=valid-harbor-token",
		"token_pepper=valid-token-pepper",
		"secrets_key=01234567890123456789012345678901",
		"signing_key=valid-signing-key",
		"task_encryption_key=valid-task-encryption-key",
		"fleet_callback_key=valid-fleet-callback-key",
		"session_hmac_key=valid-session-hmac-key",
		"flagship_admin_user=admin",
		"flagship_admin_pswd=valid-admin-password",
		"tls_cert_file=" + certFile,
		"tls_key_file=" + keyFile,
	}
	targetKeys := []string{
		"database_url", "queue_database_url", "admin_token", "harbor_api_token", "token_pepper", "secrets_key",
		"signing_key", "task_encryption_key", "fleet_callback_key", "session_hmac_key", "flagship_admin_user",
		"flagship_admin_pswd", "tls_cert_file", "tls_key_file",
	}
	configPath := filepath.Join(tempDir, "admirald.ini")
	for _, target := range targetKeys {
		t.Run(target, func(t *testing.T) {
			lines := append([]string(nil), baseConfig...)
			for i, line := range lines {
				key, _, ok := strings.Cut(line, "=")
				if ok && key == target {
					lines[i] = key + "=__REQUIRED__"
					break
				}
			}
			if err := os.WriteFile(configPath, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
				t.Fatalf("write test config: %v", err)
			}
			_, err := load(configPath)
			if err == nil || !strings.Contains(err.Error(), target) {
				t.Fatalf("load error = %v, want a placeholder rejection naming %q", err, target)
			}
		})
	}
}

func TestNormalizeWireguardNetwork(t *testing.T) {
	tests := []struct {
		name       string
		subnet     string
		hubIP      string
		wantSubnet string
		wantHubIP  string
		wantErr    bool
	}{
		{name: "default hub derives from subnet", subnet: "10.99.0.0/24", wantSubnet: "10.99.0.0/24", wantHubIP: "10.99.0.1"},
		{name: "custom subnet derives hub", subnet: "192.168.44.128/26", wantSubnet: "192.168.44.128/26", wantHubIP: "192.168.44.129"},
		{name: "explicit hub override", subnet: "192.168.44.0/24", hubIP: "192.168.44.10", wantSubnet: "192.168.44.0/24", wantHubIP: "192.168.44.10"},
		{name: "reject IPv6", subnet: "fd00::/64", wantErr: true},
		{name: "reject public subnet", subnet: "203.0.113.0/24", wantErr: true},
		{name: "reject subnet without a peer", subnet: "192.0.2.4/32", wantErr: true},
		{name: "reject hub outside subnet", subnet: "192.168.44.0/24", hubIP: "192.168.45.1", wantErr: true},
		{name: "reject broadcast as hub", subnet: "192.168.44.0/24", hubIP: "192.168.44.255", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subnet, hubIP, err := normalizeWireguardNetwork(tt.subnet, tt.hubIP)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeWireguardNetwork() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err == nil && (subnet != tt.wantSubnet || hubIP != tt.wantHubIP) {
				t.Fatalf("normalizeWireguardNetwork() = (%q, %q), want (%q, %q)", subnet, hubIP, tt.wantSubnet, tt.wantHubIP)
			}
		})
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
	setEnv(t, "ADMIRAL_WIREGUARD_SUBNET", "192.168.44.0/24")
	setEnv(t, "ADMIRAL_WIREGUARD_HUB_IP", "192.168.44.10")

	cfg, err := load("/tmp/does-not-exist.ini")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[0] != "10.0.0.1" || cfg.TrustedProxies[1] != "10.0.0.2" {
		t.Errorf("unexpected trusted proxies: %v", cfg.TrustedProxies)
	}
	if cfg.WireguardSubnet != "192.168.44.0/24" || cfg.WireguardHubIP != "192.168.44.10" {
		t.Errorf("unexpected WireGuard network: %s hub %s", cfg.WireguardSubnet, cfg.WireguardHubIP)
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
