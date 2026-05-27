package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRequiresSharedToken(t *testing.T) {
	setEnv(t, "ADMIRAL_SHARED_TOKEN", "")
	setEnv(t, "ADMIRAL_SECRETS_KEY", "")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", "")
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", "")

	_, err := load("/tmp/does-not-exist.ini")
	if err == nil {
		t.Fatal("expected error when shared token is missing")
	}
}

func TestLoadUsesSharedTokenAsDefaultSecretsKey(t *testing.T) {
	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")

	setEnv(t, "ADMIRAL_SHARED_TOKEN", "dev-token")
	setEnv(t, "ADMIRAL_SECRETS_KEY", "")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", certFile)
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", keyFile)
	setEnv(t, "ADMIRAL_RABBITMQ_URL", "amqps://guest:guest@localhost:5671/")

	cfg, err := load("/tmp/does-not-exist.ini")
	if err != nil {
		t.Fatalf("load returned error: %v", err)
	}
	if cfg.SharedToken != "dev-token" {
		t.Fatalf("expected shared token to be loaded, got %q", cfg.SharedToken)
	}
	if cfg.SecretsKey != "dev-token" {
		t.Fatalf("expected secrets key fallback to shared token, got %q", cfg.SecretsKey)
	}
	if cfg.TLSCertFile != certFile {
		t.Fatalf("expected TLS cert file to be loaded, got %q", cfg.TLSCertFile)
	}
}

func TestLoadRejectsPlainAMQP(t *testing.T) {
	tempDir := t.TempDir()
	certFile := writeTempFile(t, tempDir, "server.crt")
	keyFile := writeTempFile(t, tempDir, "server.key")

	setEnv(t, "ADMIRAL_SHARED_TOKEN", "dev-token")
	setEnv(t, "ADMIRAL_TLS_CERT_FILE", certFile)
	setEnv(t, "ADMIRAL_TLS_KEY_FILE", keyFile)
	setEnv(t, "ADMIRAL_RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")

	_, err := load("/tmp/does-not-exist.ini")
	if err == nil {
		t.Fatal("expected error for plain AMQP URL")
	}
}

func TestRedactURL(t *testing.T) {
	got := RedactURL("postgres://user:pass@db.example.com:5432/admiral?sslmode=disable")
	want := "postgres://REDACTED:REDACTED@db.example.com:5432/admiral?sslmode=disable"
	if got != want {
		t.Fatalf("expected redacted URL %q, got %q", want, got)
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
	if err := ioutil.WriteFile(path, []byte("test"), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}
