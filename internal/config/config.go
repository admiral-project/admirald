package config

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/admiral-project/admiral/admirald/pkg/admiral/tlsconfig"
)

const defaultConfigPath = "/etc/admirald.ini"

type Config struct {
	Port           string
	DatabaseURL    string
	RabbitMQURL    string
	RabbitMQCAFile string
	SharedToken    string
	SecretsKey     string
	TLSCertFile    string
	TLSKeyFile     string
}

func Load() (*Config, error) {
	return load(defaultConfigPath)
}

func load(path string) (*Config, error) {
	values := map[string]string{
		"port":             "8080",
		"database_url":     "postgres://postgres:postgres@localhost:5432/admiral?sslmode=disable",
		"rabbitmq_url":     "amqps://guest:guest@localhost:5671/",
		"rabbitmq_ca_file": "",
		"shared_token":     "",
		"secrets_key":      "",
		"tls_cert_file":    "",
		"tls_key_file":     "",
	}

	loadINI(path, values)

	applyEnv(values, "port", "ADMIRAL_PORT")
	applyEnv(values, "database_url", "ADMIRAL_DATABASE_URL")
	applyEnv(values, "rabbitmq_url", "ADMIRAL_RABBITMQ_URL")
	applyEnv(values, "shared_token", "ADMIRAL_SHARED_TOKEN")
	applyEnv(values, "secrets_key", "ADMIRAL_SECRETS_KEY")
	applyEnv(values, "tls_cert_file", "ADMIRAL_TLS_CERT_FILE")
	applyEnv(values, "tls_key_file", "ADMIRAL_TLS_KEY_FILE")
	applyEnv(values, "rabbitmq_ca_file", "ADMIRAL_RABBITMQ_CA_FILE")

	if values["shared_token"] == "" {
		return nil, fmt.Errorf("shared_token is required via %s or ADMIRAL_SHARED_TOKEN", path)
	}
	if values["tls_cert_file"] == "" {
		return nil, fmt.Errorf("tls_cert_file is required via %s or ADMIRAL_TLS_CERT_FILE", path)
	}
	if values["tls_key_file"] == "" {
		return nil, fmt.Errorf("tls_key_file is required via %s or ADMIRAL_TLS_KEY_FILE", path)
	}
	if err := tlsconfig.ValidateURLScheme(values["rabbitmq_url"], "amqps"); err != nil {
		return nil, fmt.Errorf("invalid rabbitmq_url: %w", err)
	}
	for _, filePath := range []string{values["tls_cert_file"], values["tls_key_file"]} {
		if err := requireReadableFile(filePath); err != nil {
			return nil, err
		}
	}
	if values["rabbitmq_ca_file"] != "" {
		if err := requireReadableFile(values["rabbitmq_ca_file"]); err != nil {
			return nil, err
		}
	}

	if values["secrets_key"] == "" {
		values["secrets_key"] = values["shared_token"]
	}

	return &Config{
		Port:           values["port"],
		DatabaseURL:    values["database_url"],
		RabbitMQURL:    values["rabbitmq_url"],
		RabbitMQCAFile: values["rabbitmq_ca_file"],
		SharedToken:    values["shared_token"],
		SecretsKey:     values["secrets_key"],
		TLSCertFile:    values["tls_cert_file"],
		TLSKeyFile:     values["tls_key_file"],
	}, nil
}

func loadINI(path string, values map[string]string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if _, ok := values[key]; ok {
			values[key] = val
		}
	}
}

func applyEnv(values map[string]string, key, env string) {
	if val := os.Getenv(env); val != "" {
		values[key] = val
	}
}

func RedactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User == nil {
		return raw
	}

	username := parsed.User.Username()
	if _, hasPassword := parsed.User.Password(); hasPassword {
		if username != "" {
			parsed.User = url.UserPassword("REDACTED", "REDACTED")
		} else {
			parsed.User = url.UserPassword("", "REDACTED")
		}
		return parsed.String()
	}

	parsed.User = url.User("REDACTED")
	return parsed.String()
}

func requireReadableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("required file %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("required file %q is a directory", path)
	}
	return nil
}
