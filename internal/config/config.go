package config

import (
	"bufio"
	"os"
	"strings"
)

const defaultConfigPath = "/etc/admirald.ini"

type Config struct {
	Port        string
	DatabaseURL string
	RabbitMQURL string
	SharedToken string
	SecretsKey  string
}

func Load() *Config {
	values := map[string]string{
		"port":         "8080",
		"database_url": "postgres://postgres:postgres@localhost:5432/admiral?sslmode=disable",
		"rabbitmq_url": "amqp://guest:guest@localhost:5672/",
		"shared_token": "admiral-secret-token",
		"secrets_key":  "",
	}

	loadINI(defaultConfigPath, values)

	applyEnv(values, "port", "ADMIRAL_PORT")
	applyEnv(values, "database_url", "ADMIRAL_DATABASE_URL")
	applyEnv(values, "rabbitmq_url", "ADMIRAL_RABBITMQ_URL")
	applyEnv(values, "shared_token", "ADMIRAL_SHARED_TOKEN")
	applyEnv(values, "secrets_key", "ADMIRAL_SECRETS_KEY")

	if values["secrets_key"] == "" {
		values["secrets_key"] = values["shared_token"]
	}

	return &Config{
		Port:        values["port"],
		DatabaseURL: values["database_url"],
		RabbitMQURL: values["rabbitmq_url"],
		SharedToken: values["shared_token"],
		SecretsKey:  values["secrets_key"],
	}
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
