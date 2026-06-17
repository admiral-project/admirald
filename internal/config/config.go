// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const defaultConfigPath = "/etc/admirald.ini"

type Config struct {
	Port                     string
	ListenAddress            string
	DatabaseURL              string
	QueueDatabaseURL         string
	AdminToken               string
	TokenPepper              string
	TokenTTLMinutes          int
	SecretsKey               string
	SigningKey               string
	FlagshipAdminUser        string
	FlagshipAdminPassword    string
	TLSCertFile              string
	TLSKeyFile               string
	NetworkingBaseDomain     string
	NetworkingAdminHost      string
	NetworkingAdminTarget    string
	NetworkingPortalHost     string
	NetworkingPortalTarget   string
	NetworkingAppsDomain     string
	NetworkingAppsRedirect   string
	NetworkingTLSProvider    string
	NetworkingTLSEmail       string
	NetworkingTLSCertFile    string
	NetworkingTLSKeyFile     string
	NetworkingFlagshipHost   string
	NetworkingFlagshipTarget string
	NetworkingCockpitHost    string
	NetworkingCockpitTarget  string
	CaddyAdminURL            string
}

func Load() (*Config, error) {
	return load(defaultConfigPath)
}

func load(path string) (*Config, error) {
	values := map[string]string{
		"port":                       "8080",
		"listen_address":             "127.0.0.1",
		"database_url":               "",
		"queue_database_url":         "",
		"admin_token":                "",
		"token_pepper":               "",
		"token_ttl_minutes":          "5",
		"secrets_key":                "",
		"signing_key":                "",
		"flagship_admin_user":        "",
		"flagship_admin_pswd":        "",
		"tls_cert_file":              "",
		"tls_key_file":               "",
		"networking_base_domain":     "",
		"networking_admin_host":      "",
		"networking_admin_target":    "",
		"networking_portal_host":     "",
		"networking_portal_target":   "https://127.0.0.1:5001",
		"networking_apps_domain":     "",
		"networking_apps_redirect":   "",
		"networking_tls_provider":    "letsencrypt",
		"networking_tls_email":       "",
		"networking_tls_cert_file":   "",
		"networking_tls_key_file":    "",
		"networking_flagship_host":   "",
		"networking_flagship_target": "https://127.0.0.1:5000",
		"networking_cockpit_host":    "",
		"networking_cockpit_target":  "http://127.0.0.1:9090",
		"caddy_admin_url":            "http://127.0.0.1:2019",
	}

	loadINI(path, values)

	applyEnv(values, "port", "ADMIRAL_PORT")
	applyEnv(values, "listen_address", "ADMIRAL_LISTEN_ADDRESS")
	applyEnv(values, "database_url", "DATABASE_URL")
	applyEnv(values, "database_url", "ADMIRAL_DATABASE_URL")
	applyEnv(values, "queue_database_url", "ADMIRAL_QUEUE_DATABASE_URL")
	applyEnv(values, "admin_token", "ADMIRAL_ADMIN_TOKEN")
	applyEnv(values, "token_pepper", "ADMIRAL_TOKEN_PEPPER")
	applyEnv(values, "secrets_key", "ADMIRAL_SECRETS_KEY")
	applyEnv(values, "signing_key", "ADMIRAL_ED25519_PRIVATE_KEY")
	applyEnv(values, "flagship_admin_user", "ADMIRAL_FLAGSHIP_ADMIN_USER")
	applyEnv(values, "flagship_admin_pswd", "ADMIRAL_FLAGSHIP_ADMIN_PSWD")
	applyEnv(values, "tls_cert_file", "ADMIRAL_TLS_CERT_FILE")
	applyEnv(values, "tls_key_file", "ADMIRAL_TLS_KEY_FILE")
	applyEnv(values, "networking_base_domain", "ADMIRAL_NETWORKING_BASE_DOMAIN")
	applyEnv(values, "networking_admin_host", "ADMIRAL_NETWORKING_ADMIN_HOSTNAME")
	applyEnv(values, "networking_admin_target", "ADMIRAL_NETWORKING_ADMIN_TARGET")
	applyEnv(values, "networking_portal_host", "ADMIRAL_NETWORKING_PORTAL_HOSTNAME")
	applyEnv(values, "networking_portal_target", "ADMIRAL_NETWORKING_PORTAL_TARGET")
	applyEnv(values, "networking_apps_domain", "ADMIRAL_NETWORKING_APPS_DOMAIN")
	applyEnv(values, "networking_apps_redirect", "ADMIRAL_NETWORKING_APPS_REDIRECT_TO")
	applyEnv(values, "networking_tls_provider", "ADMIRAL_NETWORKING_TLS_PROVIDER")
	applyEnv(values, "networking_tls_email", "ADMIRAL_NETWORKING_TLS_EMAIL")
	applyEnv(values, "networking_tls_cert_file", "ADMIRAL_NETWORKING_TLS_CERT_FILE")
	applyEnv(values, "networking_tls_key_file", "ADMIRAL_NETWORKING_TLS_KEY_FILE")
	applyEnv(values, "networking_flagship_host", "ADMIRAL_NETWORKING_FLAGSHIP_HOST")
	applyEnv(values, "networking_flagship_target", "ADMIRAL_NETWORKING_FLAGSHIP_TARGET")
	applyEnv(values, "networking_cockpit_host", "ADMIRAL_NETWORKING_COCKPIT_HOST")
	applyEnv(values, "networking_cockpit_target", "ADMIRAL_NETWORKING_COCKPIT_TARGET")
	applyEnv(values, "caddy_admin_url", "ADMIRAL_CADDY_ADMIN_URL")

	if values["admin_token"] == "" {
		return nil, fmt.Errorf("admin_token is required via %s or ADMIRAL_ADMIN_TOKEN", path)
	}
	if values["token_pepper"] == "" {
		return nil, fmt.Errorf("token_pepper is required via %s or ADMIRAL_TOKEN_PEPPER", path)
	}
	if values["database_url"] == "" {
		return nil, fmt.Errorf("database_url is required via %s, DATABASE_URL or ADMIRAL_DATABASE_URL", path)
	}
	if values["queue_database_url"] == "" {
		return nil, fmt.Errorf("queue_database_url is required via %s or ADMIRAL_QUEUE_DATABASE_URL", path)
	}
	if values["tls_cert_file"] == "" {
		return nil, fmt.Errorf("tls_cert_file is required via %s or ADMIRAL_TLS_CERT_FILE", path)
	}
	if values["tls_key_file"] == "" {
		return nil, fmt.Errorf("tls_key_file is required via %s or ADMIRAL_TLS_KEY_FILE", path)
	}
	for _, filePath := range []string{values["tls_cert_file"], values["tls_key_file"]} {
		if err := requireReadableFile(filePath); err != nil {
			return nil, err
		}
	}
	if sameLogicalDatabase(values["database_url"], values["queue_database_url"]) {
		return nil, fmt.Errorf("database_url and queue_database_url must reference different logical databases")
	}
	if values["networking_admin_host"] == "" && values["networking_base_domain"] != "" {
		values["networking_admin_host"] = "admin." + values["networking_base_domain"]
	}
	if values["networking_portal_host"] == "" && values["networking_base_domain"] != "" {
		values["networking_portal_host"] = "portal." + values["networking_base_domain"]
	}
	if values["networking_apps_domain"] == "" && values["networking_base_domain"] != "" {
		values["networking_apps_domain"] = "apps." + values["networking_base_domain"]
	}
	if values["networking_flagship_host"] == "" && values["networking_base_domain"] != "" {
		values["networking_flagship_host"] = "flagship." + values["networking_base_domain"]
	}
	if values["networking_cockpit_host"] == "" && values["networking_base_domain"] != "" {
		values["networking_cockpit_host"] = "cockpit." + values["networking_base_domain"]
	}
	if values["networking_tls_provider"] == "" {
		values["networking_tls_provider"] = "letsencrypt"
	}
	if values["caddy_admin_url"] == "" {
		values["caddy_admin_url"] = "http://127.0.0.1:2019"
	}

	ttl := 5
	if v := values["token_ttl_minutes"]; v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("token_ttl_minutes must be a number, got %q", v)
		}
		ttl = parsed
	}

	if values["secrets_key"] == "" {
		if os.Getenv("ADMIRAL_ENV") == "development" {
			values["secrets_key"] = "dev-ephemeral-key-change-me"
			fmt.Println("WARNING: ADMIRAL_SECRETS_KEY is missing. Using ephemeral key for development.")
			fmt.Println("WARNING: Encrypted secrets will not survive a restart if this key changes.")
		} else {
			return nil, fmt.Errorf("ADMIRAL_SECRETS_KEY is required in production. Please set it to a 32-character random string.")
		}
	}

	return &Config{
		Port:                     values["port"],
		ListenAddress:            values["listen_address"],
		DatabaseURL:              values["database_url"],
		QueueDatabaseURL:         values["queue_database_url"],
		AdminToken:               values["admin_token"],
		TokenPepper:              values["token_pepper"],
		TokenTTLMinutes:          ttl,
		SecretsKey:               values["secrets_key"],
		SigningKey:               values["signing_key"],
		FlagshipAdminUser:        values["flagship_admin_user"],
		FlagshipAdminPassword:    values["flagship_admin_pswd"],
		TLSCertFile:              values["tls_cert_file"],
		TLSKeyFile:               values["tls_key_file"],
		NetworkingBaseDomain:     values["networking_base_domain"],
		NetworkingAdminHost:      values["networking_admin_host"],
		NetworkingAdminTarget:    values["networking_admin_target"],
		NetworkingPortalHost:     values["networking_portal_host"],
		NetworkingPortalTarget:   values["networking_portal_target"],
		NetworkingAppsDomain:     values["networking_apps_domain"],
		NetworkingAppsRedirect:   values["networking_apps_redirect"],
		NetworkingTLSProvider:    values["networking_tls_provider"],
		NetworkingTLSEmail:       values["networking_tls_email"],
		NetworkingTLSCertFile:    values["networking_tls_cert_file"],
		NetworkingTLSKeyFile:     values["networking_tls_key_file"],
		NetworkingFlagshipHost:   values["networking_flagship_host"],
		NetworkingFlagshipTarget: values["networking_flagship_target"],
		NetworkingCockpitHost:    values["networking_cockpit_host"],
		NetworkingCockpitTarget:  values["networking_cockpit_target"],
		CaddyAdminURL:            values["caddy_admin_url"],
	}, nil
}

func loadINI(path string, values map[string]string) {
	path = filepath.Clean(path)
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

func sameLogicalDatabase(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	if ua.Scheme != ub.Scheme || ua.Host != ub.Host {
		return false
	}
	return strings.TrimPrefix(ua.Path, "/") == strings.TrimPrefix(ub.Path, "/")
}
