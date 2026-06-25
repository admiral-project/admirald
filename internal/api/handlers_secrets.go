package api

import (
	"strings"

	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func (h *APIHandlers) createInstanceSecrets(instanceID string, payload admiral.AppDefinitionPayload) ([]admiral.Credential, error) {
	// Load any existing secrets so persistent ones are reused.
	existingPlain := h.loadExistingPlainSecrets(instanceID)

	// First pass: generate all secrets for all services
	allPlain := make(map[string]map[string]string) // serviceName -> envName -> plaintext
	for serviceName, svc := range payload.Services {
		allPlain[serviceName] = make(map[string]string)
		for envName, secretDef := range svc.Secrets {
			var plain string
			switch {
			case secretDef.Persist:
				if existing, ok := existingPlain[serviceName][envName]; ok {
					plain = existing
				} else {
					plain = generateSecretKey()
				}
			case secretDef.Value != "":
				plain = secretDef.Value
			default:
				plain = generateSecretValue(secretDef.Generate)
			}
			allPlain[serviceName][envName] = plain
		}
	}

	// Generate top-level secrets (shared across services)
	allPlain["__global__"] = make(map[string]string)
	for envName, secretDef := range payload.Secrets {
		var plain string
		switch {
		case secretDef.Persist:
			if existing, ok := existingPlain["__global__"][envName]; ok {
				plain = existing
			} else {
				plain = generateSecretKey()
			}
		case secretDef.Value != "":
			plain = secretDef.Value
		default:
			plain = generateSecretValue(secretDef.Generate)
		}
		allPlain["__global__"][envName] = plain
	}

	// Second pass: normalize credentials that must match across services
	normalizeInstanceSecrets(allPlain, payload)

	// Encrypt and save
	var credentials []admiral.Credential
	for serviceName, svc := range payload.Services {
		for envName, secretDef := range svc.Secrets {
			plain := allPlain[serviceName][envName]

			encrypted, err := h.secrets.Encrypt(plain)
			if err != nil {
				return nil, err
			}
			if err := h.db.SaveInstanceSecret(instanceID, serviceName, envName, encrypted, secretDef.Expose); err != nil {
				return nil, err
			}
			if secretDef.Expose {
				credentials = append(credentials, admiral.Credential{Service: serviceName, Name: envName, Value: plain, Generate: secretDef.Generate})
			}
		}
	}
	// Save top-level secrets
	for envName, secretDef := range payload.Secrets {
		plain := allPlain["__global__"][envName]
		encrypted, err := h.secrets.Encrypt(plain)
		if err != nil {
			return nil, err
		}
		if err := h.db.SaveInstanceSecret(instanceID, "__global__", envName, encrypted, secretDef.Expose); err != nil {
			return nil, err
		}
		if secretDef.Expose {
			credentials = append(credentials, admiral.Credential{Service: "__global__", Name: envName, Value: plain, Generate: secretDef.Generate})
		}
	}
	credentials = append(credentials, buildSetupNotices(payload)...)
	return credentials, nil
}

func buildSetupNotices(payload admiral.AppDefinitionPayload) []admiral.Credential {
	credentials := make([]admiral.Credential, 0)
	for serviceName, svc := range payload.Services {
		for _, notice := range svc.NotifyOnSetup {
			label := strings.TrimSpace(notice.Label)
			value := strings.TrimSpace(notice.Value)
			if label == "" || value == "" {
				continue
			}
			credentials = append(credentials, admiral.Credential{
				Service: serviceName,
				Name:    label,
				Value:   value,
				Kind:    "notice",
			})
		}
	}
	return credentials
}

func (h *APIHandlers) loadExistingPlainSecrets(instanceID string) map[string]map[string]string {
	rows, err := h.db.GetInstanceSecrets(instanceID)
	if err != nil || len(rows) == 0 {
		return nil
	}
	result := make(map[string]map[string]string)
	for _, row := range rows {
		plain, err := h.secrets.Decrypt(row.EncryptedValue)
		if err != nil {
			continue
		}
		if result[row.ServiceName] == nil {
			result[row.ServiceName] = make(map[string]string)
		}
		result[row.ServiceName][row.EnvName] = plain
	}
	return result
}

// normalizeInstanceSecrets propagates database credentials from the database
// service to any client service (e.g., WORDPRESS_DB_USER gets MARIADB_USER's value).
func normalizeInstanceSecrets(all map[string]map[string]string, payload admiral.AppDefinitionPayload) {
	// Identify the database service — check for a DB image first, then fall back to volume.
	dbService := ""
	for name, svc := range payload.Services {
		img := strings.ToLower(svc.Image)
		if strings.Contains(img, "postgres") || strings.Contains(img, "mysql") || strings.Contains(img, "mariadb") {
			dbService = name
			break
		}
	}
	if dbService == "" {
		for name, svc := range payload.Services {
			if svc.Volume != "" {
				dbService = name
				break
			}
		}
	}
	if dbService == "" {
		return
	}

	dbSecrets := all[dbService]
	if dbSecrets == nil {
		return
	}

	// Find the DB user, password, and database env var names.
	// When both ROOT and non-root credentials exist, prefer the non-root variant.
	var dbUser, dbPass, dbRootPass, dbName string
	for envName := range dbSecrets {
		upper := strings.ToUpper(envName)
		if strings.HasSuffix(upper, "_USER") && (strings.HasPrefix(upper, "POSTGRES_") || strings.HasPrefix(upper, "MYSQL_") || strings.HasPrefix(upper, "MARIADB_")) {
			dbUser = envName
		}
		if strings.HasSuffix(upper, "_PASSWORD") && (strings.HasPrefix(upper, "POSTGRES_") || strings.HasPrefix(upper, "MYSQL_") || strings.HasPrefix(upper, "MARIADB_")) {
			if strings.Contains(upper, "_ROOT_") || strings.HasSuffix(upper, "_ROOT_PASSWORD") {
				dbRootPass = envName
			} else {
				dbPass = envName
			}
		}
		if strings.HasSuffix(upper, "_DATABASE") && (strings.HasPrefix(upper, "POSTGRES_") || strings.HasPrefix(upper, "MYSQL_") || strings.HasPrefix(upper, "MARIADB_")) {
			dbName = envName
		}
	}
	if dbPass == "" && dbRootPass != "" {
		dbPass = dbRootPass
	}

	// Propagate to client services
	for svcName, secrets := range all {
		if svcName == dbService || svcName == "__global__" {
			continue
		}
		for envName := range secrets {
			if exact, ok := dbSecrets[envName]; ok {
				all[svcName][envName] = exact
			}
			upper := strings.ToUpper(envName)
			if dbUser != "" && isDBUserEnv(upper) {
				all[svcName][envName] = dbSecrets[dbUser]
			}
			if dbPass != "" && isDBPasswordEnv(upper) {
				all[svcName][envName] = dbSecrets[dbPass]
			}
			if dbName != "" && isDBNameEnv(upper) {
				all[svcName][envName] = dbSecrets[dbName]
			}
		}
	}
}

// isDBUserEnv returns true if env name looks like it expects a database username.
func isDBUserEnv(upper string) bool {
	if strings.HasSuffix(upper, "_DB_USER") {
		return true
	}
	// Gitea-style: GITEA__DATABASE__USER
	return strings.Contains(upper, "__DATABASE__") && strings.HasSuffix(upper, "_USER")
}

// isDBPasswordEnv returns true if env name looks like it expects a database password.
func isDBPasswordEnv(upper string) bool {
	if strings.HasSuffix(upper, "_DB_PASSWORD") {
		return true
	}
	// Gitea-style: GITEA__DATABASE__PASSWD
	return strings.Contains(upper, "__DATABASE__") && (strings.HasSuffix(upper, "_PASSWORD") || strings.HasSuffix(upper, "_PASSWD"))
}

// isDBNameEnv returns true if env name looks like it expects a database name.
func isDBNameEnv(upper string) bool {
	if strings.HasSuffix(upper, "_DB_NAME") {
		return true
	}
	return strings.Contains(upper, "__DATABASE__") && strings.HasSuffix(upper, "_NAME")
}
