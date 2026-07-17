package api

import (
	"fmt"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

func rejectLiteralAppSecrets(payload admiral.AppDefinitionPayload) error {
	for serviceName, service := range payload.Services {
		for envName, secret := range service.Secrets {
			if secret.Value != "" {
				return fmt.Errorf("literal secret value is not allowed at services.%s.secrets.%s; use generate or persist", serviceName, envName)
			}
		}
	}
	for envName, secret := range payload.Secrets {
		if secret.Value != "" {
			return fmt.Errorf("literal secret value is not allowed at secrets.%s; use generate or persist", envName)
		}
	}
	return nil
}

func redactAppDefinitionYAML(rawYAML string) (string, error) {
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(rawYAML), &payload); err != nil {
		return "", fmt.Errorf("parse stored app definition: %w", err)
	}
	for serviceName, service := range payload.Services {
		for envName, secret := range service.Secrets {
			secret.Value = ""
			service.Secrets[envName] = secret
		}
		payload.Services[serviceName] = service
	}
	for envName, secret := range payload.Secrets {
		secret.Value = ""
		payload.Secrets[envName] = secret
	}
	redacted, err := yaml.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal redacted app definition: %w", err)
	}
	return string(redacted), nil
}

func redactAppDefinition(app database.AppDefinition) (database.AppDefinition, error) {
	redacted, err := redactAppDefinitionYAML(app.RawYAML)
	if err != nil {
		return database.AppDefinition{}, err
	}
	app.RawYAML = redacted
	return app, nil
}

func redactAppDefinitions(apps []database.AppDefinition) ([]database.AppDefinition, error) {
	for i := range apps {
		redacted, err := redactAppDefinition(apps[i])
		if err != nil {
			return nil, err
		}
		apps[i] = redacted
	}
	return apps, nil
}
