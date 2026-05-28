package admiral

import "testing"

func TestValidateAppDefinitionWithSecretsAndBackup(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "wordpress",
		DisplayName: "WordPress",
		Services: map[string]YAMLService{
			"db": {
				Image: "docker.io/library/postgres:16",
				Env: map[string]string{
					"POSTGRES_DB": "wordpress",
				},
				Secrets: map[string]YAMLSecret{
					"POSTGRES_USER":     {Generate: "username", Expose: true},
					"POSTGRES_PASSWORD": {Generate: "password", Expose: true},
				},
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G", PriceMonthly: 10},
		},
		Backup: &YAMLBackup{
			Type:        "database",
			Engine:      "postgresql",
			Service:     "db",
			DatabaseEnv: "POSTGRES_DB",
			UsernameEnv: "POSTGRES_USER",
			PasswordEnv: "POSTGRES_PASSWORD",
		},
	}

	if err := ValidateAppDefinition(payload); err != nil {
		t.Fatalf("expected valid app definition: %v", err)
	}
}

func TestValidateAppDefinitionRejectsInvalidSecretGenerator(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "bad",
		DisplayName: "Bad",
		Services: map[string]YAMLService{
			"app": {
				Image: "example.com/app:1",
				Secrets: map[string]YAMLSecret{
					"TOKEN": {Generate: "token"},
				},
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected invalid secret generator to fail")
	}
}

func TestValidateAppDefinitionRejectsMultiplePublicServices(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "multi",
		DisplayName: "Multi",
		Services: map[string]YAMLService{
			"web": {
				Image:  "example.com/web:1",
				Port:   8080,
				Public: true,
			},
			"api": {
				Image:  "example.com/api:1",
				Port:   9090,
				Public: true,
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected multiple public services to fail")
	}
}

func TestValidateAppDefinitionRejectsPublicServiceWithoutPort(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "nop",
		DisplayName: "No Port",
		Services: map[string]YAMLService{
			"web": {
				Image:  "example.com/web:1",
				Public: true,
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected public service without port to fail")
	}
}

func TestValidateAppDefinitionRejectsInvalidAppName(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "WikiApp",
		DisplayName: "Wiki",
		Services: map[string]YAMLService{
			"web": {Image: "example.com/web:1"},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected invalid app name to fail")
	}
}
