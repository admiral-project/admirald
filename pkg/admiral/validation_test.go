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
