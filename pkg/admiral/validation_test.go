// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package admiral

import "testing"

func TestValidateAppDefinitionWithServiceBackups(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "wordpress",
		DisplayName: "WordPress",
		Services: map[string]YAMLService{
			"web": {
				Image:  "docker.io/library/wordpress:6",
				Volume: "wp_content",
				Backup: &YAMLServiceBackup{
					Type: "volume",
				},
			},
			"db": {
				Image: "docker.io/library/postgres:16",
				Env: map[string]string{
					"POSTGRES_DB": "wordpress",
				},
				Secrets: map[string]YAMLSecret{
					"POSTGRES_USER":     {Generate: "username", Expose: true},
					"POSTGRES_PASSWORD": {Generate: "password", Expose: true},
				},
				Backup: &YAMLServiceBackup{
					Type:        "database",
					Engine:      "postgresql",
					DatabaseEnv: "POSTGRES_DB",
					UsernameEnv: "POSTGRES_USER",
					PasswordEnv: "POSTGRES_PASSWORD",
				},
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {
				CPU:          1,
				Memory:       "1G",
				Storage:      "10G",
				PriceMonthly: 10,
				Environment: map[string]string{
					"MAX_USERS": "3",
				},
				Backups: &BackupPolicy{
					Enabled:        true,
					Schedule:       "daily",
					Time:           "02:00",
					Timezone:       "UTC",
					Retention:      RetentionPolicy{Count: 7, Days: 30},
					BackupDatabase: true,
					BackupVolumes:  true,
				},
			},
		},
	}

	if err := ValidateAppDefinition(payload); err != nil {
		t.Fatalf("expected valid app definition: %v", err)
	}
}

func TestValidateAppDefinitionRejectsMissingServiceBackup(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "ghost",
		DisplayName: "Ghost",
		Services: map[string]YAMLService{
			"web": {
				Image: "docker.io/library/ghost:5",
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected missing service backup to fail")
	}
}

func TestValidateAppDefinitionRejectsInvalidSecretGenerator(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "bad",
		DisplayName: "Bad",
		Services: map[string]YAMLService{
			"app": {
				Image: "example.com/app:1",
				Backup: &YAMLServiceBackup{
					Type: "none",
				},
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
				Backup: &YAMLServiceBackup{Type: "none"},
			},
			"api": {
				Image:  "example.com/api:1",
				Port:   9090,
				Public: true,
				Backup: &YAMLServiceBackup{Type: "none"},
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
				Backup: &YAMLServiceBackup{Type: "none"},
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
			"web": {Image: "example.com/web:1", Backup: &YAMLServiceBackup{Type: "none"}},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected invalid app name to fail")
	}
}

func TestValidateAppDefinitionRejectsInvalidImage(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "badimg",
		DisplayName: "Bad Image",
		Services: map[string]YAMLService{
			"web": {
				Image:  "image; rm -rf /",
				Backup: &YAMLServiceBackup{Type: "none"},
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected invalid image with shell chars to fail")
	}
}

func TestValidateAppDefinitionRejectsImageWithNewline(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "nl",
		DisplayName: "Newline",
		Services: map[string]YAMLService{
			"web": {
				Image:  "docker.io/library/nginx\nAdminAuth=foo",
				Backup: &YAMLServiceBackup{Type: "none"},
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected image with newline to fail")
	}
}

func TestValidateAppDefinitionRejectsCommandWithShellChars(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "badcmd",
		DisplayName: "Bad Command",
		Services: map[string]YAMLService{
			"web": {
				Image:   "docker.io/library/nginx:1",
				Command: "/bin/sh -c 'id; rm -rf /'",
				Backup:  &YAMLServiceBackup{Type: "none"},
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected command with shell metacharacters to fail")
	}
}

func TestValidateAppDefinitionRejectsCommandWithBacktick(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "btick",
		DisplayName: "Backtick",
		Services: map[string]YAMLService{
			"web": {
				Image:   "docker.io/library/nginx:1",
				Command: "echo `whoami`",
				Backup:  &YAMLServiceBackup{Type: "none"},
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected command with backtick to fail")
	}
}

func TestValidateAppDefinitionAllowsValidImage(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "goodimg",
		DisplayName: "Good Image",
		Services: map[string]YAMLService{
			"web": {
				Image:  "docker.io/library/wordpress:6",
				Backup: &YAMLServiceBackup{Type: "none"},
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err != nil {
		t.Fatalf("expected valid image to pass: %v", err)
	}
}

func TestValidateAppDefinitionAllowsValidCommand(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "goodcmd",
		DisplayName: "Good Command",
		Services: map[string]YAMLService{
			"web": {
				Image:   "docker.io/library/nginx:1",
				Command: "/usr/sbin/nginx -g daemon off",
				Backup:  &YAMLServiceBackup{Type: "none"},
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err != nil {
		t.Fatalf("expected valid command to pass: %v", err)
	}
}

func TestValidateAppDefinitionRejectsInvalidTierEnvironmentName(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "sample",
		DisplayName: "Sample",
		Services: map[string]YAMLService{
			"web": {Image: "example.com/web:1", Backup: &YAMLServiceBackup{Type: "none"}},
		},
		Tiers: map[string]YAMLTier{
			"starter": {
				CPU:          1,
				Memory:       "1G",
				Storage:      "10G",
				PriceMonthly: 10,
				Environment: map[string]string{
					"MAX-APP": "1",
				},
			},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected invalid tier environment name to fail")
	}
}

func TestValidateRestoreSourceAllowsLocalPath(t *testing.T) {
	rec := &BackupRecord{StorageBackend: "local_path", StorageKey: "/var/lib/admiral/backups/test.tgz"}
	if err := ValidateRestoreSource(BackupRestoreSource{}, rec); err != nil {
		t.Fatalf("expected local_path restore to pass: %v", err)
	}
}

func TestValidateRestoreSourceAllowsHTTPS(t *testing.T) {
	src := BackupRestoreSource{Type: "https", URI: "https://storage.example.com/backups/test.tgz"}
	rec := &BackupRecord{}
	if err := ValidateRestoreSource(src, rec); err != nil {
		t.Fatalf("expected https restore to pass: %v", err)
	}
}

func TestValidateRestoreSourceRejectsPathTraversal(t *testing.T) {
	src := BackupRestoreSource{Type: "local_path", URI: "/var/lib/../../etc/passwd"}
	rec := &BackupRecord{}
	if err := ValidateRestoreSource(src, rec); err == nil {
		t.Fatal("expected path traversal to fail")
	}
}

func TestValidateRestoreSourceRejectsUnsupportedType(t *testing.T) {
	src := BackupRestoreSource{Type: "ftp"}
	rec := &BackupRecord{}
	if err := ValidateRestoreSource(src, rec); err == nil {
		t.Fatal("expected unsupported type to fail")
	}
}

func TestValidateRestoreSourceAllowsS3(t *testing.T) {
	src := BackupRestoreSource{Type: "s3", URI: "s3://my-bucket/backups/test.tgz"}
	rec := &BackupRecord{}
	if err := ValidateRestoreSource(src, rec); err != nil {
		t.Fatalf("expected s3 restore to pass: %v", err)
	}
}

func TestValidateRestoreSourceRejectsHTTP(t *testing.T) {
	src := BackupRestoreSource{Type: "https", URI: "http://example.com/backup.tgz"}
	rec := &BackupRecord{}
	if err := ValidateRestoreSource(src, rec); err == nil {
		t.Fatal("expected http scheme to fail")
	}
}

func TestValidateAppDefinitionRejectsReservedTierEnvironmentName(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "sample",
		DisplayName: "Sample",
		Services: map[string]YAMLService{
			"web": {Image: "example.com/web:1", Backup: &YAMLServiceBackup{Type: "none"}},
		},
		Tiers: map[string]YAMLTier{
			"starter": {
				CPU:          1,
				Memory:       "1G",
				Storage:      "10G",
				PriceMonthly: 10,
				Environment: map[string]string{
					"ADMIRAL_TENANT_ID": "fake",
				},
			},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected reserved tier environment name to fail")
	}
}
