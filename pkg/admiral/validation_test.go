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

func TestParseStorageBytes(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"1024", 1024},
		{"1K", 1024},
		{"1KB", 1024},
		{"1KiB", 1024},
		{"1M", 1024 * 1024},
		{"1MB", 1024 * 1024},
		{"1MiB", 1024 * 1024},
		{"1G", 1024 * 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"1GiB", 1024 * 1024 * 1024},
		{"1T", 1024 * 1024 * 1024 * 1024},
		{"1TB", 1024 * 1024 * 1024 * 1024},
		{"1TiB", 1024 * 1024 * 1024 * 1024},
		{"", 0},
		{"invalid", 0},
		{"-1G", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseStorageBytes(tt.input)
			if got != tt.want {
				t.Errorf("parseStorageBytes(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateHealthcheck(t *testing.T) {
	tests := []struct {
		name    string
		hc      *YAMLHealthCheck
		wantErr bool
	}{
		{"nil healthcheck", nil, false},
		{"valid http", &YAMLHealthCheck{Type: "http", Path: "/"}, false},
		{"http missing path", &YAMLHealthCheck{Type: "http"}, true},
		{"valid tcp", &YAMLHealthCheck{Type: "tcp", Port: 80}, false},
		{"tcp missing port", &YAMLHealthCheck{Type: "tcp"}, true},
		{"valid command", &YAMLHealthCheck{Type: "command", Command: []string{"ls"}}, false},
		{"command missing command", &YAMLHealthCheck{Type: "command"}, true},
		{"invalid type", &YAMLHealthCheck{Type: "invalid"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateHealthcheck("svc", tt.hc)
			if tt.wantErr && len(errs) == 0 {
				t.Errorf("expected error for %s, got none", tt.name)
			}
			if !tt.wantErr && len(errs) > 0 {
				t.Errorf("expected no error for %s, got %v", tt.name, errs)
			}
		})
	}
}

func TestValidateAppDefinitionEdgeCases(t *testing.T) {
	t.Run("missing name", func(t *testing.T) {
		payload := AppDefinitionPayload{}
		if err := ValidateAppDefinition(payload); err == nil || err.Error() != "name is required" {
			t.Errorf("expected 'name is required' error, got %v", err)
		}
	})

	t.Run("missing display_name", func(t *testing.T) {
		payload := AppDefinitionPayload{Name: "app"}
		if err := ValidateAppDefinition(payload); err == nil || err.Error() != "display_name is required" {
			t.Errorf("expected 'display_name is required' error, got %v", err)
		}
	})

	t.Run("no services", func(t *testing.T) {
		payload := AppDefinitionPayload{Name: "app", DisplayName: "App"}
		if err := ValidateAppDefinition(payload); err == nil || err.Error() != "at least one service is required" {
			t.Errorf("expected 'at least one service is required' error, got %v", err)
		}
	})

	t.Run("no tiers", func(t *testing.T) {
		payload := AppDefinitionPayload{
			Name:        "app",
			DisplayName: "App",
			Services:    map[string]YAMLService{"web": {Image: "img", Backup: &YAMLServiceBackup{Type: "none"}}},
		}
		if err := ValidateAppDefinition(payload); err == nil || err.Error() != "at least one tier is required" {
			t.Errorf("expected 'at least one tier is required' error, got %v", err)
		}
	})

	t.Run("top-level secrets", func(t *testing.T) {
		payload := AppDefinitionPayload{
			Name:        "app",
			DisplayName: "App",
			Services:    map[string]YAMLService{"web": {Image: "img", Backup: &YAMLServiceBackup{Type: "none"}}},
			Tiers:       map[string]YAMLTier{"starter": {CPU: 1, Memory: "1G", Storage: "10G"}},
			Secrets: map[string]YAMLSecret{
				"SECRET": {Generate: "random"},
			},
		}
		if err := ValidateAppDefinition(payload); err != nil {
			t.Errorf("expected valid app definition with secrets, got %v", err)
		}

		payload.Secrets["BAD"] = YAMLSecret{Generate: "invalid"}
		if err := ValidateAppDefinition(payload); err == nil {
			t.Error("expected invalid generator to fail")
		}

		payload.Secrets["BOTH"] = YAMLSecret{Generate: "random", Value: "val"}
		if err := ValidateAppDefinition(payload); err == nil {
			t.Error("expected both generate and value to fail")
		}
	})

	t.Run("registry config", func(t *testing.T) {
		payload := AppDefinitionPayload{
			Name:        "app",
			DisplayName: "App",
			Services: map[string]YAMLService{
				"web": {
					Image:  "img",
					Backup: &YAMLServiceBackup{Type: "none"},
					Registry: &YAMLRegistry{
						Server:   "reg.example.com",
						Username: "user",
						Password: "pw",
					},
				},
			},
			Tiers: map[string]YAMLTier{"starter": {CPU: 1, Memory: "1G", Storage: "10G"}},
		}
		if err := ValidateAppDefinition(payload); err != nil {
			t.Errorf("expected valid app definition with registry, got %v", err)
		}

		payload.Services["web"].Registry.Server = ""
		if err := ValidateAppDefinition(payload); err == nil {
			t.Error("expected missing registry server to fail")
		}
	})

	t.Run("tier backups", func(t *testing.T) {
		payload := AppDefinitionPayload{
			Name:        "app",
			DisplayName: "App",
			Services:    map[string]YAMLService{"web": {Image: "img", Backup: &YAMLServiceBackup{Type: "none"}}},
			Tiers: map[string]YAMLTier{
				"starter": {
					CPU:     1,
					Memory:  "1G",
					Storage: "10G",
					Backups: &BackupPolicy{
						Enabled:        true,
						Schedule:       "daily",
						Retention:      RetentionPolicy{Count: 1, Days: 1},
						BackupDatabase: true,
					},
				},
			},
		}
		if err := ValidateAppDefinition(payload); err == nil {
			t.Error("expected tier enabling database backup without database service to fail")
		}
	})

}

func TestValidateAppDefinitionAllowsSharedVolumesAndDependsOn(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "erpnext",
		DisplayName: "ERPNext",
		SharedVolumes: map[string]YAMLSharedVolume{
			"sites": {
				Mount:    "/home/frappe/frappe-bench/sites",
				Services: []string{"backend", "worker"},
			},
		},
		Services: map[string]YAMLService{
			"backend": {
				Image:     "docker.io/frappe/erpnext:v15",
				Port:      8000,
				DependsOn: []string{"db", "redis"},
				Backup:    &YAMLServiceBackup{Type: "volume"},
			},
			"worker": {
				Image:     "docker.io/frappe/erpnext:v15",
				DependsOn: []string{"backend"},
				Backup:    &YAMLServiceBackup{Type: "none"},
			},
			"db": {
				Image: "docker.io/library/mariadb:10.11",
				Env: map[string]string{
					"MARIADB_DATABASE": "erpnext",
				},
				Secrets: map[string]YAMLSecret{
					"MARIADB_USER":     {Generate: "username"},
					"MARIADB_PASSWORD": {Generate: "password"},
				},
				Backup: &YAMLServiceBackup{
					Type:        "database",
					Engine:      "mariadb",
					DatabaseEnv: "MARIADB_DATABASE",
					UsernameEnv: "MARIADB_USER",
					PasswordEnv: "MARIADB_PASSWORD",
				},
			},
			"redis": {
				Image:  "docker.io/library/redis:7",
				Port:   6379,
				Backup: &YAMLServiceBackup{Type: "none"},
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G", PriceMonthly: 10},
		},
	}

	if err := ValidateAppDefinition(payload); err != nil {
		t.Fatalf("expected valid complex app definition: %v", err)
	}
}

func TestValidateAppDefinitionRejectsDuplicateServicePort(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "dupport",
		DisplayName: "Dup Port",
		Services: map[string]YAMLService{
			"redis-cache": {Image: "redis:7", Port: 6379, Backup: &YAMLServiceBackup{Type: "none"}},
			"redis-queue": {Image: "redis:7", Port: 6379, Backup: &YAMLServiceBackup{Type: "none"}},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected duplicate internal port to fail")
	}
}

func TestValidateAppDefinitionRejectsDependencyCycle(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "cycle",
		DisplayName: "Cycle",
		Services: map[string]YAMLService{
			"a": {Image: "example.com/a:1", DependsOn: []string{"b"}, Backup: &YAMLServiceBackup{Type: "none"}},
			"b": {Image: "example.com/b:1", DependsOn: []string{"a"}, Backup: &YAMLServiceBackup{Type: "none"}},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected dependency cycle to fail")
	}
}

func TestValidateAppDefinitionRejectsDuplicateSharedMount(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "dup-shared",
		DisplayName: "Dup Shared",
		SharedVolumes: map[string]YAMLSharedVolume{
			"sites": {Mount: "/srv/app/shared", Services: []string{"app"}},
			"cache": {Mount: "/srv/app/shared", Services: []string{"app"}},
		},
		Services: map[string]YAMLService{
			"app": {Image: "example.com/app:1", Backup: &YAMLServiceBackup{Type: "volume"}},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected duplicate shared mount to fail")
	}
}
