// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package admiral

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v2"
)

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

func TestValidateERPNextExampleAppDefinition(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	examplePath := filepath.Join(filepath.Dir(file), "testdata", "erpnext.yaml")

	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("read erpnext example: %v", err)
	}

	var payload AppDefinitionPayload
	if err := yaml.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal erpnext example: %v", err)
	}

	if err := ValidateAppDefinition(payload); err != nil {
		t.Fatalf("expected erpnext example to validate, got %v", err)
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

func TestValidateAppDefinitionRejectsInvalidAppEnvironmentName(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "sample",
		DisplayName: "Sample",
		Environment: map[string]string{
			"MAX-APP": "1",
		},
		Services: map[string]YAMLService{
			"web": {Image: "example.com/web:1", Backup: &YAMLServiceBackup{Type: "none"}},
		},
		Tiers: map[string]YAMLTier{
			"starter": {
				CPU:          1,
				Memory:       "1G",
				Storage:      "10G",
				PriceMonthly: 10,
			},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected invalid app environment name to fail")
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

func TestValidateRestoreSourceEdgeCases(t *testing.T) {
	t.Run("empty source type defaults to record backend", func(t *testing.T) {
		src := BackupRestoreSource{Type: ""}
		rec := &BackupRecord{StorageBackend: "https", StorageKey: "https://example.com/b.tgz"}
		if err := ValidateRestoreSource(src, rec); err != nil {
			t.Errorf("expected empty source type to default to record backend, got %v", err)
		}
	})

	t.Run("local type mapped to local_path", func(t *testing.T) {
		src := BackupRestoreSource{Type: "local", URI: "/data/backup.tgz"}
		rec := &BackupRecord{}
		if err := ValidateRestoreSource(src, rec); err != nil {
			t.Errorf("expected 'local' type to be accepted as 'local_path', got %v", err)
		}
	})

	t.Run("URI defaults to record storage key", func(t *testing.T) {
		src := BackupRestoreSource{Type: "https", URI: ""}
		rec := &BackupRecord{StorageKey: "https://example.com/default.tgz"}
		if err := ValidateRestoreSource(src, rec); err != nil {
			t.Errorf("expected URI to default to record storage key, got %v", err)
		}
	})
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

func TestValidateAppDefinitionRejectsReservedAppEnvironmentName(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "sample",
		DisplayName: "Sample",
		Environment: map[string]string{
			"ADMIRAL_TENANT_ID": "fake",
		},
		Services: map[string]YAMLService{
			"web": {Image: "example.com/web:1", Backup: &YAMLServiceBackup{Type: "none"}},
		},
		Tiers: map[string]YAMLTier{
			"starter": {
				CPU:          1,
				Memory:       "1G",
				Storage:      "10G",
				PriceMonthly: 10,
			},
		},
	}

	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected reserved app environment name to fail")
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

func TestValidateAppDefinitionSharedVolumes(t *testing.T) {
	getPayload := func() AppDefinitionPayload {
		return AppDefinitionPayload{
			Name:        "shared-test",
			DisplayName: "Shared Test",
			Services: map[string]YAMLService{
				"app": {
					Image:  "nginx",
					Backup: &YAMLServiceBackup{Type: "none"},
				},
			},
			Tiers: map[string]YAMLTier{
				"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
			},
		}
	}

	t.Run("empty volume name", func(t *testing.T) {
		p := getPayload()
		p.SharedVolumes = map[string]YAMLSharedVolume{"": {Mount: "/data", Services: []string{"app"}}}
		if err := ValidateAppDefinition(p); err == nil || err.Error() != "shared volume name is required" {
			t.Errorf("expected error 'shared volume name is required', got %v", err)
		}
	})

	t.Run("invalid volume name", func(t *testing.T) {
		p := getPayload()
		p.SharedVolumes = map[string]YAMLSharedVolume{"Bad_Name": {Mount: "/data", Services: []string{"app"}}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for invalid shared volume name")
		}
	})

	t.Run("non-absolute mount path", func(t *testing.T) {
		p := getPayload()
		p.SharedVolumes = map[string]YAMLSharedVolume{"data": {Mount: "data", Services: []string{"app"}}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for non-absolute shared volume mount path")
		}
	})

	t.Run("no services for volume", func(t *testing.T) {
		p := getPayload()
		p.SharedVolumes = map[string]YAMLSharedVolume{"data": {Mount: "/data", Services: []string{}}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for shared volume without services")
		}
	})

	t.Run("undefined service reference", func(t *testing.T) {
		p := getPayload()
		p.SharedVolumes = map[string]YAMLSharedVolume{"data": {Mount: "/data", Services: []string{"ghost"}}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for shared volume referencing undefined service")
		}
	})

	t.Run("private and shared volume conflict", func(t *testing.T) {
		p := getPayload()
		p.Services["app"] = YAMLService{
			Image:  "postgres:16", // default mount /var/lib/postgresql/data
			Volume: "private-db",
			Backup: &YAMLServiceBackup{Type: "none"},
		}
		p.SharedVolumes = map[string]YAMLSharedVolume{
			"shared-db": {
				Mount:    "/var/lib/postgresql/data",
				Services: []string{"app"},
			},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for private and shared volume mount conflict")
		}
	})
}

func TestValidateAppDefinitionServiceBackups(t *testing.T) {
	getPayload := func() AppDefinitionPayload {
		return AppDefinitionPayload{
			Name:        "svc-backup-test",
			DisplayName: "Svc Backup Test",
			Services: map[string]YAMLService{
				"app": {
					Image:  "nginx",
					Backup: &YAMLServiceBackup{Type: "none"},
				},
			},
			Tiers: map[string]YAMLTier{
				"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
			},
		}
	}

	t.Run("empty backup type", func(t *testing.T) {
		p := getPayload()
		p.Services["app"] = YAMLService{
			Image:  "nginx",
			Backup: &YAMLServiceBackup{Type: ""},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for empty backup type")
		}
	})

	t.Run("unsupported backup type", func(t *testing.T) {
		p := getPayload()
		p.Services["app"] = YAMLService{
			Image:  "nginx",
			Backup: &YAMLServiceBackup{Type: "cloud"},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for unsupported backup type")
		}
	})

	t.Run("none type with database fields", func(t *testing.T) {
		p := getPayload()
		p.Services["app"] = YAMLService{
			Image: "nginx",
			Backup: &YAMLServiceBackup{
				Type:   "none",
				Engine: "postgresql",
			},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for none type with database fields")
		}
	})

	t.Run("database type missing engine", func(t *testing.T) {
		p := getPayload()
		p.Services["app"] = YAMLService{
			Image: "nginx",
			Backup: &YAMLServiceBackup{
				Type: "database",
			},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for database type without engine")
		}
	})

	t.Run("database type unsupported engine", func(t *testing.T) {
		p := getPayload()
		p.Services["app"] = YAMLService{
			Image: "nginx",
			Backup: &YAMLServiceBackup{
				Type:   "database",
				Engine: "sqlite",
			},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for database type with unsupported engine")
		}
	})

	t.Run("database type missing env references", func(t *testing.T) {
		p := getPayload()
		p.Services["app"] = YAMLService{
			Image: "nginx",
			Backup: &YAMLServiceBackup{
				Type:        "database",
				Engine:      "postgresql",
				DatabaseEnv: "DB_NAME",
				// UsernameEnv and PasswordEnv missing
			},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for database type with missing env references")
		}
	})

	t.Run("database type undefined env reference", func(t *testing.T) {
		p := getPayload()
		p.Services["app"] = YAMLService{
			Image: "nginx",
			Backup: &YAMLServiceBackup{
				Type:        "database",
				Engine:      "postgresql",
				DatabaseEnv: "DB_NAME",
				UsernameEnv: "DB_USER",
				PasswordEnv: "DB_PASS",
			},
			Env: map[string]string{
				"DB_NAME": "test",
				"DB_USER": "user",
				// DB_PASS missing
			},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for database type with undefined env reference")
		}
	})

	t.Run("volume type missing volumes", func(t *testing.T) {
		p := getPayload()
		p.Services["app"] = YAMLService{
			Image: "nginx",
			Backup: &YAMLServiceBackup{
				Type: "volume",
			},
		}
		// No volume and no shared volumes
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for volume type without declared volume or shared volume")
		}
	})

	t.Run("volume type with database fields", func(t *testing.T) {
		p := getPayload()
		p.Services["app"] = YAMLService{
			Image:  "nginx",
			Volume: "data",
			Backup: &YAMLServiceBackup{
				Type:   "volume",
				Engine: "postgresql",
			},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for volume type with database fields")
		}
	})
}

func TestValidateAppDefinitionTiers(t *testing.T) {
	getPayload := func() AppDefinitionPayload {
		return AppDefinitionPayload{
			Name:        "tier-test",
			DisplayName: "Tier Test",
			Services: map[string]YAMLService{
				"app": {
					Image:  "nginx",
					Backup: &YAMLServiceBackup{Type: "none"},
				},
			},
			Tiers: map[string]YAMLTier{
				"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
			},
		}
	}

	t.Run("empty tier name", func(t *testing.T) {
		p := getPayload()
		p.Tiers = map[string]YAMLTier{"": {CPU: 1, Memory: "1G", Storage: "10G"}}
		if err := ValidateAppDefinition(p); err == nil || err.Error() != "tier name is required" {
			t.Errorf("expected error 'tier name is required', got %v", err)
		}
	})

	t.Run("invalid cpu", func(t *testing.T) {
		p := getPayload()
		p.Tiers = map[string]YAMLTier{"starter": {CPU: 0, Memory: "1G", Storage: "10G"}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for zero or negative CPU")
		}
	})

	t.Run("empty memory", func(t *testing.T) {
		p := getPayload()
		p.Tiers = map[string]YAMLTier{"starter": {CPU: 1, Memory: "", Storage: "10G"}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for empty memory")
		}
	})

	t.Run("invalid memory format", func(t *testing.T) {
		p := getPayload()
		p.Tiers = map[string]YAMLTier{"starter": {CPU: 1, Memory: "1XG", Storage: "10G"}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for invalid memory format")
		}
	})

	t.Run("empty storage", func(t *testing.T) {
		p := getPayload()
		p.Tiers = map[string]YAMLTier{"starter": {CPU: 1, Memory: "1G", Storage: ""}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for empty storage")
		}
	})

	t.Run("invalid storage format", func(t *testing.T) {
		p := getPayload()
		p.Tiers = map[string]YAMLTier{"starter": {CPU: 1, Memory: "1G", Storage: "invalid"}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for invalid storage format")
		}
	})

	t.Run("zero storage", func(t *testing.T) {
		p := getPayload()
		p.Tiers = map[string]YAMLTier{"starter": {CPU: 1, Memory: "1G", Storage: "0G"}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for zero storage")
		}
	})

	t.Run("negative price", func(t *testing.T) {
		p := getPayload()
		p.Tiers = map[string]YAMLTier{"starter": {CPU: 1, Memory: "1G", Storage: "10G", PriceMonthly: -1}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for negative price_monthly")
		}
	})

	t.Run("free but has price", func(t *testing.T) {
		p := getPayload()
		p.Tiers = map[string]YAMLTier{"starter": {CPU: 1, Memory: "1G", Storage: "10G", Free: true, PriceMonthly: 10}}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for tier marked free but having a price")
		}
	})

	t.Run("invalid backup schedule", func(t *testing.T) {
		p := getPayload()
		p.Tiers["starter"] = YAMLTier{
			CPU:     1,
			Memory:  "1G",
			Storage: "10G",
			Backups: &BackupPolicy{
				Enabled:  true,
				Schedule: "monthly",
			},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for unsupported backup schedule")
		}
	})

	t.Run("invalid retention count", func(t *testing.T) {
		p := getPayload()
		p.Tiers["starter"] = YAMLTier{
			CPU:     1,
			Memory:  "1G",
			Storage: "10G",
			Backups: &BackupPolicy{
				Enabled:   true,
				Schedule:  "daily",
				Retention: RetentionPolicy{Count: 0, Days: 30},
			},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for zero backup retention count")
		}
	})

	t.Run("invalid retention days", func(t *testing.T) {
		p := getPayload()
		p.Tiers["starter"] = YAMLTier{
			CPU:     1,
			Memory:  "1G",
			Storage: "10G",
			Backups: &BackupPolicy{
				Enabled:   true,
				Schedule:  "daily",
				Retention: RetentionPolicy{Count: 7, Days: 0},
			},
		}
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for zero backup retention days")
		}
	})

	t.Run("enable volume backup but no volume", func(t *testing.T) {
		p := getPayload()
		p.Tiers["starter"] = YAMLTier{
			CPU:     1,
			Memory:  "1G",
			Storage: "10G",
			Backups: &BackupPolicy{
				Enabled:       true,
				Schedule:      "daily",
				Retention:     RetentionPolicy{Count: 7, Days: 30},
				BackupVolumes: true,
			},
		}
		// basePayload service 'app' has no volume and Backup.Type "none"
		if err := ValidateAppDefinition(p); err == nil {
			t.Error("expected error for enabling volume backup without any volume service")
		}
	})
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

func TestValidateAppDefinitionNotifyOnSetup(t *testing.T) {
	payload := AppDefinitionPayload{
		Name:        "notice-app",
		DisplayName: "Notice App",
		Services: map[string]YAMLService{
			"app": {
				Image: "example.com/app:1",
				NotifyOnSetup: []YAMLSetupNotice{
					{Label: "Usuario administrador", Value: "Administrator"},
				},
				Backup: &YAMLServiceBackup{Type: "none"},
			},
		},
		Tiers: map[string]YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G"},
		},
	}

	if err := ValidateAppDefinition(payload); err != nil {
		t.Fatalf("expected notify_on_setup to validate, got %v", err)
	}

	payload.Services["app"] = YAMLService{
		Image: "example.com/app:1",
		NotifyOnSetup: []YAMLSetupNotice{
			{Label: "", Value: "Administrator"},
		},
		Backup: &YAMLServiceBackup{Type: "none"},
	}
	if err := ValidateAppDefinition(payload); err == nil {
		t.Fatal("expected missing notify_on_setup label to fail")
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

func TestValidateTierEnvironment(t *testing.T) {
	t.Run("empty environment name", func(t *testing.T) {
		env := map[string]string{"": "value"}
		if err := ValidateTierEnvironment("starter", env); err == nil {
			t.Error("expected error for empty environment variable name")
		}
	})

	t.Run("invalid environment name", func(t *testing.T) {
		env := map[string]string{"invalid-name": "value"}
		if err := ValidateTierEnvironment("starter", env); err == nil {
			t.Error("expected error for invalid environment variable name")
		}
	})
}

func TestDefaultServiceVolumeMount(t *testing.T) {
	tests := []struct {
		name    string
		service string
		image   string
		want    string
	}{
		{"postgres image", "web", "docker.io/library/postgres:16", "/var/lib/postgresql/data"},
		{"mariadb image", "web", "mariadb:latest", "/var/lib/mysql"},
		{"mysql image", "web", "mysql:8", "/var/lib/mysql"},
		{"wordpress image", "web", "wordpress:6", "/var/www/html/wp-content"},
		{"db service name", "db", "alpine:latest", "/var/lib/postgresql/data"},
		{"default case", "app", "nginx:latest", "/data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultServiceVolumeMount(tt.service, tt.image)
			if got != tt.want {
				t.Errorf("defaultServiceVolumeMount(%q, %q) = %q, want %q", tt.service, tt.image, got, tt.want)
			}
		})
	}
}
