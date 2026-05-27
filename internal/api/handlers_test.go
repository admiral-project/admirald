package api

import (
	"reflect"
	"testing"

	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestScopeTaskSecrets(t *testing.T) {
	payload := admiral.AppDefinitionPayload{
		Services: map[string]admiral.YAMLService{
			"app": {},
			"db":  {},
		},
		Backup: &admiral.YAMLBackup{
			Service:     "db",
			DatabaseEnv: "POSTGRES_DB",
			UsernameEnv: "POSTGRES_USER",
			PasswordEnv: "POSTGRES_PASSWORD",
		},
	}
	all := map[string]map[string]string{
		"app": {
			"APP_SECRET": "app-secret",
		},
		"db": {
			"POSTGRES_DB":       "admiral",
			"POSTGRES_USER":     "postgres",
			"POSTGRES_PASSWORD": "pw",
			"UNUSED":            "skip",
		},
	}

	tests := []struct {
		name   string
		action admiral.TaskAction
		want   map[string]map[string]string
	}{
		{
			name:   "provision includes all secrets",
			action: admiral.ActionProvisionApp,
			want: map[string]map[string]string{
				"app": {
					"APP_SECRET": "app-secret",
				},
				"db": {
					"POSTGRES_DB":       "admiral",
					"POSTGRES_USER":     "postgres",
					"POSTGRES_PASSWORD": "pw",
					"UNUSED":            "skip",
				},
			},
		},
		{
			name:   "backup includes only referenced db secrets",
			action: admiral.ActionBackupDatabase,
			want: map[string]map[string]string{
				"db": {
					"POSTGRES_DB":       "admiral",
					"POSTGRES_USER":     "postgres",
					"POSTGRES_PASSWORD": "pw",
				},
			},
		},
		{
			name:   "pause includes no secrets",
			action: admiral.ActionPauseApp,
			want:   map[string]map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scopeTaskSecrets(tt.action, payload, all)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("expected %#v, got %#v", tt.want, got)
			}
		})
	}
}
