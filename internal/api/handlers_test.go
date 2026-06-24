// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"reflect"
	"testing"

	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestScopeTaskSecrets(t *testing.T) {
	payload := admiral.AppDefinitionPayload{
		Services: map[string]admiral.YAMLService{
			"app": {
				Backup: &admiral.YAMLServiceBackup{Type: "none"},
			},
			"db": {
				Backup: &admiral.YAMLServiceBackup{
					Type:        "database",
					Engine:      "postgresql",
					DatabaseEnv: "POSTGRES_DB",
					UsernameEnv: "POSTGRES_USER",
					PasswordEnv: "POSTGRES_PASSWORD",
				},
			},
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
			got := scopeTaskSecrets(tt.action, payload, all, "db")
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("expected %#v, got %#v", tt.want, got)
			}
		})
	}
}

func TestParseHostPortsFromMetadata(t *testing.T) {
	metadata := `{"executor":"systemd-podman","action":"provision_app","host_ports":{"web":8080,"db":15432}}`
	got := parseHostPortsFromMetadata(metadata)
	want := map[string]int{"web": 8080, "db": 15432}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %#v, got %#v", want, got)
	}
}

func TestRetryableAction(t *testing.T) {
	tests := []struct {
		action admiral.TaskAction
		want   admiral.TaskAction
		status string
		ok     bool
	}{
		{action: admiral.ActionProvisionApp, want: admiral.ActionProvisionApp, status: "provisioning", ok: true},
		{action: admiral.ActionPauseApp, want: admiral.ActionPauseApp, status: "stopped", ok: true},
		{action: admiral.ActionReactivateApp, want: admiral.ActionReactivateApp, status: "running", ok: true},
		{action: admiral.ActionBackupDatabase, want: "", status: "", ok: false},
	}

	for _, tt := range tests {
		gotAction, gotStatus, gotOK := retryableAction(tt.action)
		if gotAction != tt.want || gotStatus != tt.status || gotOK != tt.ok {
			t.Fatalf("retryableAction(%q) = (%q, %q, %v), want (%q, %q, %v)", tt.action, gotAction, gotStatus, gotOK, tt.want, tt.status, tt.ok)
		}
	}
}

func TestParseSetupMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata string
		want     setupCallbackMetadata
	}{
		{
			name:     "empty metadata",
			metadata: "",
			want:     setupCallbackMetadata{},
		},
		{
			name:     "no setup fields",
			metadata: `{"host_ports":{"web":8080}}`,
			want:     setupCallbackMetadata{},
		},
		{
			name:     "has_setup true",
			metadata: `{"has_setup":true}`,
			want:     setupCallbackMetadata{HasSetup: true},
		},
		{
			name:     "setup_failed true with error",
			metadata: `{"has_setup":true,"setup_failed":true,"setup_error":"bench new-site failed"}`,
			want:     setupCallbackMetadata{HasSetup: true, SetupFailed: true, SetupError: "bench new-site failed"},
		},
		{
			name:     "invalid json",
			metadata: `{not valid`,
			want:     setupCallbackMetadata{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSetupMetadata(tt.metadata)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseSetupMetadata(%q) = %#v, want %#v", tt.metadata, got, tt.want)
			}
		})
	}
}
