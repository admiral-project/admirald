// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestBuildServiceInfosMergesEnvironmentWithPrecedence(t *testing.T) {
	payload := admiral.AppDefinitionPayload{
		Name: "cacao-accounting",
		Environment: map[string]string{
			"APP_MODE":            "agency",
			"GLOBAL_ONLY":         "yes",
			"MAX_USERS":           "0",
			"ADMIRAL_INSTANCE_ID": "bad",
		},
		SharedVolumes: map[string]admiral.YAMLSharedVolume{
			"shared-data": {
				Mount:    "/srv/app/shared",
				Services: []string{"web"},
			},
		},
		Services: map[string]admiral.YAMLService{
			"web": {
				Image:     "example.com/app:1",
				DependsOn: []string{"db"},
				Env: map[string]string{
					"APP_MODE":         "saas",
					"MAX_USERS":        "1",
					"ADMIRAL_APP_CODE": "bad",
				},
			},
			"db": {
				Image: "postgres:16",
			},
		},
	}
	tier := database.AppTier{
		Name: "basic",
		Environment: map[string]string{
			"MAX_USERS":         "2",
			"ENABLE_API_ACCESS": "false",
		},
	}
	services := buildServiceInfos(payload, tier, "inst_123", "tenant_456", "https://cacao123.apps.example.com/", map[string]map[string]string{})
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
	var web admiral.ServiceInfo
	for _, service := range services {
		if service.Name == "web" {
			web = service
			break
		}
	}
	if web.Name == "" {
		t.Fatal("expected web service in build output")
	}
	env := web.Env
	if env["APP_MODE"] != "saas" {
		t.Fatalf("expected service env to override app env, got %q", env["APP_MODE"])
	}
	if env["GLOBAL_ONLY"] != "yes" {
		t.Fatalf("expected app-level environment to propagate, got %q", env["GLOBAL_ONLY"])
	}
	if env["MAX_USERS"] != "2" {
		t.Fatalf("expected tier env to override merged env, got %q", env["MAX_USERS"])
	}
	if env["ADMIRAL_APP_CODE"] != "cacao-accounting" {
		t.Fatalf("expected admiral env to override reserved key, got %q", env["ADMIRAL_APP_CODE"])
	}
	if env["ADMIRAL_TIER_CODE"] != "basic" {
		t.Fatalf("expected tier code env, got %q", env["ADMIRAL_TIER_CODE"])
	}
	if env["ADMIRAL_INSTANCE_ID"] != "inst_123" {
		t.Fatalf("expected instance id env, got %q", env["ADMIRAL_INSTANCE_ID"])
	}
	if env["ADMIRAL_TENANT_ID"] != "tenant_456" {
		t.Fatalf("expected tenant id env, got %q", env["ADMIRAL_TENANT_ID"])
	}
	if env["ADMIRAL_PUBLIC_URL"] != "https://cacao123.apps.example.com/" {
		t.Fatalf("expected public URL env, got %q", env["ADMIRAL_PUBLIC_URL"])
	}
	if env["ADMIRAL_PUBLIC_HOSTNAME"] != "cacao123.apps.example.com" {
		t.Fatalf("expected public hostname env, got %q", env["ADMIRAL_PUBLIC_HOSTNAME"])
	}
	if len(web.DependsOn) != 1 || web.DependsOn[0] != "db" {
		t.Fatalf("expected depends_on to propagate, got %#v", web.DependsOn)
	}
	if len(web.SharedVolumes) != 1 || web.SharedVolumes[0].Name != "shared-data" {
		t.Fatalf("expected shared volume mount to propagate, got %#v", web.SharedVolumes)
	}
}

func TestBuildServiceInfosResolvesAppEnvironmentReferencesForSetup(t *testing.T) {
	payload := admiral.AppDefinitionPayload{
		Name: "gitea",
		Environment: map[string]string{
			"DB_TYPE":   "postgres",
			"DB_HOST":   "127.0.0.1:5432",
			"ROOT_HOST": "apps.example.test",
		},
		Services: map[string]admiral.YAMLService{
			"web": {
				Image:        "docker.io/gitea/gitea:1.22",
				SetupCommand: "gitea migrate",
				Env: map[string]string{
					"DB_TYPE":     "${DB_TYPE}",
					"DB_HOST":     "${DB_HOST}",
					"ROOT_URL":    "https://${ROOT_HOST}/",
					"DB_USER":     "${DB_USER}",
					"DB_PASSWORD": "${DB_PASSWORD}",
				},
			},
		},
	}
	secretValues := map[string]map[string]string{
		"web": {
			"DB_USER":     "gitea-user",
			"DB_PASSWORD": "gitea-pass",
		},
	}

	services := buildServiceInfos(payload, database.AppTier{Name: "small"}, "inst_1", "tenant_1", "", secretValues)
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	env := services[0].Env
	if env["DB_TYPE"] != "postgres" {
		t.Fatalf("expected DB_TYPE from app environment, got %q", env["DB_TYPE"])
	}
	if env["DB_HOST"] != "127.0.0.1:5432" {
		t.Fatalf("expected DB_HOST from app environment, got %q", env["DB_HOST"])
	}
	if env["ROOT_URL"] != "https://apps.example.test/" {
		t.Fatalf("expected interpolated ROOT_URL, got %q", env["ROOT_URL"])
	}
	if env["DB_USER"] != "gitea-user" {
		t.Fatalf("expected DB_USER from service secret, got %q", env["DB_USER"])
	}
	if env["DB_PASSWORD"] != "gitea-pass" {
		t.Fatalf("expected DB_PASSWORD from service secret, got %q", env["DB_PASSWORD"])
	}
}

func TestBuildServiceInfosPropagatesSetupCommand(t *testing.T) {
	payload := admiral.AppDefinitionPayload{
		Name: "suite-app",
		Services: map[string]admiral.YAMLService{
			"backend": {
				Image:        "example.com/app:1",
				Requires:     []string{"db"},
				SetupCommand: "app migrate --bootstrap",
				NotifyOnSetup: []admiral.YAMLSetupNotice{
					{Label: "Usuario administrador", Value: "Administrator"},
				},
				HealthCheck: &admiral.YAMLHealthCheck{
					Type:    "command",
					Command: []string{"app", "healthcheck"},
				},
				HealthCheckWaitSecs: 180,
				User:                "1000",
			},
			"frontend": {
				Image: "example.com/web:1",
			},
		},
	}
	tier := database.AppTier{Name: "dev"}
	services := buildServiceInfos(payload, tier, "inst_1", "tenant_1", "", nil)
	var backend, frontend admiral.ServiceInfo
	for _, s := range services {
		switch s.Name {
		case "backend":
			backend = s
		case "frontend":
			frontend = s
		}
	}
	if backend.SetupCommand != "app migrate --bootstrap" {
		t.Fatalf("expected backend setup_command to propagate, got %q", backend.SetupCommand)
	}
	if len(backend.NotifyOnSetup) != 1 || backend.NotifyOnSetup[0].Label != "Usuario administrador" {
		t.Fatalf("expected notify_on_setup to propagate, got %#v", backend.NotifyOnSetup)
	}
	if backend.HealthCheck == nil || backend.HealthCheck.Type != "command" {
		t.Fatalf("expected healthcheck to propagate, got %#v", backend.HealthCheck)
	}
	if len(backend.Requires) != 1 || backend.Requires[0] != "db" {
		t.Fatalf("expected requires to propagate, got %#v", backend.Requires)
	}
	if backend.HealthCheckWaitSecs != 180 {
		t.Fatalf("expected healthcheck wait timeout to propagate, got %d", backend.HealthCheckWaitSecs)
	}
	if backend.User != "1000" {
		t.Fatalf("expected user to propagate, got %q", backend.User)
	}
	if frontend.SetupCommand != "" {
		t.Fatalf("expected frontend setup_command to be empty, got %q", frontend.SetupCommand)
	}
}

func TestHasSetupCommand(t *testing.T) {
	tests := []struct {
		name    string
		payload admiral.AppDefinitionPayload
		want    bool
	}{
		{
			name: "no setup commands",
			payload: admiral.AppDefinitionPayload{
				Services: map[string]admiral.YAMLService{
					"web": {Image: "nginx:1"},
				},
			},
			want: false,
		},
		{
			name: "one service with setup command",
			payload: admiral.AppDefinitionPayload{
				Services: map[string]admiral.YAMLService{
					"web":     {Image: "nginx:1"},
					"backend": {Image: "app:1", SetupCommand: "init-db"},
				},
			},
			want: true,
		},
		{
			name: "setup command is whitespace only",
			payload: admiral.AppDefinitionPayload{
				Services: map[string]admiral.YAMLService{
					"web": {Image: "nginx:1", SetupCommand: "   "},
				},
			},
			want: false,
		},
		{
			name:    "empty services",
			payload: admiral.AppDefinitionPayload{},
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSetupCommand(tt.payload)
			if got != tt.want {
				t.Fatalf("hasSetupCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}
