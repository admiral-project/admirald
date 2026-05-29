package api

import (
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestBuildServiceInfosMergesEnvironmentWithPrecedence(t *testing.T) {
	payload := admiral.AppDefinitionPayload{
		Name: "cacao-accounting",
		Services: map[string]admiral.YAMLService{
			"web": {
				Image: "example.com/app:1",
				Env: map[string]string{
					"APP_MODE":         "saas",
					"MAX_USERS":        "1",
					"ADMIRAL_APP_CODE": "bad",
				},
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
	services := buildServiceInfos(payload, tier, "inst_123", "tenant_456", map[string]map[string]string{})
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	env := services[0].Env
	if env["APP_MODE"] != "saas" {
		t.Fatalf("expected app env to remain, got %q", env["APP_MODE"])
	}
	if env["MAX_USERS"] != "2" {
		t.Fatalf("expected tier env to override app env, got %q", env["MAX_USERS"])
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
}
