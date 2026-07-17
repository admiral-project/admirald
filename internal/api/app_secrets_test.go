package api

import (
	"strings"
	"testing"

	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestRejectLiteralAppSecrets(t *testing.T) {
	payload := admiral.AppDefinitionPayload{
		Services: map[string]admiral.YAMLService{
			"database": {Secrets: map[string]admiral.YAMLSecret{"PASSWORD": {Value: "do-not-store"}}},
		},
	}
	if err := rejectLiteralAppSecrets(payload); err == nil {
		t.Fatal("expected literal secret to be rejected")
	}
}

func TestRedactAppDefinitionYAML(t *testing.T) {
	raw := `name: demo
services:
  database:
    image: postgres:16
    secrets:
      PASSWORD:
        value: do-not-return
      TOKEN:
        generate: hex
secrets:
  SHARED:
    value: also-do-not-return
tiers: {}
`
	redacted, err := redactAppDefinitionYAML(raw)
	if err != nil {
		t.Fatalf("redact app definition: %v", err)
	}
	if strings.Contains(redacted, "do-not-return") || strings.Contains(redacted, "also-do-not-return") {
		t.Fatalf("redacted YAML contains a literal secret: %s", redacted)
	}
	if !strings.Contains(redacted, "generate: hex") {
		t.Fatalf("redaction removed non-secret secret metadata: %s", redacted)
	}
}
