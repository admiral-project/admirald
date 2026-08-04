package api

import "testing"

func TestIsValidUpdateType(t *testing.T) {
	valid := []string{"security_critical", "security", "bugfix", "improvement"}
	invalid := []string{"", "critical", "high", "low", "SECURITY_CRITICAL", "Security"}

	for _, v := range valid {
		if !isValidUpdateType(v) {
			t.Errorf("expected %q to be valid", v)
		}
	}
	for _, v := range invalid {
		if isValidUpdateType(v) {
			t.Errorf("expected %q to be invalid", v)
		}
	}
}
