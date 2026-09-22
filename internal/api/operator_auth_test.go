// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func requestForScope(method, path string) *http.Request {
	return httptest.NewRequest(method, path, nil)
}

func TestScopeAllows(t *testing.T) {
	tests := []struct {
		name   string
		scope  string
		method string
		path   string
		want   bool
	}{
		{"admin allows destructive action", "admin", http.MethodDelete, "/api/v1/nodes/n1", true},
		{"read allows GET", "read", http.MethodGet, "/api/v1/instances", true},
		{"read rejects mutation", "read", http.MethodPost, "/api/v1/instances", false},
		{"write allows ordinary mutation", "write", http.MethodPost, "/api/v1/instances", true},
		{"write rejects node control", "write", http.MethodPost, "/api/v1/nodes/n1/disable", false},
		{"write rejects backup", "write", http.MethodPost, "/api/v1/backups", false},
		{"write rejects secrets", "write", http.MethodPut, "/api/v1/secrets/registry", false},
		{"write rejects restore", "write", http.MethodPost, "/api/v1/restore", false},
		{"write rejects delete", "write", http.MethodDelete, "/api/v1/instances/i1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scopeAllows(tt.scope, requestForScope(tt.method, tt.path)); got != tt.want {
				t.Fatalf("scopeAllows(%q, %s %s) = %v, want %v", tt.scope, tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestScopeAllowsUnknownScope(t *testing.T) {
	if scopeAllows("unknown", requestForScope(http.MethodPost, "/api/v1/apps")) {
		t.Fatal("unknown scope must not authorize mutations")
	}
}
