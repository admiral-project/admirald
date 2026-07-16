// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/logging"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	headers := map[string]string{
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none';",
	}

	for k, v := range headers {
		if got := rr.Header().Get(k); got != v {
			t.Errorf("header %q = %q, want %q", k, got, v)
		}
	}
}

func TestAdminAuthMiddleware(t *testing.T) {
	token := "secret-token"
	handler := AdminAuthMiddleware(logging.New("test"), token, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		token      string
		header     string
		wantStatus int
	}{
		{
			name:       "correct token in X-Admiral-Token",
			token:      token,
			header:     "X-Admiral-Token",
			wantStatus: http.StatusOK,
		},
		{
			name:       "correct token in Authorization Bearer",
			token:      "Bearer " + token,
			header:     "Authorization",
			wantStatus: http.StatusOK,
		},
		{
			name:       "incorrect token",
			token:      "wrong-token",
			header:     "X-Admiral-Token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "empty token",
			token:      "",
			header:     "X-Admiral-Token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "different length token",
			token:      "short",
			header:     "X-Admiral-Token",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.header != "" {
				req.Header.Set(tt.header, tt.token)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
			if rr.Code == http.StatusUnauthorized && rr.Body.String() != "{\"error\":\"unauthorized\"}\n" {
				t.Fatalf("expected generic unauthorized body, got %q", rr.Body.String())
			}
		})
	}
}

func TestAdminAuthMiddlewareProtectsHealthEndpoints(t *testing.T) {
	token := "secret-token"
	handler := AdminAuthMiddleware(logging.New("test"), token, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
	if rr.Body.String() != "{\"error\":\"unauthorized\"}\n" {
		t.Fatalf("expected generic unauthorized body, got %q", rr.Body.String())
	}
}

func TestAdminAuthMiddlewareTemporarilyBlocksRepeatedFailures(t *testing.T) {
	token := "secret-token"
	handler := AdminAuthMiddleware(logging.New("test"), token, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < authFailureLimit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = "198.51.100.10:1234"
		req.Header.Set("X-Admiral-Token", "wrong-token")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: expected 401, got %d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Header.Set("X-Admiral-Token", "wrong-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated failures, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header for temporary block")
	}
}

func TestAdminAuthMiddlewareResetsFailureCounterAfterSuccess(t *testing.T) {
	token := "secret-token"
	handler := AdminAuthMiddleware(logging.New("test"), token, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < authFailureLimit-1; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = "198.51.100.11:1234"
		req.Header.Set("X-Admiral-Token", "wrong-token")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: expected 401, got %d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}

	successReq := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	successReq.RemoteAddr = "198.51.100.11:1234"
	successReq.Header.Set("X-Admiral-Token", token)
	successRec := httptest.NewRecorder()
	handler.ServeHTTP(successRec, successReq)
	if successRec.Code != http.StatusOK {
		t.Fatalf("expected success to reset failures, got %d body=%s", successRec.Code, successRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.RemoteAddr = "198.51.100.11:1234"
	req.Header.Set("X-Admiral-Token", "wrong-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected counter reset after success, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHarborAuthMiddleware(t *testing.T) {
	adminToken := "admin-secret"
	harborToken := "harbor-secret"
	handler := HarborAuthMiddleware(logging.New("test"), adminToken, harborToken, nil, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		token      string
		header     string
		wantStatus int
	}{
		{
			name:       "harbor token in Authorization Bearer",
			token:      "Bearer " + harborToken,
			header:     "Authorization",
			wantStatus: http.StatusOK,
		},
		{
			name:       "harbor token in X-Admiral-Token",
			token:      harborToken,
			header:     "X-Admiral-Token",
			wantStatus: http.StatusOK,
		},
		{
			name:       "admin token also accepted",
			token:      adminToken,
			header:     "X-Admiral-Token",
			wantStatus: http.StatusOK,
		},
		{
			name:       "wrong token rejected",
			token:      "wrong-token",
			header:     "X-Admiral-Token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing token rejected",
			token:      "",
			header:     "X-Admiral-Token",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/harbor_ping", nil)
			if tt.header != "" {
				req.Header.Set(tt.header, tt.token)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
			if rr.Code == http.StatusUnauthorized && rr.Body.String() != "{\"error\":\"unauthorized\"}\n" {
				t.Fatalf("expected generic unauthorized body, got %q", rr.Body.String())
			}
		})
	}
}

func TestHarborAuthMiddlewareAcceptsHarborTokenForPing(t *testing.T) {
	adminToken := "admin-secret"
	harborToken := "harbor-secret"
	handler := HarborAuthMiddleware(logging.New("test"), adminToken, harborToken, nil, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	req := httptest.NewRequest("GET", "/api/v1/harbor_ping", nil)
	req.Header.Set("Authorization", "Bearer "+harborToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != `{"status":"ok"}` {
		t.Fatalf("expected ok body, got %q", rr.Body.String())
	}
}

func TestHarborAuthMiddlewareMarksAdminAsSystemPrincipal(t *testing.T) {
	called := false
	handler := HarborAuthMiddleware(logging.New("test"), "admin-secret", "harbor-secret", nil, func(w http.ResponseWriter, r *http.Request) {
		called = true
		if !isSystemPrincipal(r) {
			t.Fatal("expected admin token to create system principal")
		}
		if r.Header.Get("X-Admiral-Customer-ID") != "" {
			t.Fatal("admin request should not need a customer header")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/v1/customer-apps/inst-1", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !called {
		t.Fatalf("expected system-authenticated request, got status %d", rr.Code)
	}
}
