// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/logging"
)

func TestAdminAuthMiddleware(t *testing.T) {
	token := "secret-token"
	handler := AdminAuthMiddleware(logging.New("test"), token, func(w http.ResponseWriter, r *http.Request) {
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
