// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
)

type authLookupFailureConnector struct{}

func (authLookupFailureConnector) Connect(context.Context) (driver.Conn, error) {
	return authLookupFailureConn{}, nil
}

func (authLookupFailureConnector) Driver() driver.Driver {
	return authLookupFailureDriver{}
}

type authLookupFailureDriver struct{}

func (authLookupFailureDriver) Open(string) (driver.Conn, error) {
	return authLookupFailureConn{}, nil
}

type authLookupFailureConn struct{}

func (authLookupFailureConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepared query")
}

func (authLookupFailureConn) Close() error { return nil }

func (authLookupFailureConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}

func (authLookupFailureConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return nil, errors.New("database unavailable")
}

func TestNodeAuthDatabaseErrorsDoNotConsumeCredentialFailureBudget(t *testing.T) {
	db := &database.DB{DB: sql.OpenDB(authLookupFailureConnector{})}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})

	nextCalled := false
	handler := NodeAuthMiddleware(logging.New("test"), db, "test-pepper", "worker", nil, func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})

	for i := 0; i < authFailureLimit+5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/tasks/claim", nil)
		req.RemoteAddr = "198.51.100.20:1234"
		req.Header.Set("X-Admiral-Token", "valid-worker-token")
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("database lookup failure %d: status=%d body=%s, want %d", i+1, rec.Code, rec.Body.String(), http.StatusServiceUnavailable)
		}
		if got := rec.Header().Get("Retry-After"); got != "5" {
			t.Fatalf("database lookup failure %d: Retry-After=%q, want 5", i+1, got)
		}
	}

	if nextCalled {
		t.Fatal("request handler ran despite database lookup failures")
	}
}
