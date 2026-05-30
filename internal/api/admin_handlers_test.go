package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/security"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestHandleAdminLoginSuccess(t *testing.T) {
	h := newAdminLoginTestHandler(t)

	reqBody, err := json.Marshal(admiral.AdminLoginRequest{
		Username: "admin",
		Password: "super-secret-password",
	})
	if err != nil {
		t.Fatalf("marshal login request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/auth/login", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()

	h.HandleAdminLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp admiral.AdminLoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal login response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected login response token")
	}
	if resp.ExpiresAt == "" {
		t.Fatal("expected login response expiry")
	}
}

func TestHandleAdminLoginRejectsInvalidPassword(t *testing.T) {
	h := newAdminLoginTestHandler(t)

	reqBody, err := json.Marshal(admiral.AdminLoginRequest{
		Username: "admin",
		Password: "wrong-password",
	})
	if err != nil {
		t.Fatalf("marshal login request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/auth/login", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()

	h.HandleAdminLogin(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func newAdminLoginTestHandler(t *testing.T) *APIHandlers {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "admiral.db")
	db, err := database.Connect("sqlite://" + dbPath)
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	if err := database.RunMigrations(db.DB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	hash, err := security.HashPassword("super-secret-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := db.CreateAdminUser("admin", hash, false); err != nil {
		t.Fatalf("seed admin user: %v", err)
	}

	return NewHandlers(db, logging.New("test"), nil, nil, nil)
}
