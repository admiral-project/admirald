// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/security"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

type mockPublisher struct {
	published []*admiral.FleetTask
	rejected  []*admiral.FleetTask
}

func (m *mockPublisher) PublishTask(task *admiral.FleetTask) error {
	m.published = append(m.published, task)
	return nil
}

func (m *mockPublisher) PublishRejectedTask(task *admiral.FleetTask, reason, result string) error {
	m.rejected = append(m.rejected, task)
	return nil
}

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

func TestHandleAdminChangePasswordRequiresAuthenticatedHeader(t *testing.T) {
	h := newAdminLoginTestHandler(t)

	reqBody, err := json.Marshal(admiral.AdminChangePasswordRequest{
		Username:        "admin",
		CurrentPassword: "super-secret-password",
		NewPassword:     "new-super-secret-password",
	})
	if err != nil {
		t.Fatalf("marshal change password request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/auth/change-password", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()

	h.HandleAdminChangePassword(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleAdminChangePasswordUsesAuthenticatedUser(t *testing.T) {
	h := newAdminLoginTestHandler(t)

	reqBody, err := json.Marshal(admiral.AdminChangePasswordRequest{
		Username:        "other-user",
		CurrentPassword: "super-secret-password",
		NewPassword:     "new-super-secret-password",
	})
	if err != nil {
		t.Fatalf("marshal change password request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/auth/change-password", bytes.NewReader(reqBody))
	req.Header.Set("X-Admiral-Admin-User", "admin")
	rec := httptest.NewRecorder()

	h.HandleAdminChangePassword(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	storedHash, _, err := h.db.GetAdminUser("admin")
	if err != nil {
		t.Fatalf("fetch updated admin user: %v", err)
	}
	ok, err := security.VerifyPassword("new-super-secret-password", storedHash)
	if err != nil {
		t.Fatalf("verify updated password: %v", err)
	}
	if !ok {
		t.Fatal("expected admin password to be updated for authenticated user")
	}
}

func TestHandleAdminUsersCreateAndList(t *testing.T) {
	h := newTestHandler(t, false)

	reqBody := bytes.NewReader([]byte(`{"username":"opsadmin","password":"strong-admin-password"}`))
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users", reqBody)
	rec := httptest.NewRecorder()
	h.HandleAdminUsers(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	rec = httptest.NewRecorder()
	h.HandleAdminUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var users []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &users); err != nil {
		t.Fatalf("unmarshal users: %v", err)
	}
	if len(users) != 1 || users[0]["username"] != "opsadmin" {
		t.Fatalf("unexpected users payload: %#v", users)
	}
}

func TestHandleAdminUsersSetPassword(t *testing.T) {
	h := newAdminLoginTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/admin/set-password", bytes.NewReader([]byte(`{"new_password":"rotated-admin-password"}`)))
	rec := httptest.NewRecorder()
	h.HandleAdminUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	storedHash, _, err := h.db.GetAdminUser("admin")
	if err != nil {
		t.Fatalf("fetch updated admin user: %v", err)
	}
	ok, err := security.VerifyPassword("rotated-admin-password", storedHash)
	if err != nil {
		t.Fatalf("verify rotated password: %v", err)
	}
	if !ok {
		t.Fatal("expected admin password to be updated")
	}
}

func newAdminLoginTestHandler(t *testing.T) *APIHandlers {
	t.Helper()
	return newTestHandler(t, true)
}

func newTestHandler(t *testing.T, seedAdmin bool) *APIHandlers {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}
	db, err := database.Connect(dbURL)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := database.RunMigrations(db.DB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	if seedAdmin {
		hash, err := security.HashPassword("super-secret-password")
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		if err := db.CreateAdminUser("admin", hash, false); err != nil {
			t.Fatalf("seed admin user: %v", err)
		}
	}

	return NewHandlers(db, logging.New("test"), nil, nil, nil, "test-hmac-key")
}

func TestHandleAdminInstancesList(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	_ = h.db.UpdateCustomerAppStatus("inst_001", "active", "running")

	req := httptest.NewRequest(http.MethodGet, "/api/admin/instances", nil)
	rec := httptest.NewRecorder()
	h.HandleAdminInstances(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var list struct {
		Items []map[string]interface{} `json:"items"`
		Page  int                      `json:"page"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(list.Items))
	}
	if list.Items[0]["id"] != "inst_001" {
		t.Fatalf("expected inst_001, got %v", list.Items[0]["id"])
	}
	if list.Page != 1 || list.Total != 1 {
		t.Fatalf("expected page=1 total=1, got page=%d total=%d", list.Page, list.Total)
	}
}

func TestHandleAdminInstancesGetByID(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	_ = h.db.UpdateCustomerAppStatus("inst_001", "active", "running")

	req := httptest.NewRequest(http.MethodGet, "/api/admin/instances/inst_001", nil)
	rec := httptest.NewRecorder()
	h.HandleAdminInstances(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var inst map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &inst); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if inst["id"] != "inst_001" {
		t.Fatalf("expected inst_001, got %v", inst["id"])
	}
}

func TestHandleAdminInstancesNotFound(t *testing.T) {
	h := newTestHandler(t, false)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/instances/nonexistent", nil)
	rec := httptest.NewRecorder()
	h.HandleAdminInstances(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestHandleAdminBackupsList(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	rec := &admiral.BackupRecord{
		ID:             "bk_001",
		InstanceID:     "inst_001",
		AppID:          "testapp",
		BackupType:     "database",
		DatabaseType:   "postgresql",
		Status:         "succeeded",
		StorageBackend: "local_path",
		StorageKey:     "/tmp/backup.tgz",
		SizeBytes:      1024,
		TriggeredBy:    "scheduler",
	}
	if err := h.db.CreateBackupRecord(rec); err != nil {
		t.Fatalf("create backup record: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/backups", nil)
	recorder := httptest.NewRecorder()
	h.HandleAdminBackups(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	var list struct {
		Items []map[string]interface{} `json:"items"`
		Page  int                      `json:"page"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected 1 backup, got %d", len(list.Items))
	}
	if list.Items[0]["id"] != "bk_001" {
		t.Fatalf("expected bk_001, got %v", list.Items[0]["id"])
	}
	if list.Page != 1 || list.Total != 1 {
		t.Fatalf("expected page=1 total=1, got page=%d total=%d", list.Page, list.Total)
	}
}

func TestHandleFleetCallbackSuccess(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	_ = h.db.UpdateCustomerAppStatus("inst_001", "active", "provisioning")
	if err := h.db.CreateOperation("op_001", "inst_001", "node_001", "provision_app", "running", ""); err != nil {
		t.Fatalf("create operation: %v", err)
	}

	callback := admiral.TaskResult{
		TaskID:      "task_001",
		OperationID: "op_001",
		NodeID:      "node_001",
		Success:     true,
		Logs:        "provisioned successfully",
	}
	body, _ := json.Marshal(callback)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleFleetCallback(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	op, err := h.db.GetOperation("op_001")
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op == nil {
		t.Fatal("operation not found")
	}
	if op.Status != "succeeded" {
		t.Fatalf("expected operation status succeeded, got %s", op.Status)
	}

	inst, _ := h.db.GetCustomerApp("inst_001")
	if inst.TechnicalStatus != "running" {
		t.Fatalf("expected instance technical_status running, got %s", inst.TechnicalStatus)
	}
}

func TestHandleFleetCallbackFailure(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	_ = h.db.UpdateCustomerAppStatus("inst_001", "active", "provisioning")
	if err := h.db.CreateOperation("op_002", "inst_001", "node_001", "provision_app", "running", ""); err != nil {
		t.Fatalf("create operation: %v", err)
	}

	callback := admiral.TaskResult{
		TaskID:      "task_002",
		OperationID: "op_002",
		NodeID:      "node_001",
		Success:     false,
		Error:       "container failed to start",
	}
	body, _ := json.Marshal(callback)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleFleetCallback(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	op, err := h.db.GetOperation("op_002")
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Status != "failed" {
		t.Fatalf("expected operation status failed, got %s", op.Status)
	}
	inst, _ := h.db.GetCustomerApp("inst_001")
	if inst.TechnicalStatus != "failed" {
		t.Fatalf("expected instance technical_status failed, got %s", inst.TechnicalStatus)
	}
}

func TestHandleFleetCallbackRejectsUnknownOperation(t *testing.T) {
	h := newTestHandler(t, false)

	callback := admiral.TaskResult{
		TaskID:      "task_003",
		OperationID: "op_unknown",
		NodeID:      "node_001",
		Success:     true,
	}
	body, _ := json.Marshal(callback)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleFleetCallback(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleFleetCallbackSchedulesBackupOnInstance(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	tierSnapshot := `{"name":"starter","cpu":1,"memory":"1G","storage":"10G","backup":{"enabled":true,"schedule":"daily","retention":{"count":7,"days":30}}}`
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", tierSnapshot); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	_ = h.db.UpdateCustomerAppStatus("inst_001", "active", "running")

	backups, err := h.db.GetBackupRecords("inst_001")
	if err != nil {
		t.Fatalf("get backup records: %v", err)
	}
	if len(backups) > 0 {
		t.Fatalf("expected no backups before scheduler, got %d", len(backups))
	}
}

func TestBuildServiceInfosTierEnvPrecedence(t *testing.T) {
	payload := admiral.AppDefinitionPayload{
		Name:        "envtest",
		DisplayName: "Env Test",
		Services: map[string]admiral.YAMLService{
			"web": {
				Image: "nginx",
				Env: map[string]string{
					"APP_LEVEL":   "app-value",
					"OVERRIDE_ME": "app-default",
				},
			},
		},
		Tiers: map[string]admiral.YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "10G", PriceMonthly: 10},
		},
	}
	tier := database.AppTier{
		Name: "starter", CPU: 1, Memory: "1G", Storage: "10G",
		Environment: map[string]string{
			"TIER_LEVEL":  "tier-value",
			"OVERRIDE_ME": "tier-override",
		},
	}
	allSecretValues := map[string]map[string]string{
		"web": {"SECRET_KEY": "sk-123"},
	}

	services := buildServiceInfos(payload, tier, "inst_001", "cust_001", allSecretValues)
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	svc := services[0]
	if svc.Env["APP_LEVEL"] != "app-value" {
		t.Fatalf("expected APP_LEVEL=app-value, got %s", svc.Env["APP_LEVEL"])
	}
	if svc.Env["TIER_LEVEL"] != "tier-value" {
		t.Fatalf("expected TIER_LEVEL=tier-value, got %s", svc.Env["TIER_LEVEL"])
	}
	if svc.Env["OVERRIDE_ME"] != "tier-override" {
		t.Fatalf("expected OVERRIDE_ME=tier-override (tier env has highest priority), got %s", svc.Env["OVERRIDE_ME"])
	}
	if svc.Secrets["SECRET_KEY"] != "sk-123" {
		t.Fatalf("expected SECRET_KEY=sk-123 in Secrets, got %v", svc.Secrets["SECRET_KEY"])
	}
}
