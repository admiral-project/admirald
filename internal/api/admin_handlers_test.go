// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/security"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"golang.org/x/crypto/bcrypt"
)

type migrationTestPublisher struct {
	db         *database.DB
	failAction admiral.TaskAction
	failNodeID string
	failed     bool
	published  []*admiral.FleetTask
}

func (m *migrationTestPublisher) PublishTask(task *admiral.FleetTask) error {
	m.published = append(m.published, task)
	status := "succeeded"
	errMsg := ""
	if !m.failed && task.Action == m.failAction && (m.failNodeID == "" || m.failNodeID == task.NodeID) {
		status = "failed"
		errMsg = "simulated " + string(task.Action) + " failure"
		m.failed = true
	}
	go func(operationID, status, errMsg string) {
		time.Sleep(25 * time.Millisecond)
		_ = m.db.UpdateOperation(operationID, status, errMsg)
	}(task.OperationID, status, errMsg)
	return nil
}

func (m *migrationTestPublisher) PublishRejectedTask(task *admiral.FleetTask, reason, result string) error {
	return nil
}

func migrationTestAppYAML() string {
	return "name: migrate-app\n" +
		"display_name: Migration Test App\n" +
		"description: migration test\n" +
		"services:\n" +
		"  database:\n" +
		"    image: docker.io/library/postgres:16\n" +
		"    backup:\n" +
		"      type: database\n" +
		"      engine: postgresql\n" +
		"      database_env: POSTGRES_DB\n" +
		"      username_env: POSTGRES_USER\n" +
		"      password_env: POSTGRES_PASSWORD\n" +
		"  volumes:\n" +
		"    image: docker.io/library/busybox:latest\n" +
		"    volume: /data\n" +
		"    backup:\n" +
		"      type: volume\n" +
		"tiers:\n" +
		"  starter:\n" +
		"    cpu: 1\n" +
		"    memory: 256M\n" +
		"    storage: 1G\n" +
		"    price_monthly: 1\n"
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
	if got := rec.Body.String(); got != "{\"error\":\"Invalid credentials\"}\n" {
		t.Fatalf("expected generic invalid credentials body, got %q", got)
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
	if got := rec.Body.String(); got != "{\"error\":\"unauthorized\"}\n" {
		t.Fatalf("expected generic unauthorized body, got %q", got)
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

func TestHandleAdminLogoutRequiresToken(t *testing.T) {
	h := newAdminLoginTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/auth/logout", nil)
	rec := httptest.NewRecorder()

	h.HandleAdminLogout(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "{\"error\":\"unauthorized\"}\n" {
		t.Fatalf("expected generic unauthorized body, got %q", got)
	}
}

func TestAdminSessionMiddlewareTemporarilyBlocksRepeatedFailures(t *testing.T) {
	h := newAdminLoginTestHandler(t)
	server := &Server{
		handlers:     h,
		log:          logging.New("test"),
		adminLimiter: NewRateLimiter(),
	}
	h.server = server

	handler := server.AdminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < authFailureLimit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/auth/me", nil)
		req.RemoteAddr = "198.51.100.20:1234"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: expected 401, got %d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/auth/me", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated failures, got %d body=%s", rr.Code, rr.Body.String())
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
	if err := db.TruncateTables(); err != nil {
		t.Fatalf("truncate tables: %v", err)
	}

	seedTestAppDefinition(t, db)

	if seedAdmin {
		hash, err := security.HashPassword("super-secret-password")
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		if err := db.CreateAdminUser("admin", hash, false); err != nil {
			t.Fatalf("seed admin user: %v", err)
		}
	}

	return NewHandlers(db, logging.New("test"), nil, nil, nil, "test-hmac-key", "test-pepper", 60, "")
}

func seedTestAppDefinition(t *testing.T, db *database.DB) {
	t.Helper()
	_ = db.SaveAppDefinition("testapp", "Test App", "App for testing", "name: testapp", nil)
	_ = db.SaveAppDefinition("migrate-app", "Migrate App", "App for migration testing", "name: migrate-app", nil)
	_ = db.SaveAppDefinition("status-app", "Status App", "App for status testing", "name: status-app", nil)
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

func TestSyncKnownHostInventoryWritesNodesAndNextAssignments(t *testing.T) {
	h := newTestHandler(t, false)
	tmpDir := t.TempDir()
	h.knowHostPath = filepath.Join(tmpDir, "know_host.yaml")

	if err := h.db.RegisterNode("worker-001", "worker-1", "10.0.0.11", "10.99.0.2", "worker", "203.0.113.11", "fedora", "5.0"); err != nil {
		t.Fatalf("register worker node: %v", err)
	}
	if err := h.db.RegisterNode("portal-001", "portal-1", "10.0.0.21", "10.99.0.100", "portal", "203.0.113.21", "fedora", "5.0"); err != nil {
		t.Fatalf("register portal node: %v", err)
	}

	if err := h.syncKnownHostInventory(); err != nil {
		t.Fatalf("sync know_host inventory: %v", err)
	}

	content, err := os.ReadFile(h.knowHostPath)
	if err != nil {
		t.Fatalf("read know_host inventory: %v", err)
	}
	text := string(content)
	for _, snippet := range []string{
		"worker-001:",
		"wireguard_ip: 10.99.0.2",
		"public_ip: 203.0.113.11",
		"portal-001:",
		"wireguard_ip: 10.99.0.100",
		"node_id: worker-002",
		"wireguard_ip: 10.99.0.3",
		"node_id: portal-002",
		"wireguard_ip: 10.99.0.101",
	} {
		if !strings.Contains(text, snippet) {
			t.Fatalf("expected know_host inventory to contain %q, got:\n%s", snippet, text)
		}
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

	if rec.Code != http.StatusNotFound && rec.Code != http.StatusForbidden {
		t.Fatalf("expected 404 or 403, got %d body=%s", rec.Code, rec.Body.String())
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

func TestHandleMigrateInstanceRejectsMissingTargetNode(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.RegisterNode("node_002", "worker-2", "10.0.0.2", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	_ = h.db.UpdateCustomerAppStatus("inst_001", "active", "running")

	body, _ := json.Marshal(admiral.MigrateAppRequest{TargetNodeID: ""})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/instances/inst_001/migrate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleAdminInstances(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing target_node_id, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleMigrateInstanceRejectsNonexistentInstance(t *testing.T) {
	h := newTestHandler(t, false)

	body, _ := json.Marshal(admiral.MigrateAppRequest{TargetNodeID: "node_002"})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/instances/nonexistent/migrate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleAdminInstances(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent instance, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleMigrateInstanceRejectsSameNode(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	_ = h.db.UpdateCustomerAppStatus("inst_001", "active", "running")

	body, _ := json.Marshal(admiral.MigrateAppRequest{TargetNodeID: "node_001"})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/instances/inst_001/migrate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleAdminInstances(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for same node, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleMigrateInstanceRejectsNonexistentTargetNode(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	_ = h.db.UpdateCustomerAppStatus("inst_001", "active", "running")

	body, _ := json.Marshal(admiral.MigrateAppRequest{TargetNodeID: "node_nonexistent"})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/instances/inst_001/migrate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleAdminInstances(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent target node, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleMigrateInstanceAcceptsValidRequest(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.RegisterNode("node_002", "worker-2", "10.0.0.2", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.UpdateNodeStatus("node_001", "active"); err != nil {
		t.Fatalf("activate node_001: %v", err)
	}
	if err := h.db.UpdateNodeStatus("node_002", "active"); err != nil {
		t.Fatalf("activate node_002: %v", err)
	}
	if err := h.db.SaveAppDefinition("testapp", "Test App", "desc", `{"name":"testapp","services":{"web":{"image":"nginx"}}}`, []database.AppTier{}); err != nil {
		t.Fatalf("save app definition: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	_ = h.db.UpdateCustomerAppStatus("inst_001", "active", "running")

	body, _ := json.Marshal(admiral.MigrateAppRequest{TargetNodeID: "node_002"})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/instances/inst_001/migrate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleAdminInstances(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp admiral.MigrateAppResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal migrate response: %v", err)
	}
	if resp.OperationID == "" {
		t.Fatal("expected non-empty operation_id")
	}
	if resp.InstanceID != "inst_001" {
		t.Fatalf("expected instance_id=inst_001, got %s", resp.InstanceID)
	}
	if resp.Status != "running" {
		t.Fatalf("expected status=running, got %s", resp.Status)
	}

	op, _ := h.db.GetOperation(resp.OperationID)
	if op == nil {
		t.Fatal("expected operation to be created")
	}
	if op.Action != "migrate" {
		t.Fatalf("expected action=migrate, got %s", op.Action)
	}
	if op.Status != "running" {
		t.Fatalf("expected status=running, got %s", op.Status)
	}
}

func TestRunMigrationRollsBackBeforeCutover(t *testing.T) {
	h := newTestHandler(t, false)
	publisher := &migrationTestPublisher{db: h.db, failAction: admiral.ActionStartApp, failNodeID: "node_002"}
	h.publisher = publisher

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "10.99.0.2", "worker", "203.0.113.11", "fedora", "5.0"); err != nil {
		t.Fatalf("register source node: %v", err)
	}
	if err := h.db.RegisterNode("node_002", "worker-2", "10.0.0.2", "10.99.0.3", "worker", "203.0.113.12", "fedora", "5.0"); err != nil {
		t.Fatalf("register target node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_rollback", "cust_001", "migrate-app", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if _, err := h.db.Exec("UPDATE customer_apps SET logical_instance_id = $1, technical_status = 'running' WHERE id = $2", "li_rollback", "inst_rollback"); err != nil {
		t.Fatalf("seed logical instance id: %v", err)
	}
	if err := h.db.CreateOperation("op_migrate_rollback", "inst_rollback", "node_001", "migrate", "running", "system"); err != nil {
		t.Fatalf("create migration op: %v", err)
	}

	h.runMigration("op_migrate_rollback", "inst_rollback", "cust_001", "node_001", "node_002", migrationTestAppYAML(), database.AppTier{Name: "starter", CPU: 1, Memory: "256M", Storage: "1G"}, "li_rollback")

	inst, err := h.db.GetCustomerApp("inst_rollback")
	if err != nil {
		t.Fatalf("get instance after rollback: %v", err)
	}
	if inst == nil || inst.NodeID == nil || *inst.NodeID != "node_001" {
		t.Fatalf("expected instance to remain on source node after rollback, got %+v", inst)
	}
	if inst.LogicalInstanceID != "li_rollback" {
		t.Fatalf("expected logical_instance_id to be preserved, got %q", inst.LogicalInstanceID)
	}

	op, err := h.db.GetOperation("op_migrate_rollback")
	if err != nil {
		t.Fatalf("get migration operation: %v", err)
	}
	if op == nil || op.Status != "failed" {
		t.Fatalf("expected migration op to fail, got %+v", op)
	}
	if op.ErrorMessage == nil || !strings.Contains(*op.ErrorMessage, "start target") {
		t.Fatalf("expected start target failure in operation error, got %+v", op.ErrorMessage)
	}

	var sawTargetCleanup bool
	var sawSourceRestart bool
	for _, task := range publisher.published {
		if task.Action == admiral.ActionDeprovisionApp && task.NodeID == "node_002" {
			sawTargetCleanup = true
		}
		if task.Action == admiral.ActionStartApp && task.NodeID == "node_001" {
			sawSourceRestart = true
		}
	}
	if !sawTargetCleanup {
		t.Fatal("expected rollback to deprovision the target node workload")
	}
	if !sawSourceRestart {
		t.Fatal("expected rollback to restart the source workload")
	}
}

func TestRunMigrationCutoverPreservesLogicalInstanceID(t *testing.T) {
	h := newTestHandler(t, false)
	publisher := &migrationTestPublisher{db: h.db}
	h.publisher = publisher

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "10.99.0.2", "worker", "203.0.113.11", "fedora", "5.0"); err != nil {
		t.Fatalf("register source node: %v", err)
	}
	if err := h.db.RegisterNode("node_002", "worker-2", "10.0.0.2", "10.99.0.3", "worker", "203.0.113.12", "fedora", "5.0"); err != nil {
		t.Fatalf("register target node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_cutover", "cust_001", "migrate-app", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if _, err := h.db.Exec("UPDATE customer_apps SET logical_instance_id = $1, technical_status = 'running' WHERE id = $2", "li_cutover", "inst_cutover"); err != nil {
		t.Fatalf("seed logical instance id: %v", err)
	}
	if err := h.db.CreateBackupRecord(&admiral.BackupRecord{
		ID:             "bk_db",
		InstanceID:     "inst_cutover",
		AppID:          "migrate-app",
		TierID:         "starter",
		NodeID:         "node_001",
		BackupType:     "database",
		DatabaseType:   "postgresql",
		Status:         "succeeded",
		StorageBackend: "local",
		StorageKey:     "/var/lib/admiral/backups/inst_cutover/database.tgz",
		TriggeredBy:    "manual",
	}); err != nil {
		t.Fatalf("create database backup record: %v", err)
	}
	if err := h.db.CreateBackupRecord(&admiral.BackupRecord{
		ID:             "bk_vol",
		InstanceID:     "inst_cutover",
		AppID:          "migrate-app",
		TierID:         "starter",
		NodeID:         "node_001",
		BackupType:     "volume",
		DatabaseType:   "none",
		Status:         "succeeded",
		StorageBackend: "local",
		StorageKey:     "/var/lib/admiral/backups/inst_cutover/volume.tgz",
		TriggeredBy:    "manual",
	}); err != nil {
		t.Fatalf("create volume backup record: %v", err)
	}
	if err := h.db.CreateOperation("op_migrate_cutover", "inst_cutover", "node_001", "migrate", "running", "system"); err != nil {
		t.Fatalf("create migration op: %v", err)
	}

	h.runMigration("op_migrate_cutover", "inst_cutover", "cust_001", "node_001", "node_002", migrationTestAppYAML(), database.AppTier{Name: "starter", CPU: 1, Memory: "256M", Storage: "1G"}, "li_cutover")

	inst, err := h.db.GetCustomerApp("inst_cutover")
	if err != nil {
		t.Fatalf("get instance after cutover: %v", err)
	}
	if inst == nil || inst.NodeID == nil || *inst.NodeID != "node_002" {
		t.Fatalf("expected instance to move to target node after cutover, got %+v", inst)
	}
	if inst.LogicalInstanceID != "li_cutover" {
		t.Fatalf("expected logical_instance_id to be preserved, got %q", inst.LogicalInstanceID)
	}

	op, err := h.db.GetOperation("op_migrate_cutover")
	if err != nil {
		t.Fatalf("get migration operation: %v", err)
	}
	if op == nil || op.Status != "succeeded" {
		t.Fatalf("expected migration op to succeed, got %+v", op)
	}

	var sawRestore bool
	for _, task := range publisher.published {
		if task.Action == admiral.ActionRestoreBackup && task.NodeID == "node_002" {
			sawRestore = true
			break
		}
	}
	if !sawRestore {
		t.Fatal("expected migration to restore backups on the target node")
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

func nodeAuthWrapped(h *APIHandlers, token string, next http.HandlerFunc) http.HandlerFunc {
	return NodeAuthMiddleware(logging.New("test"), h.db, "test-pepper", "worker", next)
}

func setupNodeWithToken(t *testing.T, h *APIHandlers, nodeID, hostname, ip, wgIP, nodeRole, os, podmanV, token string) {
	t.Helper()
	if err := h.db.RegisterNode(nodeID, hostname, ip, wgIP, nodeRole, "", os, podmanV); err != nil {
		t.Fatalf("register node: %v", err)
	}
	identifier := nodeTokenIdentifier(token, "test-pepper")
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash token: %v", err)
	}
	if err := h.db.UpsertNodeToken(nodeID, identifier, string(hash), "worker", "active", "", nil, ""); err != nil {
		t.Fatalf("upsert token: %v", err)
	}
}

func TestHandleNodeHeartbeatIPValidation(t *testing.T) {
	h := newTestHandler(t, false)

	token := "test-token-heartbeat"
	setupNodeWithToken(t, h, "node_001", "worker-1", "10.0.0.1", "10.99.0.2", "worker", "fedora", "5.0", token)
	wrapped := nodeAuthWrapped(h, token, h.HandleNodeHeartbeat)

	heartbeat := admiral.HeartbeatRequest{
		NodeID: "node_001",
		Status: "active",
	}
	body, _ := json.Marshal(heartbeat)

	// Test 1: Request with mismatching IP -> 403 Forbidden
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/heartbeat", bytes.NewReader(body))
	req1.Header.Set("X-Admiral-Token", token)
	rec1 := httptest.NewRecorder()
	wrapped(rec1, req1)
	if rec1.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on mismatching IP, got %d", rec1.Code)
	}
	if got := rec1.Body.String(); got != "{\"error\":\"forbidden\"}\n" {
		t.Fatalf("expected generic forbidden body, got %q", got)
	}

	// Test 2: Request with matching WireGuard IP -> 200 OK
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/heartbeat", bytes.NewReader(body))
	req2.Header.Set("X-Admiral-Token", token)
	req2.RemoteAddr = "10.99.0.2:51820"
	rec2 := httptest.NewRecorder()
	wrapped(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on matching WireGuard IP, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}
}

func TestHandleFleetCallbackIPValidation(t *testing.T) {
	h := newTestHandler(t, false)

	token := "test-token-callback"
	setupNodeWithToken(t, h, "node_001", "worker-1", "10.0.0.1", "10.99.0.2", "worker", "fedora", "5.0", token)
	wrapped := nodeAuthWrapped(h, token, h.HandleFleetCallback)

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
	}
	body, _ := json.Marshal(callback)

	// Test 1: Request with mismatching IP -> 403 Forbidden
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
	req1.Header.Set("X-Admiral-Token", token)
	rec1 := httptest.NewRecorder()
	wrapped(rec1, req1)
	if rec1.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", rec1.Code)
	}
	if got := rec1.Body.String(); got != "{\"error\":\"forbidden\"}\n" {
		t.Fatalf("expected generic forbidden body, got %q", got)
	}

	// Test 2: Request with matching WireGuard IP -> 200 OK
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
	req2.Header.Set("X-Admiral-Token", token)
	req2.RemoteAddr = "10.99.0.2:51820"
	rec2 := httptest.NewRecorder()
	wrapped(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}
}

func TestHandleAdminHealthCallbackIPAndNodeValidation(t *testing.T) {
	h := newTestHandler(t, false)

	token1 := "test-token-health-1"
	setupNodeWithToken(t, h, "node_001", "worker-1", "10.0.0.1", "10.99.0.2", "worker", "fedora", "5.0", token1)
	wrapped1 := nodeAuthWrapped(h, token1, h.HandleAdminHealthCallback)

	token2 := "test-token-health-2"
	setupNodeWithToken(t, h, "node_002", "worker-2", "10.0.0.2", "10.99.0.3", "worker", "fedora", "5.0", token2)
	wrapped2 := nodeAuthWrapped(h, token2, h.HandleAdminHealthCallback)

	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}

	report := admiral.HealthReport{
		InstanceID:   "inst_001",
		NodeID:       "node_001",
		HealthStatus: admiral.HealthHealthy,
		Message:      "all good",
	}
	body, _ := json.Marshal(report)

	// Test 1: Mismatching IP -> 403 Forbidden
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/health", bytes.NewReader(body))
	req1.Header.Set("X-Admiral-Token", token1)
	rec1 := httptest.NewRecorder()
	wrapped1(rec1, req1)
	if rec1.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", rec1.Code)
	}
	if got := rec1.Body.String(); got != "{\"error\":\"forbidden\"}\n" {
		t.Fatalf("expected generic forbidden body, got %q", got)
	}

	// Test 2: Valid IP and Node ID -> 200 OK
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/health", bytes.NewReader(body))
	req2.Header.Set("X-Admiral-Token", token1)
	req2.RemoteAddr = "10.99.0.2:51820"
	rec2 := httptest.NewRecorder()
	wrapped1(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}

	// Test 3: node_002 token with instance that belongs to node_001 -> handler denies
	report2 := admiral.HealthReport{
		InstanceID:   "inst_001",
		NodeID:       "node_002",
		HealthStatus: admiral.HealthHealthy,
		Message:      "all good",
	}
	body2, _ := json.Marshal(report2)
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/health", bytes.NewReader(body2))
	req3.Header.Set("X-Admiral-Token", token2)
	req3.RemoteAddr = "10.99.0.3:51820"
	rec3 := httptest.NewRecorder()
	wrapped2(rec3, req3)
	if rec3.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", rec3.Code)
	}
}
