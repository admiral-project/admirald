// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/config"
	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/networking"
	"github.com/admiral-project/admiral/admirald/internal/security"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"golang.org/x/crypto/bcrypt"
)

type migrationTestPublisher struct {
	db                   *database.DB
	failAction           admiral.TaskAction
	failNodeID           string
	completeBeforeReturn bool
	invalidChecksum      bool
	targetProvisionState string
	failed               bool
	published            []*admiral.FleetTask
}

func (m *migrationTestPublisher) PublishTask(task *admiral.FleetTask) error {
	m.published = append(m.published, task)
	if task.Action == admiral.ActionProvisionApp && task.NodeID == "node_002" {
		inst, err := m.db.GetCustomerApp(task.InstanceID)
		if err != nil {
			return err
		}
		if inst != nil {
			m.targetProvisionState = inst.TechnicalStatus
		}
	}
	status := "succeeded"
	errMsg := ""
	if !m.failed && task.Action == m.failAction && (m.failNodeID == "" || m.failNodeID == task.NodeID) {
		status = "failed"
		errMsg = "simulated " + string(task.Action) + " failure"
		m.failed = true
	}
	complete := func() error {
		op, err := m.db.GetOperation(task.OperationID)
		if err != nil {
			return err
		}
		migrationChild := isMigrationSuboperation(op)
		if status == "succeeded" {
			switch task.Action {
			case admiral.ActionBackupDatabase, admiral.ActionBackupVolumes:
				if task.Storage == nil || task.Storage.BackupID == "" {
					return fmt.Errorf("%s task has no backup record identity", task.Action)
				}
				rec, err := m.db.GetBackupRecord(task.Storage.BackupID)
				if err != nil {
					return err
				}
				if rec == nil {
					return fmt.Errorf("backup record %q was not created before dispatch", task.Storage.BackupID)
				}
				rec.Status = "succeeded"
				rec.StorageBackend = task.Storage.Backend
				rec.StorageKey = task.Storage.Key
				rec.SizeBytes = 128
				rec.ChecksumSHA256 = strings.Repeat("a", 64)
				if m.invalidChecksum {
					rec.ChecksumSHA256 = "invalid"
				}
				rec.CompletedAt = time.Now().UTC().Format(time.RFC3339)
				rec.ExpiresAt = time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339)
				if err := m.db.UpdateBackupRecord(rec); err != nil {
					return err
				}
			case admiral.ActionProvisionApp, admiral.ActionStartApp, admiral.ActionResumeApp, admiral.ActionReactivateApp:
				if !migrationChild {
					if err := m.db.UpdateCustomerAppStatus(task.InstanceID, "", "running"); err != nil {
						return err
					}
				}
				if migrationChild && (task.Action == admiral.ActionStartApp || task.Action == admiral.ActionResumeApp) {
					op.Metadata.HostPorts = map[string]int{"web": 43121}
					if err := m.db.UpdateOperationMetadata(op.ID, op.Metadata); err != nil {
						return err
					}
					go func() {
						for i := 0; i < 20; i++ {
							time.Sleep(500 * time.Millisecond)
							inst, err := m.db.GetCustomerApp(task.InstanceID)
							if err == nil && inst != nil && inst.NodeID != nil && *inst.NodeID == task.NodeID {
								_ = m.db.UpdateInstanceHealthForBoot(task.InstanceID, "healthy", "running", "test health", "test-boot", true)
							}
						}
					}()
				}
			case admiral.ActionStopApp, admiral.ActionPauseApp:
				if !migrationChild {
					if err := m.db.UpdateCustomerAppStatus(task.InstanceID, "", "stopped"); err != nil {
						return err
					}
				}
			case admiral.ActionRestoreBackup:
				if !migrationChild {
					if err := m.db.UpdateCustomerAppStatus(task.InstanceID, "", "paused"); err != nil {
						return err
					}
				}
			}
		}
		if err := m.db.UpdateOperation(task.OperationID, status, errMsg); err != nil {
			return err
		}
		return nil
	}
	if m.completeBeforeReturn {
		return complete()
	}
	go func() {
		time.Sleep(25 * time.Millisecond)
		_ = complete()
	}()
	return nil
}

func (m *migrationTestPublisher) PublishRejectedTask(task *admiral.FleetTask, reason, result string) error {
	return nil
}

func (m *migrationTestPublisher) ClaimTask(nodeID string) (*admiral.FleetTask, string, int, int, error) {
	return nil, "", 30, 0, nil
}

func (m *migrationTestPublisher) MarkRunningForNode(commandID, nodeID string) error {
	return nil
}

func (m *migrationTestPublisher) RenewLeaseForNode(commandID, nodeID string) error {
	return nil
}

func (m *migrationTestPublisher) DiscardCommandForNode(commandID, nodeID, reason string) error {
	return nil
}

func (m *migrationTestPublisher) CancelCommandForNode(commandID, nodeID, reason string) error {
	return nil
}

func (m *migrationTestPublisher) CancelTaskForNode(taskPublicID, nodeID, reason string) error {
	return nil
}

func (m *migrationTestPublisher) AcknowledgeTaskForNode(taskPublicID, nodeID string) error {
	return nil
}

func (m *migrationTestPublisher) CompleteTask(taskPublicID string, success bool, errorMsg string) error {
	return nil
}

func (m *migrationTestPublisher) HasActiveTasksForNode(nodeID string) (bool, error) {
	return false, nil
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

func prepareMigrationCapacity(t *testing.T, h *APIHandlers, sourceNodeID, targetNodeID string) {
	t.Helper()
	if err := h.db.SaveBackupStorageConfig(&admiral.BackupStorageConfig{ID: "migration-test", Backend: "s3", Enabled: true, Endpoint: "https://s3.test", Region: "test", Bucket: "migration"}); err != nil {
		t.Fatalf("configure shared migration storage: %v", err)
	}
	const ram = int64(1 << 30)
	const disk = int64(10 << 30)
	for _, nodeID := range []string{sourceNodeID, targetNodeID} {
		if _, err := h.db.Exec(`UPDATE nodes
			SET status = 'active', health_status = 'healthy', available_for_provisioning = TRUE,
				boot_id = 'test-boot', last_heartbeat = CURRENT_TIMESTAMP,
				ram_commit_limit_bytes = $1, disk_commit_limit_bytes = $2
			WHERE id = $3`, ram, disk, nodeID); err != nil {
			t.Fatalf("set migration capacity for %s: %v", nodeID, err)
		}
	}
	if err := h.db.AddNodeCommitment(sourceNodeID, int64(256<<20), int64(1<<30)); err != nil {
		t.Fatalf("seed source commitment: %v", err)
	}
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

func TestHandleAdminChangePasswordInvalidatesOtherSessions(t *testing.T) {
	h := newAdminLoginTestHandler(t)
	now := time.Now()
	currentToken := "current-session-token"
	otherToken := "other-session-token"
	if err := h.db.CreateAdminSession(h.hashToken(currentToken), "admin", now.Add(time.Hour), now); err != nil {
		t.Fatalf("create current session: %v", err)
	}
	if err := h.db.CreateAdminSession(h.hashToken(otherToken), "admin", now.Add(time.Hour), now); err != nil {
		t.Fatalf("create other session: %v", err)
	}

	body, _ := json.Marshal(admiral.AdminChangePasswordRequest{
		CurrentPassword: "super-secret-password",
		NewPassword:     "new-super-secret-password",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/auth/change-password", bytes.NewReader(body))
	req.Header.Set("X-Admiral-Admin-User", "admin")
	req.Header.Set("X-Admiral-Admin-Token", currentToken)
	rec := httptest.NewRecorder()
	h.HandleAdminChangePassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if username, _, _, err := h.db.GetAdminSession(h.hashToken(otherToken)); err != nil {
		t.Fatalf("lookup other session: %v", err)
	} else if username != "" {
		t.Fatal("expected other admin session to be invalidated")
	}
	if username, _, _, err := h.db.GetAdminSession(h.hashToken(currentToken)); err != nil {
		t.Fatalf("lookup current session: %v", err)
	} else if username != "admin" {
		t.Fatal("expected current admin session to remain active")
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
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test db: %v", err)
		}
	})
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

	return NewHandlers(db, logging.New("test"), &mockPublisher{}, nil, nil, "test-hmac-key", "test-pepper", 60)
}

type mockPublisher struct {
	mu         sync.Mutex
	tasks      []*admiral.FleetTask
	publishErr error
	entered    chan struct{}
	release    chan struct{}
	enteredOne sync.Once
}

func (m *mockPublisher) PublishTask(task *admiral.FleetTask) error {
	if m.entered != nil {
		m.enteredOne.Do(func() { close(m.entered) })
	}
	if m.release != nil {
		<-m.release
	}
	if m.publishErr != nil {
		return m.publishErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks = append(m.tasks, task)
	return nil
}

func (m *mockPublisher) taskCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tasks)
}
func (m *mockPublisher) PublishRejectedTask(task *admiral.FleetTask, reason, result string) error {
	return nil
}
func (m *mockPublisher) ClaimTask(nodeID string) (*admiral.FleetTask, string, int, int, error) {
	return nil, "", 30, 0, nil
}
func (m *mockPublisher) MarkRunningForNode(commandID, nodeID string) error            { return nil }
func (m *mockPublisher) RenewLeaseForNode(commandID, nodeID string) error             { return nil }
func (m *mockPublisher) DiscardCommandForNode(commandID, nodeID, reason string) error { return nil }
func (m *mockPublisher) CancelCommandForNode(commandID, nodeID, reason string) error  { return nil }
func (m *mockPublisher) CancelTaskForNode(taskPublicID, nodeID, reason string) error  { return nil }
func (m *mockPublisher) AcknowledgeTaskForNode(taskPublicID, nodeID string) error     { return nil }
func (m *mockPublisher) CompleteTask(taskPublicID string, success bool, errorMsg string) error {
	return nil
}
func (m *mockPublisher) HasActiveTasksForNode(nodeID string) (bool, error) { return false, nil }

func seedTestAppDefinition(t *testing.T, db *database.DB) {
	t.Helper()
	_ = db.SaveAppDefinition("testapp", "Test App", "App for testing", "name: testapp", nil, "improvement")
	_ = db.SaveAppDefinition("migrate-app", "Migrate App", "App for migration testing", "name: migrate-app", nil, "improvement")
	_ = db.SaveAppDefinition("status-app", "Status App", "App for status testing", "name: status-app", nil, "improvement")
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

func TestClientIP(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		trustedProxies []string
		headers        map[string]string
		want           string
	}{
		{
			name:       "fallback to remote addr (not trusted)",
			remoteAddr: "192.168.1.1:1234",
			want:       "192.168.1.1",
		},
		{
			name:       "X-Forwarded-For ignored when not trusted",
			remoteAddr: "192.168.1.1:1234",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1"},
			want:       "192.168.1.1",
		},
		{
			name:           "X-Forwarded-For single (trusted proxy)",
			remoteAddr:     "10.0.0.1:1234",
			trustedProxies: []string{"10.0.0.1"},
			headers:        map[string]string{"X-Forwarded-For": "203.0.113.1"},
			want:           "203.0.113.1",
		},
		{
			name:           "X-Forwarded-For multiple (trusted proxy)",
			remoteAddr:     "10.0.0.1:1234",
			trustedProxies: []string{"10.0.0.1"},
			headers:        map[string]string{"X-Forwarded-For": "203.0.113.1, 10.0.0.2"},
			want:           "203.0.113.1",
		},
		{
			name:           "X-Real-IP (trusted proxy)",
			remoteAddr:     "10.0.0.1:1234",
			trustedProxies: []string{"10.0.0.1"},
			headers:        map[string]string{"X-Real-IP": "203.0.113.2"},
			want:           "203.0.113.2",
		},
		{
			name:       "Localhost does not trust forwarded headers by default",
			remoteAddr: "127.0.0.1:1234",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.5"},
			want:       "127.0.0.1",
		},
		{
			name:           "X-Forwarded-For takes precedence over X-Real-IP (trusted)",
			remoteAddr:     "10.0.0.1:1234",
			trustedProxies: []string{"10.0.0.1"},
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
				"X-Real-IP":       "203.0.113.2",
			},
			want: "203.0.113.1",
		},
		{
			name:       "IPv6 remote addr",
			remoteAddr: "[::1]:1234",
			want:       "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			got := getClientIP(req, tt.trustedProxies)
			if got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
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

func TestHandleFleetCallbackMigrationDeprovisionPreservesLogicalInstance(t *testing.T) {
	const reservedRAM = int64(256 << 20)
	const reservedDisk = int64(1 << 30)

	tests := []struct {
		name        string
		step        string
		currentNode string
		cleanupNode string
	}{
		{name: "rollback target cleanup", step: "rollback_target_cleanup", currentNode: "node_source", cleanupNode: "node_target"},
		{name: "source cleanup after cutover", step: "deprovisioning_source", currentNode: "node_target", cleanupNode: "node_source"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler(t, false)
			for _, nodeID := range []string{"node_source", "node_target"} {
				if err := h.db.RegisterNode(nodeID, nodeID, "10.0.0.1", "", "worker", "", "rocky", "5.0"); err != nil {
					t.Fatalf("register node %s: %v", nodeID, err)
				}
			}
			tierSnapshot := `{"name":"starter","memory":"256M","storage":"1G"}`
			if err := h.db.CreateCustomerApp("inst_migration_cleanup", "cust_001", "testapp", "starter", tt.currentNode, tierSnapshot); err != nil {
				t.Fatalf("create instance: %v", err)
			}
			if err := h.db.UpdateCustomerAppStatus("inst_migration_cleanup", "active", "running"); err != nil {
				t.Fatalf("set instance state: %v", err)
			}
			if err := h.db.AddNodeCommitment(tt.currentNode, reservedRAM, reservedDisk); err != nil {
				t.Fatalf("reserve logical instance capacity: %v", err)
			}
			metadata := &database.OperationMetadata{
				TargetNodeID: "node_target", SourceNodeID: "node_source", LogicalInstanceID: "logical_migration_cleanup", MigrationStep: tt.step,
			}
			if err := h.db.CreateOperationWithMetadata("op_migration_cleanup", "inst_migration_cleanup", tt.cleanupNode, string(admiral.ActionDeprovisionApp), "running", "system", metadata); err != nil {
				t.Fatalf("create migration cleanup operation: %v", err)
			}

			body, _ := json.Marshal(admiral.TaskResult{OperationID: "op_migration_cleanup", NodeID: tt.cleanupNode, Success: true})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			h.HandleFleetCallback(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected callback 200, got %d body=%s", rec.Code, rec.Body.String())
			}

			inst, err := h.db.GetCustomerApp("inst_migration_cleanup")
			if err != nil {
				t.Fatalf("get instance: %v", err)
			}
			if inst.NodeID == nil || *inst.NodeID != tt.currentNode || inst.TechnicalStatus != "running" || inst.CommercialStatus != "active" {
				t.Fatalf("migration cleanup changed logical instance state: %+v", inst)
			}
			gotRAM, gotDisk, err := h.db.GetCommittedResources(tt.currentNode)
			if err != nil {
				t.Fatalf("get current node commitment: %v", err)
			}
			if gotRAM != reservedRAM || gotDisk != reservedDisk {
				t.Fatalf("migration cleanup changed capacity on current node: RAM=%d disk=%d", gotRAM, gotDisk)
			}
		})
	}
}

func TestHandleFleetCallbackMigrationProvisionFailureKeepsSourceCapacity(t *testing.T) {
	const reservedRAM = int64(256 << 20)
	const reservedDisk = int64(1 << 30)
	h := newTestHandler(t, false)
	for _, nodeID := range []string{"node_source", "node_target"} {
		if err := h.db.RegisterNode(nodeID, nodeID, "10.0.0.1", "", "worker", "", "rocky", "5.0"); err != nil {
			t.Fatalf("register node %s: %v", nodeID, err)
		}
	}
	tierSnapshot := `{"name":"starter","memory":"256M","storage":"1G"}`
	if err := h.db.CreateCustomerApp("inst_migration_provision", "cust_001", "testapp", "starter", "node_source", tierSnapshot); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_migration_provision", "active", "running"); err != nil {
		t.Fatalf("set instance state: %v", err)
	}
	if err := h.db.AddNodeCommitment("node_source", reservedRAM, reservedDisk); err != nil {
		t.Fatalf("reserve source capacity: %v", err)
	}
	metadata := &database.OperationMetadata{
		TargetNodeID: "node_target", SourceNodeID: "node_source", LogicalInstanceID: "logical_migration_provision", MigrationStep: "provisioning_target",
	}
	if err := h.db.CreateOperationWithMetadata("op_migration_provision", "inst_migration_provision", "node_target", string(admiral.ActionProvisionApp), "running", "system", metadata); err != nil {
		t.Fatalf("create migration provision operation: %v", err)
	}

	body, _ := json.Marshal(admiral.TaskResult{OperationID: "op_migration_provision", NodeID: "node_target", Success: false, Error: "simulated target provisioning failure"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleFleetCallback(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected callback 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	inst, err := h.db.GetCustomerApp("inst_migration_provision")
	if err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if inst.NodeID == nil || *inst.NodeID != "node_source" || inst.TechnicalStatus != "running" || inst.CommercialStatus != "active" {
		t.Fatalf("failed target provision changed the source instance state: %+v", inst)
	}
	gotRAM, gotDisk, err := h.db.GetCommittedResources("node_source")
	if err != nil {
		t.Fatalf("get source commitment: %v", err)
	}
	if gotRAM != reservedRAM || gotDisk != reservedDisk {
		t.Fatalf("failed target provision released source capacity: RAM=%d disk=%d", gotRAM, gotDisk)
	}
}

func TestHandleFleetCallbackMigrationStartAndResumeRecordTargetPorts(t *testing.T) {
	for _, action := range []admiral.TaskAction{admiral.ActionStartApp, admiral.ActionResumeApp} {
		t.Run(string(action), func(t *testing.T) {
			h := newTestHandler(t, false)
			for _, nodeID := range []string{"node_source", "node_target"} {
				if err := h.db.RegisterNode(nodeID, nodeID, "10.0.0.1", "", "worker", "", "rocky", "5.0"); err != nil {
					t.Fatalf("register node: %v", err)
				}
			}
			instanceID := "inst_migration_" + string(action)
			operationID := "op_migration_" + string(action)
			if err := h.db.CreateCustomerApp(instanceID, "cust_001", "testapp", "starter", "node_source", `{}`); err != nil {
				t.Fatalf("create instance: %v", err)
			}
			if err := h.db.UpdateCustomerAppStatus(instanceID, "active", "migrating"); err != nil {
				t.Fatalf("set migration state: %v", err)
			}
			meta := &database.OperationMetadata{MigrationStep: "resuming_target", SourceNodeID: "node_source", TargetNodeID: "node_target"}
			if err := h.db.CreateOperationWithMetadata(operationID, instanceID, "node_target", string(action), "running", "system", meta); err != nil {
				t.Fatalf("create migration child operation: %v", err)
			}
			body, _ := json.Marshal(admiral.TaskResult{OperationID: operationID, NodeID: "node_target", Success: true, Metadata: `{"host_ports":{"web":43121}}`})
			rec := httptest.NewRecorder()
			h.HandleFleetCallback(rec, httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body)))
			if rec.Code != http.StatusOK {
				t.Fatalf("callback returned %d: %s", rec.Code, rec.Body.String())
			}
			op, err := h.db.GetOperation(operationID)
			if err != nil || op == nil || op.Metadata == nil || op.Metadata.HostPorts["web"] != 43121 || op.Status != "succeeded" {
				t.Fatalf("target ports were not recorded: op=%+v err=%v", op, err)
			}
			inst, err := h.db.GetCustomerApp(instanceID)
			if err != nil || inst == nil || inst.TechnicalStatus != "migrating" {
				t.Fatalf("target callback changed migration status: inst=%+v err=%v", inst, err)
			}
		})
	}
}

func TestHealthReportPreservesMigratingStatus(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_source", "source", "10.0.0.1", "", "worker", "", "rocky", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_migrating", "cust_001", "testapp", "starter", "node_source", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_migrating", "active", "migrating"); err != nil {
		t.Fatalf("set migration state: %v", err)
	}
	if err := h.db.CreateOperation("op_migrating", "inst_migrating", "node_source", "migrate", "running", "system"); err != nil {
		t.Fatalf("create migration operation: %v", err)
	}
	body, _ := json.Marshal(admiral.HealthReport{InstanceID: "inst_migrating", NodeID: "node_source", BootID: "boot-source", HealthStatus: admiral.HealthHealthy})
	rec := httptest.NewRecorder()
	h.HandleAdminHealthCallback(rec, httptest.NewRequest(http.MethodPost, "/api/admin/health", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("health callback returned %d: %s", rec.Code, rec.Body.String())
	}
	inst, err := h.db.GetCustomerApp("inst_migrating")
	if err != nil || inst == nil || inst.TechnicalStatus != "migrating" {
		t.Fatalf("health callback changed migration status: inst=%+v err=%v", inst, err)
	}
	if err := h.db.UpdateOperation("op_migrating", "failed", "cutover outcome uncertain"); err != nil {
		t.Fatalf("mark migration failed: %v", err)
	}
	rec = httptest.NewRecorder()
	h.HandleAdminHealthCallback(rec, httptest.NewRequest(http.MethodPost, "/api/admin/health", bytes.NewReader(body)))
	inst, err = h.db.GetCustomerApp("inst_migrating")
	if rec.Code != http.StatusOK || err != nil || inst == nil || inst.TechnicalStatus != "migrating" {
		t.Fatalf("health callback cleared unresolved migration state: code=%d inst=%+v err=%v", rec.Code, inst, err)
	}
}

func TestHealthReconciliationKeepsDisabledRoute(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_source", "source", "10.0.0.1", "10.99.0.2", "worker", "", "rocky", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_disabled_route", "cust_001", "testapp", "starter", "node_source", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	node := "node_source"
	route := database.PublicRoute{ID: "route_disabled", Hostname: "disabled.example.test", AppInstanceID: "inst_disabled_route", NodeID: &node, ServiceName: "web", RouteKind: string(admiral.RouteKindInstance), Status: string(admiral.RouteStatusDisabled)}
	if err := h.db.CreatePublicRoute(route); err != nil {
		t.Fatalf("create disabled route: %v", err)
	}
	manager := &networking.Manager{DB: h.db, Config: &config.Config{}}
	if err := manager.ActivateInstanceRoutes(context.Background(), "inst_disabled_route", map[string]int{"web": 43121}); err != nil {
		t.Fatalf("reconcile health route: %v", err)
	}
	got, err := h.db.GetPublicRoute(route.Hostname)
	if err != nil || got == nil || got.Status != string(admiral.RouteStatusDisabled) {
		t.Fatalf("health reconciliation reopened disabled route: route=%+v err=%v", got, err)
	}
}

func TestRouteSyncKeepsMigrationMaintenanceWithoutChangingOriginalStatus(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_source", "source", "10.0.0.1", "10.99.0.2", "worker", "", "rocky", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_sync_maintenance", "cust_001", "testapp", "starter", "node_source", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	node := "node_source"
	route := database.PublicRoute{ID: "route_sync_maintenance", Hostname: "sync.example.test", AppInstanceID: "inst_sync_maintenance", NodeID: &node, ServiceName: "web", TargetHost: "10.99.0.2", TargetPort: 40000, TargetURL: "http://10.99.0.2:40000", RouteKind: string(admiral.RouteKindInstance), Status: string(admiral.RouteStatusActive)}
	if err := h.db.CreatePublicRoute(route); err != nil {
		t.Fatalf("create route: %v", err)
	}
	meta := &database.OperationMetadata{MigrationStep: "starting"}
	if err := h.db.CreateOperationWithMetadata("op_sync_maintenance", "inst_sync_maintenance", "node_source", "migrate", "running", "system", meta); err != nil {
		t.Fatalf("create migration operation: %v", err)
	}
	var mu sync.Mutex
	var loaded string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		loaded = string(body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	manager := &networking.Manager{DB: h.db, Caddy: &networking.CaddyAdminClient{BaseURL: server.URL, HTTP: server.Client()}, Config: &config.Config{}, Log: h.log}
	if err := manager.Sync(context.Background()); err != nil {
		t.Fatalf("sync maintenance: %v", err)
	}
	mu.Lock()
	maintenanceLoaded := strings.Contains(loaded, `"status_code":503`)
	mu.Unlock()
	if !maintenanceLoaded {
		t.Fatal("Caddy did not receive a maintenance route")
	}
	got, err := h.db.GetPublicRoute(route.Hostname)
	if err != nil || got == nil || got.Status != string(admiral.RouteStatusActive) {
		t.Fatalf("maintenance sync overwrote original route status: route=%+v err=%v", got, err)
	}
}

func TestHandleFleetCallbackIgnoresSignedDuplicateAfterTerminalOperation(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	_ = h.db.UpdateCustomerAppStatus("inst_001", "active", "provisioning")
	if err := h.db.CreateOperation("op_duplicate", "inst_001", "node_001", "provision_app", "succeeded", ""); err != nil {
		t.Fatalf("create operation: %v", err)
	}

	callback := admiral.TaskResult{
		TaskID:      "task_duplicate",
		OperationID: "op_duplicate",
		NodeID:      "node_001",
		Success:     false,
		Error:       "stale failure",
	}
	body, _ := json.Marshal(callback)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleFleetCallback(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected duplicate callback 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	op, err := h.db.GetOperation("op_duplicate")
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Status != "succeeded" {
		t.Fatalf("stale callback changed terminal operation to %s", op.Status)
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
	publisher := &mockPublisher{entered: make(chan struct{}), release: make(chan struct{}), publishErr: fmt.Errorf("test dispatch failure")}
	h.publisher = publisher
	defer func() {
		select {
		case <-publisher.release:
		default:
			close(publisher.release)
		}
	}()

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
	if err := h.db.SaveAppDefinition("testapp", "Test App", "desc", migrationTestAppYAML(), []database.AppTier{}, "improvement"); err != nil {
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
	select {
	case <-publisher.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("migration did not dispatch its first backup")
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
	close(publisher.release)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		op, err := h.db.GetOperation(resp.OperationID)
		if err == nil && op != nil && op.Status == "failed" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("migration did not finish after the simulated dispatch failure")
}

func TestCreateMigrationOperationSerializesRequests(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_source", "source", "10.0.0.1", "", "worker", "", "rocky", "5.0"); err != nil {
		t.Fatalf("register source: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_concurrent", "cust_001", "testapp", "starter", "node_source", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_concurrent", "active", "running"); err != nil {
		t.Fatalf("set instance state: %v", err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{"op_migrate_concurrent_1", "op_migrate_concurrent_2"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			results <- h.db.CreateMigrationOperation(id, "inst_concurrent", "node_source", "system", &database.OperationMetadata{MigrationStep: "starting"})
		}(id)
	}
	wg.Wait()
	close(results)
	succeeded, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, database.ErrMigrationConflict):
			conflicts++
		default:
			t.Fatalf("create migration: %v", err)
		}
	}
	if succeeded != 1 || conflicts != 1 {
		t.Fatalf("expected one migration and one conflict, got %d successes and %d conflicts", succeeded, conflicts)
	}
}

func TestRunMigrationRollsBackBeforeCutover(t *testing.T) {
	h := newTestHandler(t, false)
	publisher := &migrationTestPublisher{db: h.db, failAction: admiral.ActionResumeApp, failNodeID: "node_002"}
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
	prepareMigrationCapacity(t, h, "node_001", "node_002")
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
	sourceRAM, sourceDisk, err := h.db.GetCommittedResources("node_001")
	if err != nil {
		t.Fatalf("get source capacity after rollback: %v", err)
	}
	targetRAM, targetDisk, err := h.db.GetCommittedResources("node_002")
	if err != nil {
		t.Fatalf("get target capacity after rollback: %v", err)
	}
	if sourceRAM != int64(256<<20) || sourceDisk != int64(1<<30) || targetRAM != 0 || targetDisk != 0 {
		t.Fatalf("rollback capacity is inconsistent: source=(%d,%d) target=(%d,%d)", sourceRAM, sourceDisk, targetRAM, targetDisk)
	}

	op, err := h.db.GetOperation("op_migrate_rollback")
	if err != nil {
		t.Fatalf("get migration operation: %v", err)
	}
	if op == nil || op.Status != "failed" {
		t.Fatalf("expected migration op to fail, got %+v", op)
	}
	if op.ErrorMessage == nil || !strings.Contains(*op.ErrorMessage, "resume target") {
		t.Fatalf("expected resume target failure in operation error, got %+v", op.ErrorMessage)
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

func TestRunMigrationBackupFailureRestoresMaintenanceRoute(t *testing.T) {
	h := newTestHandler(t, false)
	publisher := &migrationTestPublisher{db: h.db, failAction: admiral.ActionBackupDatabase, completeBeforeReturn: true}
	h.publisher = publisher
	for _, nodeID := range []string{"node_001", "node_002"} {
		if err := h.db.RegisterNode(nodeID, nodeID, "10.0.0.1", "10.99.0.2", "worker", "", "rocky", "5.0"); err != nil {
			t.Fatalf("register node: %v", err)
		}
	}
	if err := h.db.CreateCustomerApp("inst_maintenance", "cust_001", "migrate-app", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_maintenance", "active", "running"); err != nil {
		t.Fatalf("set instance state: %v", err)
	}
	prepareMigrationCapacity(t, h, "node_001", "node_002")
	if err := h.db.CreateOperation("op_migrate_maintenance", "inst_maintenance", "node_001", "migrate", "running", "system"); err != nil {
		t.Fatalf("create migration operation: %v", err)
	}
	sourceNode := "node_001"
	route := database.PublicRoute{ID: "route_maintenance", Hostname: "migration.example.test", AppInstanceID: "inst_maintenance", NodeID: &sourceNode, ServiceName: "web", TargetHost: "10.99.0.2", TargetPort: 8080, TargetURL: "http://10.99.0.2:8080", RouteKind: string(admiral.RouteKindInstance), Status: string(admiral.RouteStatusActive)}
	if err := h.db.CreatePublicRoute(route); err != nil {
		t.Fatalf("create public route: %v", err)
	}
	var mu sync.Mutex
	var loads []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		loads = append(loads, string(body))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	h.networking = &networking.Manager{DB: h.db, Caddy: &networking.CaddyAdminClient{BaseURL: server.URL, HTTP: server.Client()}, Config: &config.Config{}, Log: h.log}

	started := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.runMigration("op_migrate_maintenance", "inst_maintenance", "cust_001", "node_001", "node_002", migrationTestAppYAML(), database.AppTier{Name: "starter", CPU: 1, Memory: "256M", Storage: "1G"}, "inst_maintenance")
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		loaded := len(loads) > 0
		mu.Unlock()
		if loaded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("maintenance was not loaded in Caddy")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// An already-running reconciliation must not re-enable public traffic.
	if err := h.networking.EnableRoute(context.Background(), route.Hostname); err == nil {
		t.Fatal("route change was accepted during migration")
	}
	mu.Lock()
	stillUnavailable := strings.Contains(loads[len(loads)-1], `"status_code":503`)
	mu.Unlock()
	if !stillUnavailable {
		t.Fatal("concurrent reconciliation reopened traffic during migration")
	}
	<-done
	if time.Since(started) < 30*time.Second {
		t.Fatal("backup started before the maintenance drain interval")
	}
	inst, err := h.db.GetCustomerApp("inst_maintenance")
	if err != nil || inst == nil || inst.TechnicalStatus != "running" || inst.NodeID == nil || *inst.NodeID != sourceNode {
		t.Fatalf("source must remain running after backup failure: instance=%+v err=%v", inst, err)
	}
	currentRoute, err := h.db.GetPublicRoute(route.Hostname)
	if err != nil || currentRoute == nil || currentRoute.Status != string(admiral.RouteStatusActive) || currentRoute.NodeID == nil || *currentRoute.NodeID != sourceNode {
		t.Fatalf("source route was not restored: route=%+v err=%v", currentRoute, err)
	}
	for _, task := range publisher.published {
		if task.Action == admiral.ActionStopApp || task.Action == admiral.ActionPauseApp || task.Action == admiral.ActionProvisionApp {
			t.Fatalf("backup failure dispatched %s", task.Action)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(loads) < 2 || !strings.Contains(loads[0], `"status_code":503`) || !strings.Contains(loads[len(loads)-1], `"reverse_proxy"`) {
		t.Fatalf("expected Caddy maintenance followed by original route, got %d config loads", len(loads))
	}
}

func TestRunMigrationRejectsInvalidBackupChecksumBeforePause(t *testing.T) {
	h := newTestHandler(t, false)
	publisher := &migrationTestPublisher{db: h.db, invalidChecksum: true, completeBeforeReturn: true}
	h.publisher = publisher
	for _, nodeID := range []string{"node_001", "node_002"} {
		if err := h.db.RegisterNode(nodeID, nodeID, "10.0.0.1", "", "worker", "", "rocky", "5.0"); err != nil {
			t.Fatalf("register node: %v", err)
		}
	}
	if err := h.db.CreateCustomerApp("inst_bad_checksum", "cust_001", "migrate-app", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_bad_checksum", "active", "running"); err != nil {
		t.Fatalf("set instance state: %v", err)
	}
	prepareMigrationCapacity(t, h, "node_001", "node_002")
	if err := h.db.CreateOperation("op_bad_checksum", "inst_bad_checksum", "node_001", "migrate", "running", "system"); err != nil {
		t.Fatalf("create migration operation: %v", err)
	}
	h.runMigration("op_bad_checksum", "inst_bad_checksum", "cust_001", "node_001", "node_002", migrationTestAppYAML(), database.AppTier{Name: "starter", CPU: 1, Memory: "256M", Storage: "1G"}, "inst_bad_checksum")
	op, err := h.db.GetOperation("op_bad_checksum")
	if err != nil || op == nil || op.Status != "failed" || op.ErrorMessage == nil || !strings.Contains(*op.ErrorMessage, "valid SHA-256 checksum") {
		t.Fatalf("invalid checksum did not fail migration: op=%+v err=%v", op, err)
	}
	inst, err := h.db.GetCustomerApp("inst_bad_checksum")
	if err != nil || inst == nil || inst.TechnicalStatus != "running" || inst.NodeID == nil || *inst.NodeID != "node_001" {
		t.Fatalf("invalid checksum changed source: inst=%+v err=%v", inst, err)
	}
	for _, task := range publisher.published {
		if task.Action == admiral.ActionPauseApp || task.Action == admiral.ActionProvisionApp {
			t.Fatalf("invalid backup dispatched %s", task.Action)
		}
	}
}

func TestRunMigrationUncertainCutoverPreservesBothWorkloads(t *testing.T) {
	h := newTestHandler(t, false)
	publisher := &migrationTestPublisher{db: h.db, completeBeforeReturn: true}
	h.publisher = publisher
	for i, nodeID := range []string{"node_001", "node_002"} {
		wireguardIP := fmt.Sprintf("10.99.0.%d", i+2)
		if err := h.db.RegisterNode(nodeID, nodeID, "10.0.0.1", wireguardIP, "worker", "", "rocky", "5.0"); err != nil {
			t.Fatalf("register node: %v", err)
		}
	}
	if err := h.db.CreateCustomerApp("inst_uncertain", "cust_001", "migrate-app", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_uncertain", "active", "running"); err != nil {
		t.Fatalf("set instance state: %v", err)
	}
	prepareMigrationCapacity(t, h, "node_001", "node_002")
	if err := h.db.CreateOperation("op_uncertain", "inst_uncertain", "node_001", "migrate", "running", "system"); err != nil {
		t.Fatalf("create migration operation: %v", err)
	}
	sourceNode := "node_001"
	route := database.PublicRoute{ID: "route_uncertain", Hostname: "uncertain.example.test", AppInstanceID: "inst_uncertain", NodeID: &sourceNode, ServiceName: "web", TargetHost: "10.99.0.2", TargetPort: 40000, TargetURL: "http://10.99.0.2:40000", RouteKind: string(admiral.RouteKindInstance), Status: string(admiral.RouteStatusActive)}
	if err := h.db.CreatePublicRoute(route); err != nil {
		t.Fatalf("create source route: %v", err)
	}
	var mu sync.Mutex
	loads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		mu.Lock()
		loads++
		current := loads
		mu.Unlock()
		if current == 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	h.networking = &networking.Manager{DB: h.db, Caddy: &networking.CaddyAdminClient{BaseURL: server.URL, HTTP: server.Client()}, Config: &config.Config{}, Log: h.log}

	h.runMigration("op_uncertain", "inst_uncertain", "cust_001", "node_001", "node_002", migrationTestAppYAML(), database.AppTier{Name: "starter", CPU: 1, Memory: "256M", Storage: "1G"}, "inst_uncertain")
	op, err := h.db.GetOperation("op_uncertain")
	if err != nil || op == nil || op.Status != "failed" || op.ErrorMessage == nil || !strings.Contains(*op.ErrorMessage, "outcome is uncertain") {
		t.Fatalf("uncertain cutover was not reported: op=%+v err=%v", op, err)
	}
	currentRoute, err := h.db.GetPublicRoute(route.Hostname)
	if err != nil || currentRoute == nil || currentRoute.Status != string(admiral.RouteStatusDisabled) {
		t.Fatalf("uncertain cutover did not restore maintenance: route=%+v err=%v", currentRoute, err)
	}
	for _, task := range publisher.published {
		if task.Action == admiral.ActionDeprovisionApp {
			t.Fatalf("uncertain cutover deleted workload on %s", task.NodeID)
		}
	}
	for _, nodeID := range []string{"node_001", "node_002"} {
		ram, disk, err := h.db.GetCommittedResources(nodeID)
		if err != nil || ram != int64(256<<20) || disk != int64(1<<30) {
			t.Fatalf("uncertain cutover did not retain %s capacity: ram=%d disk=%d err=%v", nodeID, ram, disk, err)
		}
	}
}

func TestRunMigrationCutoverPreservesLogicalInstanceID(t *testing.T) {
	h := newTestHandler(t, false)
	publisher := &migrationTestPublisher{db: h.db, completeBeforeReturn: true}
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
	prepareMigrationCapacity(t, h, "node_001", "node_002")
	if err := h.db.CreateOperation("op_migrate_cutover", "inst_cutover", "node_001", "migrate", "running", "system"); err != nil {
		t.Fatalf("create migration op: %v", err)
	}
	sourceNode := "node_001"
	route := database.PublicRoute{ID: "route_cutover", Hostname: "cutover.example.test", AppInstanceID: "inst_cutover", NodeID: &sourceNode, ServiceName: "web", TargetHost: "10.99.0.2", TargetPort: 40000, TargetURL: "http://10.99.0.2:40000", RouteKind: string(admiral.RouteKindInstance), Status: string(admiral.RouteStatusActive)}
	if err := h.db.CreatePublicRoute(route); err != nil {
		t.Fatalf("create source route: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	h.networking = &networking.Manager{DB: h.db, Caddy: &networking.CaddyAdminClient{BaseURL: server.URL, HTTP: server.Client()}, Config: &config.Config{}, Log: h.log}

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
	cutoverRoute, err := h.db.GetPublicRoute(route.Hostname)
	if err != nil || cutoverRoute == nil || cutoverRoute.NodeID == nil || *cutoverRoute.NodeID != "node_002" || cutoverRoute.TargetHost != "10.99.0.3" || cutoverRoute.TargetPort != 43121 || cutoverRoute.Status != string(admiral.RouteStatusActive) {
		t.Fatalf("route did not use the target worker and port: route=%+v err=%v", cutoverRoute, err)
	}
	sourceRAM, sourceDisk, err := h.db.GetCommittedResources("node_001")
	if err != nil {
		t.Fatalf("get source capacity after cutover: %v", err)
	}
	targetRAM, targetDisk, err := h.db.GetCommittedResources("node_002")
	if err != nil {
		t.Fatalf("get target capacity after cutover: %v", err)
	}
	if sourceRAM != 0 || sourceDisk != 0 || targetRAM != int64(256<<20) || targetDisk != int64(1<<30) {
		t.Fatalf("cutover capacity is inconsistent: source=(%d,%d) target=(%d,%d)", sourceRAM, sourceDisk, targetRAM, targetDisk)
	}

	op, err := h.db.GetOperation("op_migrate_cutover")
	if err != nil {
		t.Fatalf("get migration operation: %v", err)
	}
	if op == nil || op.Status != "succeeded" {
		t.Fatalf("expected migration op to succeed, got %+v", op)
	}
	if publisher.targetProvisionState != "migrating" {
		t.Fatalf("target was provisioned with instance state %q, expected migrating", publisher.targetProvisionState)
	}
	if op.Metadata == nil || len(op.Metadata.BackupRecordIDs) != 2 {
		t.Fatalf("migration did not record the fresh backup identities: %+v", op.Metadata)
	}
	fresh := make(map[string]bool)
	for _, id := range op.Metadata.BackupRecordIDs {
		fresh[id] = true
	}
	for _, task := range publisher.published {
		if task.Action == admiral.ActionRestoreBackup {
			if task.Restore == nil || !fresh[task.Restore.BackupID] {
				t.Fatalf("restore did not use a fresh migration backup: %+v", task.Restore)
			}
			delete(fresh, task.Restore.BackupID)
		}
	}
	if len(fresh) != 0 {
		t.Fatalf("migration did not restore every fresh backup: %v", fresh)
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
	backups, err := h.db.GetBackupRecords("inst_cutover")
	if err != nil {
		t.Fatalf("load migration backup records: %v", err)
	}
	if len(backups) != 2 {
		t.Fatalf("expected two migration backup records, got %d", len(backups))
	}
	for _, backup := range backups {
		if backup.Status != "succeeded" || backup.ChecksumSHA256 == "" || backup.StorageKey == "" {
			t.Errorf("migration backup record is incomplete: %+v", backup)
		}
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

	services := buildServiceInfos(payload, tier, "inst_001", "cust_001", "", allSecretValues)
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
	return NodeAuthMiddleware(logging.New("test"), h.db, "test-pepper", "worker", nil, next)
}

func setupNodeWithToken(t *testing.T, h *APIHandlers, nodeID, hostname, ip, wgIP, nodeRole, os, podmanV, token string) {
	t.Helper()
	if err := h.db.RegisterNode(nodeID, hostname, ip, wgIP, nodeRole, "", os, podmanV); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if _, err := h.db.Exec("UPDATE nodes SET boot_id = $1 WHERE id = $2", "test-boot-id", nodeID); err != nil {
		t.Fatalf("set test node boot ID: %v", err)
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
		BootID: "test-boot-id",
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
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(body)
	req2.Header.Set("X-Admiral-Task-Signature", hex.EncodeToString(mac.Sum(nil)))
	req2.RemoteAddr = "10.99.0.2:51820"
	rec2 := httptest.NewRecorder()
	wrapped(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on matching WireGuard IP, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}

	// A valid node token must not be able to update a different node by
	// changing the node_id in the authenticated request body.
	forged := admiral.HeartbeatRequest{NodeID: "node_002", BootID: "test-boot-id", Status: "active"}
	forgedBody, _ := json.Marshal(forged)
	forgedReq := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/heartbeat", bytes.NewReader(forgedBody))
	forgedReq.Header.Set("X-Admiral-Token", token)
	forgedReq.RemoteAddr = "10.99.0.2:51820"
	forgedRec := httptest.NewRecorder()
	wrapped(forgedRec, forgedReq)
	if forgedRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for node identity mismatch, got %d", forgedRec.Code)
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
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(body)
	req2.Header.Set("X-Admiral-Task-Signature", hex.EncodeToString(mac.Sum(nil)))
	req2.RemoteAddr = "10.99.0.2:51820"
	rec2 := httptest.NewRecorder()
	wrapped(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}
}

func TestFleetCallbackDedicatedSignatureRequiresFreshTimestamp(t *testing.T) {
	h := newTestHandler(t, false)
	token := "test-token-dedicated-callback"
	setupNodeWithToken(t, h, "node_001", "worker-1", "10.0.0.1", "10.99.0.2", "worker", "fedora", "5.0", token)
	next := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	wrapped := NodeAuthMiddleware(logging.New("test"), h.db, "test-pepper", "worker", nil, next, "callback-key")
	body := []byte(`{"task_id":"task_1"}`)

	makeRequest := func(timestamp string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
		req.Header.Set("X-Admiral-Token", token)
		req.Header.Set("X-Admiral-Task-Timestamp", timestamp)
		mac := hmac.New(sha256.New, []byte("callback-key"))
		_, _ = mac.Write([]byte(timestamp + "."))
		_, _ = mac.Write(body)
		req.Header.Set("X-Admiral-Task-Signature", hex.EncodeToString(mac.Sum(nil)))
		req.RemoteAddr = "10.99.0.2:51820"
		rec := httptest.NewRecorder()
		wrapped(rec, req)
		return rec
	}

	if rec := makeRequest(strconv.FormatInt(time.Now().Add(-16*time.Minute).Unix(), 10)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected stale callback signature to be rejected, got %d", rec.Code)
	}
	if rec := makeRequest(strconv.FormatInt(time.Now().Unix(), 10)); rec.Code != http.StatusNoContent {
		t.Fatalf("expected fresh callback signature to pass, got %d", rec.Code)
	}
}

func TestInstanceAvailabilityTracksNodeAndFreshRuntimeWithoutMutatingObservation(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_001", "active", "running"); err != nil {
		t.Fatalf("set instance status: %v", err)
	}
	heartbeat := &admiral.HeartbeatRequest{NodeID: "node_001", BootID: "test-boot-before", DiskTotal: 100, DiskUsed: 10, RAMTotal: 100, RAMUsed: 10}
	if err := h.db.UpdateNodeHeartbeat("node_001", heartbeat); err != nil {
		t.Fatalf("set initial heartbeat: %v", err)
	}
	if err := h.db.UpdateNodeHealth("node_001", "healthy", "", true, ""); err != nil {
		t.Fatalf("set initial worker health: %v", err)
	}
	unobserved, err := h.db.GetCustomerApp("inst_001")
	if err != nil {
		t.Fatalf("get instance before first runtime observation: %v", err)
	}
	if unobserved.EffectiveAvailability != "unknown" || unobserved.AvailabilityReason != "runtime_not_observed" {
		t.Fatalf("expected unknown/runtime_not_observed before first health report, got %s/%s", unobserved.EffectiveAvailability, unobserved.AvailabilityReason)
	}
	if err := h.db.UpdateInstanceHealth("inst_001", "healthy", "last worker observation"); err != nil {
		t.Fatalf("set last runtime observation: %v", err)
	}
	available, err := h.db.GetCustomerApp("inst_001")
	if err != nil {
		t.Fatalf("get initially available instance: %v", err)
	}
	if available.EffectiveAvailability != "available" {
		t.Fatalf("expected available worker, got %q (%s)", available.EffectiveAvailability, available.AvailabilityReason)
	}
	lastHealthCheck := available.LastHealthChecked

	if _, err := h.db.Exec("UPDATE nodes SET last_heartbeat = CURRENT_TIMESTAMP - INTERVAL '3 minutes' WHERE id = $1", "node_001"); err != nil {
		t.Fatalf("expire worker heartbeat: %v", err)
	}
	if _, err := h.db.MarkNodesOffline(2 * time.Minute); err != nil {
		t.Fatalf("mark stale worker offline: %v", err)
	}
	unavailable, err := h.db.GetCustomerApp("inst_001")
	if err != nil {
		t.Fatalf("get unavailable instance: %v", err)
	}
	if unavailable.EffectiveAvailability != "unavailable" || unavailable.AvailabilityReason != "heartbeat_timeout" {
		t.Fatalf("expected unavailable/heartbeat_timeout, got %s/%s", unavailable.EffectiveAvailability, unavailable.AvailabilityReason)
	}
	if unavailable.HealthStatus != "healthy" || unavailable.HealthMessage != "last worker observation" {
		t.Fatalf("worker outage overwrote last runtime observation: %s/%s", unavailable.HealthStatus, unavailable.HealthMessage)
	}
	if unavailable.LastHealthChecked == nil || lastHealthCheck == nil || !unavailable.LastHealthChecked.Equal(*lastHealthCheck) {
		t.Fatalf("worker outage changed last health check: before=%v after=%v", lastHealthCheck, unavailable.LastHealthChecked)
	}
	page, _, err := h.db.GetCustomerAppsPage(10, 0, "cust_001")
	if err != nil {
		t.Fatalf("list unavailable instance: %v", err)
	}
	if len(page) != 1 || page[0].EffectiveAvailability != "unavailable" {
		t.Fatalf("customer list did not derive unavailable state: %+v", page)
	}
	filtered, _, err := h.db.GetCustomerAppsPageFiltered(10, 0, "cust_001", false, "")
	if err != nil {
		t.Fatalf("list filtered unavailable instance: %v", err)
	}
	if len(filtered) != 1 || filtered[0].EffectiveAvailability != "unavailable" {
		t.Fatalf("filtered list did not derive unavailable state: %+v", filtered)
	}

	if err := h.db.UpdateNodeHeartbeat("node_001", heartbeat); err != nil {
		t.Fatalf("restore worker heartbeat: %v", err)
	}
	if err := h.db.UpdateNodeHealth("node_001", "healthy", "", true, ""); err != nil {
		t.Fatalf("restore worker health: %v", err)
	}
	recovered, err := h.db.GetCustomerApp("inst_001")
	if err != nil {
		t.Fatalf("get recovered instance: %v", err)
	}
	if recovered.EffectiveAvailability != "available" {
		t.Fatalf("expected availability to recover on same node, got %s/%s", recovered.EffectiveAvailability, recovered.AvailabilityReason)
	}
	if recovered.NodeID == nil || *recovered.NodeID != "node_001" {
		t.Fatalf("recovery changed node placement: %v", recovered.NodeID)
	}

	if _, err := h.db.Exec("UPDATE customer_apps SET last_health_checked_at = CURRENT_TIMESTAMP - INTERVAL '90 seconds' WHERE id = $1", "inst_001"); err != nil {
		t.Fatalf("expire runtime observation: %v", err)
	}
	stale, err := h.db.GetCustomerApp("inst_001")
	if err != nil {
		t.Fatalf("get instance with stale runtime observation: %v", err)
	}
	if stale.EffectiveAvailability != "unavailable" || stale.AvailabilityReason != "runtime_observation_stale" {
		t.Fatalf("expected unavailable/runtime_observation_stale, got %s/%s", stale.EffectiveAvailability, stale.AvailabilityReason)
	}
	if stale.HealthStatus != "healthy" || stale.HealthMessage != "last worker observation" {
		t.Fatalf("stale availability changed last runtime observation: %s/%s", stale.HealthStatus, stale.HealthMessage)
	}
	if stale.LastHealthChecked == nil || time.Since(*stale.LastHealthChecked) < 85*time.Second {
		t.Fatalf("stale availability did not preserve the old health timestamp: %v", stale.LastHealthChecked)
	}

	if err := h.db.UpdateInstanceHealth("inst_001", "stopped", "pod not running after reboot"); err != nil {
		t.Fatalf("record stopped workload: %v", err)
	}
	stopped, err := h.db.GetCustomerApp("inst_001")
	if err != nil {
		t.Fatalf("get instance with fresh stopped runtime observation: %v", err)
	}
	if stopped.EffectiveAvailability != "unavailable" || stopped.AvailabilityReason != "runtime_not_healthy" {
		t.Fatalf("expected unavailable/runtime_not_healthy, got %s/%s", stopped.EffectiveAvailability, stopped.AvailabilityReason)
	}
	if stopped.HealthStatus != "stopped" || stopped.HealthMessage != "pod not running after reboot" {
		t.Fatalf("fresh stopped observation was lost: %s/%s", stopped.HealthStatus, stopped.HealthMessage)
	}
	if err := h.db.UpdateInstanceHealth("inst_001", "healthy", "recovered after reboot"); err != nil {
		t.Fatalf("record recovered workload: %v", err)
	}
	available, err = h.db.GetCustomerApp("inst_001")
	if err != nil {
		t.Fatalf("get recovered runtime availability: %v", err)
	}
	if available.EffectiveAvailability != "available" || available.AvailabilityReason != "" {
		t.Fatalf("fresh healthy runtime did not restore availability: %s/%s", available.EffectiveAvailability, available.AvailabilityReason)
	}

	for _, tc := range []struct {
		commercialStatus   string
		technicalStatus    string
		availabilityReason string
	}{
		{commercialStatus: "active", technicalStatus: "stopped", availabilityReason: "instance_stopped"},
		{commercialStatus: "active", technicalStatus: "paused_for_storage", availabilityReason: "instance_paused_for_storage"},
		{commercialStatus: "active", technicalStatus: "deprovisioning", availabilityReason: "instance_deprovisioning"},
		{commercialStatus: "cancelled", technicalStatus: "deprovisioned", availabilityReason: "instance_deprovisioned"},
	} {
		if err := h.db.UpdateCustomerAppStatus("inst_001", tc.commercialStatus, tc.technicalStatus); err != nil {
			t.Fatalf("set non-serving instance status %q: %v", tc.technicalStatus, err)
		}
		nonServing, err := h.db.GetCustomerApp("inst_001")
		if err != nil {
			t.Fatalf("get instance in %q state: %v", tc.technicalStatus, err)
		}
		if nonServing.EffectiveAvailability != "unavailable" || nonServing.AvailabilityReason != tc.availabilityReason {
			t.Fatalf("expected unavailable/%s for %s, got %s/%s", tc.availabilityReason, tc.technicalStatus, nonServing.EffectiveAvailability, nonServing.AvailabilityReason)
		}
		if nonServing.HealthStatus != "healthy" || nonServing.HealthMessage != "recovered after reboot" {
			t.Fatalf("lifecycle availability overwrote last runtime observation: %s/%s", nonServing.HealthStatus, nonServing.HealthMessage)
		}
	}
}

func TestInstanceAvailabilityInvalidatesHealthFromPreviousNodeBoot(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_reboot", "worker-reboot", "10.0.0.8", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_reboot", "cust_reboot", "testapp", "starter", "node_reboot", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_reboot", "active", "running"); err != nil {
		t.Fatalf("set instance status: %v", err)
	}
	if err := h.db.UpdateNodeHeartbeat("node_reboot", &admiral.HeartbeatRequest{NodeID: "node_reboot", BootID: "boot-before"}); err != nil {
		t.Fatalf("record initial heartbeat: %v", err)
	}
	if err := h.db.UpdateNodeHealth("node_reboot", "healthy", "", true, ""); err != nil {
		t.Fatalf("set node health: %v", err)
	}
	if err := h.db.UpdateInstanceHealthForBoot("inst_reboot", "healthy", "running", "all services ready", "boot-before", false); err != nil {
		t.Fatalf("record pre-reboot runtime health: %v", err)
	}
	before, err := h.db.GetCustomerApp("inst_reboot")
	if err != nil {
		t.Fatalf("get pre-reboot instance: %v", err)
	}
	if before.EffectiveAvailability != "available" {
		t.Fatalf("expected available before reboot, got %s/%s", before.EffectiveAvailability, before.AvailabilityReason)
	}

	if err := h.db.UpdateNodeHeartbeat("node_reboot", &admiral.HeartbeatRequest{NodeID: "node_reboot", BootID: "boot-after"}); err != nil {
		t.Fatalf("record post-reboot heartbeat: %v", err)
	}
	afterBoot, err := h.db.GetCustomerApp("inst_reboot")
	if err != nil {
		t.Fatalf("get instance after node reboot: %v", err)
	}
	if afterBoot.EffectiveAvailability != "unavailable" || afterBoot.AvailabilityReason != "runtime_observation_before_node_boot" {
		t.Fatalf("expected unavailable until a post-boot observation, got %s/%s", afterBoot.EffectiveAvailability, afterBoot.AvailabilityReason)
	}
	if afterBoot.HealthStatus != before.HealthStatus || afterBoot.HealthMessage != before.HealthMessage {
		t.Fatalf("reboot overwrote historical runtime health: before=%s/%s after=%s/%s", before.HealthStatus, before.HealthMessage, afterBoot.HealthStatus, afterBoot.HealthMessage)
	}
	if before.LastHealthChecked == nil || afterBoot.LastHealthChecked == nil || !before.LastHealthChecked.Equal(*afterBoot.LastHealthChecked) {
		t.Fatalf("reboot changed the historical health timestamp: before=%v after=%v", before.LastHealthChecked, afterBoot.LastHealthChecked)
	}

	if err := h.db.UpdateInstanceHealthForBoot("inst_reboot", "healthy", "running", "all services ready after reboot", "boot-after", false); err != nil {
		t.Fatalf("record post-reboot runtime health: %v", err)
	}
	recovered, err := h.db.GetCustomerApp("inst_reboot")
	if err != nil {
		t.Fatalf("get recovered instance: %v", err)
	}
	if recovered.EffectiveAvailability != "available" {
		t.Fatalf("expected available after a fresh post-boot observation, got %s/%s", recovered.EffectiveAvailability, recovered.AvailabilityReason)
	}
}

func TestInstanceAvailabilityExpiresPreBootHealthBeforeHeartbeatChangesBootID(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_boot_pending", "worker-boot-pending", "10.0.0.9", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_boot_pending", "cust_boot_pending", "testapp", "starter", "node_boot_pending", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_boot_pending", "active", "running"); err != nil {
		t.Fatalf("set instance status: %v", err)
	}
	if err := h.db.UpdateNodeHeartbeat("node_boot_pending", &admiral.HeartbeatRequest{NodeID: "node_boot_pending", BootID: "boot-before"}); err != nil {
		t.Fatalf("record pre-reboot heartbeat: %v", err)
	}
	if err := h.db.UpdateNodeHealth("node_boot_pending", "healthy", "", true, ""); err != nil {
		t.Fatalf("set node health: %v", err)
	}
	if err := h.db.UpdateInstanceHealthForBoot("inst_boot_pending", "healthy", "running", "pre-boot observation", "boot-before", false); err != nil {
		t.Fatalf("record pre-reboot runtime health: %v", err)
	}
	if _, err := h.db.Exec("UPDATE customer_apps SET last_health_checked_at = CURRENT_TIMESTAMP - INTERVAL '16 seconds' WHERE id = $1", "inst_boot_pending"); err != nil {
		t.Fatalf("age pre-reboot health while the new heartbeat is pending: %v", err)
	}

	stale, err := h.db.GetCustomerApp("inst_boot_pending")
	if err != nil {
		t.Fatalf("get instance before the post-boot heartbeat: %v", err)
	}
	if stale.EffectiveAvailability != "unavailable" || stale.AvailabilityReason != "runtime_observation_stale" {
		t.Fatalf("expected stale pre-boot health to be unavailable before heartbeat, got %s/%s", stale.EffectiveAvailability, stale.AvailabilityReason)
	}
	if stale.HealthStatus != "healthy" || stale.HealthMessage != "pre-boot observation" {
		t.Fatalf("stale availability changed historical health: %s/%s", stale.HealthStatus, stale.HealthMessage)
	}
	if stale.LastHealthChecked == nil || time.Since(*stale.LastHealthChecked) < 15*time.Second {
		t.Fatalf("stale availability did not preserve the old health timestamp: %v", stale.LastHealthChecked)
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
		BootID:       "test-boot-id",
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
		BootID:       "test-boot-id",
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

func TestHandleAdminHealthCallbackPreservesInitializingTechnicalStatus(t *testing.T) {
	h := newTestHandler(t, false)

	token := "test-token-health-preserve"
	setupNodeWithToken(t, h, "node_001", "worker-1", "10.0.0.1", "10.99.0.2", "worker", "fedora", "5.0", token)
	wrapped := nodeAuthWrapped(h, token, h.HandleAdminHealthCallback)

	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_001", "", "initializing"); err != nil {
		t.Fatalf("set technical status: %v", err)
	}

	body, _ := json.Marshal(admiral.HealthReport{
		InstanceID:   "inst_001",
		NodeID:       "node_001",
		BootID:       "test-boot-id",
		HealthStatus: admiral.HealthHealthy,
		Message:      "all good",
		HostPorts:    map[string]int{"web": 18080},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/health", bytes.NewReader(body))
	req.Header.Set("X-Admiral-Token", token)
	req.RemoteAddr = "10.99.0.2:51820"
	rec := httptest.NewRecorder()

	wrapped(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d body=%s", rec.Code, rec.Body.String())
	}

	inst, err := h.db.GetCustomerApp("inst_001")
	if err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if inst.TechnicalStatus != "initializing" {
		t.Fatalf("expected technical_status to remain initializing, got %q", inst.TechnicalStatus)
	}
	if inst.HealthStatus != string(admiral.HealthHealthy) {
		t.Fatalf("expected health_status healthy, got %q", inst.HealthStatus)
	}
}

func TestHandleAdminHealthCallbackDoesNotActivateRoutesForUnhealthyInstance(t *testing.T) {
	h := newTestHandler(t, false)
	token := "test-token-unhealthy-route"
	setupNodeWithToken(t, h, "node_001", "worker-1", "10.0.0.1", "10.99.0.2", "worker", "fedora", "5.0", token)
	wrapped := nodeAuthWrapped(h, token, h.HandleAdminHealthCallback)

	payload := admiral.AppDefinitionPayload{
		Name:        "health-app",
		DisplayName: "Health App",
		Services: map[string]admiral.YAMLService{
			"web": {Image: "docker.io/library/nginx:1.27", Port: 8080, Public: true},
		},
		Tiers: map[string]admiral.YAMLTier{
			"starter": {CPU: 1, Memory: "512MiB", Storage: "1GiB"},
		},
	}
	rawYAML := "name: health-app\nservices:\n  web:\n    image: docker.io/library/nginx:1.27\n    port: 8080\n    public: true\ntiers:\n  starter:\n    cpu: 1\n    memory: 512MiB\n    storage: 1GiB\n"
	if err := h.db.SaveAppDefinition(payload.Name, payload.DisplayName, "", rawYAML, nil, "improvement"); err != nil {
		t.Fatalf("save app definition: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", payload.Name, "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	manager := &networking.Manager{DB: h.db, Config: &config.Config{DevMode: true, NetworkingAppsDomain: "apps.example.com"}}
	routes, err := manager.CreateInstanceRoutes("inst_001", payload, "node_001")
	if err != nil {
		t.Fatalf("create instance route: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("created routes = %d, want 1", len(routes))
	}
	h.networking = manager

	body, _ := json.Marshal(admiral.HealthReport{
		InstanceID:   "inst_001",
		NodeID:       "node_001",
		BootID:       "test-boot-id",
		HealthStatus: admiral.HealthUnhealthy,
		Message:      "database service unavailable",
		HostPorts:    map[string]int{"web": 43123},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/health", bytes.NewReader(body))
	req.Header.Set("X-Admiral-Token", token)
	req.RemoteAddr = "10.99.0.2:51820"
	rec := httptest.NewRecorder()
	wrapped(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health callback status = %d body=%s", rec.Code, rec.Body.String())
	}

	stored, err := h.db.GetPublicRoute(routes[0].Hostname)
	if err != nil {
		t.Fatalf("get instance route: %v", err)
	}
	if stored.Status != string(admiral.RouteStatusPending) || stored.TargetPort == 43123 {
		t.Fatalf("unhealthy callback activated the public route: %+v", stored)
	}
}
