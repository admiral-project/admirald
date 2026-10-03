package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestHandleCustomerAppActionRejectsOtherCustomer(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_customer_scope", "worker-scope", "10.0.0.10", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_customer_scope", "customer_a", "testapp", "starter", "node_customer_scope", `{}`); err != nil {
		t.Fatalf("create customer app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/customer-apps/action", bytes.NewBufferString(`{"instance_id":"inst_customer_scope","action":"stop"}`))
	req.Header.Set("X-Admiral-Customer-ID", "customer_b")
	rec := httptest.NewRecorder()

	h.HandleCustomerAppAction(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-customer action, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleCustomerAppByIDRejectsMissingInstanceID(t *testing.T) {
	h := &APIHandlers{}
	rec := httptest.NewRecorder()
	h.HandleCustomerAppByID(rec, httptest.NewRequest(http.MethodGet, "/api/v1/customer-apps/", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCustomerOperationStatusEnforcesOwnership(t *testing.T) {
	h := newTestHandler(t, false)
	nodeID := "node_operation_scope"
	if err := h.db.RegisterNode(nodeID, "worker-scope", "10.0.0.10", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ instance, customer, operation string }{
		{"inst_operation_a", "customer_a", "op_operation_a"},
		{"inst_operation_b", "customer_b", "op_operation_b"},
	} {
		if err := h.db.CreateCustomerApp(item.instance, item.customer, "testapp", "starter", nodeID, `{}`); err != nil {
			t.Fatal(err)
		}
		if err := h.db.CreateOperation(item.operation, item.instance, nodeID, "restore_backup", "queued", "harbor-token"); err != nil {
			t.Fatal(err)
		}
	}
	server := &Server{adminToken: "admin-secret", harborToken: "harbor-secret", handlers: h}
	handler := server.V1HarborAuthMiddleware(h.HandleCustomerAppByID)
	for _, test := range []struct {
		name, customer, operation string
		status                    int
	}{
		{"owner", "customer_a", "op_operation_a", http.StatusOK},
		{"other customer", "customer_b", "op_operation_a", http.StatusForbidden},
		{"other instance operation", "customer_a", "op_operation_b", http.StatusNotFound},
		{"unknown operation", "customer_a", "op_missing", http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/customer-apps/inst_operation_a/operations/"+test.operation, nil)
			req.Header.Set("Authorization", "Bearer harbor-secret")
			req.Header.Set("X-Admiral-Customer-ID", test.customer)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != test.status {
				t.Fatalf("expected %d, got %d: %s", test.status, rec.Code, rec.Body.String())
			}
			if test.status == http.StatusOK {
				var result map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if len(result) != 3 || result["id"] != test.operation || result["instance_id"] != "inst_operation_a" || result["status"] != "queued" {
					t.Fatalf("unexpected customer operation response: %#v", result)
				}
			}
		})
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/operations", nil)
	req.Header.Set("Authorization", "Bearer harbor-secret")
	rec := httptest.NewRecorder()
	server.V1AuthMiddleware(h.HandleOperations).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Harbor accessed administrative operations: %d", rec.Code)
	}
}

func TestHandleCustomerAppsRejectsOtherCustomerProvision(t *testing.T) {
	h := newTestHandler(t, false)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/customer-apps", bytes.NewBufferString(`{"app_definition_name":"testapp","tier_name":"starter","customer_id":"customer_a"}`))
	req.Header.Set("X-Admiral-Customer-ID", "customer_b")
	rec := httptest.NewRecorder()

	h.HandleCustomerApps(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-customer provision, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHarborCustomerAppResponsesHideInfrastructureFields(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_customer_view", "worker-private", "10.0.0.10", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatal(err)
	}
	if err := h.db.CreateCustomerApp("inst_customer_view", "customer_view", "testapp", "starter", "node_customer_view", `{"private":"tier snapshot"}`); err != nil {
		t.Fatal(err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_customer_view", "", "running"); err != nil {
		t.Fatal(err)
	}

	server := &Server{adminToken: "admin-secret", harborToken: "harbor-secret", handlers: h}
	detailHandler := server.V1HarborAuthMiddleware(h.HandleCustomerAppByID)
	listHandler := server.V1HarborAuthMiddleware(h.HandleCustomerApps)
	request := func(handler http.HandlerFunc, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer harbor-secret")
		req.Header.Set("X-Admiral-Customer-ID", "customer_view")
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec
	}
	assertCustomerSafe := func(body []byte) {
		t.Helper()
		var response map[string]interface{}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{
			"node_id", "hostname", "logical_instance_id", "inspect_data", "tier_snapshot_json",
			"customer_id", "emergency_limit_bytes",
		} {
			if _, exists := response[field]; exists {
				t.Errorf("Harbor response exposed internal field %q: %#v", field, response)
			}
		}
		if response["id"] != "inst_customer_view" || response["technical_status"] != "running" {
			t.Errorf("Harbor response is missing customer-visible state: %#v", response)
		}
	}

	detail := request(detailHandler, "/api/v1/customer-apps/inst_customer_view")
	if detail.Code != http.StatusOK {
		t.Fatalf("customer detail returned %d: %s", detail.Code, detail.Body.String())
	}
	assertCustomerSafe(detail.Body.Bytes())

	list := request(listHandler, "/api/v1/customer-apps?customer_id=customer_view")
	if list.Code != http.StatusOK {
		t.Fatalf("customer list returned %d: %s", list.Code, list.Body.String())
	}
	var records []json.RawMessage
	if err := json.Unmarshal(list.Body.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("customer list returned %d apps, want 1", len(records))
	}
	assertCustomerSafe(records[0])

	adminRequest := httptest.NewRequest(http.MethodGet, "/api/v1/customer-apps/inst_customer_view", nil)
	adminRequest.Header.Set("Authorization", "Bearer admin-secret")
	adminResponse := httptest.NewRecorder()
	detailHandler(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("system detail returned %d: %s", adminResponse.Code, adminResponse.Body.String())
	}
	var systemRecord map[string]interface{}
	if err := json.Unmarshal(adminResponse.Body.Bytes(), &systemRecord); err != nil {
		t.Fatal(err)
	}
	if systemRecord["node_id"] == nil || systemRecord["tier_snapshot_json"] == nil {
		t.Fatalf("system detail lost control-plane fields: %#v", systemRecord)
	}
}

func TestCustomerBackupListAndReadAreInstanceScoped(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_backup_scope", "worker-scope", "10.0.0.10", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ instance, customer string }{
		{"inst_backup_owner", "customer_a"},
		{"inst_backup_other", "customer_b"},
	} {
		if err := h.db.CreateCustomerApp(item.instance, item.customer, "testapp", "starter", "node_backup_scope", `{}`); err != nil {
			t.Fatal(err)
		}
		if err := h.db.CreateBackupRecord(&admiral.BackupRecord{
			ID: item.instance + "_record", InstanceID: item.instance, AppID: "testapp", TierID: "starter",
			NodeID: "private-node-id", BackupType: "database", Service: "db", DatabaseType: "postgresql",
			Status: "succeeded", StorageBackend: "s3", StorageKey: "private/bucket/key", SizeBytes: 42,
			ChecksumSHA256: "abc123", TriggeredBy: "manual",
		}); err != nil {
			t.Fatal(err)
		}
	}

	server := &Server{adminToken: "admin-secret", harborToken: "harbor-secret", handlers: h}
	handler := server.V1HarborAuthMiddleware(h.HandleCustomerAppByID)
	request := func(path, customer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer harbor-secret")
		req.Header.Set("X-Admiral-Customer-ID", customer)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	list := request("/api/v1/customer-apps/inst_backup_owner/backups", "customer_a")
	if list.Code != http.StatusOK {
		t.Fatalf("owner backup list returned %d: %s", list.Code, list.Body.String())
	}
	var records []map[string]interface{}
	if err := json.Unmarshal(list.Body.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0]["id"] != "inst_backup_owner_record" {
		t.Fatalf("unexpected customer backup list: %#v", records)
	}
	if _, ok := records[0]["node_id"]; ok {
		t.Fatal("customer backup response exposed the node ID")
	}
	if _, ok := records[0]["storage_key"]; ok {
		t.Fatal("customer backup response exposed the storage key")
	}

	if got := request("/api/v1/customer-apps/inst_backup_owner/backups", "customer_b").Code; got != http.StatusForbidden {
		t.Fatalf("cross-customer backup list returned %d, want 403", got)
	}
	if got := request("/api/v1/customer-apps/inst_backup_owner/backups/inst_backup_other_record", "customer_a").Code; got != http.StatusNotFound {
		t.Fatalf("cross-instance backup read returned %d, want 404", got)
	}
}

func TestCustomerRestoreRejectsBackupOwnedByAnotherCustomer(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_restore_scope", "worker-scope", "10.0.0.10", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ instance, customer string }{
		{"inst_restore_owner", "customer_a"},
		{"inst_restore_other", "customer_b"},
	} {
		if err := h.db.CreateCustomerApp(item.instance, item.customer, "testapp", "starter", "node_restore_scope", `{}`); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.db.CreateBackupRecord(&admiral.BackupRecord{
		ID: "bk_restore_other", InstanceID: "inst_restore_other", AppID: "testapp", TierID: "starter",
		NodeID: "node_restore_scope", BackupType: "database", Service: "db", DatabaseType: "postgresql",
		Status: "succeeded", StorageBackend: "s3", StorageKey: "customer-b/private-backup",
	}); err != nil {
		t.Fatal(err)
	}

	server := &Server{adminToken: "admin-secret", harborToken: "harbor-secret", handlers: h}
	handler := server.V1HarborAuthMiddleware(h.HandleCustomerAppByID)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/customer-apps/inst_restore_owner/backups/restore", bytes.NewBufferString(
		`{"backup_id":"bk_restore_other","target_app_id":"inst_restore_owner","service":"db"}`,
	))
	req.Header.Set("Authorization", "Bearer harbor-secret")
	req.Header.Set("X-Admiral-Customer-ID", "customer_a")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-customer restore returned %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

func TestCustomerRestorePOSTDispatchesAndQueuesS3Restore(t *testing.T) {
	h := newTestHandler(t, false)
	rawYAML := `name: testapp
services:
  db:
    image: postgres:16
    backup:
      type: database
      engine: postgresql
`
	if err := h.db.SaveAppDefinition("testapp", "Test App", "Restore test app", rawYAML, []database.AppTier{{
		AppName: "testapp", Name: "starter", CPU: 1, Memory: "512MiB", Storage: "1GiB",
	}}, "improvement"); err != nil {
		t.Fatalf("save app definition and tier: %v", err)
	}
	if err := h.db.RegisterNode("node_customer_restore", "worker-restore", "10.0.0.10", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_customer_restore", "customer_restore", "testapp", "starter", "node_customer_restore", `{"backups":{"manual_backups":true,"backup_database":true,"restore_allowed":true}}`); err != nil {
		t.Fatalf("create customer app: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_customer_restore", "", "paused"); err != nil {
		t.Fatalf("pause customer app: %v", err)
	}
	if err := h.db.CreateBackupRecord(&admiral.BackupRecord{
		ID: "bk_customer_restore", InstanceID: "inst_customer_restore", AppID: "testapp", TierID: "starter",
		NodeID: "node_customer_restore", BackupType: "database", Service: "db", DatabaseType: "postgresql",
		Status: "succeeded", StorageBackend: "s3", StorageKey: "admiral/backups/db.dump",
	}); err != nil {
		t.Fatalf("create backup record: %v", err)
	}
	if err := h.db.SaveBackupStorageConfig(&admiral.BackupStorageConfig{
		ID: "global", Backend: "s3", Enabled: true, Endpoint: "https://s3.example.test", Bucket: "admiral",
	}); err != nil {
		t.Fatalf("save storage config: %v", err)
	}
	publisher := &migrationTestPublisher{db: h.db}
	h.publisher = publisher

	server := &Server{adminToken: "admin-secret", harborToken: "harbor-secret", handlers: h}
	handler := server.V1HarborAuthMiddleware(h.HandleCustomerAppByID)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/customer-apps/inst_customer_restore/backups/restore", bytes.NewBufferString(
		`{"backup_id":"bk_customer_restore","target_app_id":"inst_customer_restore","service":"db"}`,
	))
	req.Header.Set("Authorization", "Bearer harbor-secret")
	req.Header.Set("X-Admiral-Customer-ID", "customer_restore")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("customer restore returned %d, want 202: %s", rec.Code, rec.Body.String())
	}
	var response admiral.RestoreBackupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode restore response: %v", err)
	}
	if response.OperationID == "" || response.Status != "queued" {
		t.Fatalf("unexpected restore response: %+v", response)
	}
	if len(publisher.published) != 1 {
		t.Fatalf("published %d restore tasks, want one", len(publisher.published))
	}
	task := publisher.published[0]
	if task.Action != admiral.ActionRestoreBackup || task.NodeID != "node_customer_restore" || task.Storage == nil || task.Storage.Backend != "s3" {
		t.Fatalf("unexpected restore task: %+v", task)
	}
	instance, err := h.db.GetCustomerApp("inst_customer_restore")
	if err != nil {
		t.Fatalf("load restored app: %v", err)
	}
	if instance.TechnicalStatus != "restoring" {
		t.Fatalf("instance status is %q, want restoring", instance.TechnicalStatus)
	}

	badMethod := httptest.NewRequest(http.MethodPut, "/api/v1/customer-apps/inst_customer_restore/backups/restore", nil)
	badMethod.Header.Set("Authorization", "Bearer harbor-secret")
	badMethod.Header.Set("X-Admiral-Customer-ID", "customer_restore")
	badMethodRec := httptest.NewRecorder()
	handler.ServeHTTP(badMethodRec, badMethod)
	if badMethodRec.Code != http.StatusMethodNotAllowed || !strings.Contains(badMethodRec.Body.String(), "restore requires POST") {
		t.Fatalf("unsupported restore method returned %d: %s", badMethodRec.Code, badMethodRec.Body.String())
	}
}

func TestCustomerBackupPolicyBlocksDisabledRestoreAndManualBackup(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("node_backup_policy", "worker-policy", "10.0.0.20", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_backup_policy", "customer_policy", "testapp", "starter", "node_backup_policy", `{"backups":{"manual_backups":false,"backup_database":false,"backup_volumes":false,"restore_allowed":false}}`); err != nil {
		t.Fatalf("create customer app: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_backup_policy", "", "paused"); err != nil {
		t.Fatalf("pause customer app: %v", err)
	}

	restoreReq := httptest.NewRequest(http.MethodPost, "/api/v1/customer-apps/inst_backup_policy/backups/restore", bytes.NewBufferString(
		`{"backup_id":"uploaded_policy_backup","service":"db","source":{"type":"https","uri":"https://backup.example.test/file.dump"}}`,
	))
	restoreReq.Header.Set("X-Admiral-Customer-ID", "customer_policy")
	restoreRec := httptest.NewRecorder()
	h.HandleCustomerAppBackups(restoreRec, restoreReq, "inst_backup_policy", []string{"restore"})
	if restoreRec.Code != http.StatusForbidden || !strings.Contains(restoreRec.Body.String(), "Restore is disabled") {
		t.Fatalf("disabled restore returned %d: %s", restoreRec.Code, restoreRec.Body.String())
	}
	if err := h.db.UpdateCustomerAppStatus("inst_backup_policy", "", "running"); err != nil {
		t.Fatalf("resume customer app: %v", err)
	}

	backupReq := httptest.NewRequest(http.MethodPost, "/api/v1/customer-apps/action", bytes.NewBufferString(
		`{"instance_id":"inst_backup_policy","action":"backup","service":"db"}`,
	))
	backupReq.Header.Set("X-Admiral-Customer-ID", "customer_policy")
	backupRec := httptest.NewRecorder()
	h.HandleCustomerAppAction(backupRec, backupReq)
	if backupRec.Code != http.StatusForbidden || !strings.Contains(backupRec.Body.String(), "Manual backups are disabled") {
		t.Fatalf("disabled manual backup returned %d: %s", backupRec.Code, backupRec.Body.String())
	}
}
