package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestIsEligibleStorageTestNode(t *testing.T) {
	now := time.Now()
	heartbeat := now.Add(-time.Minute)
	base := database.Node{
		ID: "worker-1", NodeRole: "worker", Status: "active", LastHeartbeat: &heartbeat,
		TokenType: "worker", TokenStatus: "consumed",
	}
	for _, test := range []struct {
		name   string
		mutate func(*database.Node)
		want   bool
	}{
		{name: "live worker", want: true},
		{name: "portal", mutate: func(n *database.Node) { n.NodeRole = "portal" }},
		{name: "inactive", mutate: func(n *database.Node) { n.Status = "offline" }},
		{name: "stale heartbeat", mutate: func(n *database.Node) {
			stale := now.Add(-storageTestHeartbeatTimeout - time.Second)
			n.LastHeartbeat = &stale
		}},
		{name: "missing heartbeat", mutate: func(n *database.Node) { n.LastHeartbeat = nil }},
		{name: "manually disabled", mutate: func(n *database.Node) { n.ManualDisabled = true }},
		{name: "pending token", mutate: func(n *database.Node) { n.TokenStatus = "pending" }},
		{name: "wrong token type", mutate: func(n *database.Node) { n.TokenType = "portal" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			node := base
			if test.mutate != nil {
				test.mutate(&node)
			}
			if got := isEligibleStorageTestNode(node, now); got != test.want {
				t.Fatalf("eligibility = %t, want %t", got, test.want)
			}
		})
	}
}

func TestStorageTestRequiresLiveFleetWorker(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.SaveBackupStorageConfig(&admiral.BackupStorageConfig{
		ID: "global", Backend: "s3", Enabled: true, Endpoint: "https://s3.example.test",
	}); err != nil {
		t.Fatalf("save storage config: %v", err)
	}
	if err := h.db.RegisterNode("portal-storage-test", "portal", "10.0.0.10", "", "portal", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register portal node: %v", err)
	}
	if err := h.db.UpdateNodeStatus("portal-storage-test", "active"); err != nil {
		t.Fatalf("activate portal node: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/settings/backup-storage/test", nil)
	rec := httptest.NewRecorder()
	h.HandleAdminSettingsStorage(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("storage test returned %d, want 503: %s", rec.Code, rec.Body.String())
	}
	operations, err := h.db.GetOperations()
	if err != nil {
		t.Fatalf("list operations: %v", err)
	}
	if len(operations) != 0 {
		t.Fatalf("created %d operation(s) without a Fleet worker", len(operations))
	}
}

func TestStorageTestSelectsLiveWorkerOverPortal(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.SaveBackupStorageConfig(&admiral.BackupStorageConfig{
		ID: "global", Backend: "s3", Enabled: true, Endpoint: "https://s3.example.test",
	}); err != nil {
		t.Fatalf("save storage config: %v", err)
	}
	if err := h.db.RegisterNode("portal-storage-test", "portal", "10.0.0.10", "", "portal", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register portal node: %v", err)
	}
	if err := h.db.UpdateNodeStatus("portal-storage-test", "active"); err != nil {
		t.Fatalf("activate portal node: %v", err)
	}
	if err := h.db.RegisterNode("worker-storage-test", "worker", "10.0.0.11", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register worker node: %v", err)
	}
	if _, err := h.db.Exec(`UPDATE nodes SET status = 'active', last_heartbeat = CURRENT_TIMESTAMP,
		token_type = 'worker', token_status = 'consumed' WHERE id = $1`, "worker-storage-test"); err != nil {
		t.Fatalf("activate worker token and heartbeat: %v", err)
	}
	publisher := &migrationTestPublisher{db: h.db}
	h.publisher = publisher

	req := httptest.NewRequest(http.MethodPost, "/api/admin/settings/backup-storage/test", nil)
	rec := httptest.NewRecorder()
	h.HandleAdminSettingsStorage(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("storage test returned %d, want 202: %s", rec.Code, rec.Body.String())
	}
	if len(publisher.published) != 1 {
		t.Fatalf("published %d task(s), want one", len(publisher.published))
	}
	if publisher.published[0].NodeID != "worker-storage-test" || publisher.published[0].Action != admiral.TaskAction("test_backup_storage") {
		t.Fatalf("storage test task sent to wrong executor: %+v", publisher.published[0])
	}
}
