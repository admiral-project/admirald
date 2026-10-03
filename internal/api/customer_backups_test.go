// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestUploadedRestoreRecordUsesTargetBackupContract(t *testing.T) {
	instance := &database.CustomerApp{ID: "inst_owner", AppDefinitionName: "wordpress"}
	request := admiral.RestoreBackupRequest{
		BackupID:    "upbk_uploaded",
		TargetAppID: instance.ID,
		Service:     "db",
		Source: admiral.BackupRestoreSource{
			Type:      "https",
			URI:       "https://harbor.example.test/backups/upbk_uploaded",
			Checksum:  "0123456789abcdef",
			SizeBytes: 1024,
		},
	}
	rawYAML := `name: wordpress
services:
  db:
    image: docker.io/library/postgres:16
    backup:
      type: database
      engine: postgresql
`

	record, err := uploadedRestoreRecord(request, instance, rawYAML)
	if err != nil {
		t.Fatalf("build uploaded restore record: %v", err)
	}
	if record.ID != request.BackupID || record.InstanceID != instance.ID {
		t.Fatalf("unexpected restore identity: %#v", record)
	}
	if record.BackupType != "database" || record.Service != "db" || record.DatabaseType != "postgresql" {
		t.Fatalf("restore contract does not match target service: %#v", record)
	}
	if record.StorageBackend != "https" || record.StorageKey != request.Source.URI || record.ChecksumSHA256 != request.Source.Checksum {
		t.Fatalf("restore source was not preserved: %#v", record)
	}
}

func TestUploadedRestoreRecordRejectsUnbackedService(t *testing.T) {
	_, err := uploadedRestoreRecord(
		admiral.RestoreBackupRequest{BackupID: "upbk_uploaded", Service: "web", Source: admiral.BackupRestoreSource{Type: "https", URI: "https://example.test/archive"}},
		&database.CustomerApp{ID: "inst_owner", AppDefinitionName: "wordpress"},
		"name: wordpress\nservices:\n  web:\n    image: docker.io/library/nginx:latest\n",
	)
	if err == nil {
		t.Fatal("expected a service without backup configuration to be rejected")
	}
}

func TestCustomerBackupPolicyReadsPersistedAppTierSnapshot(t *testing.T) {
	instance := &database.CustomerApp{TierSnapshotJSON: `{"app_name":"wordpress","name":"small","cpu":1,"memory":"512M","storage":"1G","backup_policy_json":"{\"enabled\":true,\"manual_backups\":true,\"backup_database\":true,\"backup_volumes\":false,\"restore_allowed\":true}"}`}

	policy, err := customerBackupPolicy(instance)
	if err != nil {
		t.Fatalf("decode persisted tier backup policy: %v", err)
	}
	if policy == nil || !policy.ManualBackups || !policy.BackupDatabase || policy.BackupVolumes || !policy.RestoreAllowed {
		t.Fatalf("unexpected persisted tier backup policy: %+v", policy)
	}
}

func TestCustomerBackupPolicyRejectsMalformedPersistedPolicy(t *testing.T) {
	instance := &database.CustomerApp{TierSnapshotJSON: `{"backup_policy_json":"{invalid"}`}
	if _, err := customerBackupPolicy(instance); err == nil {
		t.Fatal("expected malformed persisted backup policy to return an error")
	}
}

func TestCustomerBackupActionAllowsPersistedAppTierPolicy(t *testing.T) {
	h := newTestHandler(t, false)
	rawYAML := `name: testapp
services:
  db:
    image: docker.io/library/mariadb:10
    backup:
      type: database
      engine: mariadb
      database_env: MARIADB_DATABASE
      username_env: MARIADB_USER
      password_env: MARIADB_PASSWORD
`
	policyJSON := `{"enabled":true,"manual_backups":true,"backup_database":true,"backup_volumes":false,"restore_allowed":true}`
	tier := database.AppTier{
		AppName: "testapp", Name: "starter", CPU: 1, Memory: "512M", Storage: "1G",
		BackupPolicyJSON: policyJSON,
	}
	if err := h.db.SaveAppDefinition("testapp", "Test App", "Backup policy test", rawYAML, []database.AppTier{tier}, "improvement"); err != nil {
		t.Fatalf("save app definition: %v", err)
	}
	if err := h.db.RegisterNode("node_persisted_policy", "worker-policy", "10.0.0.30", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	snapshot, err := json.Marshal(tier)
	if err != nil {
		t.Fatalf("encode persisted tier snapshot: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_persisted_policy", "customer_policy", "testapp", "starter", "node_persisted_policy", string(snapshot)); err != nil {
		t.Fatalf("create customer app: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_persisted_policy", "", "running"); err != nil {
		t.Fatalf("mark customer app running: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/customer-apps/action", bytes.NewBufferString(
		`{"instance_id":"inst_persisted_policy","action":"backup","service":"db"}`,
	))
	request.Header.Set("X-Admiral-Customer-ID", "customer_policy")
	recorder := httptest.NewRecorder()
	h.HandleCustomerAppAction(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("allowed persisted-policy backup returned %d: %s", recorder.Code, recorder.Body.String())
	}
	instance, err := h.db.GetCustomerApp("inst_persisted_policy")
	if err != nil {
		t.Fatalf("reload customer app: %v", err)
	}
	response := newHarborCustomerAppResponse(instance)
	if !response.ManualBackupsAllowed || !response.BackupDatabaseAllowed || response.BackupVolumesAllowed || !response.RestoreAllowed {
		t.Fatalf("Harbor response did not preserve persisted tier policy: %+v", response)
	}
}
