// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestNormalizeInstanceSecretsPropagatesExactMatchFromDBService(t *testing.T) {
	payload := admiral.AppDefinitionPayload{
		Services: map[string]admiral.YAMLService{
			"backend": {
				Image: "docker.io/frappe/erpnext:v15",
				Secrets: map[string]admiral.YAMLSecret{
					"MARIADB_ROOT_PASSWORD": {},
				},
			},
			"db": {
				Image: "docker.io/library/mariadb:10.11",
				Secrets: map[string]admiral.YAMLSecret{
					"MARIADB_ROOT_PASSWORD": {},
					"MARIADB_USER":          {},
					"MARIADB_PASSWORD":      {},
				},
			},
		},
	}
	all := map[string]map[string]string{
		"backend": {
			"MARIADB_ROOT_PASSWORD": "backend-placeholder",
		},
		"db": {
			"MARIADB_ROOT_PASSWORD": "db-root-password",
			"MARIADB_USER":          "db-user",
			"MARIADB_PASSWORD":      "db-password",
		},
		"__global__": {
			"MARIADB_ROOT_PASSWORD": "global-placeholder",
		},
	}

	normalizeInstanceSecrets(all, payload)

	if got := all["backend"]["MARIADB_ROOT_PASSWORD"]; got != "db-root-password" {
		t.Fatalf("expected backend root password to be copied from db service, got %q", got)
	}
	if got := all["__global__"]["MARIADB_ROOT_PASSWORD"]; got != "global-placeholder" {
		t.Fatalf("expected global secret bucket to remain unchanged, got %q", got)
	}
}

func TestNormalizeInstanceSecretsPropagatesWordPressAndGiteaDBCredentials(t *testing.T) {
	payload := admiral.AppDefinitionPayload{
		Services: map[string]admiral.YAMLService{
			"web": {
				Image: "docker.io/library/wordpress:6",
				Secrets: map[string]admiral.YAMLSecret{
					"WORDPRESS_DB_USER":     {},
					"WORDPRESS_DB_PASSWORD": {},
					"WORDPRESS_DB_NAME":     {},
				},
			},
			"setup": {
				Image: "docker.io/gitea/gitea:1.22",
				Secrets: map[string]admiral.YAMLSecret{
					"GITEA__database__USER":   {},
					"GITEA__database__PASSWD": {},
				},
			},
			"db": {
				Image: "docker.io/library/mariadb:10.11",
				Secrets: map[string]admiral.YAMLSecret{
					"MARIADB_USER":     {},
					"MARIADB_PASSWORD": {},
					"MARIADB_DATABASE": {},
				},
			},
		},
	}
	all := map[string]map[string]string{
		"web": {
			"WORDPRESS_DB_USER":     "wp-user",
			"WORDPRESS_DB_PASSWORD": "wp-pass",
			"WORDPRESS_DB_NAME":     "wp-name",
		},
		"setup": {
			"GITEA__database__USER":   "gitea-user",
			"GITEA__database__PASSWD": "gitea-pass",
		},
		"db": {
			"MARIADB_USER":     "db-user",
			"MARIADB_PASSWORD": "db-pass",
			"MARIADB_DATABASE": "db-name",
		},
	}

	normalizeInstanceSecrets(all, payload)

	if got := all["web"]["WORDPRESS_DB_USER"]; got != "db-user" {
		t.Fatalf("expected wordpress db user to match db user, got %q", got)
	}
	if got := all["web"]["WORDPRESS_DB_PASSWORD"]; got != "db-pass" {
		t.Fatalf("expected wordpress db password to match db password, got %q", got)
	}
	if got := all["web"]["WORDPRESS_DB_NAME"]; got != "db-name" {
		t.Fatalf("expected wordpress db name to match db name, got %q", got)
	}
	if got := all["setup"]["GITEA__database__USER"]; got != "db-user" {
		t.Fatalf("expected gitea db user to match db user, got %q", got)
	}
	if got := all["setup"]["GITEA__database__PASSWD"]; got != "db-pass" {
		t.Fatalf("expected gitea db password to match db password, got %q", got)
	}
}

func TestValidateTechnicalStatusAction(t *testing.T) {
	tests := []struct {
		name           string
		technicalState string
		action         string
		wantBlocked    bool
	}{
		{name: "initializing blocks pause", technicalState: "initializing", action: "pause", wantBlocked: true},
		{name: "setup_failed blocks resize", technicalState: "setup_failed", action: "resize", wantBlocked: true},
		{name: "setup_failed allows deprovision", technicalState: "setup_failed", action: "deprovision", wantBlocked: false},
		{name: "running allows stop", technicalState: "running", action: "stop", wantBlocked: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, blocked := validateTechnicalStatusAction(tt.technicalState, tt.action)
			if blocked != tt.wantBlocked {
				t.Fatalf("validateTechnicalStatusAction(%q, %q) blocked=%v, want %v", tt.technicalState, tt.action, blocked, tt.wantBlocked)
			}
		})
	}
}

func TestHandleCustomerAppActionRejectsInitializingPause(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_001", "", "initializing"); err != nil {
		t.Fatalf("set technical status: %v", err)
	}

	reqBody := bytes.NewReader([]byte(`{"instance_id":"inst_001","action":"pause"}`))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/customer-apps/action", reqBody)
	req.Header.Set("X-Admiral-Customer-ID", "cust_001")
	rec := httptest.NewRecorder()
	h.HandleCustomerAppAction(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleFleetCallbackProvisionSetupFailureEnqueuesCleanup(t *testing.T) {
	h := newTestHandler(t, false)
	publisher := &migrationTestPublisher{db: h.db}
	h.publisher = publisher

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	rawYAML := "name: testapp\nservices:\n  web:\n    image: docker.io/library/nginx:latest\n    backup:\n      type: none\n"
	if err := h.db.SaveAppDefinition("testapp", "Test App", "App for testing", rawYAML, nil); err != nil {
		t.Fatalf("save app definition: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{"name":"starter","cpu":1,"memory":"256M","storage":"1G"}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_001", "active", "initializing"); err != nil {
		t.Fatalf("set initializing status: %v", err)
	}
	if err := h.db.CreateOperation("op_001", "inst_001", "node_001", string(admiral.ActionProvisionApp), "queued", "system"); err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if err := h.db.UpdateOperationTaskID("op_001", "task_001"); err != nil {
		t.Fatalf("set task id: %v", err)
	}

	body, _ := json.Marshal(admiral.TaskResult{
		OperationID: "op_001",
		TaskID:      "task_001",
		NodeID:      "node_001",
		Success:     false,
		Error:       "setup failed",
		Metadata:    `{"has_setup":true,"setup_failed":true,"setup_error":"bench new-site failed"}`,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.HandleFleetCallback(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	inst, err := h.db.GetCustomerApp("inst_001")
	if err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if inst.TechnicalStatus != "setup_failed" {
		t.Fatalf("expected setup_failed, got %q", inst.TechnicalStatus)
	}
	if inst.CommercialStatus != "cancelled" {
		t.Fatalf("expected commercial_status cancelled, got %q", inst.CommercialStatus)
	}

	var actions []admiral.TaskAction
	for _, task := range publisher.published {
		actions = append(actions, task.Action)
	}
	if !reflect.DeepEqual(actions, []admiral.TaskAction{admiral.ActionDeprovisionApp}) {
		t.Fatalf("expected one cleanup task, got %#v", actions)
	}
}

func TestHandleFleetCallbackDeprovisionPreservesSetupFailed(t *testing.T) {
	h := newTestHandler(t, false)

	if err := h.db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := h.db.CreateCustomerApp("inst_001", "cust_001", "testapp", "starter", "node_001", `{"name":"starter","cpu":1,"memory":"256M","storage":"1G"}`); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	if err := h.db.UpdateCustomerAppStatus("inst_001", "cancelled", "setup_failed"); err != nil {
		t.Fatalf("set setup_failed status: %v", err)
	}
	if err := h.db.CreateOperation("op_002", "inst_001", "node_001", string(admiral.ActionDeprovisionApp), "queued", "system"); err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if err := h.db.UpdateOperationTaskID("op_002", "task_002"); err != nil {
		t.Fatalf("set task id: %v", err)
	}

	body, _ := json.Marshal(admiral.TaskResult{
		OperationID: "op_002",
		TaskID:      "task_002",
		NodeID:      "node_001",
		Success:     true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/callback", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.HandleFleetCallback(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	inst, err := h.db.GetCustomerApp("inst_001")
	if err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if inst.TechnicalStatus != "setup_failed" {
		t.Fatalf("expected technical_status setup_failed to be preserved, got %q", inst.TechnicalStatus)
	}
	if inst.CommercialStatus != "cancelled" {
		t.Fatalf("expected commercial_status cancelled, got %q", inst.CommercialStatus)
	}
}
