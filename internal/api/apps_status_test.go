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
)

func TestHandleAppsUpdateStatus(t *testing.T) {
	h := newTestHandler(t, false)

	appName := "status-app"
	t.Cleanup(func() {
		_, _ = h.db.Exec("DELETE FROM app_definitions WHERE name = $1", appName)
	})
	if err := h.db.SaveAppDefinition(appName, "Status App", "test", minimalAppYAML(appName), []database.AppTier{
		{AppName: appName, Name: "small", CPU: 1, Memory: "256M", Storage: "1G", PriceMonthly: 1},
	}); err != nil {
		t.Fatalf("save app definition: %v", err)
	}

	body, err := json.Marshal(map[string]string{"status": "inactive"})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/apps/"+appName+"/status", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleApps(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	app, err := h.db.GetAppDefinition(appName)
	if err != nil {
		t.Fatalf("get app definition: %v", err)
	}
	if app == nil || app.Status != "inactive" {
		t.Fatalf("expected inactive app status, got %#v", app)
	}
}

func TestHandleCustomerAppsRejectsInactiveDefinition(t *testing.T) {
	h := newTestHandler(t, false)

	nodeID := "node_status_001"
	t.Cleanup(func() {
		_, _ = h.db.Exec("DELETE FROM customer_apps WHERE customer_id = $1", "cust_inactive_001")
		_, _ = h.db.Exec("DELETE FROM app_definitions WHERE name = $1", "inactive-app")
		_, _ = h.db.Exec("DELETE FROM nodes WHERE id = $1", nodeID)
	})
	if err := h.db.RegisterNode(nodeID, "worker-status", "10.0.0.10", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}

	appName := "inactive-app"
	if err := h.db.SaveAppDefinition(appName, "Inactive App", "test", minimalAppYAML(appName), []database.AppTier{
		{AppName: appName, Name: "small", CPU: 1, Memory: "256M", Storage: "1G", PriceMonthly: 1},
	}); err != nil {
		t.Fatalf("save app definition: %v", err)
	}
	if err := h.db.UpdateAppDefinitionStatus(appName, "inactive"); err != nil {
		t.Fatalf("set inactive app status: %v", err)
	}

	body, err := json.Marshal(map[string]string{
		"app_definition_name": appName,
		"tier_name":           "small",
		"customer_id":         "cust_inactive_001",
	})
	if err != nil {
		t.Fatalf("marshal provision body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/customer-apps", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.HandleCustomerApps(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func minimalAppYAML(name string) string {
	return "name: " + name + "\n" +
		"display_name: Test App\n" +
		"description: test\n" +
		"services:\n" +
		"  web:\n" +
		"    image: docker.io/library/nginx:alpine\n" +
		"    port: 80\n" +
		"    public: true\n" +
		"    backup:\n" +
		"      type: none\n" +
		"tiers:\n" +
		"  small:\n" +
		"    cpu: 1\n" +
		"    memory: 256M\n" +
		"    storage: 1G\n" +
		"    price_monthly: 1\n"
}
