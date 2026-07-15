package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
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
