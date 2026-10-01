package api

import (
	"bytes"
	"encoding/json"
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
