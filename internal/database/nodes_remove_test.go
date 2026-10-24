// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestRemoveNodeWithHookRollsBackWhenRevocationFails(t *testing.T) {
	db := OpenTestDB(t)
	nodeID := fmt.Sprintf("remove-hook-%d", time.Now().UnixNano())
	if err := db.RegisterNode(nodeID, "worker.example", "192.0.2.10", "10.99.0.3", "worker", "192.0.2.10", "el10", "podman"); err != nil {
		t.Fatalf("register test node: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec("DELETE FROM nodes WHERE id = $1", nodeID) })

	wantErr := errors.New("revoker unavailable")
	called := false
	err := db.RemoveNodeWithHook(nodeID, false, func(node Node) (func(), error) {
		called = true
		if node.ID != nodeID || node.WireguardIP != "10.99.0.3" {
			t.Fatalf("hook received node %+v", node)
		}
		return nil, wantErr
	})
	if !called {
		t.Fatal("revocation hook was not called")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("RemoveNodeWithHook() error = %v, want wrapped revocation error", err)
	}
	remaining, err := db.GetNode(nodeID)
	if err != nil {
		t.Fatalf("read node after rollback: %v", err)
	}
	if remaining == nil {
		t.Fatal("node was deleted after peer revocation failed")
	}
}

func TestRemoveNodeWithHookRunsBeforeDeleteAndRemovesNode(t *testing.T) {
	db := OpenTestDB(t)
	nodeID := fmt.Sprintf("remove-hook-%d", time.Now().UnixNano())
	if err := db.RegisterNode(nodeID, "worker.example", "192.0.2.11", "10.99.0.4", "worker", "192.0.2.11", "el10", "podman"); err != nil {
		t.Fatalf("register test node: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec("DELETE FROM nodes WHERE id = $1", nodeID) })

	called := false
	releasedAfterCommit := false
	err := db.RemoveNodeWithHook(nodeID, false, func(node Node) (func(), error) {
		called = true
		if node.ID != nodeID || node.WireguardIP != "10.99.0.4" {
			t.Fatalf("hook received node %+v", node)
		}
		remaining, err := db.GetNode(nodeID)
		if err != nil {
			return nil, err
		}
		if remaining == nil {
			return nil, errors.New("node disappeared before revocation hook")
		}
		return func() {
			remaining, err := db.GetNode(nodeID)
			releasedAfterCommit = err == nil && remaining == nil
		}, nil
	})
	if err != nil {
		t.Fatalf("RemoveNodeWithHook() error = %v", err)
	}
	if !called {
		t.Fatal("revocation hook was not called")
	}
	if !releasedAfterCommit {
		t.Fatal("revocation lock was released before the node deletion committed")
	}
	remaining, err := db.GetNode(nodeID)
	if err != nil {
		t.Fatalf("read removed node: %v", err)
	}
	if remaining != nil {
		t.Fatal("node remains after successful removal")
	}
}

func TestRemoveNodePreservesTerminalInstanceAndOperationHistory(t *testing.T) {
	db := OpenTestDB(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	nodeID := "remove-history-node-" + suffix
	appName := "remove-history-app-" + suffix
	instanceID := "remove-history-instance-" + suffix
	provisionOperationID := "remove-history-provision-" + suffix
	deprovisionOperationID := "remove-history-deprovision-" + suffix
	backupID := "remove-history-backup-" + suffix
	if err := db.RegisterNode(nodeID, "worker.example", "192.0.2.12", "10.99.0.5", "worker", "192.0.2.12", "el10", "podman"); err != nil {
		t.Fatalf("register test node: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM customer_apps WHERE id = $1", instanceID)
		_, _ = db.Exec("DELETE FROM app_definitions WHERE name = $1", appName)
		_, _ = db.Exec("DELETE FROM nodes WHERE id = $1", nodeID)
	})
	if _, err := db.Exec(`INSERT INTO app_definitions (name, display_name, description, raw_yaml, status) VALUES ($1, $1, '', '', 'active')`, appName); err != nil {
		t.Fatalf("insert app definition: %v", err)
	}
	if err := db.CreateCustomerApp(instanceID, "customer-"+suffix, appName, "small", nodeID, `{}`); err != nil {
		t.Fatalf("create customer app: %v", err)
	}
	if err := db.UpdateCustomerAppStatus(instanceID, "cancelled", "deprovisioned"); err != nil {
		t.Fatalf("mark customer app terminal: %v", err)
	}
	if err := db.CreateOperation(provisionOperationID, instanceID, nodeID, "provision_app", "succeeded", "test"); err != nil {
		t.Fatalf("create provision operation: %v", err)
	}
	if err := db.CreateOperation(deprovisionOperationID, instanceID, nodeID, "deprovision_app", "succeeded", "test"); err != nil {
		t.Fatalf("create deprovision operation: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO backups (id, instance_id, node_id, status) VALUES ($1, $2, $3, 'succeeded')`, backupID, instanceID, nodeID); err != nil {
		t.Fatalf("create backup record: %v", err)
	}

	if err := db.RemoveNodeWithHook(nodeID, false, func(Node) (func(), error) { return nil, nil }); err != nil {
		t.Fatalf("remove idle node: %v", err)
	}

	removedNode, err := db.GetNode(nodeID)
	if err != nil {
		t.Fatalf("read removed node: %v", err)
	}
	if removedNode != nil {
		t.Fatal("node remains after successful removal")
	}
	instance, err := db.GetCustomerApp(instanceID)
	if err != nil {
		t.Fatalf("read preserved customer app: %v", err)
	}
	if instance == nil {
		t.Fatal("terminal customer app was deleted during node removal")
	}
	if instance.NodeID != nil {
		t.Fatalf("customer app still references removed node %q", *instance.NodeID)
	}
	if instance.CommercialStatus != "cancelled" || instance.TechnicalStatus != "deprovisioned" {
		t.Fatalf("customer app terminal state changed: commercial=%q technical=%q", instance.CommercialStatus, instance.TechnicalStatus)
	}
	var operationCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM operations WHERE instance_id = $1", instanceID).Scan(&operationCount); err != nil {
		t.Fatalf("count preserved operations: %v", err)
	}
	if operationCount != 2 {
		t.Fatalf("operation count = %d, want 2", operationCount)
	}
	var historicalNodeID string
	if err := db.QueryRow("SELECT node_id FROM operations WHERE id = $1", provisionOperationID).Scan(&historicalNodeID); err != nil {
		t.Fatalf("read operation historical node ID: %v", err)
	}
	if historicalNodeID != nodeID {
		t.Fatalf("operation historical node ID = %q, want %q", historicalNodeID, nodeID)
	}
	var backupNodeID sql.NullString
	if err := db.QueryRow("SELECT node_id FROM backups WHERE id = $1", backupID).Scan(&backupNodeID); err != nil {
		t.Fatalf("read preserved backup record: %v", err)
	}
	if backupNodeID.Valid {
		t.Fatalf("backup still references removed node %q", backupNodeID.String)
	}
}
