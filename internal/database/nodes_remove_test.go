// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
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
