// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"strings"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
)

func TestRuntimeNodeAddressRequiresWireGuardInProduction(t *testing.T) {
	t.Setenv("ADMIRAL_SINGLE_NODE", "false")
	h := &APIHandlers{}

	address, err := h.runtimeNodeAddress(&database.Node{ID: "worker-1", IP: "192.0.2.10"})
	if err == nil || address != "" {
		t.Fatalf("expected missing WireGuard address to be rejected, got address=%q err=%v", address, err)
	}
	if !strings.Contains(err.Error(), "WireGuard") {
		t.Fatalf("expected WireGuard error, got %v", err)
	}

	address, err = h.runtimeNodeAddress(&database.Node{ID: "worker-1", IP: "192.0.2.10", WireguardIP: "10.99.0.2"})
	if err != nil || address != "10.99.0.2" {
		t.Fatalf("expected WireGuard address, got address=%q err=%v", address, err)
	}
}

func TestRuntimeNodeAddressUsesLoopbackInSingleNode(t *testing.T) {
	t.Setenv("ADMIRAL_SINGLE_NODE", "true")
	h := &APIHandlers{}

	address, err := h.runtimeNodeAddress(&database.Node{ID: "node-1", IP: "192.0.2.10"})
	if err != nil || address != "127.0.0.1" {
		t.Fatalf("expected loopback address, got address=%q err=%v", address, err)
	}
}
