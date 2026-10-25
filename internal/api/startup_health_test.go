// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/logging"
)

func TestStartupReconcileMarksStaleWorkersUnavailable(t *testing.T) {
	h := newTestHandler(t, false)
	for _, nodeID := range []string{"stale-worker", "fresh-worker"} {
		if err := h.db.RegisterNode(nodeID, nodeID, "192.0.2.10", "", "worker", "", "Fedora", "6.0"); err != nil {
			t.Fatalf("register %s: %v", nodeID, err)
		}
	}
	if _, err := h.db.Exec(`
		UPDATE nodes SET status = 'active', health_status = 'healthy',
			health_reason_codes = '', available_for_provisioning = TRUE,
			unavailable_reason_codes = '',
			last_heartbeat = CASE WHEN id = 'stale-worker'
				THEN CURRENT_TIMESTAMP - INTERVAL '5 minutes' ELSE CURRENT_TIMESTAMP END,
			last_metrics_at = CASE WHEN id = 'stale-worker'
				THEN CURRENT_TIMESTAMP - INTERVAL '5 minutes' ELSE CURRENT_TIMESTAMP END
		WHERE id IN ('stale-worker', 'fresh-worker')
	`); err != nil {
		t.Fatalf("seed worker states: %v", err)
	}

	server := &Server{handlers: h, log: logging.New("test")}
	if err := server.reconcileOfflineWorkers(); err != nil {
		t.Fatalf("reconcile stale workers: %v", err)
	}

	stale, err := h.db.GetNode("stale-worker")
	if err != nil {
		t.Fatalf("get stale worker: %v", err)
	}
	if stale.Status != "offline" || stale.HealthStatus != "degraded" || stale.AvailableForProvisioning || stale.UnavailableReasonCodes != "heartbeat_timeout" {
		t.Fatalf("stale worker remained eligible after startup reconciliation: %#v", stale)
	}

	fresh, err := h.db.GetNode("fresh-worker")
	if err != nil {
		t.Fatalf("get fresh worker: %v", err)
	}
	if fresh.Status != "active" || fresh.HealthStatus != "healthy" || !fresh.AvailableForProvisioning {
		t.Fatalf("fresh worker was incorrectly marked offline: %#v", fresh)
	}
}
