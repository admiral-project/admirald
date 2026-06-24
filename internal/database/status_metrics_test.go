// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"testing"
	"time"
)

func seedTestAppDefinition(t *testing.T, db *DB) {
	t.Helper()

	err := db.SaveAppDefinition(
		"app",
		"App",
		"Test app",
		"name: app",
		[]AppTier{{
			AppName:      "app",
			Name:         "starter",
			CPU:          1,
			Memory:       "1G",
			Storage:      "10G",
			PriceMonthly: 10,
		}},
	)
	if err != nil {
		t.Fatalf("seed app definition: %v", err)
	}
}

func TestGetNodeMetricsIncludesInitializingAndSetupFailed(t *testing.T) {
	db := OpenTestDB(t)
	if err := db.TruncateTables(); err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
	seedTestAppDefinition(t, db)

	if err := db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := db.CreateCustomerApp("inst_running", "cust", "app", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create running app: %v", err)
	}
	if err := db.CreateCustomerApp("inst_init", "cust", "app", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create initializing app: %v", err)
	}
	if err := db.CreateCustomerApp("inst_failed", "cust", "app", "starter", "node_001", `{}`); err != nil {
		t.Fatalf("create failed app: %v", err)
	}
	if err := db.UpdateCustomerAppStatus("inst_running", "", "running"); err != nil {
		t.Fatalf("set running status: %v", err)
	}
	if err := db.UpdateCustomerAppStatus("inst_init", "", "initializing"); err != nil {
		t.Fatalf("set initializing status: %v", err)
	}
	if err := db.UpdateCustomerAppStatus("inst_failed", "", "setup_failed"); err != nil {
		t.Fatalf("set setup_failed status: %v", err)
	}

	metrics, err := db.GetNodeMetrics("node_001")
	if err != nil {
		t.Fatalf("get node metrics: %v", err)
	}
	if metrics.Instances.Running != 1 {
		t.Fatalf("expected 1 running instance, got %d", metrics.Instances.Running)
	}
	if metrics.Instances.Provisioning != 1 {
		t.Fatalf("expected 1 provisioning instance, got %d", metrics.Instances.Provisioning)
	}
	if metrics.Instances.Failed != 1 {
		t.Fatalf("expected 1 failed instance, got %d", metrics.Instances.Failed)
	}
}

func TestGetExpiredGracePeriodAppsExcludesTransientAndTerminalStates(t *testing.T) {
	db := OpenTestDB(t)
	if err := db.TruncateTables(); err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
	seedTestAppDefinition(t, db)

	if err := db.RegisterNode("node_001", "worker-1", "10.0.0.1", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}

	expired := time.Now().Add(-time.Hour)
	statuses := []string{"running", "initializing", "setup_failed", "deprovisioning", "deprovisioned", "paused_for_storage"}
	for _, status := range statuses {
		instanceID := "inst_" + status
		if err := db.CreateCustomerApp(instanceID, "cust", "app", "starter", "node_001", `{}`); err != nil {
			t.Fatalf("create app %s: %v", status, err)
		}
		if err := db.UpdateCustomerAppStatus(instanceID, "", status); err != nil {
			t.Fatalf("set status %s: %v", status, err)
		}
		if _, err := db.Exec(`UPDATE customer_apps
			SET storage_state = 'over_quota', grace_period_starts_at = CURRENT_TIMESTAMP - INTERVAL '2 days',
			    grace_period_ends_at = $1
			WHERE id = $2`, expired, instanceID); err != nil {
			t.Fatalf("seed grace period for %s: %v", status, err)
		}
	}

	apps, err := db.GetExpiredGracePeriodApps()
	if err != nil {
		t.Fatalf("get expired grace period apps: %v", err)
	}
	if len(apps) != 1 || apps[0].TechnicalStatus != "running" {
		t.Fatalf("expected only running app to require pause, got %#v", apps)
	}
}
