// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"testing"
	"time"
)

func seedUpdateTypeTestNode(t *testing.T, db *DB) {
	t.Helper()
	if err := db.RegisterNode("node_ut", "worker-ut", "10.0.0.99", "", "worker", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register test node: %v", err)
	}
}

func TestSaveAppDefinitionWithUpdateType(t *testing.T) {
	db := OpenTestDB(t)
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM customer_apps WHERE app_definition_name = $1", "updatetype-app")
		_, _ = db.Exec("DELETE FROM app_definitions WHERE name = $1", "updatetype-app")
	})

	seedUpdateTypeTestNode(t, db)

	if err := db.SaveAppDefinition("updatetype-app", "Update Type App", "Test", "name: updatetype-app", nil, "security_critical"); err != nil {
		t.Fatalf("save app definition: %v", err)
	}

	if err := db.CreateCustomerApp("inst_ut1", "cust_1", "updatetype-app", "small", "node_ut", "{}"); err != nil {
		t.Fatalf("create customer app: %v", err)
	}

	// Re-save to trigger definitionChanged path
	if err := db.SaveAppDefinition("updatetype-app", "Update Type App", "Test", "name: updatetype-app-v2", nil, "security_critical"); err != nil {
		t.Fatalf("re-save app definition: %v", err)
	}

	inst, err := db.GetCustomerApp("inst_ut1")
	if err != nil {
		t.Fatalf("get customer app: %v", err)
	}
	if !inst.NeedRestarting {
		t.Error("expected need_restarting to be true")
	}
	if inst.UpdateType != "security_critical" {
		t.Errorf("expected update_type 'security_critical', got %q", inst.UpdateType)
	}
	if inst.UpdateStartedAt == nil {
		t.Error("expected update_started_at to be set")
	}
}

func TestSaveAppDefinitionDefaultUpdateType(t *testing.T) {
	db := OpenTestDB(t)
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM customer_apps WHERE app_definition_name = $1", "default-app")
		_, _ = db.Exec("DELETE FROM app_definitions WHERE name = $1", "default-app")
	})

	seedUpdateTypeTestNode(t, db)

	if err := db.SaveAppDefinition("default-app", "Default App", "Test", "name: default-app", nil, "improvement"); err != nil {
		t.Fatalf("save app definition: %v", err)
	}
	if err := db.CreateCustomerApp("inst_def1", "cust_1", "default-app", "small", "node_ut", "{}"); err != nil {
		t.Fatalf("create customer app: %v", err)
	}

	if err := db.SaveAppDefinition("default-app", "Default App", "Test", "name: default-app-v2", nil, "improvement"); err != nil {
		t.Fatalf("re-save app definition: %v", err)
	}

	inst, err := db.GetCustomerApp("inst_def1")
	if err != nil {
		t.Fatalf("get customer app: %v", err)
	}
	if inst.UpdateType != "improvement" {
		t.Errorf("expected update_type 'improvement', got %q", inst.UpdateType)
	}
}

func TestClearCustomerAppRestartRequiredClearsUpdateType(t *testing.T) {
	db := OpenTestDB(t)
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM customer_apps WHERE app_definition_name = $1", "clear-app")
		_, _ = db.Exec("DELETE FROM app_definitions WHERE name = $1", "clear-app")
	})

	seedUpdateTypeTestNode(t, db)

	if err := db.SaveAppDefinition("clear-app", "Clear App", "Test", "name: clear-app", nil, "security"); err != nil {
		t.Fatalf("save app definition: %v", err)
	}
	if err := db.CreateCustomerApp("inst_clr1", "cust_1", "clear-app", "small", "node_ut", "{}"); err != nil {
		t.Fatalf("create customer app: %v", err)
	}

	if err := db.SaveAppDefinition("clear-app", "Clear App", "Test", "name: clear-app-v2", nil, "security"); err != nil {
		t.Fatalf("re-save app definition: %v", err)
	}

	inst, _ := db.GetCustomerApp("inst_clr1")
	if !inst.NeedRestarting {
		t.Fatal("expected need_restarting to be true before clear")
	}

	if err := db.ClearCustomerAppRestartRequired("inst_clr1"); err != nil {
		t.Fatalf("clear restart required: %v", err)
	}

	inst, _ = db.GetCustomerApp("inst_clr1")
	if inst.NeedRestarting {
		t.Error("expected need_restarting to be false after clear")
	}
	if inst.UpdateType != "" {
		t.Errorf("expected update_type to be empty after clear, got %q", inst.UpdateType)
	}
	if inst.UpdateStartedAt != nil {
		t.Error("expected update_started_at to be nil after clear")
	}
}

func TestGetCustomerAppsPageFiltered(t *testing.T) {
	db := OpenTestDB(t)
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM customer_apps WHERE app_definition_name IN ('filt-app1', 'filt-app2')")
		_, _ = db.Exec("DELETE FROM app_definitions WHERE name IN ('filt-app1', 'filt-app2')")
	})

	seedUpdateTypeTestNode(t, db)

	_ = db.SaveAppDefinition("filt-app1", "Filter App 1", "", "name: filt-app1", nil, "security_critical")
	_ = db.SaveAppDefinition("filt-app2", "Filter App 2", "", "name: filt-app2", nil, "bugfix")
	_ = db.CreateCustomerApp("inst_f1", "cust_1", "filt-app1", "small", "node_ut", "{}")
	_ = db.CreateCustomerApp("inst_f2", "cust_1", "filt-app2", "small", "node_ut", "{}")
	_ = db.CreateCustomerApp("inst_f3", "cust_2", "filt-app1", "small", "node_ut", "{}")

	// Filter by need_restarting only
	apps, total, err := db.GetCustomerAppsPageFiltered(100, 0, "", true, "")
	if err != nil {
		t.Fatalf("filter need_restarting: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3 total with need_restarting, got %d", total)
	}
	if len(apps) != 3 {
		t.Errorf("expected 3 apps with need_restarting, got %d", len(apps))
	}

	// Filter by need_restarting + update_type
	apps, total, err = db.GetCustomerAppsPageFiltered(100, 0, "", true, "bugfix")
	if err != nil {
		t.Fatalf("filter need_restarting + update_type: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 total for bugfix, got %d", total)
	}
	if len(apps) == 1 && apps[0].UpdateType != "bugfix" {
		t.Errorf("expected bugfix update_type, got %q", apps[0].UpdateType)
	}

	// Filter by customer + need_restarting
	apps, total, err = db.GetCustomerAppsPageFiltered(100, 0, "cust_1", true, "")
	if err != nil {
		t.Fatalf("filter customer + need_restarting: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 for cust_1, got %d", total)
	}

	// No filter - should return all 3
	apps, total, err = db.GetCustomerAppsPageFiltered(100, 0, "", false, "")
	if err != nil {
		t.Fatalf("no filter: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3 total without filter, got %d", total)
	}
	_ = apps
}

func TestFlagOverdueInstances(t *testing.T) {
	db := OpenTestDB(t)
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM customer_apps WHERE app_definition_name = $1", "overdue-app")
		_, _ = db.Exec("DELETE FROM app_definitions WHERE name = $1", "overdue-app")
	})

	seedUpdateTypeTestNode(t, db)

	_ = db.SaveAppDefinition("overdue-app", "Overdue App", "", "name: overdue-app", nil, "security_critical")
	_ = db.CreateCustomerApp("inst_od1", "cust_1", "overdue-app", "small", "node_ut", "{}")

	_, err := db.Exec(`UPDATE customer_apps SET update_started_at = $1 WHERE id = 'inst_od1'`,
		time.Now().Add(-3*time.Hour))
	if err != nil {
		t.Fatalf("set update_started_at: %v", err)
	}

	affected, err := db.FlagOverdueInstances(2 * time.Hour)
	if err != nil {
		t.Fatalf("flag overdue: %v", err)
	}
	if affected != 1 {
		t.Errorf("expected 1 flagged, got %d", affected)
	}

	inst, err := db.GetCustomerApp("inst_od1")
	if err != nil {
		t.Fatalf("get customer app: %v", err)
	}
	if inst.TechnicalStatus != "restart_overdue" {
		t.Errorf("expected technical_status 'restart_overdue', got %q", inst.TechnicalStatus)
	}
}

func TestFlagOverdueInstancesSkipsNonSecurity(t *testing.T) {
	db := OpenTestDB(t)
	t.Cleanup(func() {
		_, _ = db.Exec("DELETE FROM customer_apps WHERE app_definition_name = $1", "nonsec-app")
		_, _ = db.Exec("DELETE FROM app_definitions WHERE name = $1", "nonsec-app")
	})

	seedUpdateTypeTestNode(t, db)

	_ = db.SaveAppDefinition("nonsec-app", "NonSec App", "", "name: nonsec-app", nil, "bugfix")
	_ = db.CreateCustomerApp("inst_ns1", "cust_1", "nonsec-app", "small", "node_ut", "{}")

	_, err := db.Exec(`UPDATE customer_apps SET update_started_at = $1 WHERE id = 'inst_ns1'`,
		time.Now().Add(-3*time.Hour))
	if err != nil {
		t.Fatalf("set update_started_at: %v", err)
	}

	affected, err := db.FlagOverdueInstances(2 * time.Hour)
	if err != nil {
		t.Fatalf("flag overdue: %v", err)
	}
	if affected != 0 {
		t.Errorf("expected 0 flagged for non-security_critical, got %d", affected)
	}

	inst, err := db.GetCustomerApp("inst_ns1")
	if err != nil {
		t.Fatalf("get customer app: %v", err)
	}
	if inst.TechnicalStatus == "restart_overdue" {
		t.Error("bugfix instance should not be flagged as restart_overdue")
	}
}
