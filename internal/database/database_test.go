package database

import (
	"path/filepath"
	"testing"
)

func TestDriverAndDSNSelectsSQLite(t *testing.T) {
	driver, dsn := driverAndDSN("sqlite://:memory:")
	if driver != "sqlite3" {
		t.Fatalf("expected sqlite3 driver, got %q", driver)
	}
	if dsn != ":memory:" {
		t.Fatalf("expected memory DSN, got %q", dsn)
	}
}

func TestSQLiteMigrationsAndCRUD(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "admiral.db")
	db, err := Connect("sqlite://" + dbPath)
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	defer db.Close()

	if err := RunMigrations(db.DB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	if err := db.RegisterNode("node_1", "worker", "127.0.0.1", "ubuntu", "5.0.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}
	node, err := db.GetNode("node_1")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if node == nil || node.Status != "registered" {
		t.Fatalf("unexpected node: %+v", node)
	}

	tiers := []AppTier{{
		Name:         "small",
		CPU:          1,
		Memory:       "512M",
		Storage:      "1G",
		PriceMonthly: 5,
	}}
	if err := db.SaveAppDefinition("whoami", "Whoami", "demo app", "name: whoami", tiers); err != nil {
		t.Fatalf("save app definition: %v", err)
	}
	if err := db.CreateCustomerApp("inst_1", "cust_1", "whoami", "small", "node_1"); err != nil {
		t.Fatalf("create customer app: %v", err)
	}
	if err := db.CreateOperation("op_1", "inst_1", "provision_app", "queued"); err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if err := db.SaveInstanceSecret("inst_1", "app", "PASSWORD", "ciphertext", true); err != nil {
		t.Fatalf("save instance secret: %v", err)
	}

	secrets, err := db.GetExposedInstanceSecrets("inst_1")
	if err != nil {
		t.Fatalf("get exposed secrets: %v", err)
	}
	if len(secrets) != 1 || secrets[0].EncryptedValue != "ciphertext" {
		t.Fatalf("unexpected exposed secrets: %+v", secrets)
	}
}
