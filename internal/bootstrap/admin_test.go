package bootstrap

import (
	"path/filepath"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/config"
	"github.com/admiral-project/admiral/admirald/internal/database"
)

func TestEnsureInitialAdminCreatesBootstrapAdmin(t *testing.T) {
	db := openTestDB(t)
	cfg := &config.Config{
		FlagshipAdminUser:     "admin",
		FlagshipAdminPassword: "super-secret-password",
	}

	created, err := EnsureInitialAdmin(db, cfg)
	if err != nil {
		t.Fatalf("ensure initial admin: %v", err)
	}
	if !created {
		t.Fatal("expected admin to be created")
	}

	storedHash, err := db.GetAdminUser("admin")
	if err != nil {
		t.Fatalf("get admin user: %v", err)
	}
	if storedHash == "" {
		t.Fatal("expected admin hash to be stored")
	}
}

func TestEnsureInitialAdminSkipsWhenAdminExists(t *testing.T) {
	db := openTestDB(t)
	if err := db.CreateAdminUser("existing", "stored-hash"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	cfg := &config.Config{
		FlagshipAdminUser:     "ignored",
		FlagshipAdminPassword: "ignored-password",
	}

	created, err := EnsureInitialAdmin(db, cfg)
	if err != nil {
		t.Fatalf("ensure initial admin: %v", err)
	}
	if created {
		t.Fatal("expected bootstrap to be skipped when an admin already exists")
	}

	storedHash, err := db.GetAdminUser("existing")
	if err != nil {
		t.Fatalf("get existing admin user: %v", err)
	}
	if storedHash != "stored-hash" {
		t.Fatalf("expected existing hash to remain untouched, got %q", storedHash)
	}
}

func TestEnsureInitialAdminRequiresCredentialsWhenMissing(t *testing.T) {
	db := openTestDB(t)
	cfg := &config.Config{}

	created, err := EnsureInitialAdmin(db, cfg)
	if err == nil {
		t.Fatal("expected bootstrap to fail without credentials")
	}
	if created {
		t.Fatal("expected no admin to be created")
	}
	want := "No administrative user exists. Set ADMIRAL_FLAGSHIP_ADMIN_USER and ADMIRAL_FLAGSHIP_ADMIN_PSWD to bootstrap the first admin."
	if err.Error() != want {
		t.Fatalf("unexpected error message: got %q want %q", err.Error(), want)
	}
}

func openTestDB(t *testing.T) *database.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "admiral.db")
	db, err := database.Connect("sqlite://" + dbPath)
	if err != nil {
		t.Fatalf("connect sqlite: %v", err)
	}
	if err := database.RunMigrations(db.DB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return db
}
