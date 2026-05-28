package networking

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/config"
	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func TestCreateInstanceRoutesGeneratesPersistentHostname(t *testing.T) {
	db := openTestDB(t)
	if err := db.RegisterNode("node_1", "worker", "10.0.0.8", "linux", "5.0.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}

	payload := admiral.AppDefinitionPayload{
		Name:        "wiki",
		DisplayName: "Wiki",
		Services: map[string]admiral.YAMLService{
			"web": {
				Image:  "example.com/wiki:1",
				Port:   8080,
				Public: true,
			},
		},
		Tiers: map[string]admiral.YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "5G"},
		},
	}
	if err := db.SaveAppDefinition(payload.Name, payload.DisplayName, "", "name: wiki", []database.AppTier{{
		AppName:      payload.Name,
		Name:         "starter",
		CPU:          1,
		Memory:       "1G",
		Storage:      "5G",
		PriceMonthly: 1,
	}}); err != nil {
		t.Fatalf("save app definition: %v", err)
	}
	if err := db.CreateCustomerApp("inst_1", "cust_1", payload.Name, "starter", "node_1", "{}"); err != nil {
		t.Fatalf("create customer app: %v", err)
	}

	cfg := &config.Config{NetworkingAppsDomain: "apps.example.com"}
	mgr, err := NewManager(db, cfg, logging.New("test"), secrets.NewManager("secret"))
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr.Caddy = nil

	routes, err := mgr.CreateInstanceRoutes("inst_1", payload, "node_1")
	if err != nil {
		t.Fatalf("create instance routes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected one route, got %d", len(routes))
	}
	got := routes[0]
	if matched, _ := regexp.MatchString(`^wiki\d{6}\.apps\.example\.com$`, got.Hostname); !matched {
		t.Fatalf("unexpected hostname %q", got.Hostname)
	}
	if got.Status != string(admiral.RouteStatusPending) {
		t.Fatalf("expected pending route, got %q", got.Status)
	}

	stored, err := db.GetPublicRoute(got.Hostname)
	if err != nil {
		t.Fatalf("get public route: %v", err)
	}
	if stored == nil {
		t.Fatal("expected stored public route")
	}
	if stored.TargetHost != "10.0.0.8" || stored.TargetPort != 8080 {
		t.Fatalf("unexpected target: %+v", stored)
	}
}

func TestSeedStaticRoutesCreatesAdminAndPortal(t *testing.T) {
	db := openTestDB(t)
	if err := db.SaveAppDefinition("wiki", "Wiki", "", "name: wiki", []database.AppTier{{
		AppName:      "wiki",
		Name:         "starter",
		CPU:          1,
		Memory:       "1G",
		Storage:      "5G",
		PriceMonthly: 1,
	}}); err != nil {
		t.Fatalf("save app definition: %v", err)
	}
	cfg := &config.Config{
		NetworkingBaseDomain:   "example.com",
		NetworkingAdminHost:    "admin.example.com",
		NetworkingPortalHost:   "portal.example.com",
		NetworkingAppsDomain:   "apps.example.com",
		NetworkingAppsRedirect: "portal.example.com",
	}
	mgr, err := NewManager(db, cfg, logging.New("test"), secrets.NewManager("secret"))
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr.Caddy = nil

	if err := mgr.SeedStaticRoutes(nil); err != nil {
		t.Fatalf("seed static routes: %v", err)
	}

	routes, err := db.GetPublicRoutes()
	if err != nil {
		t.Fatalf("get public routes: %v", err)
	}
	if len(routes) != 3 {
		t.Fatalf("expected 3 seeded routes, got %d", len(routes))
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
	t.Cleanup(func() { _ = db.Close() })
	return db
}
