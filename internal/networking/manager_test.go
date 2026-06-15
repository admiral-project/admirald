// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package networking

import (
	"context"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/config"
	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCreateInstanceRoutesGeneratesPersistentHostname(t *testing.T) {
	db := openTestDB(t)
	if err := db.RegisterNode("node_1", "worker", "10.0.0.8", "", "worker", "", "linux", "5.0.0"); err != nil {
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
	rawYAML := "name: wiki\nservices:\n  web:\n    image: example.com/wiki:1\n    port: 8080\n    public: true\ntiers:\n  starter:\n    cpu: 1\n    memory: 1G\n    storage: 5G\n"
	if err := db.SaveAppDefinition(payload.Name, payload.DisplayName, "", rawYAML, []database.AppTier{{
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

func TestActivateInstanceRoutesUsesFleetHostPorts(t *testing.T) {
	db := openTestDB(t)
	if err := db.RegisterNode("node_1", "worker", "10.0.0.8", "", "worker", "", "linux", "5.0.0"); err != nil {
		t.Fatalf("register node: %v", err)
	}

	payload := admiral.AppDefinitionPayload{
		Name:        "wiki",
		DisplayName: "Wiki",
		Services: map[string]admiral.YAMLService{
			"web": {Image: "example.com/wiki:1", Port: 8080, Public: true},
		},
		Tiers: map[string]admiral.YAMLTier{
			"starter": {CPU: 1, Memory: "1G", Storage: "5G"},
		},
	}
	rawYAML := "name: wiki\nservices:\n  web:\n    image: example.com/wiki:1\n    port: 8080\n    public: true\ntiers:\n  starter:\n    cpu: 1\n    memory: 1G\n    storage: 5G\n"
	if err := db.SaveAppDefinition(payload.Name, payload.DisplayName, "", rawYAML, []database.AppTier{{
		AppName: payload.Name, Name: "starter", CPU: 1, Memory: "1G", Storage: "5G", PriceMonthly: 1,
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
	if err := mgr.ActivateInstanceRoutes(context.Background(), "inst_1", map[string]int{"web": 43123}); err != nil {
		t.Fatalf("activate routes: %v", err)
	}

	stored, err := db.GetPublicRoute(routes[0].Hostname)
	if err != nil {
		t.Fatalf("get public route: %v", err)
	}
	if stored.TargetHost != "127.0.0.1" || stored.TargetPort != 43123 {
		t.Fatalf("expected fleet host port target, got %+v", stored)
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
		NetworkingAdminTarget:  "http://10.0.0.1:3000",
		NetworkingPortalHost:   "portal.example.com",
		NetworkingPortalTarget: "http://10.0.0.1:3001",
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

func TestCheckRouteHealthUsesPublicHostnameThroughCaddy(t *testing.T) {
	mgr := &Manager{
		Caddy: &CaddyAdminClient{
			HTTP: &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.String() != "https://demo.apps.example.com/" {
						t.Fatalf("unexpected healthcheck URL: %s", req.URL.String())
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader("ok")),
					}, nil
				}),
			},
		},
	}

	health, lastErr := mgr.checkRouteHealth(database.PublicRoute{
		Hostname:    "demo.apps.example.com",
		RouteKind:   string(admiral.RouteKindInstance),
		TargetHost:  "127.0.0.1",
		TargetPort:  40005,
		TargetURL:   "http://127.0.0.1:40005",
		Status:      string(admiral.RouteStatusActive),
		ServiceName: "web",
	}, nil)
	if health != "healthy" {
		t.Fatalf("expected healthy route, got %q (%s)", health, lastErr)
	}
}

func TestCheckRouteHealthUsesServiceHTTPHealthcheckPathAndExpectedStatus(t *testing.T) {
	mgr := &Manager{
		Caddy: &CaddyAdminClient{
			HTTP: &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.String() != "https://minio.apps.example.com/minio/health/live" {
						t.Fatalf("unexpected healthcheck URL: %s", req.URL.String())
					}
					return &http.Response{
						StatusCode: http.StatusNoContent,
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				}),
			},
		},
	}

	appDef := &admiral.AppDefinitionPayload{
		Services: map[string]admiral.YAMLService{
			"storage": {
				Image:  "docker.io/minio/minio:latest",
				Public: true,
				Port:   9000,
				HealthCheck: &admiral.YAMLHealthCheck{
					Type:           "http",
					Path:           "/minio/health/live",
					ExpectedStatus: http.StatusNoContent,
				},
			},
		},
	}

	health, lastErr := mgr.checkRouteHealth(database.PublicRoute{
		Hostname:    "minio.apps.example.com",
		RouteKind:   string(admiral.RouteKindInstance),
		TargetHost:  "127.0.0.1",
		TargetPort:  40008,
		TargetURL:   "http://127.0.0.1:40008",
		Status:      string(admiral.RouteStatusActive),
		ServiceName: "storage",
	}, appDef)
	if health != "healthy" {
		t.Fatalf("expected healthy route, got %q (%s)", health, lastErr)
	}
}

func openTestDB(t *testing.T) *database.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	db, err := database.Connect(dbURL)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := database.RunMigrations(db.DB); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return db
}
