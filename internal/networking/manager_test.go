// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package networking

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

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
	if err := db.RegisterNode("node_1", "worker", "10.0.0.8", "10.99.0.8", "worker", "", "linux", "5.0.0"); err != nil {
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
	if stored.TargetHost != "10.99.0.8" || stored.TargetPort != 8080 {
		t.Fatalf("unexpected target: %+v", stored)
	}
}

func TestActivateInstanceRoutesUsesFleetHostPorts(t *testing.T) {
	db := openTestDB(t)
	if err := db.RegisterNode("node_1", "worker", "10.0.0.8", "10.99.0.8", "worker", "", "linux", "5.0.0"); err != nil {
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
	if stored.TargetHost != "10.99.0.8" || stored.TargetPort != 43123 {
		t.Fatalf("expected WireGuard IP target, got %+v", stored)
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

	if err := mgr.SeedStaticRoutes(context.Background()); err != nil {
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

func TestSeedStaticRoutesUpdatesDefaultPortalTarget(t *testing.T) {
	db := openTestDB(t)
	cfg := &config.Config{
		NetworkingPortalHost:   "portal.example.com",
		NetworkingPortalTarget: "https://10.99.0.100:5001",
	}
	mgr, err := NewManager(db, cfg, logging.New("test"), secrets.NewManager("secret"))
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr.Caddy = nil

	if err := db.CreatePublicRoute(mgr.staticRoute("portal.example.com", string(admiral.RouteKindPortal), "portal", defaultLocalPortalTarget)); err != nil {
		t.Fatalf("create default portal route: %v", err)
	}
	if err := mgr.SeedStaticRoutes(context.Background()); err != nil {
		t.Fatalf("seed static routes: %v", err)
	}

	route, err := db.GetPublicRoute("portal.example.com")
	if err != nil {
		t.Fatalf("get portal route: %v", err)
	}
	if route.TargetURL != "https://10.99.0.100:5001" {
		t.Fatalf("expected WireGuard portal target, got %q", route.TargetURL)
	}
}

func TestSeedStaticRoutesPreservesCustomPortalTarget(t *testing.T) {
	db := openTestDB(t)
	cfg := &config.Config{
		NetworkingPortalHost:   "portal.example.com",
		NetworkingPortalTarget: "https://10.99.0.100:5001",
	}
	mgr, err := NewManager(db, cfg, logging.New("test"), secrets.NewManager("secret"))
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr.Caddy = nil

	customTarget := "https://portal.internal.example.com:5001"
	if err := db.CreatePublicRoute(mgr.staticRoute("portal.example.com", string(admiral.RouteKindPortal), "portal", customTarget)); err != nil {
		t.Fatalf("create custom portal route: %v", err)
	}
	if err := mgr.SeedStaticRoutes(context.Background()); err != nil {
		t.Fatalf("seed static routes: %v", err)
	}

	route, err := db.GetPublicRoute("portal.example.com")
	if err != nil {
		t.Fatalf("get portal route: %v", err)
	}
	if route.TargetURL != customTarget {
		t.Fatalf("expected custom portal target to be preserved, got %q", route.TargetURL)
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

func TestIsSafePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"valid/path", true},
		{"/abs/path", true},
		{"../traversal", false},
		{"path/../traversal", false},
		{"clean/path/.", false}, // filepath.Clean("clean/path/.") -> "clean/path"
	}
	for _, tt := range tests {
		if got := isSafePath(tt.path); got != tt.want {
			t.Errorf("isSafePath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestShouldReplaceSeededStaticRoute(t *testing.T) {
	desired := database.PublicRoute{RouteKind: string(admiral.RouteKindPortal), TargetURL: "https://10.99.0.100:5001"}

	tests := []struct {
		name     string
		existing *database.PublicRoute
		desired  database.PublicRoute
		want     bool
	}{
		{
			name:     "nil existing",
			existing: nil,
			desired:  desired,
			want:     false,
		},
		{
			name:     "different kind",
			existing: &database.PublicRoute{RouteKind: string(admiral.RouteKindAdmin)},
			desired:  desired,
			want:     true,
		},
		{
			name:     "default portal target",
			existing: &database.PublicRoute{RouteKind: string(admiral.RouteKindPortal), TargetURL: defaultLocalPortalTarget},
			desired:  desired,
			want:     true,
		},
		{
			name:     "custom portal target",
			existing: &database.PublicRoute{RouteKind: string(admiral.RouteKindPortal), TargetURL: "https://custom:5001"},
			desired:  desired,
			want:     false,
		},
		{
			name:     "not portal route desired",
			existing: &database.PublicRoute{RouteKind: string(admiral.RouteKindAdmin)},
			desired:  database.PublicRoute{RouteKind: string(admiral.RouteKindAdmin), TargetURL: "https://admin:3000"},
			want:     false,
		},
		{
			name:     "desired target empty",
			existing: &database.PublicRoute{RouteKind: string(admiral.RouteKindPortal), TargetURL: defaultLocalPortalTarget},
			desired:  database.PublicRoute{RouteKind: string(admiral.RouteKindPortal), TargetURL: ""},
			want:     false,
		},
		{
			name:     "desired target equal existing",
			existing: &database.PublicRoute{RouteKind: string(admiral.RouteKindPortal), TargetURL: "https://10.99.0.100:5001"},
			desired:  database.PublicRoute{RouteKind: string(admiral.RouteKindPortal), TargetURL: "https://10.99.0.100:5001"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldReplaceSeededStaticRoute(tt.existing, tt.desired); got != tt.want {
				t.Errorf("shouldReplaceSeededStaticRoute() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRouteNodeID(t *testing.T) {
	t.Run("nil NodeID", func(t *testing.T) {
		route := database.PublicRoute{NodeID: nil}
		if got := routeNodeID(route); got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})

	t.Run("non-nil NodeID", func(t *testing.T) {
		nodeID := "node-abc"
		route := database.PublicRoute{NodeID: &nodeID}
		if got := routeNodeID(route); got != "node-abc" {
			t.Errorf("expected 'node-abc', got %q", got)
		}
	})
}

func TestRandomDigits(t *testing.T) {
	got, err := randomDigits(6)
	if err != nil {
		t.Fatalf("randomDigits failed: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("expected 6 digits, got %d", len(got))
	}
	for _, c := range got {
		if c < '0' || c > '9' {
			t.Fatalf("unexpected character %q in random digits", c)
		}
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
	if err := db.TruncateTables(); err != nil {
		t.Fatalf("truncate tables: %v", err)
	}
	return db
}

func generateTestCert(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		DNSNames:  []string{"test.example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "test_cert_*.pem")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	err = pem.Encode(tmpFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		t.Fatalf("failed to pem encode cert: %v", err)
	}

	return tmpFile.Name()
}

func TestManagerRuntimeNodeAddress(t *testing.T) {
	t.Run("single node mode", func(t *testing.T) {
		t.Setenv("ADMIRAL_SINGLE_NODE", "true")
		mgr := &Manager{}
		node := &database.Node{ID: "node1"}
		addr, err := mgr.runtimeNodeAddress(node)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if addr != "127.0.0.1" {
			t.Errorf("expected 127.0.0.1, got %q", addr)
		}
	})

	t.Run("dev mode config", func(t *testing.T) {
		t.Setenv("ADMIRAL_SINGLE_NODE", "false")
		mgr := &Manager{
			Config: &config.Config{DevMode: true},
		}
		node := &database.Node{ID: "node1"}
		addr, err := mgr.runtimeNodeAddress(node)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if addr != "127.0.0.1" {
			t.Errorf("expected 127.0.0.1, got %q", addr)
		}
	})

	t.Run("production empty wireguard IP", func(t *testing.T) {
		t.Setenv("ADMIRAL_SINGLE_NODE", "false")
		mgr := &Manager{
			Config: &config.Config{DevMode: false},
		}
		node := &database.Node{ID: "node1", WireguardIP: ""}
		_, err := mgr.runtimeNodeAddress(node)
		if err == nil {
			t.Fatal("expected error for empty wireguard IP in production")
		}
	})

	t.Run("production valid wireguard IP", func(t *testing.T) {
		t.Setenv("ADMIRAL_SINGLE_NODE", "false")
		mgr := &Manager{
			Config: &config.Config{DevMode: false},
		}
		node := &database.Node{ID: "node1", WireguardIP: "10.99.0.5"}
		addr, err := mgr.runtimeNodeAddress(node)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if addr != "10.99.0.5" {
			t.Errorf("expected 10.99.0.5, got %q", addr)
		}
	})
}

func TestCheckRouteHealthOffline(t *testing.T) {
	mgr := &Manager{}

	t.Run("disabled route", func(t *testing.T) {
		health, lastErr := mgr.checkRouteHealth(database.PublicRoute{
			Status: "disabled",
		}, nil)
		if health != "disabled" || lastErr != "" {
			t.Errorf("expected disabled health, got %q (%q)", health, lastErr)
		}
	})

	t.Run("static route kinds", func(t *testing.T) {
		kinds := []string{"admin", "portal", "apps_root", "flagship", "cockpit"}
		for _, k := range kinds {
			health, lastErr := mgr.checkRouteHealth(database.PublicRoute{
				RouteKind: k,
			}, nil)
			if health != "healthy" || lastErr != "" {
				t.Errorf("expected healthy for %q, got %q (%q)", k, health, lastErr)
			}
		}
	})

	t.Run("missing target", func(t *testing.T) {
		health, lastErr := mgr.checkRouteHealth(database.PublicRoute{
			RouteKind: "instance",
		}, nil)
		if health != "unhealthy" || lastErr != "missing target" {
			t.Errorf("expected missing target error, got %q (%q)", health, lastErr)
		}
	})

	t.Run("build target from host and port", func(t *testing.T) {
		mgrWithCaddy := &Manager{
			Caddy: &CaddyAdminClient{
				HTTP: &http.Client{
					Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader("ok")),
						}, nil
					}),
				},
			},
		}
		// target is empty but Host/Port is filled
		health, lastErr := mgrWithCaddy.checkRouteHealth(database.PublicRoute{
			RouteKind:  "instance",
			TargetHost: "127.0.0.1",
			TargetPort: 8080,
			Hostname:   "test.example.com",
		}, nil)
		if health != "healthy" {
			t.Errorf("expected healthy, got %q (%q)", health, lastErr)
		}
	})

	t.Run("http healthcheck path doesn't start with slash", func(t *testing.T) {
		mgrWithCaddy := &Manager{
			Caddy: &CaddyAdminClient{
				HTTP: &http.Client{
					Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						if req.URL.Path != "/status" {
							t.Errorf("expected path /status, got %q", req.URL.Path)
						}
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader("ok")),
						}, nil
					}),
				},
			},
		}
		appDef := &admiral.AppDefinitionPayload{
			Services: map[string]admiral.YAMLService{
				"web": {
					HealthCheck: &admiral.YAMLHealthCheck{
						Type: "http",
						Path: "status", // no leading slash
					},
				},
			},
		}
		health, lastErr := mgrWithCaddy.checkRouteHealth(database.PublicRoute{
			RouteKind:   "instance",
			TargetURL:   "http://127.0.0.1:8080",
			Hostname:    "test.example.com",
			ServiceName: "web",
		}, appDef)
		if health != "healthy" {
			t.Errorf("expected healthy, got %q (%q)", health, lastErr)
		}
	})

	t.Run("unexpected status code", func(t *testing.T) {
		mgrWithCaddy := &Manager{
			Caddy: &CaddyAdminClient{
				HTTP: &http.Client{
					Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Body:       io.NopCloser(strings.NewReader("error")),
						}, nil
					}),
				},
			},
		}
		health, lastErr := mgrWithCaddy.checkRouteHealth(database.PublicRoute{
			RouteKind: "instance",
			TargetURL: "http://127.0.0.1:8080",
			Hostname:  "test.example.com",
		}, nil)
		if health != "unhealthy" || !strings.Contains(lastErr, "returned HTTP 500") {
			t.Errorf("expected unhealthy with status mismatch, got %q (%q)", health, lastErr)
		}
	})
}

func TestManagerCertificateInfoAndWarnings(t *testing.T) {
	// Generate a cert valid from 10 days ago to 30 days from now
	notBefore := time.Now().AddDate(0, 0, -10)
	notAfter := time.Now().AddDate(0, 0, 30)
	certPath := generateTestCert(t, notBefore, notAfter)
	defer os.Remove(certPath)

	mgr := &Manager{
		Config: &config.Config{
			NetworkingTLSCertFile: certPath,
		},
		Log: logging.New("test-networking"),
	}

	info, err := mgr.CertificateInfo()
	if err != nil {
		t.Fatalf("unexpected error parsing cert: %v", err)
	}

	if info.Subject != "test.example.com" {
		t.Errorf("expected common name 'test.example.com', got %q", info.Subject)
	}

	// Verify warnings run without crashing
	mgr.WarnExpiringCert()

	// Test with certificate almost expired (expired in 2 days)
	expiringNotBefore := time.Now().AddDate(0, 0, -88)
	expiringNotAfter := time.Now().AddDate(0, 0, 2)
	expiringCertPath := generateTestCert(t, expiringNotBefore, expiringNotAfter)
	defer os.Remove(expiringCertPath)

	mgrExpiring := &Manager{
		Config: &config.Config{
			NetworkingTLSCertFile: expiringCertPath,
		},
		Log: logging.New("test-networking"),
	}

	mgrExpiring.WarnExpiringCert()
}

func TestNewManager(t *testing.T) {
	cfg := &config.Config{CaddyAdminURL: "http://localhost:2019"}
	log := logging.New("test")
	sec := secrets.NewManager("secret")
	mgr, err := NewManager(nil, cfg, log, sec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}

	// Invalid URL should cause NewManager to fail
	badCfg := &config.Config{CaddyAdminURL: ":%abc"}
	_, err = NewManager(nil, badCfg, log, sec)
	if err == nil {
		t.Fatal("expected error for invalid CaddyAdminURL")
	}
}

func TestManagerCertificateInfoErrors(t *testing.T) {
	log := logging.New("test-networking")

	t.Run("empty cert path", func(t *testing.T) {
		mgr := &Manager{Config: &config.Config{}, Log: log}
		_, err := mgr.CertificateInfo()
		if err == nil {
			t.Fatal("expected error for empty certificate path")
		}
	})

	t.Run("unsafe cert path", func(t *testing.T) {
		mgr := &Manager{Config: &config.Config{NetworkingTLSCertFile: "../unsafe/path"}, Log: log}
		_, err := mgr.CertificateInfo()
		if err == nil {
			t.Fatal("expected error for unsafe certificate path")
		}
	})

	t.Run("non-existent cert path", func(t *testing.T) {
		mgr := &Manager{Config: &config.Config{NetworkingTLSCertFile: "/tmp/nonexistent-file-123456"}, Log: log}
		_, err := mgr.CertificateInfo()
		if err == nil {
			t.Fatal("expected error for non-existent certificate file")
		}
	})

	t.Run("no PEM block in cert file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "invalid_pem_*.pem")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		_, _ = tmpFile.WriteString("not a pem certificate")

		mgr := &Manager{
			Config: &config.Config{NetworkingTLSCertFile: tmpFile.Name()},
			Log:    log,
		}
		_, err = mgr.CertificateInfo()
		if err == nil {
			t.Fatal("expected error for invalid PEM block")
		}
		// Also triggers error in WarnExpiringCert
		mgr.WarnExpiringCert()
	})

	t.Run("invalid certificate bytes", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "invalid_cert_*.pem")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		err = pem.Encode(tmpFile, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid bytes")})
		if err != nil {
			t.Fatalf("failed to pem encode: %v", err)
		}

		mgr := &Manager{
			Config: &config.Config{NetworkingTLSCertFile: tmpFile.Name()},
			Log:    log,
		}
		_, err = mgr.CertificateInfo()
		if err == nil {
			t.Fatal("expected error for invalid certificate bytes")
		}
	})
}
