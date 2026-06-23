// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package networking

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/config"
	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
	"gopkg.in/yaml.v2"
)

var appCodePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

type Manager struct {
	DB      *database.DB
	Caddy   *CaddyAdminClient
	Config  *config.Config
	Log     *logging.Logger
	Secrets *secrets.Manager
}

func NewManager(db *database.DB, cfg *config.Config, log *logging.Logger, secretManager *secrets.Manager) (*Manager, error) {
	caddy, err := NewCaddyAdminClient(cfg.CaddyAdminURL)
	if err != nil {
		return nil, err
	}
	return &Manager{
		DB:      db,
		Caddy:   caddy,
		Config:  cfg,
		Log:     log,
		Secrets: secretManager,
	}, nil
}

func (m *Manager) SeedStaticRoutes(ctx context.Context) error {
	if m.Caddy != nil {
		if err := m.Caddy.Bootstrap(ctx, RouteConfig{
			ServerName:  "admiral-public",
			TLSCertFile: m.Config.NetworkingTLSCertFile,
			TLSKeyFile:  m.Config.NetworkingTLSKeyFile,
		}, m.Config.NetworkingTLSEmail); err != nil {
			return err
		}
	}
	var routes []database.PublicRoute
	if m.Config.NetworkingAdminHost != "" && m.Config.NetworkingAdminTarget != "" {
		routes = append(routes, m.staticRoute(m.Config.NetworkingAdminHost, string(admiral.RouteKindAdmin), "admin", m.Config.NetworkingAdminTarget))
	}
	if m.Config.NetworkingPortalHost != "" && m.Config.NetworkingPortalTarget != "" {
		routes = append(routes, m.staticRoute(m.Config.NetworkingPortalHost, string(admiral.RouteKindPortal), "portal", m.Config.NetworkingPortalTarget))
	}
	if m.Config.NetworkingAppsDomain != "" && m.Config.NetworkingAppsRedirect != "" {
		routes = append(routes, m.staticRoute(m.Config.NetworkingAppsDomain, string(admiral.RouteKindAppsRoot), "apps", m.Config.NetworkingAppsRedirect))
	}
	if m.Config.NetworkingFlagshipHost != "" && m.Config.NetworkingFlagshipTarget != "" {
		routes = append(routes, m.staticRoute(m.Config.NetworkingFlagshipHost, string(admiral.RouteKindFlagship), "flagship", m.Config.NetworkingFlagshipTarget))
	}
	if m.Config.NetworkingCockpitHost != "" && m.Config.NetworkingCockpitTarget != "" {
		routes = append(routes, m.staticRoute(m.Config.NetworkingCockpitHost, string(admiral.RouteKindCockpit), "cockpit", m.Config.NetworkingCockpitTarget))
	}
	// Remove stale static routes.
	staticKinds := map[string]bool{"admin": true, "portal": true, "apps_root": true, "flagship": true, "cockpit": true}
	seededKinds := map[string]bool{}
	for _, route := range routes {
		seededKinds[route.RouteKind] = true
		if route.Hostname != "" {
			_ = m.DB.DeletePublicRouteByKindAndNotHostname(route.RouteKind, route.Hostname)
		}
	}
	for kind := range staticKinds {
		if !seededKinds[kind] {
			_ = m.DB.DeletePublicRouteByKind(kind)
		}
	}
	for _, route := range routes {
		if route.Hostname == "" {
			continue
		}
		existing, err := m.DB.GetPublicRoute(route.Hostname)
		if err != nil {
			return err
		}
		if existing == nil {
			if err := m.DB.CreatePublicRoute(route); err != nil {
				return err
			}
			continue
		}
		// Do not overwrite routes that have been configured with a real proxy target.
		if strings.HasPrefix(existing.TargetURL, "http://") || strings.HasPrefix(existing.TargetURL, "https://") ||
			existing.TargetHost != "" && existing.TargetPort > 0 {
			continue
		}
		existing.PublicID = route.PublicID
		existing.AppInstanceID = route.AppInstanceID
		existing.AppTemplateCode = route.AppTemplateCode
		existing.ServiceName = route.ServiceName
		existing.TargetScheme = route.TargetScheme
		existing.TargetHost = route.TargetHost
		existing.TargetPort = route.TargetPort
		existing.TargetURL = route.TargetURL
		existing.RouteKind = route.RouteKind
		existing.TLSMode = route.TLSMode
		existing.Status = route.Status
		if err := m.DB.UpdatePublicRoute(existing); err != nil {
			return err
		}
	}
	return m.Sync(ctx)
}

func (m *Manager) CreateInstanceRoutes(instanceID string, appDef admiral.AppDefinitionPayload, nodeID string) ([]database.PublicRoute, error) {
	if m.Config.NetworkingAppsDomain == "" {
		return nil, nil
	}
	node, err := m.DB.GetNode(nodeID)
	if err != nil {
		return nil, err
	}
	if node == nil {
		return nil, fmt.Errorf("node %q not found for public routes", nodeID)
	}

	var publicServiceName string
	var publicService admiral.YAMLService
	for name, svc := range appDef.Services {
		if svc.Public {
			publicServiceName = name
			publicService = svc
			break
		}
	}
	if publicServiceName == "" {
		return nil, nil
	}

	hostname, err := m.generateHostname(appDef.Name)
	if err != nil {
		return nil, err
	}

	route := database.PublicRoute{
		ID:               generatePublicRouteID(),
		Hostname:         hostname,
		PublicID:         instanceID,
		AppInstanceID:    instanceID,
		AppTemplateCode:  appDef.Name,
		NodeID:           &node.ID,
		ServiceName:      publicServiceName,
		TargetScheme:     "http",
		TargetHost:       node.IP,
		TargetPort:       publicService.Port,
		TargetURL:        fmt.Sprintf("http://%s:%d", node.IP, publicService.Port),
		RouteKind:        string(admiral.RouteKindInstance),
		TLSMode:          "auto",
		Status:           string(admiral.RouteStatusPending),
		LastError:        "",
		LastHealthStatus: "",
	}
	if err := m.DB.CreatePublicRoute(route); err != nil {
		return nil, err
	}
	return []database.PublicRoute{route}, nil
}

func (m *Manager) ActivateInstanceRoutes(ctx context.Context, instanceID string, hostPorts ...map[string]int) error {
	routes, err := m.DB.GetPublicRoutes()
	if err != nil {
		return err
	}
	appDef, err := m.appDefinitionForInstance(instanceID)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.AppInstanceID != instanceID || route.RouteKind != string(admiral.RouteKindInstance) {
			continue
		}
		node, err := m.DB.GetNode(routeNodeID(route))
		if err != nil {
			return err
		}
		if node == nil {
			route.Status = string(admiral.RouteStatusFailed)
			route.LastError = "node not found"
			if err := m.DB.UpdatePublicRoute(&route); err != nil {
				return err
			}
			continue
		}
		svc, ok := appDef.Services[route.ServiceName]
		if !ok || !svc.Public || svc.Port <= 0 {
			route.Status = string(admiral.RouteStatusFailed)
			route.LastError = "public service unavailable"
			if err := m.DB.UpdatePublicRoute(&route); err != nil {
				return err
			}
			continue
		}
		targetHost := node.IP
		targetPort := svc.Port
		if len(hostPorts) > 0 && hostPorts[0] != nil {
			if hostPort, ok := hostPorts[0][route.ServiceName]; ok && hostPort > 0 {
				if node.WireguardIP != "" && node.WireguardIP != "127.0.0.1" {
					targetHost = node.WireguardIP
				} else {
					targetHost = node.IP
				}
				targetPort = hostPort
			}
		}
		route.NodeID = &node.ID
		route.TargetHost = targetHost
		route.TargetPort = targetPort
		route.TargetURL = fmt.Sprintf("http://%s:%d", targetHost, targetPort)
		route.TargetScheme = "http"
		route.Status = string(admiral.RouteStatusActive)
		route.LastError = ""
		if err := m.DB.UpdatePublicRoute(&route); err != nil {
			return err
		}
	}
	return m.Sync(ctx)
}

func (m *Manager) DisableRoute(ctx context.Context, hostname string) error {
	route, err := m.DB.GetPublicRoute(hostname)
	if err != nil {
		return err
	}
	if route == nil {
		return fmt.Errorf("route %q not found", hostname)
	}
	route.Status = string(admiral.RouteStatusDisabled)
	if err := m.DB.UpdatePublicRoute(route); err != nil {
		return err
	}
	return m.Sync(ctx)
}

func (m *Manager) EnableRoute(ctx context.Context, hostname string) error {
	route, err := m.DB.GetPublicRoute(hostname)
	if err != nil {
		return err
	}
	if route == nil {
		return fmt.Errorf("route %q not found", hostname)
	}
	if route.RouteKind == string(admiral.RouteKindInstance) {
		route.Status = string(admiral.RouteStatusActive)
	} else {
		route.Status = string(admiral.RouteStatusActive)
	}
	if err := m.DB.UpdatePublicRoute(route); err != nil {
		return err
	}
	return m.Sync(ctx)
}

func (m *Manager) DeleteRoute(ctx context.Context, hostname string) error {
	route, err := m.DB.GetPublicRoute(hostname)
	if err != nil {
		return err
	}
	if route == nil {
		return nil
	}
	route.Status = string(admiral.RouteStatusDeleting)
	if err := m.DB.UpdatePublicRoute(route); err != nil {
		return err
	}
	if err := m.Sync(ctx); err != nil {
		return err
	}
	return m.DB.DeletePublicRoute(hostname)
}

func (m *Manager) DeleteInstanceRoutes(ctx context.Context, instanceID string) error {
	routes, err := m.DB.GetPublicRoutes()
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.AppInstanceID != instanceID {
			continue
		}
		if err := m.DeleteRoute(ctx, route.Hostname); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Sync(ctx context.Context) error {
	routes, err := m.DB.GetPublicRoutes()
	if err != nil {
		return err
	}
	if m.Caddy == nil {
		return nil
	}
	cfg := RouteConfig{
		ServerName:     "admiral-public",
		AdminHostname:  m.Config.NetworkingAdminHost,
		PortalHostname: m.Config.NetworkingPortalHost,
		AppsHostname:   m.Config.NetworkingAppsDomain,
		AppsRedirectTo: m.Config.NetworkingAppsRedirect,
		TLSCertFile:    m.Config.NetworkingTLSCertFile,
		TLSKeyFile:     m.Config.NetworkingTLSKeyFile,
	}
	if err := m.Caddy.SyncRoutes(ctx, routes, cfg); err != nil {
		for _, route := range routes {
			if route.Status == string(admiral.RouteStatusDeleted) {
				continue
			}
			route.LastError = err.Error()
			route.LastHealthStatus = "unavailable"
			now := time.Now().UTC()
			route.LastHealthCheckedAt = &now
			_ = m.DB.UpdatePublicRoute(&route)
		}
		return err
	}
	for _, route := range routes {
		if route.Status == string(admiral.RouteStatusDeleted) {
			continue
		}
		var appDef *admiral.AppDefinitionPayload
		if route.RouteKind == string(admiral.RouteKindInstance) && route.AppInstanceID != "" {
			appDef, err = m.appDefinitionForInstance(route.AppInstanceID)
			if err != nil {
				now := time.Now().UTC()
				route.LastHealthCheckedAt = &now
				route.LastHealthStatus = "unhealthy"
				route.LastError = fmt.Sprintf("load app definition: %v", err)
				_ = m.DB.UpdatePublicRoute(&route)
				continue
			}
		}
		health, lastErr := m.checkRouteHealth(route, appDef)
		now := time.Now().UTC()
		route.LastHealthCheckedAt = &now
		route.LastHealthStatus = health
		route.LastError = lastErr
		if route.Status == string(admiral.RouteStatusPending) && health == "healthy" {
			route.Status = string(admiral.RouteStatusActive)
		}
		_ = m.DB.UpdatePublicRoute(&route)
	}
	return nil
}

func (m *Manager) checkRouteHealth(route database.PublicRoute, appDef *admiral.AppDefinitionPayload) (string, string) {
	if route.Status == string(admiral.RouteStatusDisabled) {
		return "disabled", ""
	}
	switch route.RouteKind {
	case string(admiral.RouteKindAdmin), string(admiral.RouteKindPortal), string(admiral.RouteKindAppsRoot),
		string(admiral.RouteKindFlagship), string(admiral.RouteKindCockpit):
		return "healthy", ""
	}
	target := route.TargetURL
	if target == "" && route.TargetHost != "" && route.TargetPort > 0 {
		target = fmt.Sprintf("http://%s:%d", route.TargetHost, route.TargetPort)
	}
	if target == "" {
		return "unhealthy", "missing target"
	}
	checkPath := "/"
	expectedStatus := http.StatusOK
	if appDef != nil {
		if svc, ok := appDef.Services[route.ServiceName]; ok && svc.HealthCheck != nil && strings.EqualFold(svc.HealthCheck.Type, "http") {
			if strings.TrimSpace(svc.HealthCheck.Path) != "" {
				checkPath = svc.HealthCheck.Path
			}
			if svc.HealthCheck.ExpectedStatus > 0 {
				expectedStatus = svc.HealthCheck.ExpectedStatus
			}
		}
	}
	if !strings.HasPrefix(checkPath, "/") {
		checkPath = "/" + checkPath
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("https://%s%s", route.Hostname, checkPath), nil)
	if err != nil {
		return "unhealthy", err.Error()
	}
	resp, err := routeHealthHTTPClient(m.Caddy, route.Hostname).Do(req)
	if err != nil {
		return "unhealthy", err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode == expectedStatus {
		return "healthy", ""
	}
	return "unhealthy", fmt.Sprintf("backend returned HTTP %d, expected %d", resp.StatusCode, expectedStatus)
}

func routeHealthHTTPClient(caddy *CaddyAdminClient, hostname string) *http.Client {
	base := &http.Client{Timeout: 10 * time.Second}
	if caddy != nil && caddy.HTTP != nil {
		base = caddy.HTTP
	}
	client := *base
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	if base.Transport != nil {
		if _, ok := base.Transport.(*http.Transport); !ok {
			return &client
		}
	}

	client.Transport = &http.Transport{
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{
			ServerName: hostname,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, "127.0.0.1:443")
		},
	}
	return &client
}

func (m *Manager) appDefinitionForInstance(instanceID string) (*admiral.AppDefinitionPayload, error) {
	inst, err := m.DB.GetCustomerApp(instanceID)
	if err != nil {
		return nil, err
	}
	if inst == nil {
		return nil, fmt.Errorf("instance %q not found", instanceID)
	}
	appDef, err := m.DB.GetAppDefinition(inst.AppDefinitionName)
	if err != nil {
		return nil, err
	}
	if appDef == nil {
		return nil, fmt.Errorf("app definition %q not found", inst.AppDefinitionName)
	}
	var payload admiral.AppDefinitionPayload
	if err := yaml.Unmarshal([]byte(appDef.RawYAML), &payload); err != nil {
		return nil, fmt.Errorf("parse app definition %q: %w", appDef.Name, err)
	}
	return &payload, nil
}

func (m *Manager) generateHostname(appCode string) (string, error) {
	if !appCodePattern.MatchString(appCode) {
		return "", fmt.Errorf("invalid app code %q", appCode)
	}
	for i := 0; i < 20; i++ {
		suffix, err := randomDigits(6)
		if err != nil {
			return "", err
		}
		hostname := fmt.Sprintf("%s%s.%s", appCode, suffix, m.Config.NetworkingAppsDomain)
		existing, err := m.DB.GetPublicRoute(hostname)
		if err != nil {
			return "", err
		}
		if existing == nil {
			return hostname, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique hostname after retries")
}

func randomDigits(n int) (string, error) {
	if n <= 0 {
		return "", nil
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("generate random digit: %w", err)
		}
		b.WriteByte(byte('0' + v.Int64())) //nolint:gosec // v.Int64() is 0-9 from rand.Int(..., big.NewInt(10))
	}
	return b.String(), nil
}

func generatePublicRouteID() string {
	digits, err := randomDigits(8)
	if err != nil {
		return fmt.Sprintf("route_%d", time.Now().UnixNano())
	}
	return "route_" + digits
}

func (m *Manager) staticRoute(hostname, kind, serviceName, target string) database.PublicRoute {
	return database.PublicRoute{
		ID:               generatePublicRouteID(),
		Hostname:         hostname,
		PublicID:         kind,
		AppTemplateCode:  kind,
		ServiceName:      serviceName,
		TargetScheme:     "respond",
		TargetHost:       "",
		TargetPort:       0,
		TargetURL:        target,
		RouteKind:        kind,
		TLSMode:          "auto",
		Status:           string(admiral.RouteStatusActive),
		LastHealthStatus: "healthy",
	}
}

func routeNodeID(route database.PublicRoute) string {
	if route.NodeID == nil {
		return ""
	}
	return *route.NodeID
}

type CertInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DNSNames  []string  `json:"dns_names"`
	AgeDays   int       `json:"age_days"`
	ExpiresIn int       `json:"expires_in_days"`
	CertFile  string    `json:"cert_file"`
}

func isSafePath(p string) bool {
	cleaned := filepath.Clean(p)
	return cleaned == p && !strings.Contains(p, "..")
}

func (m *Manager) CertificateInfo() (*CertInfo, error) {
	certPath := m.Config.NetworkingTLSCertFile
	if certPath == "" {
		certPath = m.Config.TLSCertFile
	}
	if certPath == "" {
		return nil, fmt.Errorf("no TLS certificate configured")
	}
	if !isSafePath(certPath) {
		return nil, fmt.Errorf("unsafe certificate path %q", certPath)
	}
	data, err := os.ReadFile(certPath) //nolint:gosec // path validated by isSafePath()
	if err != nil {
		return nil, fmt.Errorf("read cert file %q: %w", certPath, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %q", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert %q: %w", certPath, err)
	}
	age := int(time.Since(cert.NotBefore).Hours() / 24)
	expiresIn := int(time.Until(cert.NotAfter).Hours() / 24)
	return &CertInfo{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		DNSNames:  cert.DNSNames,
		AgeDays:   age,
		ExpiresIn: expiresIn,
		CertFile:  certPath,
	}, nil
}

func (m *Manager) WarnExpiringCert() {
	info, err := m.CertificateInfo()
	if err != nil {
		m.Log.Warn("certificate check", map[string]interface{}{"error": err.Error()})
		return
	}
	if info.ExpiresIn <= 5 {
		m.Log.Warn("TLS wildcard certificate expires soon", map[string]interface{}{
			"cert_file":       info.CertFile,
			"not_after":       info.NotAfter.Format(time.RFC3339),
			"expires_in_days": info.ExpiresIn,
			"age_days":        info.AgeDays,
			"message":         "Renew the wildcard certificate via certbot DNS-01 challenge (see docs/setup_guide_el10.md section 7)",
		})
	}
	if info.AgeDays >= 85 {
		m.Log.Warn("TLS wildcard certificate age exceeds threshold", map[string]interface{}{
			"cert_file": info.CertFile,
			"not_after": info.NotAfter.Format(time.RFC3339),
			"age_days":  info.AgeDays,
			"message":   "Certificate is 85+ days old and may expire soon. Renew via certbot DNS-01 challenge.",
		})
	}
}
