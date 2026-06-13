// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package networking

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

type CaddyAdminClient struct {
	BaseURL string
	HTTP    *http.Client
}

func NewCaddyAdminClient(baseURL string) (*CaddyAdminClient, error) {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:2019"
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse caddy admin url %q: %w", baseURL, err)
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" && !net.ParseIP(host).IsLoopback() {
			u.Scheme = "https"
			baseURL = u.String()
		}
	}
	return &CaddyAdminClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

func (c *CaddyAdminClient) GetConfig(ctx context.Context) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/config/", nil)
	if err != nil {
		return nil, fmt.Errorf("create caddy config request: %w", err)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("get caddy config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get caddy config: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var cfg map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode caddy config: %w", err)
	}
	return cfg, nil
}

func (c *CaddyAdminClient) ValidateConfig(ctx context.Context, cfg map[string]interface{}) error {
	payload, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal caddy config: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/load", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create caddy validate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("validate caddy config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("validate caddy config: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *CaddyAdminClient) SyncRoutes(ctx context.Context, routes []database.PublicRoute, cfg RouteConfig) error {
	current, err := c.GetConfig(ctx)
	if err != nil {
		return err
	}
	merged := ensureBootstrapConfig(current, cfg)
	servers := merged["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	servers[cfg.ServerName] = buildServerConfig(routes, cfg)
	servers["admiral-http-redirect"] = httpRedirectServer()
	return c.load(ctx, merged)
}

func httpRedirectServer() map[string]interface{} {
	return map[string]interface{}{
		"listen": []interface{}{":80"},
		"routes": []interface{}{
			map[string]interface{}{
				"handle": []interface{}{
					map[string]interface{}{
						"handler":     "static_response",
						"headers":     map[string]interface{}{"Location": []interface{}{"https://{host}{uri}"}},
						"status_code": 308,
					},
				},
				"terminal": true,
			},
		},
	}
}

func (c *CaddyAdminClient) ApplyRoute(ctx context.Context, route database.PublicRoute, cfg RouteConfig) error {
	return c.SyncRoutes(ctx, []database.PublicRoute{route}, cfg)
}

func (c *CaddyAdminClient) RemoveRoute(ctx context.Context, hostname string, cfg RouteConfig) error {
	return c.SyncRoutes(ctx, nil, cfg.WithRemovedHostname(hostname))
}

func (c *CaddyAdminClient) EnableRoute(ctx context.Context, route database.PublicRoute, cfg RouteConfig) error {
	route.Status = string(admiral.RouteStatusActive)
	return c.ApplyRoute(ctx, route, cfg)
}

func (c *CaddyAdminClient) DisableRoute(ctx context.Context, route database.PublicRoute, cfg RouteConfig) error {
	route.Status = string(admiral.RouteStatusDisabled)
	return c.ApplyRoute(ctx, route, cfg)
}

func (c *CaddyAdminClient) Healthcheck(ctx context.Context) error {
	_, err := c.GetConfig(ctx)
	return err
}

func (c *CaddyAdminClient) Bootstrap(ctx context.Context, cfg RouteConfig, email string) error {
	current, err := c.GetConfig(ctx)
	if err != nil {
		return err
	}
	if len(current) > 0 {
		return nil
	}
	bootstrap := bootstrapConfig(cfg, email)
	return c.load(ctx, bootstrap)
}

func (c *CaddyAdminClient) load(ctx context.Context, cfg map[string]interface{}) error {
	payload, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal caddy load payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/load", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create caddy load request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("load caddy config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("load caddy config: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *CaddyAdminClient) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

type RouteConfig struct {
	ServerName     string
	AdminHostname  string
	PortalHostname string
	AppsHostname   string
	AppsRedirectTo string
	TLSCertFile    string
	TLSKeyFile     string
}

func (r RouteConfig) WithRemovedHostname(hostname string) RouteConfig {
	return r
}

func ensureManagedServer(cfg map[string]interface{}) map[string]interface{} {
	apps, ok := cfg["apps"].(map[string]interface{})
	if !ok {
		apps = map[string]interface{}{}
		cfg["apps"] = apps
	}
	httpApps, ok := apps["http"].(map[string]interface{})
	if !ok {
		httpApps = map[string]interface{}{}
		apps["http"] = httpApps
	}
	servers, ok := httpApps["servers"].(map[string]interface{})
	if !ok {
		servers = map[string]interface{}{}
		httpApps["servers"] = servers
	}
	return cfg
}

func ensureBootstrapConfig(cfg map[string]interface{}, routeCfg RouteConfig) map[string]interface{} {
	cfg = ensureManagedServer(cfg)
	apps := cfg["apps"].(map[string]interface{})
	if _, ok := apps["tls"]; !ok {
		apps["tls"] = map[string]interface{}{
			"automation": map[string]interface{}{
				"policies": []interface{}{},
			},
		}
	}
	if routeCfg.TLSCertFile != "" && routeCfg.TLSKeyFile != "" {
		tlsApp := apps["tls"].(map[string]interface{})
		tlsApp["certificates"] = map[string]interface{}{
			"load_files": []interface{}{
				map[string]interface{}{
					"certificate": routeCfg.TLSCertFile,
					"key":         routeCfg.TLSKeyFile,
				},
			},
		}
	}
	if _, ok := apps["http"].(map[string]interface{})["servers"].(map[string]interface{})[routeCfg.ServerName]; !ok {
		apps["http"].(map[string]interface{})["servers"].(map[string]interface{})[routeCfg.ServerName] = map[string]interface{}{
			"listen": []interface{}{":443"},
			"automatic_https": map[string]interface{}{
				"disable_redirects": false,
			},
			"routes": []interface{}{},
		}
	}
	return cfg
}

func bootstrapConfig(routeCfg RouteConfig, email string) map[string]interface{} {
	cfg := ensureBootstrapConfig(map[string]interface{}{}, routeCfg)
	cfg["admin"] = map[string]interface{}{
		"listen": "127.0.0.1:2019",
	}
	tlsApps := cfg["apps"].(map[string]interface{})["tls"].(map[string]interface{})
	tlsApps["automation"] = map[string]interface{}{
		"policies": []interface{}{
			map[string]interface{}{
				"issuers": []interface{}{
					map[string]interface{}{
						"module": "acme",
						"email":  email,
					},
				},
			},
		},
	}
	return cfg
}

func buildServerConfig(routes []database.PublicRoute, cfg RouteConfig) map[string]interface{} {
	server := map[string]interface{}{
		"listen": []interface{}{":443"},
		"automatic_https": map[string]interface{}{
			"disable_redirects": false,
		},
	}
	caddyRoutes := make([]interface{}, 0, len(routes))
	for _, route := range routes {
		if route.Status == string(admiral.RouteStatusDeleting) || route.Status == string(admiral.RouteStatusDeleted) {
			continue
		}
		caddyRoutes = append(caddyRoutes, buildCaddyRoute(route, cfg))
	}
	server["routes"] = caddyRoutes
	return server
}

func buildCaddyRoute(route database.PublicRoute, cfg RouteConfig) map[string]interface{} {
	match := []interface{}{map[string]interface{}{"host": []interface{}{route.Hostname}}}
	if route.Status == string(admiral.RouteStatusDisabled) {
		return map[string]interface{}{
			"match": match,
			"handle": []interface{}{
				map[string]interface{}{
					"handler":     "static_response",
					"status_code": 503,
					"body":        "route disabled",
				},
			},
			"terminal": true,
		}
	}
	var target string
	if route.TargetHost != "" && route.TargetPort > 0 {
		target = fmt.Sprintf("http://%s:%d", route.TargetHost, route.TargetPort)
	} else if strings.HasPrefix(route.TargetURL, "http://") || strings.HasPrefix(route.TargetURL, "https://") {
		target = route.TargetURL
	}
	switch route.RouteKind {
	case string(admiral.RouteKindAdmin):
		if target != "" {
			return reverseProxyRoute(match, target)
		}
		return staticResponseRoute(match, "Admiral admin placeholder")
	case string(admiral.RouteKindPortal):
		if target != "" {
			return reverseProxyRoute(match, target)
		}
		return staticResponseRoute(match, "Admiral portal placeholder")
	case string(admiral.RouteKindFlagship), string(admiral.RouteKindCockpit):
		if target != "" {
			return reverseProxyRoute(match, target)
		}
		return staticResponseRoute(match, "Service placeholder")
	case string(admiral.RouteKindAppsRoot):
		return redirectRoute(match, cfg.AppsRedirectTo)
	default:
		if route.TargetURL != "" {
			target = route.TargetURL
		}
		return reverseProxyRoute(match, target)
	}
}

func staticResponseRoute(match []interface{}, body string) map[string]interface{} {
	return map[string]interface{}{
		"match": match,
		"handle": []interface{}{
			map[string]interface{}{
				"handler":     "static_response",
				"status_code": 200,
				"body":        body,
			},
		},
		"terminal": true,
	}
}

func redirectRoute(match []interface{}, location string) map[string]interface{} {
	headers := map[string]interface{}{}
	if location != "" {
		headers["Location"] = []interface{}{location}
	}
	return map[string]interface{}{
		"match": match,
		"handle": []interface{}{
			map[string]interface{}{
				"handler":     "static_response",
				"status_code": 308,
				"headers":     headers,
			},
		},
		"terminal": true,
	}
}

func reverseProxyRoute(match []interface{}, upstream string) map[string]interface{} {
	upstreams := []interface{}{}
	var transport map[string]interface{}
	if upstream != "" {
		dial := upstream
		scheme := ""
		if parsed, err := url.Parse(upstream); err == nil && parsed.Host != "" {
			dial = parsed.Host
			scheme = parsed.Scheme
		} else {
			if strings.HasPrefix(dial, "http://") {
				dial = dial[len("http://"):]
				scheme = "http"
			} else if strings.HasPrefix(dial, "https://") {
				dial = dial[len("https://"):]
				scheme = "https"
			}
		}
		if scheme == "https" {
			transport = map[string]interface{}{
				"protocol": "http",
				"tls": map[string]interface{}{
					"insecure_skip_verify": true,
				},
			}
		}
		upstreams = append(upstreams, map[string]interface{}{"dial": dial})
	}
	handle := map[string]interface{}{
		"handler":   "reverse_proxy",
		"upstreams": upstreams,
		"headers": map[string]interface{}{
			"request": map[string]interface{}{
				"set": map[string]interface{}{
					"X-Forwarded-Proto": []interface{}{"{http.request.scheme}"},
				},
			},
		},
	}
	if transport != nil {
		handle["transport"] = transport
	}
	return map[string]interface{}{
		"match":    match,
		"handle":   []interface{}{handle},
		"terminal": true,
	}
}
