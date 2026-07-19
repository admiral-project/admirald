// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package networking

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
)

func TestNewCaddyAdminClient(t *testing.T) {
	// 1. empty URL defaults to http://127.0.0.1:2019
	c1, err := NewCaddyAdminClient("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c1.BaseURL != "http://127.0.0.1:2019" {
		t.Errorf("expected default BaseURL, got %q", c1.BaseURL)
	}

	// 2. Loopback remains http
	c2, err := NewCaddyAdminClient("http://localhost:2019")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c2.BaseURL != "http://localhost:2019" {
		t.Errorf("expected loopback BaseURL to remain http, got %q", c2.BaseURL)
	}

	// 3. Non-loopback becomes https
	c3, err := NewCaddyAdminClient("http://example.com:2019")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c3.BaseURL != "https://example.com:2019" {
		t.Errorf("expected non-loopback BaseURL to be updated to https, got %q", c3.BaseURL)
	}

	// 4. Invalid URL returns error
	_, err = NewCaddyAdminClient(":%abc")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestCaddyAdminClientHTTPMethods(t *testing.T) {
	mockResponseMap := map[string]interface{}{"apps": map[string]interface{}{}}
	respBytes, _ := json.Marshal(mockResponseMap)

	c := &CaddyAdminClient{
		BaseURL: "http://127.0.0.1:2019",
		HTTP: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/config/" && req.Method == http.MethodGet {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(respBytes)),
					}, nil
				}
				if req.URL.Path == "/load" && req.Method == http.MethodPost {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader("ok")),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader("not found")),
				}, nil
			}),
		},
	}

	ctx := context.Background()

	cfg, err := c.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if _, ok := cfg["apps"]; !ok {
		t.Fatal("expected 'apps' in config")
	}

	err = c.ValidateConfig(ctx, mockResponseMap)
	if err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}

	err = c.Healthcheck(ctx)
	if err != nil {
		t.Fatalf("Healthcheck failed: %v", err)
	}

	cEmpty := &CaddyAdminClient{
		BaseURL: "http://127.0.0.1:2019",
		HTTP: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/config/" {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader("{}")),
					}, nil
				}
				if req.URL.Path == "/load" {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				}
				return &http.Response{StatusCode: 404}, nil
			}),
		},
	}
	err = cEmpty.Bootstrap(ctx, RouteConfig{ServerName: "admiral-public"}, "test@example.com")
	if err != nil {
		t.Fatalf("Bootstrap failed: %v", err)
	}

	routes := []database.PublicRoute{
		{
			Hostname: "test.example.com",
			Status:   "active",
		},
	}
	err = c.SyncRoutes(ctx, routes, RouteConfig{ServerName: "admiral-public"})
	if err != nil {
		t.Fatalf("SyncRoutes failed: %v", err)
	}

	err = c.ApplyRoute(ctx, routes[0], RouteConfig{ServerName: "admiral-public"})
	if err != nil {
		t.Fatalf("ApplyRoute failed: %v", err)
	}

	err = c.RemoveRoute(ctx, "test.example.com", RouteConfig{ServerName: "admiral-public"})
	if err != nil {
		t.Fatalf("RemoveRoute failed: %v", err)
	}

	err = c.EnableRoute(ctx, routes[0], RouteConfig{ServerName: "admiral-public"})
	if err != nil {
		t.Fatalf("EnableRoute failed: %v", err)
	}

	err = c.DisableRoute(ctx, routes[0], RouteConfig{ServerName: "admiral-public"})
	if err != nil {
		t.Fatalf("DisableRoute failed: %v", err)
	}
}

func TestCaddyAdminClientErrors(t *testing.T) {
	c := &CaddyAdminClient{
		BaseURL: "http://127.0.0.1:2019",
		HTTP: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(strings.NewReader("some error")),
				}, nil
			}),
		},
	}

	ctx := context.Background()

	_, err := c.GetConfig(ctx)
	if err == nil {
		t.Fatal("expected GetConfig error on 500 status")
	}

	err = c.ValidateConfig(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected ValidateConfig error on 500 status")
	}

	err = c.load(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected load error on 500 status")
	}
}

func TestBuildCaddyRouteCases(t *testing.T) {
	cfg := RouteConfig{
		ServerName:     "admiral-public",
		AppsRedirectTo: "https://portal.example.com",
	}

	t.Run("disabled status returns 503 Route Disabled", func(t *testing.T) {
		route := database.PublicRoute{
			Hostname: "disabled.example.com",
			Status:   "disabled",
		}
		caddyRoute := buildCaddyRoute(route, cfg)
		handle := caddyRoute["handle"].([]interface{})
		handler := handle[0].(map[string]interface{})
		if handler["handler"] != "static_response" || handler["status_code"] != 503 {
			t.Errorf("unexpected handle for disabled route: %v", handler)
		}
	})

	t.Run("RouteKindAdmin with target", func(t *testing.T) {
		route := database.PublicRoute{
			Hostname:  "admin.example.com",
			RouteKind: "admin",
			TargetURL: "http://10.0.0.1:3000",
			Status:    "active",
		}
		caddyRoute := buildCaddyRoute(route, cfg)
		handle := caddyRoute["handle"].([]interface{})
		handler := handle[0].(map[string]interface{})
		if handler["handler"] != "reverse_proxy" {
			t.Errorf("expected reverse_proxy, got %v", handler["handler"])
		}
	})

	t.Run("RouteKindAdmin without target", func(t *testing.T) {
		route := database.PublicRoute{
			Hostname:  "admin.example.com",
			RouteKind: "admin",
			Status:    "active",
		}
		caddyRoute := buildCaddyRoute(route, cfg)
		handle := caddyRoute["handle"].([]interface{})
		handler := handle[0].(map[string]interface{})
		if handler["handler"] != "static_response" || handler["body"] != "Admiral admin placeholder" {
			t.Errorf("expected placeholder static response, got %v", handler)
		}
	})

	t.Run("RouteKindPortal with target", func(t *testing.T) {
		route := database.PublicRoute{
			Hostname:  "portal.example.com",
			RouteKind: "portal",
			TargetURL: "http://10.0.0.2:3000",
			Status:    "active",
		}
		caddyRoute := buildCaddyRoute(route, cfg)
		handle := caddyRoute["handle"].([]interface{})
		handler := handle[0].(map[string]interface{})
		if handler["handler"] != "reverse_proxy" {
			t.Errorf("expected reverse_proxy, got %v", handler)
		}
	})

	t.Run("RouteKindPortal without target", func(t *testing.T) {
		route := database.PublicRoute{
			Hostname:  "portal.example.com",
			RouteKind: "portal",
			Status:    "active",
		}
		caddyRoute := buildCaddyRoute(route, cfg)
		handle := caddyRoute["handle"].([]interface{})
		handler := handle[0].(map[string]interface{})
		if handler["handler"] != "static_response" || handler["body"] != "Admiral portal placeholder" {
			t.Errorf("expected placeholder static response, got %v", handler)
		}
	})

	t.Run("RouteKindFlagship / Cockpit without target", func(t *testing.T) {
		route := database.PublicRoute{
			Hostname:  "flagship.example.com",
			RouteKind: "flagship",
			Status:    "active",
		}
		caddyRoute := buildCaddyRoute(route, cfg)
		handle := caddyRoute["handle"].([]interface{})
		handler := handle[0].(map[string]interface{})
		if handler["handler"] != "static_response" || handler["body"] != "Service placeholder" {
			t.Errorf("expected service placeholder static response, got %v", handler)
		}
	})

	t.Run("RouteKindAppsRoot", func(t *testing.T) {
		route := database.PublicRoute{
			Hostname:  "apps.example.com",
			RouteKind: "apps_root",
			Status:    "active",
		}
		caddyRoute := buildCaddyRoute(route, cfg)
		handle := caddyRoute["handle"].([]interface{})
		handler := handle[0].(map[string]interface{})
		if handler["handler"] != "static_response" || handler["status_code"] != 308 {
			t.Errorf("expected 308 redirect, got %v", handler)
		}
	})

	t.Run("Instance with custom target URL", func(t *testing.T) {
		route := database.PublicRoute{
			Hostname:  "instance.example.com",
			RouteKind: "instance",
			TargetURL: "http://10.99.0.5:8080",
			Status:    "active",
		}
		caddyRoute := buildCaddyRoute(route, cfg)
		handle := caddyRoute["handle"].([]interface{})
		handler := handle[0].(map[string]interface{})
		if handler["handler"] != "reverse_proxy" {
			t.Errorf("expected reverse_proxy, got %v", handler)
		}
	})
}

func TestReverseProxyRouteUsesTLSTransportForHTTPSUpstreams(t *testing.T) {
	t.Setenv("ADMIRAL_DEV_MODE", "true")
	route := reverseProxyRoute(nil, "https://127.0.0.1:5000")
	handle, ok := route["handle"].([]interface{})
	if !ok || len(handle) != 1 {
		t.Fatalf("unexpected handle payload: %#v", route["handle"])
	}
	proxy, ok := handle[0].(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected proxy payload: %#v", handle[0])
	}
	transport, ok := proxy["transport"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected TLS transport for https upstream, got %#v", proxy["transport"])
	}
	if transport["protocol"] != "http" {
		t.Fatalf("unexpected protocol %v", transport["protocol"])
	}
	tlsConfig, ok := transport["tls"].(map[string]interface{})
	if !ok || tlsConfig["insecure_skip_verify"] != true {
		t.Fatalf("unexpected tls transport payload: %#v", transport["tls"])
	}
}

func TestReverseProxyRouteUsesConfiguredCA(t *testing.T) {
	t.Setenv("ADMIRAL_DEV_MODE", "false")
	t.Setenv("ADMIRAL_TLS_CA_FILE", "/etc/admiral/tls/ca.pem")
	route := reverseProxyRoute(nil, "https://10.99.0.100:5001")
	transport := route["handle"].([]interface{})[0].(map[string]interface{})["transport"].(map[string]interface{})
	tlsConfig := transport["tls"].(map[string]interface{})
	if _, ok := tlsConfig["insecure_skip_verify"]; ok {
		t.Fatal("production transport must not disable TLS verification")
	}
	if got := tlsConfig["ca"].([]interface{}); len(got) != 1 || got[0] != "/etc/admiral/tls/ca.pem" {
		t.Fatalf("unexpected CA configuration: %#v", got)
	}
	_ = os.Getenv("ADMIRAL_TLS_CA_FILE")
}

func TestReverseProxyRouteOmitsTLSTransportForHTTPUpstreams(t *testing.T) {
	route := reverseProxyRoute(nil, "http://127.0.0.1:5001")
	handle := route["handle"].([]interface{})
	proxy := handle[0].(map[string]interface{})
	if _, ok := proxy["transport"]; ok {
		t.Fatalf("did not expect TLS transport for http upstream: %#v", proxy["transport"])
	}
}
