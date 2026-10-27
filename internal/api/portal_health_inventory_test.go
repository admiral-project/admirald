// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/logging"
)

type portalHealthRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip portalHealthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return roundTrip(req)
}

func TestPortalHealthCheckSyncsKnownHostInventoryAfterActivation(t *testing.T) {
	h := newTestHandler(t, false)
	h.knowHostPath = filepath.Join(t.TempDir(), "know_host.yaml")
	if err := h.db.RegisterNode("portal-001", "portal-1", "10.77.0.21", "10.99.0.3", "portal", "10.77.0.21", "Rocky 10.2", "5.0"); err != nil {
		t.Fatalf("register portal node: %v", err)
	}
	if err := h.syncKnownHostInventory(); err != nil {
		t.Fatalf("write initial known-host inventory: %v", err)
	}

	server := &Server{handlers: h, log: logging.New("test")}
	client := &http.Client{Transport: portalHealthRoundTripper(func(req *http.Request) (*http.Response, error) {
		if got, want := req.URL.Host, "10.99.0.3:5001"; got != want {
			t.Fatalf("portal health request host = %q, want %q", got, want)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})}
	server.checkPortalNodeHealth(context.Background(), client)

	content, err := os.ReadFile(h.knowHostPath)
	if err != nil {
		t.Fatalf("read synchronized known-host inventory: %v", err)
	}
	if !strings.Contains(string(content), "portal-001:\n    node_id: portal-001\n    hostname: portal-1\n    node_role: portal\n    public_ip: 10.77.0.21\n    wireguard_ip: 10.99.0.3\n    status: active") {
		t.Fatalf("known-host inventory did not record the healthy portal as active:\n%s", content)
	}
}
