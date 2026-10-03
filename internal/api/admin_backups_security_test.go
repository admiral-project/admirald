// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net"
	"net/http/httptest"
	"testing"
)

func TestTrustedHarborRestoreSourceRequiresRegisteredOriginOrSingleNodeLoopback(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("portal_restore", "portal", "192.0.2.20", "10.99.0.100", "portal", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register portal: %v", err)
	}

	request := func(principal, uri string, singleNode bool) (trustedHarborRestoreCapability, error) {
		r := httptest.NewRequest("POST", "/api/v1/admin/restore", nil)
		r = withAuthPrincipal(r, principal)
		return trustedHarborRestoreSource(h, r, "https", uri, singleNode)
	}

	portalURL := "https://10.99.0.100:5001/api/v1/backups/uploads/upbk_123/download?customer_id=cus_123&expires=2000000000&signature=abc"
	portal, err := request(harborTokenAuthPrincipal, portalURL, false)
	if err != nil {
		t.Fatalf("registered portal origin was rejected: %v", err)
	}
	if portal.origin != "https://10.99.0.100:5001" || portal.legacyIP != "10.99.0.100" || len(portal.ips) != 1 || portal.ips[0] != "10.99.0.100" {
		t.Fatalf("unexpected registered portal capability: %+v", portal)
	}

	localURL := "https://localhost:5001/api/v1/backups/uploads/upbk_123/download?customer_id=cus_123&expires=2000000000&signature=abc"
	local, err := request(harborTokenAuthPrincipal, localURL, true)
	if err != nil {
		t.Fatalf("single-node localhost origin was rejected: %v", err)
	}
	if local.origin != "https://localhost:5001" || local.pathPrefix != harborUploadedBackupPathPrefix || len(local.ips) == 0 {
		t.Fatalf("unexpected single-node localhost capability: %+v", local)
	}
	for _, rawIP := range local.ips {
		if ip := net.ParseIP(rawIP); ip == nil || !ip.IsLoopback() {
			t.Fatalf("single-node capability contains non-loopback address %q", rawIP)
		}
	}

	for _, uri := range []string{
		"https://10.99.0.101:5001/api/v1/backups/uploads/upbk_123/download?customer_id=cus_123&expires=2000000000&signature=abc",
		"https://localhost:5002/api/v1/backups/uploads/upbk_123/download?customer_id=cus_123&expires=2000000000&signature=abc",
		"https://localhost:5001/admin?customer_id=cus_123&expires=2000000000&signature=abc",
		"https://localhost:5001/api/v1/backups/uploads/upbk_123/extra/download?customer_id=cus_123&expires=2000000000&signature=abc",
		"https://localhost:5001/api/v1/backups/uploads/upbk_123%2F..%2Fadmin/download?customer_id=cus_123&expires=2000000000&signature=abc",
		"https://localhost:5001/api/v1/backups/uploads/upbk_123/download?customer_id=cus_123",
	} {
		if _, err := request(harborTokenAuthPrincipal, uri, true); err == nil {
			t.Fatalf("expected unsupported Harbor source URL %q to be rejected", uri)
		}
	}
	if _, err := request(harborTokenAuthPrincipal, localURL, false); err == nil {
		t.Fatal("single-node localhost origin was trusted in multi-node mode")
	}

	admin, err := request(adminTokenAuthPrincipal, portalURL, false)
	if err != nil {
		t.Fatalf("admin source should not need a Harbor capability: %v", err)
	}
	if admin.origin != "" || len(admin.ips) != 0 {
		t.Fatalf("non-Harbor principal received trusted source capability: %+v", admin)
	}

	_, err = request(harborTokenAuthPrincipal, "https://203.0.113.20:5001/api/v1/backups/uploads/upbk_123/download?customer_id=cus_123&expires=2000000000&signature=abc", false)
	if err == nil {
		t.Fatal("expected unregistered private source to be rejected")
	}
}
