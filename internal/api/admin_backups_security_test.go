// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http/httptest"
	"testing"
)

func TestTrustedHarborRestoreSourceIPRequiresRegisteredPortal(t *testing.T) {
	h := newTestHandler(t, false)
	if err := h.db.RegisterNode("portal_restore", "portal", "192.0.2.20", "10.99.0.100", "portal", "", "fedora", "5.0"); err != nil {
		t.Fatalf("register portal: %v", err)
	}

	request := func(principal, uri string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/admin/restore", nil)
		r = withAuthPrincipal(r, principal)
		w := httptest.NewRecorder()
		ip, err := trustedHarborRestoreSourceIP(h, r, "https", uri)
		if err != nil {
			w.Header().Set("X-Test-Error", err.Error())
		}
		w.Header().Set("X-Test-IP", ip)
		return w
	}

	portal := request(harborTokenAuthPrincipal, "https://10.99.0.100/upload/restore")
	if got := portal.Header().Get("X-Test-IP"); got != "10.99.0.100" {
		t.Fatalf("registered portal IP was not trusted: %q error=%s", got, portal.Header().Get("X-Test-Error"))
	}

	otherPrivate := request(harborTokenAuthPrincipal, "https://10.99.0.101/upload/restore")
	if otherPrivate.Header().Get("X-Test-Error") == "" {
		t.Fatal("expected unregistered private source to be rejected")
	}

	admin := request(adminTokenAuthPrincipal, "https://10.99.0.100/upload/restore")
	if got := admin.Header().Get("X-Test-IP"); got != "" {
		t.Fatalf("non-Harbor principal received trusted IP %q", got)
	}
}
