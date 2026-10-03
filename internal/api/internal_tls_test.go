// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInternalHTTPClientDevModeAllowsDevelopmentTLS(t *testing.T) {
	client, err := internalHTTPClient(time.Second, true)
	if err != nil {
		t.Fatalf("dev client: %v", err)
	}
	transport := client.Transport.(*http.Transport)
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("dev-node client should permit its local self-signed certificate")
	}
}

func TestInternalHTTPClientProductionRejectsInvalidCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADMIRAL_TLS_CA_FILE", path)
	if _, err := internalHTTPClient(time.Second, false); err == nil {
		t.Fatal("production client accepted an invalid CA")
	}
}

func TestPortalHealthAddresses(t *testing.T) {
	tests := []struct {
		name       string
		wireguard  string
		singleNode bool
		want       []string
	}{
		{
			name:       "single-node uses local portal address",
			wireguard:  "10.99.0.1",
			singleNode: true,
			want:       []string{"127.0.0.1"},
		},
		{
			name:      "multi-node uses portal WireGuard address",
			wireguard: "10.99.0.2",
			want:      []string{"10.99.0.2"},
		},
		{
			name: "multi-node with no WireGuard address has no candidate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := portalHealthAddresses(test.wireguard, test.singleNode)
			if len(got) != len(test.want) {
				t.Fatalf("addresses = %v, want %v", got, test.want)
			}
			for i := range got {
				if got[i] != test.want[i] {
					t.Fatalf("addresses = %v, want %v", got, test.want)
				}
			}
		})
	}
}
