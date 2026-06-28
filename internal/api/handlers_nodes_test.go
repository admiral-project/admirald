// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"reflect"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
)

func TestWireguardLastOctet(t *testing.T) {
	tests := []struct {
		ip   string
		want int
	}{
		{"10.99.0.2", 2},
		{"10.99.0.100", 100},
		{"  10.99.0.5  ", 5},
		{"invalid", 0},
		{"1.2.3", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := wireguardLastOctet(tt.ip)
		if got != tt.want {
			t.Errorf("wireguardLastOctet(%q) = %d, want %d", tt.ip, got, tt.want)
		}
	}
}

func TestNextKnownHostAssignment(t *testing.T) {
	tests := []struct {
		name  string
		nodes []database.Node
		role  string
		want  knownHostBootstrapAssignment
	}{
		{
			name:  "empty workers",
			nodes: []database.Node{},
			role:  "worker",
			want:  knownHostBootstrapAssignment{NodeID: "worker-001", WireguardIP: "10.99.0.2"},
		},
		{
			name:  "empty portal",
			nodes: []database.Node{},
			role:  "portal",
			want:  knownHostBootstrapAssignment{NodeID: "portal-001", WireguardIP: "10.99.0.100"},
		},
		{
			name: "increment worker",
			nodes: []database.Node{
				{ID: "worker-001", NodeRole: "worker", WireguardIP: "10.99.0.2"},
			},
			role: "worker",
			want: knownHostBootstrapAssignment{NodeID: "worker-002", WireguardIP: "10.99.0.3"},
		},
		{
			name: "increment portal",
			nodes: []database.Node{
				{ID: "portal-001", NodeRole: "portal", WireguardIP: "10.99.0.100"},
			},
			role: "portal",
			want: knownHostBootstrapAssignment{NodeID: "portal-002", WireguardIP: "10.99.0.101"},
		},
		{
			name: "fill gap in IPs",
			nodes: []database.Node{
				{ID: "worker-001", NodeRole: "worker", WireguardIP: "10.99.0.2"},
				{ID: "worker-002", NodeRole: "worker", WireguardIP: "10.99.0.4"},
			},
			role: "worker",
			want: knownHostBootstrapAssignment{NodeID: "worker-003", WireguardIP: "10.99.0.3"},
		},
		{
			name: "ignore other roles",
			nodes: []database.Node{
				{ID: "portal-001", NodeRole: "portal", WireguardIP: "10.99.0.100"},
			},
			role: "worker",
			want: knownHostBootstrapAssignment{NodeID: "worker-001", WireguardIP: "10.99.0.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nextKnownHostAssignment(tt.nodes, tt.role)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("nextKnownHostAssignment() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
