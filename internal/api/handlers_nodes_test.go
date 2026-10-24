// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/admiral-project/admiral/admirald/internal/database"
)

func TestNodeRemovalErrorStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{
			name: "active instances are a conflict",
			err:  fmt.Errorf("remove node: %w (1 active instance)", database.ErrNodeHasActiveInstances),
			want: http.StatusConflict,
		},
		{
			name: "missing node is not found",
			err:  errors.New("remove node: node not found"),
			want: http.StatusNotFound,
		},
		{
			name: "WireGuard revocation failure is unavailable",
			err:  fmt.Errorf("remove node: pre-delete revocation: %w: helper unavailable", ErrWireGuardPeerRevocation),
			want: http.StatusServiceUnavailable,
		},
		{
			name: "unexpected database error is internal",
			err:  errors.New("database unavailable"),
			want: http.StatusInternalServerError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := nodeRemovalErrorStatus(test.err); got != test.want {
				t.Fatalf("nodeRemovalErrorStatus(%v) = %d, want %d", test.err, got, test.want)
			}
		})
	}
}

func TestNextKnownHostAssignment(t *testing.T) {
	tests := []struct {
		name   string
		nodes  []database.Node
		role   string
		subnet string
		hubIP  string
		want   knownHostBootstrapAssignment
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
		{
			name:   "custom subnet worker",
			role:   "worker",
			subnet: "192.168.44.0/24",
			hubIP:  "192.168.44.1",
			want:   knownHostBootstrapAssignment{NodeID: "worker-001", WireguardIP: "192.168.44.2"},
		},
		{
			name:   "custom subnet portal keeps reserved pool offset",
			role:   "portal",
			subnet: "192.168.44.0/24",
			hubIP:  "192.168.44.1",
			want:   knownHostBootstrapAssignment{NodeID: "portal-001", WireguardIP: "192.168.44.100"},
		},
		{
			name:   "small custom subnet falls back to first available peer address",
			role:   "portal",
			subnet: "192.168.44.0/29",
			hubIP:  "192.168.44.1",
			want:   knownHostBootstrapAssignment{NodeID: "portal-001", WireguardIP: "192.168.44.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nextKnownHostAssignment(tt.nodes, tt.role, tt.subnet, tt.hubIP)
			if err != nil {
				t.Fatalf("nextKnownHostAssignment() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("nextKnownHostAssignment() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestNextKnownHostAssignmentFailsWhenSubnetIsExhausted(t *testing.T) {
	nodes := []database.Node{{ID: "worker-001", NodeRole: "worker", WireguardIP: "192.168.44.2"}}
	_, err := nextKnownHostAssignment(nodes, "worker", "192.168.44.0/30", "192.168.44.1")
	if err == nil {
		t.Fatal("nextKnownHostAssignment() error = nil, want exhausted-subnet error")
	}
}

func TestNextKnownHostAssignmentsKeepsWorkerAndPortalAddressesUnique(t *testing.T) {
	worker, portal, err := nextKnownHostAssignments(nil, "192.168.44.0/29", "192.168.44.1")
	if err != nil {
		t.Fatalf("nextKnownHostAssignments() error = %v", err)
	}
	if worker.WireguardIP == portal.WireguardIP {
		t.Fatalf("worker and portal share WireGuard address %q", worker.WireguardIP)
	}
	if worker.WireguardIP != "192.168.44.2" || portal.WireguardIP != "192.168.44.3" {
		t.Fatalf("unexpected addresses: worker=%q portal=%q", worker.WireguardIP, portal.WireguardIP)
	}
}

func TestNextKnownHostAssignmentsFailsWhenOnlyOnePeerAddressRemains(t *testing.T) {
	_, _, err := nextKnownHostAssignments(nil, "192.168.44.0/30", "192.168.44.1")
	if err == nil {
		t.Fatal("nextKnownHostAssignments() error = nil, want no-addresses-remain error")
	}
}
