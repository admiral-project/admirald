// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnixWireGuardPeerRevokerSendsAddressAndReadsSuccess(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "revoke.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on temporary Unix socket: %v", err)
	}
	defer listener.Close()
	request := make(chan string, 1)
	serverReleased := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		line, readErr := bufio.NewReader(connection).ReadString('\n')
		if readErr != nil {
			return
		}
		request <- line
		_ = json.NewEncoder(connection).Encode(wireGuardPeerRevocationResponse{Success: true})
		_, _ = io.Copy(io.Discard, connection)
		close(serverReleased)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	release, err := (unixWireGuardPeerRevoker{socketPath: socketPath}).RevokePeer(ctx, "worker-001", "worker", "10.99.0.3")
	if err != nil {
		t.Fatalf("RevokePeer() error = %v", err)
	}
	select {
	case got := <-request:
		var gotRequest wireGuardPeerRevocationRequest
		if err := json.Unmarshal([]byte(got), &gotRequest); err != nil {
			t.Fatalf("decode socket request %q: %v", got, err)
		}
		if gotRequest != (wireGuardPeerRevocationRequest{
			NodeID: "worker-001", NodeRole: "worker", WireGuardIP: "10.99.0.3",
		}) {
			t.Fatalf("socket request = %+v, want node identity and address", gotRequest)
		}
	case <-time.After(time.Second):
		t.Fatal("revocation helper did not receive a request")
	}
	select {
	case <-serverReleased:
		t.Fatal("revocation socket closed before the database caller released it")
	default:
	}
	release()
	select {
	case <-serverReleased:
	case <-time.After(time.Second):
		t.Fatal("revocation socket did not close after the caller released it")
	}
}

func TestUnixWireGuardPeerRevokerRejectsInvalidAddressWithoutConnecting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := (unixWireGuardPeerRevoker{socketPath: filepath.Join(t.TempDir(), "missing.sock")}).RevokePeer(ctx, "worker-001", "worker", "127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "WireGuard IPv4") {
		t.Fatalf("RevokePeer() error = %v, want invalid private IPv4 error", err)
	}
}

func TestUnixWireGuardPeerRevokerRejectsInvalidNodeIdentityWithoutConnecting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	revoker := unixWireGuardPeerRevoker{socketPath: filepath.Join(t.TempDir(), "missing.sock")}
	for _, test := range []struct {
		name, nodeID, role string
	}{
		{name: "path traversal", nodeID: "../worker", role: "worker"},
		{name: "unsupported role", nodeID: "worker-001", role: "admin"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := revoker.RevokePeer(ctx, test.nodeID, test.role, "10.99.0.3"); err == nil {
				t.Fatal("RevokePeer() unexpectedly accepted invalid node identity")
			}
		})
	}
}

func TestUnixWireGuardPeerRevokerReturnsHelperFailure(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "revoke.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on temporary Unix socket: %v", err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		buffer := make([]byte, 64)
		_, _ = connection.Read(buffer)
		_ = json.NewEncoder(connection).Encode(wireGuardPeerRevocationResponse{Error: "helper unavailable"})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = (unixWireGuardPeerRevoker{socketPath: socketPath}).RevokePeer(ctx, "worker-001", "worker", "10.99.0.3")
	if err == nil || !strings.Contains(err.Error(), "helper unavailable") {
		t.Fatalf("RevokePeer() error = %v, want helper failure", err)
	}
}
