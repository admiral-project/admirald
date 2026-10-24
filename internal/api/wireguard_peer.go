// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const wireGuardPeerRevokerSocket = "/run/admiral-wireguard-peer-revoke.sock"

var ErrWireGuardPeerRevocation = errors.New("WireGuard peer revocation failed")

type WireGuardPeerRevoker interface {
	RevokePeer(context.Context, string) (func(), error)
}

type unixWireGuardPeerRevoker struct {
	socketPath string
}

type wireGuardPeerRevocationResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

func (r unixWireGuardPeerRevoker) RevokePeer(ctx context.Context, address string) (func(), error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return nil, errors.New("node has an invalid WireGuard IPv4 address")
	}
	if r.socketPath == "" {
		return nil, errors.New("WireGuard peer revocation socket is not configured")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", r.socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to local WireGuard peer revoker: %w", err)
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = connection.Close()
		}
	}()
	deadline := time.Now().Add(15 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set WireGuard peer revocation deadline: %w", err)
	}
	if _, err := io.WriteString(connection, ip.String()+"\n"); err != nil {
		return nil, fmt.Errorf("send WireGuard peer revocation request: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(connection, 2048))
	var response wireGuardPeerRevocationResponse
	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf("read WireGuard peer revocation result: %w", err)
	}
	if !response.Success {
		message := strings.TrimSpace(response.Error)
		if message == "" {
			message = "privileged helper rejected the request"
		}
		return nil, fmt.Errorf("WireGuard peer revocation failed: %s", message)
	}
	keepOpen = true
	var closeOnce sync.Once
	return func() { closeOnce.Do(func() { _ = connection.Close() }) }, nil
}
