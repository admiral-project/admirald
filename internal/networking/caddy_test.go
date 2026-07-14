// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package networking

import (
	"os"
	"testing"
)

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
