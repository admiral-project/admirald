// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package networking

import "testing"

func TestReverseProxyRouteUsesTLSTransportForHTTPSUpstreams(t *testing.T) {
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

func TestReverseProxyRouteOmitsTLSTransportForHTTPUpstreams(t *testing.T) {
	route := reverseProxyRoute(nil, "http://127.0.0.1:5001")
	handle := route["handle"].([]interface{})
	proxy := handle[0].(map[string]interface{})
	if _, ok := proxy["transport"]; ok {
		t.Fatalf("did not expect TLS transport for http upstream: %#v", proxy["transport"])
	}
}
