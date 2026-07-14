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
