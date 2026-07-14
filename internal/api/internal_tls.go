// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

func internalHTTPClient(timeout time.Duration, devMode bool) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if devMode {
		tlsConfig.InsecureSkipVerify = true // #nosec G402 -- explicitly limited to dev-node
	} else {
		caFile := os.Getenv("ADMIRAL_TLS_CA_FILE")
		if caFile == "" {
			caFile = "/etc/admiral/tls/ca.pem"
		}
		pemData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read Admiral CA %q: %w", caFile, err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("parse Admiral CA %q", caFile)
		}
		tlsConfig.RootCAs = roots
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}
