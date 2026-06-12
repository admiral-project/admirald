// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

func ValidateURLScheme(raw string, allowed ...string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse URL %q: %w", raw, err)
	}
	if parsed.Scheme == "" {
		return fmt.Errorf("URL %q must include a scheme", raw)
	}

	for _, scheme := range allowed {
		if parsed.Scheme == scheme {
			return nil
		}
	}

	return fmt.Errorf("URL %q must use one of: %v", raw, allowed)
}

func NewClientConfig(caFile string) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if caFile != "" {
		caFile = filepath.Clean(caFile)
		pemData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", caFile, err)
		}
		if ok := pool.AppendCertsFromPEM(pemData); !ok {
			return nil, fmt.Errorf("parse CA file %q: no certificates found", caFile)
		}
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}, nil
}

func NewServerConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}
