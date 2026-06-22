// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/admiral-project/admiral/admirald/internal/logging"
)

func writeGenericAuthError(w http.ResponseWriter, status int) {
	msg := "unauthorized"
	if status == http.StatusForbidden {
		msg = "forbidden"
	}
	writeJSON(w, status, map[string]string{"error": msg})
}

func logAuthFailure(log *logging.Logger, level, authKind, reason string, status int, r *http.Request, err error) {
	if log == nil {
		return
	}
	fields := map[string]interface{}{
		"path":      r.URL.Path,
		"method":    r.Method,
		"remote_ip": clientIP(r.RemoteAddr),
		"auth_kind": authKind,
		"reason":    reason,
		"status":    status,
	}
	if err != nil {
		log.Error("authentication failed", err, fields)
		return
	}
	switch level {
	case "WARN":
		log.Warn("authentication failed", fields)
	default:
		log.Info("authentication failed", fields)
	}
}
