// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strconv"
	"strings"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

type pagedResponse struct {
	Items    interface{} `json:"items"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
	Total    int         `json:"total"`
}

func parsePagination(r *http.Request) (int, int) {
	page := 1
	pageSize := defaultPageSize

	if raw := r.URL.Query().Get("page"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if raw := r.URL.Query().Get("page_size"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			pageSize = parsed
		}
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}

func (s *Server) clientIP(r *http.Request) string {
	return getClientIP(r, s.trustedProxies)
}

func (h *APIHandlers) clientIP(r *http.Request) string {
	if h.server != nil {
		return h.server.clientIP(r)
	}
	return getClientIP(r, nil)
}

func getClientIP(r *http.Request, trustedProxies []string) string {
	remoteAddr := r.RemoteAddr
	if idx := strings.LastIndex(remoteAddr, ":"); idx >= 0 {
		remoteAddr = remoteAddr[:idx]
	}
	remoteAddr = strings.TrimPrefix(remoteAddr, "[")
	remoteAddr = strings.TrimSuffix(remoteAddr, "]")

	isTrusted := false
	if len(trustedProxies) > 0 {
		for _, proxy := range trustedProxies {
			if remoteAddr == proxy {
				isTrusted = true
				break
			}
		}
	} else if remoteAddr == "127.0.0.1" || remoteAddr == "::1" {
		// By default trust localhost if no proxies are defined
		isTrusted = true
	}

	if isTrusted {
		// Check X-Forwarded-For header
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}

		// Check X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	return remoteAddr
}
