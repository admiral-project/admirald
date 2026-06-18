package api

import (
	"net/http"
	"strings"
)

func (h *APIHandlers) HandleCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	info, err := h.networking.CertificateInfo()
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (h *APIHandlers) HandleRoutes(w http.ResponseWriter, r *http.Request) {
	if h.networking == nil {
		writeError(w, http.StatusServiceUnavailable, "networking manager unavailable")
		return
	}

	trimmed := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(trimmed, "/")

	if len(parts) == 3 {
		switch r.Method {
		case http.MethodGet:
			routes, err := h.db.GetPublicRoutes()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Failed to fetch routes")
				return
			}
			writeJSON(w, http.StatusOK, routes)
		case http.MethodPost:
			if err := h.networking.Sync(r.Context()); err != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	if len(parts) < 4 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	hostname := parts[3]
	if hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}

	if len(parts) == 4 {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		route, err := h.db.GetPublicRoute(hostname)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to fetch route")
			return
		}
		if route == nil {
			writeError(w, http.StatusNotFound, "Route not found")
			return
		}
		writeJSON(w, http.StatusOK, route)
		return
	}

	switch parts[4] {
	case "enable":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := h.networking.EnableRoute(r.Context(), hostname); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	case "disable":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := h.networking.DisableRoute(r.Context(), hostname); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	case "sync":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := h.networking.Sync(r.Context()); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	case "delete":
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := h.networking.DeleteRoute(r.Context(), hostname); err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
