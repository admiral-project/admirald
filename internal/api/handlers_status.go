package api

import (
	"encoding/json"
	"net/http"

	"github.com/admiral-project/admiral/admirald/pkg/admiral"
)

func (h *APIHandlers) HandleRateLimitReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"error":"method not allowed"}`))
		return
	}

	var req admiral.RateLimitResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid request body"}`))
		return
	}

	if req.Identifier == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"identifier is required"}`))
		return
	}

	if err := h.db.ResetRateLimit(req.Identifier); err != nil {
		h.log.Error("rate limit reset failed", err, nil)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"rate limit reset failed"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{}`))
}

func (h *APIHandlers) HandleRateLimitCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"error":"method not allowed"}`))
		return
	}

	var req admiral.RateLimitCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid request body"}`))
		return
	}

	if req.Identifier == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"identifier is required"}`))
		return
	}

	maxAttempts := req.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	windowSeconds := req.WindowSeconds
	if windowSeconds <= 0 {
		windowSeconds = 60
	}

	allowed, remaining, err := h.db.CheckRateLimit(req.Identifier, maxAttempts, float64(windowSeconds))
	if err != nil {
		h.log.Error("rate limit check failed", err, nil)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"rate limit check failed"}`))
		return
	}

	resp := admiral.RateLimitCheckResponse{
		Allowed:   allowed,
		Remaining: remaining,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.log.Error("failed to encode rate limit response", err, nil)
	}
}

func (h *APIHandlers) HandleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":   "healthy",
		"database": "connected",
	}
	if err := h.db.DB.Ping(); err != nil {
		status["status"] = "degraded"
		status["database"] = err.Error()
	}
	writeJSON(w, http.StatusOK, status)
}
