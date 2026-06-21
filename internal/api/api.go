// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/networking"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
	"github.com/admiral-project/admiral/admirald/pkg/admiral/tlsconfig"
)

type Server struct {
	handlers     *APIHandlers
	log          *logging.Logger
	adminToken   string
	tokenPepper  string
	fleetLimiter *RateLimiter
	adminLimiter *RateLimiter
}

func NewServer(db *database.DB, log *logging.Logger, pub TaskPublisher, adminToken, tokenPepper string, tokenTTL int, sessionHMACKey string, secretManager *secrets.Manager, networkingManager *networking.Manager, taskEncryptionKey string) *Server {
	// session_hmac_key is intentionally optional. When empty, a volatile
	// ephemeral key is generated in memory. This means a server restart
	// invalidates all active admin web sessions (flagship/harbor must
	// re-authenticate). Production deployments may set a persistent key
	// via ADMIRAL_SESSION_HMAC_KEY or session_hmac_key in admirald.ini
	// to avoid this, but the ephemeral default is a deliberate choice.
	if sessionHMACKey == "" {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil { //nolint:gosec // ephemeral key for session HMAC, not cryptographic auth
			log.Fatal("failed to generate ephemeral session HMAC key", nil, nil)
		}
		sessionHMACKey = hex.EncodeToString(key[:])
		log.Info("Using volatile ephemeral session HMAC key. Admin sessions will not survive a restart.", nil)
	}
	return &Server{
		handlers:     NewHandlers(db, log, pub, secretManager, networkingManager, sessionHMACKey, tokenPepper, tokenTTL, taskEncryptionKey),
		log:          log,
		adminToken:   adminToken,
		tokenPepper:  tokenPepper,
		fleetLimiter: NewRateLimiter(),
		adminLimiter: NewRateLimiter(),
	}
}

func (s *Server) Listen(ctx context.Context, addr, port, certFile, keyFile string) error {
	mux := http.NewServeMux()

	// Register authenticated endpoints
	const jsonLimit = 1 << 20 // 1 MiB for JSON payloads
	const yamlLimit = 5 << 20 // 5 MiB for YAML app definitions

	// Admin-only routes (use AdminAuthMiddleware)
	mux.HandleFunc("/api/v1/nodes", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleNodes)))
	mux.HandleFunc("/api/v1/nodes/", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleNodeByID)))
	mux.HandleFunc("/api/v1/apps", AdminAuthMiddleware(s.adminToken, MaxBody(yamlLimit, s.handlers.HandleApps)))
	mux.HandleFunc("/api/v1/apps/", AdminAuthMiddleware(s.adminToken, MaxBody(yamlLimit, s.handlers.HandleApps)))
	mux.HandleFunc("/api/v1/customer-apps", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleCustomerApps)))
	mux.HandleFunc("/api/v1/customer-apps/", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleCustomerAppByID)))
	mux.HandleFunc("/api/v1/customer-apps/action", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleCustomerAppAction)))
	mux.HandleFunc("/api/v1/operations", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleOperations)))
	mux.HandleFunc("/api/v1/routes", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleRoutes)))
	mux.HandleFunc("/api/v1/routes/", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleRoutes)))
	mux.HandleFunc("/api/v1/instances", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleAdminInstances)))
	mux.HandleFunc("/api/v1/instances/", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleAdminInstances)))
	mux.HandleFunc("/api/v1/backups", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleAdminBackups)))
	mux.HandleFunc("/api/v1/backups/", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleAdminBackups)))
	mux.HandleFunc("/api/v1/backups/restore", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleAdminRestoreBackup)))
	mux.HandleFunc("/api/v1/networking/certificate", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleCertificate)))
	mux.HandleFunc("/api/v1/operations/", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleOperationByID)))
	mux.HandleFunc("/api/v1/status", AdminAuthMiddleware(s.adminToken, s.handlers.HandleStatus))
	mux.HandleFunc("/api/v1/rate-limit/check", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleRateLimitCheck)))
	mux.HandleFunc("/api/v1/rate-limit/reset", AdminAuthMiddleware(s.adminToken, MaxBody(jsonLimit, s.handlers.HandleRateLimitReset)))

	// Node-authenticated routes (heartbeat and claim use node auth middleware)
	mux.HandleFunc("/api/v1/nodes/heartbeat", NodeAuthMiddleware(s.handlers.db, s.tokenPepper, "worker", MaxBody(jsonLimit, s.handlers.HandleNodeHeartbeat)))
	mux.HandleFunc("/api/v1/nodes/task-encryption-key", NodeAuthMiddleware(s.handlers.db, s.tokenPepper, "worker", MaxBody(jsonLimit, s.handlers.HandleTaskEncryptionKey)))

	// Fleet worker routes (worker token required)
	mux.HandleFunc("/api/v1/fleet/callback", NodeAuthMiddleware(s.handlers.db, s.tokenPepper, "worker", RateLimit(s.fleetLimiter, "fleet-callback", 60, time.Minute, MaxBody(jsonLimit, s.handlers.HandleFleetCallback))))
	mux.HandleFunc("/api/v1/fleet/health", NodeAuthMiddleware(s.handlers.db, s.tokenPepper, "worker", RateLimit(s.fleetLimiter, "fleet-health", 60, time.Minute, MaxBody(jsonLimit, s.handlers.HandleAdminHealthCallback))))
	mux.HandleFunc("/api/v1/fleet/storage", NodeAuthMiddleware(s.handlers.db, s.tokenPepper, "worker", RateLimit(s.fleetLimiter, "fleet-storage", 30, time.Minute, MaxBody(jsonLimit, s.handlers.HandleStorageReport))))

	// Administrative endpoints (admin session)
	mux.HandleFunc("/api/admin/auth/login", MaxBody(jsonLimit, s.handlers.HandleAdminLogin))
	// logout is intentionally unauthenticated. Adding AdminAuthMiddleware would require
	// a valid session token to log out, but the handler already derives the token hash
	// from the request header and silently ignores invalid/missing tokens. An attacker
	// who can guess a valid 128-bit session token could invalidate it via this endpoint,
	// but the same token would give them full access anyway. The marginal denial-of-session
	// risk is accepted. See admirald#7 (wontfix).
	mux.HandleFunc("/api/admin/auth/logout", MaxBody(jsonLimit, s.handlers.HandleAdminLogout))
	mux.HandleFunc("/api/admin/auth/me", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminMe)))
	mux.HandleFunc("/api/admin/auth/change-password", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminChangePassword)))
	mux.HandleFunc("/api/admin/apps", s.AdminAuthMiddleware(MaxBody(yamlLimit, s.handlers.HandleAdminApps)))
	mux.HandleFunc("/api/admin/apps/", s.AdminAuthMiddleware(MaxBody(yamlLimit, s.handlers.HandleAdminApps)))
	mux.HandleFunc("/api/admin/instances", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminInstances)))
	mux.HandleFunc("/api/admin/instances/", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminInstances)))
	mux.HandleFunc("/api/admin/backups", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminBackups)))
	mux.HandleFunc("/api/admin/backups/", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminBackups)))
	mux.HandleFunc("/api/admin/backups/restore", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminRestoreBackup)))
	mux.HandleFunc("/api/admin/settings/backup-storage", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminSettingsStorage)))
	mux.HandleFunc("/api/admin/settings/backup-storage/", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminSettingsStorage)))
	mux.HandleFunc("/api/admin/nodes", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminNodes)))
	mux.HandleFunc("/api/admin/nodes/", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminNodes)))
	mux.HandleFunc("/api/admin/tasks", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminTasks)))
	mux.HandleFunc("/api/admin/tasks/", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminTasks)))
	mux.HandleFunc("/api/admin/users", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminUsers)))
	mux.HandleFunc("/api/admin/users/", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminUsers)))

	// Unauthenticated health and status endpoints
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	}
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/health", healthHandler)

	s.log.Info("Starting admirald API server", map[string]interface{}{"port": port, "scheme": "https"})
	server := &http.Server{
		Addr:           addr + ":" + port,
		Handler:        mux,
		TLSConfig:      tlsconfig.NewServerConfig(),
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Start background processors
	if err := s.handlers.syncKnownHostInventory(); err != nil {
		s.log.Error("Failed to sync know_host inventory at startup", err, nil)
	}
	go s.StartBackupScheduler(ctx)
	go s.StartSessionCleaner(ctx)
	go s.StartNodeHealthMonitor(ctx)
	go s.StartTokenGarbageCollector(ctx)
	if s.handlers.networking != nil {
		if err := s.handlers.networking.SeedStaticRoutes(ctx); err != nil {
			s.log.Error("Failed to seed public routes", err, nil)
		}
		s.handlers.networking.WarnExpiringCert()
		go s.StartRouteReconciler(ctx)
	}

	// Graceful shutdown on context cancellation
	go func() { //nolint:gosec // intentional: shutdown goroutine uses background context for timeout
		<-ctx.Done()
		s.log.Info("Shutting down HTTP server...", nil)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			s.log.Error("HTTP server shutdown error", err, nil)
		}
	}()

	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) StartSessionCleaner(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	s.log.Info("Admin session cleaner started", nil)
	for {
		select {
		case <-ctx.Done():
			s.log.Info("Admin session cleaner stopped", nil)
			return
		case <-ticker.C:
			s.cleanExpiredSessions()
		}
	}
}

func (s *Server) StartTokenGarbageCollector(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	s.log.Info("Token garbage collector started", nil)
	for {
		select {
		case <-ctx.Done():
			s.log.Info("Token garbage collector stopped", nil)
			return
		case <-ticker.C:
			count, err := s.handlers.db.ReapExpiredNodeTokens()
			if err != nil {
				s.log.Error("Token garbage collector failed", err, nil)
				continue
			}
			if count > 0 {
				s.log.Info("Reaped expired node tokens", map[string]interface{}{"count": count})
			}
		}
	}
}

func (s *Server) cleanExpiredSessions() {
	err := s.handlers.db.DeleteExpiredAdminSessions()
	if err != nil {
		s.log.Error("Failed to clean expired admin sessions", err, nil)
	}
}

func (s *Server) StartRouteReconciler(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.handlers.networking == nil {
				continue
			}
			if err := s.handlers.networking.Sync(ctx); err != nil {
				s.log.Error("Route reconciliation failed", err, nil)
			}
		}
	}
}

func (s *Server) StartNodeHealthMonitor(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	s.log.Info("Node health monitor started", nil)

	portalClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for {
		select {
		case <-ctx.Done():
			s.log.Info("Node health monitor stopped", nil)
			return
		case <-ticker.C:
			ids, err := s.handlers.db.MarkNodesOffline(2 * time.Minute)
			if err != nil {
				s.log.Error("Node health monitor failed", err, nil)
				continue
			}
			if len(ids) > 0 {
				s.log.Warn("Nodes marked offline by health monitor", map[string]interface{}{"count": len(ids), "node_ids": ids})
			}

			s.checkPortalNodeHealth(ctx, portalClient)
		}
	}
}

func (s *Server) checkPortalNodeHealth(ctx context.Context, client *http.Client) {
	portals, err := s.handlers.db.GetPortalNodes()
	if err != nil {
		s.log.Error("Failed to query portal nodes", err, nil)
		return
	}
	if len(portals) == 0 {
		return
	}
	for _, portal := range portals {
		if portal.Status == "disabled" {
			continue
		}
		addr := portal.WireguardIP
		if addr == "" {
			addr = portal.PublicIP
		}
		if addr == "" {
			addr = portal.IP
		}
		if addr == "" {
			continue
		}
		healthURL := fmt.Sprintf("https://%s:5001/health", addr)
		resp, err := client.Get(healthURL)
		if err != nil {
			s.log.Warn("Portal node health check failed", map[string]interface{}{"node_id": portal.ID, "error": err.Error()})
			if err := s.handlers.db.UpdateNodeHealth(portal.ID, "unhealthy", "service_unreachable", false, "service_unreachable"); err != nil {
				s.log.Error("Failed to update portal node health", err, map[string]interface{}{"node_id": portal.ID})
			}
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			if err := s.handlers.db.UpdatePortalHeartbeat(portal.ID, addr); err != nil {
				s.log.Error("Failed to update portal heartbeat", err, map[string]interface{}{"node_id": portal.ID})
			}
			if err := s.handlers.recomputeNodePolicy(portal.ID); err != nil {
				s.log.Error("Failed to recompute portal node policy", err, map[string]interface{}{"node_id": portal.ID})
			}
		} else {
			s.log.Warn("Portal node health check returned non-OK", map[string]interface{}{"node_id": portal.ID, "status_code": resp.StatusCode})
			if err := s.handlers.db.UpdateNodeHealth(portal.ID, "unhealthy", "service_unexpected_status", false, "service_unexpected_status"); err != nil {
				s.log.Error("Failed to update portal node health", err, map[string]interface{}{"node_id": portal.ID})
			}
		}
	}
}
