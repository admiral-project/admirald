// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/networking"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
	"github.com/admiral-project/admiral/admirald/pkg/admiral/tlsconfig"
)

type Server struct {
	handlers       *APIHandlers
	log            *logging.Logger
	adminToken     string
	harborToken    string
	tokenPepper    string
	fleetLimiter   Limiter
	adminLimiter   Limiter
	trustedProxies []string
	devMode        bool
}

const (
	authFailureLimit  = 10
	authFailureWindow = 5 * time.Minute
)

func NewServer(db *database.DB, log *logging.Logger, pub TaskPublisher, adminToken, harborToken, tokenPepper string, tokenTTL int, sessionHMACKey string, secretManager *secrets.Manager, networkingManager *networking.Manager, trustedProxies []string, devMode bool) *Server {
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
	handlers := NewHandlers(db, log, pub, secretManager, networkingManager, sessionHMACKey, tokenPepper, tokenTTL)
	server := &Server{
		handlers:       handlers,
		log:            log,
		adminToken:     adminToken,
		harborToken:    harborToken,
		tokenPepper:    tokenPepper,
		fleetLimiter:   NewDBRateLimiter(db),
		adminLimiter:   NewDBRateLimiter(db),
		trustedProxies: trustedProxies,
		devMode:        devMode,
	}
	handlers.server = server
	return server
}

func (s *Server) Listen(ctx context.Context, addr, port, certFile, keyFile string) error {
	mux := http.NewServeMux()

	// Register authenticated endpoints
	const jsonLimit = 1 << 20 // 1 MiB for JSON payloads
	const yamlLimit = 5 << 20 // 5 MiB for YAML app definitions

	// Admin-only routes (use AdminAuthMiddleware)
	mux.HandleFunc("/api/v1/nodes", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleNodes)))
	mux.HandleFunc("/api/v1/nodes/", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleNodeByID)))

	// Harbor-readable routes (use HarborAuthMiddleware — accepts admin token and harbor token)
	mux.HandleFunc("/api/v1/apps", HarborAuthMiddleware(s.log, s.adminToken, s.harborToken, s.trustedProxies, MaxBody(yamlLimit, s.handlers.HandleApps)))
	mux.HandleFunc("/api/v1/apps/", HarborAuthMiddleware(s.log, s.adminToken, s.harborToken, s.trustedProxies, MaxBody(yamlLimit, s.handlers.HandleApps)))
	mux.HandleFunc("/api/v1/customer-apps", HarborAuthMiddleware(s.log, s.adminToken, s.harborToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleCustomerApps)))
	mux.HandleFunc("/api/v1/customer-apps/", HarborAuthMiddleware(s.log, s.adminToken, s.harborToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleCustomerAppByID)))
	mux.HandleFunc("/api/v1/customer-apps/action", HarborAuthMiddleware(s.log, s.adminToken, s.harborToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleCustomerAppAction)))
	mux.HandleFunc("/api/v1/harbor_ping", HarborAuthMiddleware(s.log, s.adminToken, s.harborToken, s.trustedProxies, s.handlers.HandleHarborPing))
	mux.HandleFunc("/api/v1/operations", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleOperations)))
	mux.HandleFunc("/api/v1/routes", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleRoutes)))
	mux.HandleFunc("/api/v1/routes/", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleRoutes)))
	mux.HandleFunc("/api/v1/instances", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleAdminInstances)))
	mux.HandleFunc("/api/v1/instances/", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleAdminInstances)))
	mux.HandleFunc("/api/v1/backups", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleAdminBackups)))
	mux.HandleFunc("/api/v1/backups/", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleAdminBackups)))
	mux.HandleFunc("/api/v1/backups/restore", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleAdminRestoreBackup)))
	mux.HandleFunc("/api/v1/networking/certificate", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleCertificate)))
	mux.HandleFunc("/api/v1/operations/", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleOperationByID)))
	mux.HandleFunc("/api/v1/status", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, s.handlers.HandleStatus))
	mux.HandleFunc("/api/v1/rate-limit/check", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleRateLimitCheck)))
	mux.HandleFunc("/api/v1/rate-limit/reset", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleRateLimitReset)))
	mux.HandleFunc("/api/v1/secrets/rotate", AdminAuthMiddleware(s.log, s.adminToken, s.trustedProxies, s.handlers.HandleSecretRotation))

	// Node-authenticated routes (heartbeat and claim use node auth middleware)
	mux.HandleFunc("/api/v1/nodes/heartbeat", NodeAuthMiddleware(s.log, s.handlers.db, s.tokenPepper, "worker", s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleNodeHeartbeat)))

	// Fleet worker routes (worker token required)
	mux.HandleFunc("/api/v1/fleet/callback", NodeAuthMiddleware(s.log, s.handlers.db, s.tokenPepper, "worker", s.trustedProxies, RateLimit(s.fleetLimiter, "fleet-callback", 60, time.Minute, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleFleetCallback))))
	mux.HandleFunc("/api/v1/fleet/health", NodeAuthMiddleware(s.log, s.handlers.db, s.tokenPepper, "worker", s.trustedProxies, RateLimit(s.fleetLimiter, "fleet-health", 60, time.Minute, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleAdminHealthCallback))))
	mux.HandleFunc("/api/v1/fleet/storage", NodeAuthMiddleware(s.log, s.handlers.db, s.tokenPepper, "worker", s.trustedProxies, RateLimit(s.fleetLimiter, "fleet-storage", 30, time.Minute, s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleStorageReport))))
	mux.HandleFunc("/api/v1/fleet/tasks/claim", NodeAuthMiddleware(s.log, s.handlers.db, s.tokenPepper, "worker", s.trustedProxies, MaxBody(jsonLimit, s.handlers.HandleTaskClaim)))
	mux.HandleFunc("/api/v1/fleet/tasks/", NodeAuthMiddleware(s.log, s.handlers.db, s.tokenPepper, "worker", s.trustedProxies, MaxBody(jsonLimit, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/running") {
			s.handlers.HandleTaskRunning(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/renew-lease") {
			s.handlers.HandleTaskRenewLease(w, r)
		} else if strings.HasSuffix(r.URL.Path, "/discard") {
			s.handlers.HandleTaskDiscard(w, r)
		} else {
			writeError(w, http.StatusNotFound, "unknown task endpoint")
		}
	})))

	// Administrative endpoints (admin session)
	mux.HandleFunc("/api/admin/auth/login", MaxBody(jsonLimit, s.handlers.HandleAdminLogin))
	mux.HandleFunc("/api/admin/auth/logout", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminLogout)))
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
	mux.HandleFunc("/api/admin/settings/backup-storage/test", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminSettingsStorage)))
	mux.HandleFunc("/api/admin/nodes", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminNodes)))
	mux.HandleFunc("/api/admin/nodes/", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminNodes)))
	mux.HandleFunc("/api/admin/tasks", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminTasks)))
	mux.HandleFunc("/api/admin/tasks/", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminTasks)))
	mux.HandleFunc("/api/admin/users", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminUsers)))
	mux.HandleFunc("/api/admin/users/", s.AdminAuthMiddleware(MaxBody(jsonLimit, s.handlers.HandleAdminUsers)))

	// Admin-authenticated health and status endpoints
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	}
	mux.HandleFunc("/health", s.AdminAuthMiddleware(healthHandler))
	mux.HandleFunc("/api/v1/health", s.AdminAuthMiddleware(healthHandler))

	s.log.Info("Starting admirald API server", map[string]interface{}{"port": port, "scheme": "https"})
	server := &http.Server{
		Addr:           addr + ":" + port,
		Handler:        SecurityHeadersMiddleware(mux),
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
	go s.StartBackupVerifier(ctx)
	go s.StartSessionCleaner(ctx)
	go s.StartNodeHealthMonitor(ctx)
	go s.StartTokenGarbageCollector(ctx)
	go s.StartResourceReconciler(ctx)
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

func (s *Server) StartResourceReconciler(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	s.log.Info("Resource reconciler started", nil)
	for {
		select {
		case <-ctx.Done():
			s.log.Info("Resource reconciler stopped", nil)
			return
		case <-ticker.C:
			s.reconcileResources()
		}
	}
}

func (s *Server) reconcileResources() {
	apps, err := s.handlers.db.GetInconsistentInstances()
	if err != nil {
		s.log.Error("Resource reconciler failed to query inconsistent instances", err, nil)
		return
	}

	for _, app := range apps {
		s.log.Warn("Detected inconsistent instance state: instance running on offline node", map[string]interface{}{
			"instance_id": app.ID,
			"node_id":     *app.NodeID,
		})
		// For now, we just mark it as unhealthy. Future improvements could trigger a failover or restart.
		if err := s.handlers.db.UpdateInstanceHealth(app.ID, "unhealthy", "node_offline"); err != nil {
			s.log.Error("Failed to update instance health in reconciler", err, map[string]interface{}{"instance_id": app.ID})
		}
	}
}

func (s *Server) StartNodeHealthMonitor(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	s.log.Info("Node health monitor started", nil)

	portalClient, err := internalHTTPClient(5*time.Second, s.devMode)
	if err != nil {
		s.log.Error("Node health monitor could not configure internal TLS", err, nil)
		return
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
		candidates := []string{portal.WireguardIP}
		if s.devMode || os.Getenv("ADMIRAL_SINGLE_NODE") == "true" {
			candidates = append(candidates, "127.0.0.1")
		}
		var ok bool
		for _, addr := range candidates {
			if addr == "" {
				continue
			}
			scheme := "https"
			if s.devMode {
				scheme = "http"
			}
			healthURL := fmt.Sprintf("%s://%s:5001/health", scheme, addr)
			resp, err := client.Get(healthURL)
			if err != nil {
				s.log.Info("Portal node health check attempt failed", map[string]interface{}{"node_id": portal.ID, "addr": addr, "error": err.Error()})
				continue
			}
			if cerr := resp.Body.Close(); cerr != nil {
				_ = cerr
			}
			if resp.StatusCode == http.StatusOK {
				ok = true
				if err := s.handlers.db.UpdatePortalHeartbeat(portal.ID, addr); err != nil {
					s.log.Error("Failed to update portal heartbeat", err, map[string]interface{}{"node_id": portal.ID})
				}
				if err := s.handlers.recomputeNodePolicy(portal.ID); err != nil {
					s.log.Error("Failed to recompute portal node policy", err, map[string]interface{}{"node_id": portal.ID})
				}
				break
			}
			s.log.Info("Portal node health check returned non-OK", map[string]interface{}{"node_id": portal.ID, "addr": addr, "status_code": resp.StatusCode})
		}
		if !ok {
			s.log.Warn("Portal node health check failed on all addresses", map[string]interface{}{"node_id": portal.ID})
			if err := s.handlers.db.UpdateNodeHealth(portal.ID, "unhealthy", "service_unreachable", false, "service_unreachable"); err != nil {
				s.log.Error("Failed to update portal node health", err, map[string]interface{}{"node_id": portal.ID})
			}
		}
	}
}
