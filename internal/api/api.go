// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
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
	token        string
	fleetLimiter *RateLimiter
	adminLimiter *RateLimiter
}

func NewServer(db *database.DB, log *logging.Logger, pub TaskPublisher, token string, secretManager *secrets.Manager, networkingManager *networking.Manager) *Server {
	return &Server{
		handlers:     NewHandlers(db, log, pub, secretManager, networkingManager, token),
		log:          log,
		token:        token,
		fleetLimiter: NewRateLimiter(),
		adminLimiter: NewRateLimiter(),
	}
}

func (s *Server) Listen(ctx context.Context, addr, port, certFile, keyFile string) error {
	mux := http.NewServeMux()

	// Register authenticated endpoints
	const jsonLimit = 1 << 20 // 1 MiB for JSON payloads
	const yamlLimit = 5 << 20 // 5 MiB for YAML app definitions

	mux.HandleFunc("/api/v1/nodes", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleNodes)))
	mux.HandleFunc("/api/v1/nodes/", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleNodeByID)))
	mux.HandleFunc("/api/v1/nodes/heartbeat", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleNodeHeartbeat)))
	mux.HandleFunc("/api/v1/apps", AuthMiddleware(s.token, MaxBody(yamlLimit, s.handlers.HandleApps)))
	mux.HandleFunc("/api/v1/apps/", AuthMiddleware(s.token, MaxBody(yamlLimit, s.handlers.HandleApps)))
	mux.HandleFunc("/api/v1/customer-apps", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleCustomerApps)))
	mux.HandleFunc("/api/v1/customer-apps/", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleCustomerAppByID)))
	mux.HandleFunc("/api/v1/customer-apps/action", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleCustomerAppAction)))
	mux.HandleFunc("/api/v1/operations", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleOperations)))
	mux.HandleFunc("/api/v1/fleet/callback", AuthMiddleware(s.token, RateLimit(s.fleetLimiter, "fleet-callback", 60, time.Minute, MaxBody(jsonLimit, s.handlers.HandleFleetCallback))))
	mux.HandleFunc("/api/v1/fleet/health", AuthMiddleware(s.token, RateLimit(s.fleetLimiter, "fleet-health", 60, time.Minute, MaxBody(jsonLimit, s.handlers.HandleAdminHealthCallback))))
	mux.HandleFunc("/api/v1/fleet/storage", AuthMiddleware(s.token, RateLimit(s.fleetLimiter, "fleet-storage", 30, time.Minute, MaxBody(jsonLimit, s.handlers.HandleStorageReport))))
	mux.HandleFunc("/api/v1/routes", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleRoutes)))
	mux.HandleFunc("/api/v1/routes/", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleRoutes)))
	mux.HandleFunc("/api/v1/instances", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleAdminInstances)))
	mux.HandleFunc("/api/v1/instances/", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleAdminInstances)))
	mux.HandleFunc("/api/v1/backups", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleAdminBackups)))
	mux.HandleFunc("/api/v1/backups/", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleAdminBackups)))
	mux.HandleFunc("/api/v1/backups/restore", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleAdminRestoreBackup)))
	mux.HandleFunc("/api/v1/networking/certificate", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleCertificate)))

	// Administrative endpoints
	mux.HandleFunc("/api/admin/auth/login", MaxBody(jsonLimit, s.handlers.HandleAdminLogin))
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
	mux.HandleFunc("/api/v1/operations/", AuthMiddleware(s.token, MaxBody(jsonLimit, s.handlers.HandleOperationByID)))

	// Unauthenticated health and status endpoints
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	}
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/health", healthHandler)
	mux.HandleFunc("/api/v1/status", AuthMiddleware(s.token, s.handlers.HandleStatus))

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
	if s.handlers.networking != nil {
		if err := s.handlers.networking.SeedStaticRoutes(ctx); err != nil {
			s.log.Error("Failed to seed public routes", err, nil)
		}
		s.handlers.networking.WarnExpiringCert()
		go s.StartRouteReconciler(ctx)
	}

	// Graceful shutdown on context cancellation
	go func() {
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
		}
	}
}
