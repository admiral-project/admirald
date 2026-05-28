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
	handlers *APIHandlers
	log      *logging.Logger
	token    string
}

func NewServer(db *database.DB, log *logging.Logger, pub TaskPublisher, token string, secretManager *secrets.Manager, networkingManager *networking.Manager) *Server {
	return &Server{
		handlers: NewHandlers(db, log, pub, secretManager, networkingManager),
		log:      log,
		token:    token,
	}
}

func (s *Server) Listen(port, certFile, keyFile string) error {
	mux := http.NewServeMux()

	// Register authenticated endpoints
	mux.HandleFunc("/api/v1/nodes", AuthMiddleware(s.token, s.handlers.HandleNodes))
	mux.HandleFunc("/api/v1/nodes/heartbeat", AuthMiddleware(s.token, s.handlers.HandleNodeHeartbeat))
	mux.HandleFunc("/api/v1/apps", AuthMiddleware(s.token, s.handlers.HandleApps))
	mux.HandleFunc("/api/v1/customer-apps", AuthMiddleware(s.token, s.handlers.HandleCustomerApps))
	mux.HandleFunc("/api/v1/customer-apps/action", AuthMiddleware(s.token, s.handlers.HandleCustomerAppAction))
	mux.HandleFunc("/api/v1/operations", AuthMiddleware(s.token, s.handlers.HandleOperations))
	mux.HandleFunc("/api/v1/fleet/callback", AuthMiddleware(s.token, s.handlers.HandleFleetCallback))
	mux.HandleFunc("/api/v1/routes", AuthMiddleware(s.token, s.handlers.HandleRoutes))
	mux.HandleFunc("/api/v1/routes/", AuthMiddleware(s.token, s.handlers.HandleRoutes))

	// Administrative endpoints
	mux.HandleFunc("/api/admin/auth/login", s.handlers.HandleAdminLogin)
	mux.HandleFunc("/api/admin/auth/logout", s.handlers.HandleAdminLogout)
	mux.HandleFunc("/api/admin/auth/me", s.AdminAuthMiddleware(s.handlers.HandleAdminMe))
	mux.HandleFunc("/api/admin/apps", s.AdminAuthMiddleware(s.handlers.HandleAdminApps))
	mux.HandleFunc("/api/admin/apps/", s.AdminAuthMiddleware(s.handlers.HandleAdminApps))
	mux.HandleFunc("/api/admin/instances", s.AdminAuthMiddleware(s.handlers.HandleAdminInstances))
	mux.HandleFunc("/api/admin/instances/", s.AdminAuthMiddleware(s.handlers.HandleAdminInstances))
	mux.HandleFunc("/api/admin/backups", s.AdminAuthMiddleware(s.handlers.HandleAdminBackups))
	mux.HandleFunc("/api/admin/backups/", s.AdminAuthMiddleware(s.handlers.HandleAdminBackups))
	mux.HandleFunc("/api/admin/backups/restore", s.AdminAuthMiddleware(s.handlers.HandleAdminRestoreBackup))
	mux.HandleFunc("/api/admin/settings/backup-storage", s.AdminAuthMiddleware(s.handlers.HandleAdminSettingsStorage))
	mux.HandleFunc("/api/admin/settings/backup-storage/", s.AdminAuthMiddleware(s.handlers.HandleAdminSettingsStorage))
	mux.HandleFunc("/api/admin/nodes", s.AdminAuthMiddleware(s.handlers.HandleAdminNodes))
	mux.HandleFunc("/api/admin/nodes/", s.AdminAuthMiddleware(s.handlers.HandleAdminNodes))
	mux.HandleFunc("/api/admin/tasks", s.AdminAuthMiddleware(s.handlers.HandleAdminTasks))
	mux.HandleFunc("/api/admin/tasks/", s.AdminAuthMiddleware(s.handlers.HandleAdminTasks))

	// Public health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	s.log.Info("Starting admirald API server", map[string]interface{}{"port": port, "scheme": "https"})
	server := &http.Server{
		Addr:      ":" + port,
		Handler:   mux,
		TLSConfig: tlsconfig.NewServerConfig(),
	}

	// Start backup scheduler in background
	go s.StartBackupScheduler(context.Background())
	if s.handlers.networking != nil {
		if err := s.handlers.networking.SeedStaticRoutes(context.Background()); err != nil {
			s.log.Error("Failed to seed public routes", err, nil)
		}
		go s.StartRouteReconciler(context.Background())
	}

	return server.ListenAndServeTLS(certFile, keyFile)
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
