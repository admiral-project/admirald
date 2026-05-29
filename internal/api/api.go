package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/networking"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
	"github.com/admiral-project/admiral/admirald/pkg/admiral"
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
	mux.HandleFunc("/api/v1/fleet/health", AuthMiddleware(s.token, s.handlers.HandleAdminHealthCallback))
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

	// Start background processors
	go s.StartOutboxProcessor(context.Background())
	go s.StartBackupScheduler(context.Background())
	if s.handlers.networking != nil {
		if err := s.handlers.networking.SeedStaticRoutes(context.Background()); err != nil {
			s.log.Error("Failed to seed public routes", err, nil)
		}
		go s.StartRouteReconciler(context.Background())
	}

	return server.ListenAndServeTLS(certFile, keyFile)
}

func (s *Server) StartOutboxProcessor(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	s.log.Info("Task outbox processor started", nil)
	for {
		select {
		case <-ctx.Done():
			s.log.Info("Task outbox processor stopped", nil)
			return
		case <-ticker.C:
			s.processOutboxBatch(ctx)
		}
	}
}

func (s *Server) processOutboxBatch(ctx context.Context) {
	entries, err := s.handlers.db.GetPendingOutboxEntries(10)
	if err != nil {
		s.log.Error("Failed to fetch pending outbox entries", err, nil)
		return
	}
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.processOutboxEntry(entry)
	}
}

func (s *Server) processOutboxEntry(entry database.OutboxEntry) {
	var task admiral.FleetTask
	if err := json.Unmarshal([]byte(entry.TaskJSON), &task); err != nil {
		s.log.Error("Failed to unmarshal outbox task, marking as failed", err, map[string]interface{}{"outbox_id": entry.ID})
		if uerr := s.handlers.db.UpdateOutboxEntryRetry(entry.ID, "invalid task JSON", entry.MaxRetries); uerr != nil {
			s.log.Error("Failed to mark outbox entry as failed", uerr, map[string]interface{}{"outbox_id": entry.ID})
		}
		return
	}

	err := s.handlers.publisher.PublishTask(&task)
	if err != nil {
		newRetry := entry.RetryCount + 1
		s.log.Error("Outbox publish failed", err, map[string]interface{}{
			"outbox_id": entry.ID, "task_id": task.TaskID, "retry": newRetry, "max_retries": entry.MaxRetries,
		})
		if uerr := s.handlers.db.UpdateOutboxEntryRetry(entry.ID, err.Error(), newRetry); uerr != nil {
			s.log.Error("Failed to update outbox retry count", uerr, map[string]interface{}{"outbox_id": entry.ID})
		}
		if newRetry >= entry.MaxRetries {
			s.log.Error("Outbox entry exceeded max retries, marking operation as failed", nil, map[string]interface{}{
				"outbox_id": entry.ID, "operation_id": entry.OperationID, "instance_id": entry.InstanceID,
			})
			if uerr := s.handlers.db.UpdateOperation(entry.OperationID, "failed", "outbox retries exhausted"); uerr != nil {
				s.log.Error("Failed to mark operation as failed after outbox exhaustion", uerr, map[string]interface{}{"operation_id": entry.OperationID})
			}
			if uerr := s.handlers.db.UpdateCustomerAppStatus(entry.InstanceID, "", "failed"); uerr != nil {
				s.log.Error("Failed to mark instance as failed after outbox exhaustion", uerr, map[string]interface{}{"instance_id": entry.InstanceID})
			}
		}
		return
	}

	if uerr := s.handlers.db.UpdateOperation(entry.OperationID, "running", ""); uerr != nil {
		s.log.Error("Failed to update operation as running after outbox publish", uerr, map[string]interface{}{"operation_id": entry.OperationID})
	}
	if err := s.handlers.db.DeleteOutboxEntry(entry.ID); err != nil {
		s.log.Error("Failed to delete outbox entry after successful publish", err, map[string]interface{}{"outbox_id": entry.ID})
	}
	s.log.Info("Outbox task published successfully", map[string]interface{}{
		"outbox_id": entry.ID, "task_id": task.TaskID, "operation_id": entry.OperationID,
	})
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
