package api

import (
	"net/http"

	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
)

type Server struct {
	handlers *APIHandlers
	log      *logging.Logger
	token    string
}

func NewServer(db *database.DB, log *logging.Logger, pub TaskPublisher, token string, secretManager *secrets.Manager) *Server {
	return &Server{
		handlers: NewHandlers(db, log, pub, secretManager),
		log:      log,
		token:    token,
	}
}

func (s *Server) Listen(port string) error {
	mux := http.NewServeMux()

	// Register authenticated endpoints
	mux.HandleFunc("/api/v1/nodes", AuthMiddleware(s.token, s.handlers.HandleNodes))
	mux.HandleFunc("/api/v1/nodes/heartbeat", AuthMiddleware(s.token, s.handlers.HandleNodeHeartbeat))
	mux.HandleFunc("/api/v1/apps", AuthMiddleware(s.token, s.handlers.HandleApps))
	mux.HandleFunc("/api/v1/customer-apps", AuthMiddleware(s.token, s.handlers.HandleCustomerApps))
	mux.HandleFunc("/api/v1/customer-apps/action", AuthMiddleware(s.token, s.handlers.HandleCustomerAppAction))
	mux.HandleFunc("/api/v1/operations", AuthMiddleware(s.token, s.handlers.HandleOperations))
	mux.HandleFunc("/api/v1/fleet/callback", AuthMiddleware(s.token, s.handlers.HandleFleetCallback))

	// Public health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	s.log.Info("Starting admirald API server", map[string]interface{}{"port": port})
	return http.ListenAndServe(":"+port, mux)
}
