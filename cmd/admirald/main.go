package main

import (
	"log"

	"github.com/admiral-project/admiral/admirald/internal/api"
	"github.com/admiral-project/admiral/admirald/internal/config"
	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/networking"
	"github.com/admiral-project/admiral/admirald/internal/queue"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
	"github.com/admiral-project/admiral/admirald/pkg/admiral/tlsconfig"
)

func main() {
	// Initialize config
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Fatal: invalid configuration: %v", err)
	}

	// Initialize logger
	logger := logging.New("admirald")
	logger.Info("Initializing Admiral Control Plane (admirald)", nil)
	secretManager := secrets.NewManager(cfg.SecretsKey)

	// Connect to Database
	logger.Info("Connecting to database...", map[string]interface{}{"url": config.RedactURL(cfg.DatabaseURL)})
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		logger.Error("Database connection failed", err, nil)
		log.Fatalf("Fatal: database connection failed: %v", err)
	}
	defer db.Close()

	networkingManager, err := networking.NewManager(db, cfg, logger, secretManager)
	if err != nil {
		logger.Error("Networking manager initialization failed", err, nil)
		log.Fatalf("Fatal: networking manager initialization failed: %v", err)
	}

	// Run Migrations
	logger.Info("Running database schema migrations...", nil)
	if err := database.RunMigrations(db.DB); err != nil {
		logger.Error("Database migrations failed", err, nil)
		log.Fatalf("Fatal: migrations failed: %v", err)
	}
	logger.Info("Database migrations completed successfully", nil)

	// Ensure default admin user is present
	if err := api.EnsureDefaultAdmin(db); err != nil {
		logger.Error("Failed to initialize default admin user", err, nil)
	}

	// Initialize RabbitMQ Task Publisher
	rabbitMQTLSConfig, err := tlsconfig.NewClientConfig(cfg.RabbitMQCAFile)
	if err != nil {
		log.Fatalf("Fatal: invalid RabbitMQ TLS configuration: %v", err)
	}
	publisher := queue.NewPublisher(cfg.RabbitMQURL, rabbitMQTLSConfig, logger)
	defer publisher.Close()

	// Initialize API Server
	server := api.NewServer(db, logger, publisher, cfg.SharedToken, secretManager, networkingManager)

	// Start server
	if err := server.Listen(cfg.Port, cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		logger.Error("API Server crashed", err, nil)
		log.Fatalf("Fatal: server listen failed: %v", err)
	}
}
