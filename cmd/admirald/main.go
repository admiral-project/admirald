// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/admiral-project/admiral/admirald/internal/api"
	"github.com/admiral-project/admiral/admirald/internal/bootstrap"
	"github.com/admiral-project/admiral/admirald/internal/config"
	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/logging"
	"github.com/admiral-project/admiral/admirald/internal/networking"
	"github.com/admiral-project/admiral/admirald/internal/queue"
	"github.com/admiral-project/admiral/admirald/internal/queuedb"
	"github.com/admiral-project/admiral/admirald/internal/secrets"
)

var Version = "dev"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	// Initialize config
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	// Initialize logger
	logger := logging.New("admirald")
	logger.Info("Initializing Admiral Control Plane (admirald)", map[string]interface{}{"version": Version})
	secretManager := secrets.NewManager(cfg.SecretsKey)

	// Connect to Database
	logger.Info("Connecting to database...", map[string]interface{}{"url": config.RedactURL(cfg.DatabaseURL)})
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		logger.Fatal("Database connection failed", err, nil)
	}
	defer db.Close()

	networkingManager, err := networking.NewManager(db, cfg, logger, secretManager)
	if err != nil {
		logger.Fatal("Networking manager initialization failed", err, nil)
	}

	// Run Migrations
	logger.Info("Running database schema migrations...", nil)
	if err := database.RunMigrations(db.DB); err != nil {
		logger.Fatal("Database migrations failed", err, nil)
	}
	logger.Info("Database migrations completed successfully", nil)

	logger.Info("Connecting to queue database...", map[string]interface{}{"url": config.RedactURL(cfg.QueueDatabaseURL)})
	queueDB, err := queuedb.Connect(cfg.QueueDatabaseURL)
	if err != nil {
		logger.Fatal("Queue database connection failed", err, nil)
	}
	defer queueDB.Close()
	logger.Info("Running queue database migrations...", nil)
	if err := queuedb.RunMigrations(queueDB.DB); err != nil {
		logger.Fatal("Queue database migrations failed", err, nil)
	}
	logger.Info("Queue database migrations completed successfully", nil)

	// Ensure initial admin user exists
	created, err := bootstrap.EnsureInitialAdmin(db, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize administrative user", err, nil)
	}
	if created {
		logger.Info("Initial administrative user created from environment configuration", map[string]interface{}{"username": cfg.FlagshipAdminUser})
	}

	seed, err := hex.DecodeString(cfg.SigningKey)
	if err != nil {
		logger.Fatal("invalid signing key (ADMIRAL_ED25519_PRIVATE_KEY must be 64 hex chars)", err, nil)
	}
	var encKey []byte
	if cfg.TaskEncryptionKey != "" {
		encKey, err = hex.DecodeString(cfg.TaskEncryptionKey)
		if err != nil || len(encKey) != 32 {
			logger.Fatal("invalid task encryption key (ADMIRAL_TASK_ENCRYPTION_KEY must be 64 hex chars = 32 bytes)", err, nil)
		}
	}
	publisher := queue.NewPublisher(queueDB, logger, seed, encKey)
	defer publisher.Close()

	// Initialize API Server
	server := api.NewServer(db, logger, publisher, cfg.AdminToken, cfg.HarborAPIToken, cfg.TokenPepper, cfg.TokenTTLMinutes, cfg.SessionHMACKey, secretManager, networkingManager, cfg.TaskEncryptionKey, cfg.TrustedProxies, cfg.DevMode)

	// Start server
	if err := server.Listen(ctx, cfg.ListenAddress, cfg.Port, cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		logger.Fatal("API Server crashed", err, nil)
	}
	logger.Info("Server stopped gracefully", nil)
}
