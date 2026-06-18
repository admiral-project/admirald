// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"fmt"
	"strings"

	"github.com/admiral-project/admiral/admirald/internal/config"
	"github.com/admiral-project/admiral/admirald/internal/database"
	"github.com/admiral-project/admiral/admirald/internal/security"
)

func EnsureInitialAdmin(db *database.DB, cfg *config.Config) (bool, error) {
	exists, err := db.HasAnyAdminUser()
	if err != nil {
		return false, fmt.Errorf("check existing admin users: %w", err)
	}
	if exists {
		return false, nil
	}

	username := strings.TrimSpace(cfg.FlagshipAdminUser)
	password := strings.TrimSpace(cfg.FlagshipAdminPassword)
	if username == "" {
		return false, fmt.Errorf("no administrative user exists; set ADMIRAL_FLAGSHIP_ADMIN_USER and ADMIRAL_FLAGSHIP_ADMIN_PSWD to bootstrap the first admin")
	}
	if password == "" {
		return false, fmt.Errorf("no administrative user exists; set ADMIRAL_FLAGSHIP_ADMIN_USER and ADMIRAL_FLAGSHIP_ADMIN_PSWD to bootstrap the first admin")
	}
	if err := security.ValidateInitialAdminPassword(username, password); err != nil {
		return false, err
	}

	hash, err := security.HashPassword(password)
	if err != nil {
		return false, fmt.Errorf("hash initial admin password: %w", err)
	}
	if err := db.CreateAdminUser(username, hash, true); err != nil {
		return false, fmt.Errorf("create initial admin user: %w", err)
	}
	return true, nil
}
