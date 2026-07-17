// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"fmt"
	"time"
)

func (d *DB) DeleteExpiredAdminSessions() error {
	_, err := d.Exec("DELETE FROM admin_sessions WHERE expires_at < CURRENT_TIMESTAMP OR last_activity_at < $1", time.Now().Add(-30*time.Minute))
	if err != nil {
		return fmt.Errorf("delete expired admin sessions: %w", err)
	}
	return nil
}

func (d *DB) CreateAdminSession(tokenHash, username string, expiresAt, lastActivityAt time.Time) error {
	query := `
		INSERT INTO admin_sessions (token_hash, username, expires_at, last_activity_at)
		VALUES ($1, $2, $3, $4)
	`
	_, err := d.Exec(query, tokenHash, username, expiresAt, lastActivityAt)
	if err != nil {
		return fmt.Errorf("create admin session: %w", err)
	}
	return nil
}

func (d *DB) GetAdminSession(tokenHash string) (string, time.Time, time.Time, error) {
	var username string
	var expiresAt, lastActivityAt time.Time
	query := "SELECT username, expires_at, last_activity_at FROM admin_sessions WHERE token_hash = $1"
	err := d.QueryRow(query, tokenHash).Scan(&username, &expiresAt, &lastActivityAt)
	if err == sql.ErrNoRows {
		return "", time.Time{}, time.Time{}, nil
	} else if err != nil {
		return "", time.Time{}, time.Time{}, fmt.Errorf("get admin session: %w", err)
	}
	return username, expiresAt, lastActivityAt, nil
}

func (d *DB) UpdateAdminSessionActivity(tokenHash string, lastActivity time.Time) error {
	_, err := d.Exec("UPDATE admin_sessions SET last_activity_at = $1 WHERE token_hash = $2", lastActivity, tokenHash)
	if err != nil {
		return fmt.Errorf("update admin session activity: %w", err)
	}
	return nil
}

func (d *DB) DeleteAdminSession(tokenHash string) error {
	_, err := d.Exec("DELETE FROM admin_sessions WHERE token_hash = $1", tokenHash)
	if err != nil {
		return fmt.Errorf("delete admin session: %w", err)
	}
	return nil
}

// DeleteOtherAdminSessions invalidates every session for a user except the
// session currently being used to change the password.
func (d *DB) DeleteOtherAdminSessions(username, currentTokenHash string) error {
	_, err := d.Exec(
		"DELETE FROM admin_sessions WHERE username = $1 AND token_hash <> $2",
		username,
		currentTokenHash,
	)
	if err != nil {
		return fmt.Errorf("delete other admin sessions: %w", err)
	}
	return nil
}

// --- Backup Storage Config CRUD ---
