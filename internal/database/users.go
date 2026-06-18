// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"fmt"
	"time"
)

type AdminUserRecord struct {
	Username           string    `json:"username"`
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
}

func (d *DB) CreateAdminUser(username, passwordHash string, mustChangePassword bool) error {
	query := `
		INSERT INTO admin_users (username, password_hash, must_change_password)
		VALUES ($1, $2, $3)
		ON CONFLICT (username) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			must_change_password = EXCLUDED.must_change_password
	`
	_, err := d.Exec(query, username, passwordHash, mustChangePassword)
	if err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}
	return nil
}

func (d *DB) GetAdminUser(username string) (string, bool, error) {
	var passwordHash string
	var mustChange bool
	query := "SELECT password_hash, must_change_password FROM admin_users WHERE username = $1"
	err := d.QueryRow(query, username).Scan(&passwordHash, &mustChange)
	if err == sql.ErrNoRows {
		return "", false, nil
	} else if err != nil {
		return "", false, fmt.Errorf("get admin user: %w", err)
	}
	return passwordHash, mustChange, nil
}

func (d *DB) GetAdminUserCreatedAt(username string) (time.Time, error) {
	var createdAt time.Time
	query := "SELECT created_at FROM admin_users WHERE username = $1"
	err := d.QueryRow(query, username).Scan(&createdAt)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	} else if err != nil {
		return time.Time{}, fmt.Errorf("get admin user created at: %w", err)
	}
	return createdAt, nil
}

func (d *DB) UpdateAdminPassword(username, passwordHash string) error {
	query := "UPDATE admin_users SET password_hash = $1, must_change_password = FALSE WHERE username = $2"
	_, err := d.Exec(query, passwordHash, username)
	if err != nil {
		return fmt.Errorf("update admin password: %w", err)
	}
	return nil
}

func (d *DB) ListAdminUsers() ([]AdminUserRecord, error) {
	rows, err := d.Query(`
		SELECT username, must_change_password, created_at
		FROM admin_users
		ORDER BY username ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list admin users: %w", err)
	}
	defer rows.Close()

	var users []AdminUserRecord
	for rows.Next() {
		var user AdminUserRecord
		if err := rows.Scan(&user.Username, &user.MustChangePassword, &user.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan admin user: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin users: %w", err)
	}
	return users, nil
}

func (d *DB) HasAnyAdminUser() (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM admin_users)"
	if err := d.QueryRow(query).Scan(&exists); err != nil {
		return false, fmt.Errorf("check admin users: %w", err)
	}
	return exists, nil
}

// --- Admin Sessions CRUD ---
