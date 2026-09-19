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

type OperatorProfile struct {
	Username        string     `json:"username"`
	Email           string     `json:"email"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	MFAEmailEnabled bool       `json:"mfa_email_enabled"`
}

type OperatorToken struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Label       string     `json:"label"`
	TokenPrefix string     `json:"token_prefix"`
	TokenHash   string     `json:"-"`
	Scope       string     `json:"scope"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (d *DB) GetOperatorProfile(username string) (OperatorProfile, error) {
	var p OperatorProfile
	err := d.QueryRow(`SELECT username, email, email_verified_at, mfa_email_enabled FROM admin_users WHERE username=$1`, username).Scan(&p.Username, &p.Email, &p.EmailVerifiedAt, &p.MFAEmailEnabled)
	if err == sql.ErrNoRows {
		return p, nil
	}
	if err != nil {
		return p, fmt.Errorf("get operator profile: %w", err)
	}
	return p, nil
}

func (d *DB) UpdateOperatorProfile(username, email string, verified bool, mfa bool) error {
	_, err := d.Exec(`UPDATE admin_users SET email=$1, email_verified_at=CASE WHEN $2 THEN CURRENT_TIMESTAMP ELSE NULL END, mfa_email_enabled=$3 WHERE username=$4`, email, verified, mfa, username)
	if err != nil {
		return fmt.Errorf("update operator profile: %w", err)
	}
	return nil
}

func (d *DB) CreateOperatorToken(t OperatorToken) error {
	_, err := d.Exec(`INSERT INTO operator_tokens (id,username,label,token_prefix,token_hash,scope,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, t.ID, t.Username, t.Label, t.TokenPrefix, t.TokenHash, t.Scope, t.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create operator token: %w", err)
	}
	return nil
}
func (d *DB) ListOperatorTokens(username string) ([]OperatorToken, error) {
	rows, err := d.Query(`SELECT id,username,label,token_prefix,scope,expires_at,revoked_at,last_used_at,created_at FROM operator_tokens WHERE username=$1 ORDER BY created_at DESC`, username)
	if err != nil {
		return nil, fmt.Errorf("list operator tokens: %w", err)
	}
	defer rows.Close()
	var out []OperatorToken
	for rows.Next() {
		var t OperatorToken
		if err := rows.Scan(&t.ID, &t.Username, &t.Label, &t.TokenPrefix, &t.Scope, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func (d *DB) GetOperatorToken(hash string) (OperatorToken, error) {
	var t OperatorToken
	err := d.QueryRow(`SELECT id,username,label,token_prefix,token_hash,scope,expires_at,revoked_at,last_used_at,created_at FROM operator_tokens WHERE token_hash=$1`, hash).Scan(&t.ID, &t.Username, &t.Label, &t.TokenPrefix, &t.TokenHash, &t.Scope, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return t, nil
	}
	if err != nil {
		return t, fmt.Errorf("get operator token: %w", err)
	}
	return t, nil
}
func (d *DB) RevokeOperatorToken(id, username string) (bool, error) {
	r, err := d.Exec(`UPDATE operator_tokens SET revoked_at=CURRENT_TIMESTAMP WHERE id=$1 AND username=$2 AND revoked_at IS NULL`, id, username)
	if err != nil {
		return false, fmt.Errorf("revoke operator token: %w", err)
	}
	n, _ := r.RowsAffected()
	return n == 1, nil
}
func (d *DB) TouchOperatorToken(id string) {
	_, _ = d.Exec(`UPDATE operator_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE id=$1`, id)
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
