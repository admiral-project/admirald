// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"fmt"
	"time"
)

// CheckRateLimit checks and updates the rate limit for an identifier.
// Returns allowed bool and remaining seconds until the window resets.
func (d *DB) CheckRateLimit(identifier string, maxAttempts int, windowSeconds float64) (bool, int, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	now := time.Now().Unix()
	cutoff := float64(now) - windowSeconds

	var windowStart float64
	var attempts int
	err = tx.QueryRow("SELECT window_start, attempts FROM rate_limits WHERE identifier = $1 FOR UPDATE", identifier).Scan(&windowStart, &attempts)
	if err == sql.ErrNoRows {
		_, err = tx.Exec("INSERT INTO rate_limits (identifier, window_start, attempts) VALUES ($1, $2, 1)", identifier, float64(now))
		if err != nil {
			return false, 0, fmt.Errorf("insert rate limit: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return false, 0, fmt.Errorf("commit: %w", err)
		}
		return true, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("select rate limit: %w", err)
	}

	if windowStart < cutoff {
		_, err = tx.Exec("UPDATE rate_limits SET window_start = $1, attempts = 1 WHERE identifier = $2", float64(now), identifier)
		if err != nil {
			return false, 0, fmt.Errorf("update rate limit reset: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return false, 0, fmt.Errorf("commit: %w", err)
		}
		return true, 0, nil
	}

	if attempts >= maxAttempts {
		remaining := int(windowSeconds - (float64(now) - windowStart) + 1)
		if remaining < 1 {
			remaining = 1
		}
		if err := tx.Commit(); err != nil {
			return false, 0, fmt.Errorf("commit: %w", err)
		}
		return false, remaining, nil
	}

	_, err = tx.Exec("UPDATE rate_limits SET attempts = attempts + 1 WHERE identifier = $1", identifier)
	if err != nil {
		return false, 0, fmt.Errorf("update rate limit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, 0, fmt.Errorf("commit: %w", err)
	}
	return true, 0, nil
}

// ResetRateLimit removes the rate limit entry for an identifier.
func (d *DB) ResetRateLimit(identifier string) error {
	_, err := d.Exec("DELETE FROM rate_limits WHERE identifier = $1", identifier)
	return err
}
