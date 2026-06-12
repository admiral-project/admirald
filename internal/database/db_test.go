// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"os"
	"testing"
)

func OpenTestDB(t *testing.T) *DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	db, err := Connect(dbURL)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}

	if err := RunMigrations(db.DB); err != nil {
		t.Fatalf("run migrations on test db: %v", err)
	}

	return db
}
