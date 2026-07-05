// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package queuedb

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type DB struct {
	*sql.DB
}

func Connect(dbURL string) (*DB, error) {
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return nil, fmt.Errorf("open queue db: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	var pingErr error
	for i := 0; i < 30; i++ {
		if pingErr = db.Ping(); pingErr == nil {
			return &DB{db}, nil
		}
		if i < 29 {
			time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("ping queue db after retries: %w", pingErr)
}
