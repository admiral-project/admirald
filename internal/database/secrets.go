// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"fmt"
	"time"
)

type InstanceSecret struct {
	InstanceID       string    `json:"instance_id"`
	ServiceName      string    `json:"service_name"`
	EnvName          string    `json:"env_name"`
	EncryptedValue   string    `json:"-"`
	ExposeToCustomer bool      `json:"expose_to_customer"`
	CreatedAt        time.Time `json:"created_at"`
}

type InstanceSecretUpdate struct {
	InstanceID     string
	ServiceName    string
	EnvName        string
	EncryptedValue string
}

func (d *DB) SaveInstanceSecret(instanceID, serviceName, envName, encryptedValue string, expose bool) error {
	query := `
		INSERT INTO instance_secrets (instance_id, service_name, env_name, encrypted_value, expose_to_customer)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (instance_id, service_name, env_name) DO UPDATE SET
			encrypted_value = EXCLUDED.encrypted_value,
			expose_to_customer = EXCLUDED.expose_to_customer
	`
	_, err := d.Exec(query, instanceID, serviceName, envName, encryptedValue, expose)
	if err != nil {
		return fmt.Errorf("save instance secret: %w", err)
	}
	return nil
}

func (d *DB) GetInstanceSecrets(instanceID string) ([]InstanceSecret, error) {
	rows, err := d.Query("SELECT instance_id, service_name, env_name, encrypted_value, expose_to_customer, created_at FROM instance_secrets WHERE instance_id = $1 ORDER BY service_name, env_name", instanceID)
	if err != nil {
		return nil, fmt.Errorf("query instance secrets: %w", err)
	}
	defer rows.Close()

	var secrets []InstanceSecret
	for rows.Next() {
		var s InstanceSecret
		if err := rows.Scan(&s.InstanceID, &s.ServiceName, &s.EnvName, &s.EncryptedValue, &s.ExposeToCustomer, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan instance secret row: %w", err)
		}
		secrets = append(secrets, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate instance secrets: %w", err)
	}
	return secrets, nil
}

func (d *DB) GetAllInstanceSecrets() ([]InstanceSecret, error) {
	rows, err := d.Query("SELECT instance_id, service_name, env_name, encrypted_value, expose_to_customer, created_at FROM instance_secrets ORDER BY instance_id, service_name, env_name")
	if err != nil {
		return nil, fmt.Errorf("query all instance secrets: %w", err)
	}
	defer rows.Close()
	var secrets []InstanceSecret
	for rows.Next() {
		var s InstanceSecret
		if err := rows.Scan(&s.InstanceID, &s.ServiceName, &s.EnvName, &s.EncryptedValue, &s.ExposeToCustomer, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan instance secret row: %w", err)
		}
		secrets = append(secrets, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate instance secrets: %w", err)
	}
	return secrets, nil
}

func (d *DB) UpdateInstanceSecretCiphertexts(updates []InstanceSecretUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	tx, err := d.Begin()
	if err != nil {
		return fmt.Errorf("begin secret rotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(`UPDATE instance_secrets SET encrypted_value = $1 WHERE instance_id = $2 AND service_name = $3 AND env_name = $4`)
	if err != nil {
		return fmt.Errorf("prepare secret rotation: %w", err)
	}
	defer stmt.Close()
	for _, update := range updates {
		result, err := stmt.Exec(update.EncryptedValue, update.InstanceID, update.ServiceName, update.EnvName)
		if err != nil {
			return fmt.Errorf("update secret %s/%s/%s: %w", update.InstanceID, update.ServiceName, update.EnvName, err)
		}
		if count, err := result.RowsAffected(); err != nil || count != 1 {
			return fmt.Errorf("update secret %s/%s/%s affected %d rows", update.InstanceID, update.ServiceName, update.EnvName, count)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit secret rotation: %w", err)
	}
	return nil
}

func (d *DB) GetExposedInstanceSecrets(instanceID string) ([]InstanceSecret, error) {
	rows, err := d.Query("SELECT instance_id, service_name, env_name, encrypted_value, expose_to_customer, created_at FROM instance_secrets WHERE instance_id = $1 AND expose_to_customer = TRUE ORDER BY service_name, env_name", instanceID)
	if err != nil {
		return nil, fmt.Errorf("query exposed instance secrets: %w", err)
	}
	defer rows.Close()

	var secrets []InstanceSecret
	for rows.Next() {
		var s InstanceSecret
		if err := rows.Scan(&s.InstanceID, &s.ServiceName, &s.EnvName, &s.EncryptedValue, &s.ExposeToCustomer, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan exposed instance secret row: %w", err)
		}
		secrets = append(secrets, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate exposed instance secrets: %w", err)
	}
	return secrets, nil
}

// --- Public Routes CRUD ---
