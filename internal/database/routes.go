// SPDX-FileCopyrightText: William Moreno Reyes CP | MBA
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"database/sql"
	"fmt"
	"time"
)

type PublicRoute struct {
	ID                  string     `json:"id"`
	Hostname            string     `json:"hostname"`
	PublicID            string     `json:"public_id"`
	AppInstanceID       string     `json:"app_instance_id"`
	AppTemplateCode     string     `json:"app_template_code"`
	NodeID              *string    `json:"node_id"`
	ServiceName         string     `json:"service_name"`
	TargetScheme        string     `json:"target_scheme"`
	TargetHost          string     `json:"target_host"`
	TargetPort          int        `json:"target_port"`
	TargetURL           string     `json:"target_url"`
	RouteKind           string     `json:"route_kind"`
	TLSMode             string     `json:"tls_mode"`
	Status              string     `json:"status"`
	LastError           string     `json:"last_error"`
	LastHealthStatus    string     `json:"last_health_status"`
	LastHealthCheckedAt *time.Time `json:"last_health_checked_at"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

func (d *DB) CreatePublicRoute(route PublicRoute) error {
	query := `
		INSERT INTO public_routes (
			id, hostname, public_id, app_instance_id, app_template_code, node_id,
			service_name, target_scheme, target_host, target_port, target_url,
			route_kind, tls_mode, status, last_error, last_health_status, last_health_checked_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (hostname) DO UPDATE SET
			public_id = EXCLUDED.public_id,
			app_instance_id = EXCLUDED.app_instance_id,
			app_template_code = EXCLUDED.app_template_code,
			node_id = EXCLUDED.node_id,
			service_name = EXCLUDED.service_name,
			target_scheme = EXCLUDED.target_scheme,
			target_host = EXCLUDED.target_host,
			target_port = EXCLUDED.target_port,
			target_url = EXCLUDED.target_url,
			route_kind = EXCLUDED.route_kind,
			tls_mode = EXCLUDED.tls_mode,
			status = EXCLUDED.status,
			last_error = EXCLUDED.last_error,
			last_health_status = EXCLUDED.last_health_status,
			last_health_checked_at = EXCLUDED.last_health_checked_at,
			updated_at = CURRENT_TIMESTAMP
	`
	var nodeID interface{}
	if route.NodeID != nil && *route.NodeID != "" {
		nodeID = *route.NodeID
	}
	var appInstanceID interface{}
	if route.AppInstanceID != "" {
		appInstanceID = route.AppInstanceID
	}
	var lastHealthCheckedAt interface{}
	if route.LastHealthCheckedAt != nil {
		lastHealthCheckedAt = *route.LastHealthCheckedAt
	}
	_, err := d.Exec(
		query,
		route.ID,
		route.Hostname,
		route.PublicID,
		appInstanceID,
		route.AppTemplateCode,
		nodeID,
		route.ServiceName,
		route.TargetScheme,
		route.TargetHost,
		route.TargetPort,
		route.TargetURL,
		route.RouteKind,
		route.TLSMode,
		route.Status,
		route.LastError,
		route.LastHealthStatus,
		lastHealthCheckedAt,
	)
	if err != nil {
		return fmt.Errorf("create public route %q: %w", route.Hostname, err)
	}
	return nil
}

func (d *DB) GetPublicRoutes() ([]PublicRoute, error) {
	rows, err := d.Query(`
		SELECT id, hostname, public_id, app_instance_id, app_template_code, node_id,
		       service_name, target_scheme, target_host, target_port, target_url,
		       route_kind, tls_mode, status, last_error, last_health_status,
		       last_health_checked_at, created_at, updated_at
		FROM public_routes
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query public routes: %w", err)
	}
	defer rows.Close()

	var routes []PublicRoute
	for rows.Next() {
		var r PublicRoute
		var appInstanceID sql.NullString
		var nodeID sql.NullString
		var lastHealthCheckedAt sql.NullTime
		if err := rows.Scan(
			&r.ID, &r.Hostname, &r.PublicID, &appInstanceID, &r.AppTemplateCode, &nodeID,
			&r.ServiceName, &r.TargetScheme, &r.TargetHost, &r.TargetPort, &r.TargetURL,
			&r.RouteKind, &r.TLSMode, &r.Status, &r.LastError, &r.LastHealthStatus,
			&lastHealthCheckedAt, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan public route row: %w", err)
		}
		if appInstanceID.Valid {
			r.AppInstanceID = appInstanceID.String
		}
		if nodeID.Valid {
			n := nodeID.String
			r.NodeID = &n
		}
		if lastHealthCheckedAt.Valid {
			t := lastHealthCheckedAt.Time
			r.LastHealthCheckedAt = &t
		}
		routes = append(routes, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate public routes: %w", err)
	}
	return routes, nil
}

func (d *DB) GetRoutesByInstance(instanceID string) ([]PublicRoute, error) {
	rows, err := d.Query(`
		SELECT id, hostname, public_id, app_instance_id, app_template_code, node_id,
		       service_name, target_scheme, target_host, target_port, target_url,
		       route_kind, tls_mode, status, last_error, last_health_status,
		       last_health_checked_at, created_at, updated_at
		FROM public_routes
		WHERE app_instance_id = $1
		ORDER BY created_at ASC
	`, instanceID)
	if err != nil {
		return nil, fmt.Errorf("query routes by instance %q: %w", instanceID, err)
	}
	defer rows.Close()

	var routes []PublicRoute
	for rows.Next() {
		var r PublicRoute
		var appInstanceID sql.NullString
		var nodeID sql.NullString
		var lastHealthCheckedAt sql.NullTime
		if err := rows.Scan(
			&r.ID, &r.Hostname, &r.PublicID, &appInstanceID, &r.AppTemplateCode, &nodeID,
			&r.ServiceName, &r.TargetScheme, &r.TargetHost, &r.TargetPort, &r.TargetURL,
			&r.RouteKind, &r.TLSMode, &r.Status, &r.LastError, &r.LastHealthStatus,
			&lastHealthCheckedAt, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan route row for instance %q: %w", instanceID, err)
		}
		if appInstanceID.Valid {
			r.AppInstanceID = appInstanceID.String
		}
		if nodeID.Valid {
			n := nodeID.String
			r.NodeID = &n
		}
		if lastHealthCheckedAt.Valid {
			t := lastHealthCheckedAt.Time
			r.LastHealthCheckedAt = &t
		}
		routes = append(routes, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate routes by instance %q: %w", instanceID, err)
	}
	return routes, nil
}

func (d *DB) GetPublicRoute(hostname string) (*PublicRoute, error) {
	var r PublicRoute
	var appInstanceID sql.NullString
	var nodeID sql.NullString
	var lastHealthCheckedAt sql.NullTime
	query := `
		SELECT id, hostname, public_id, app_instance_id, app_template_code, node_id,
		       service_name, target_scheme, target_host, target_port, target_url,
		       route_kind, tls_mode, status, last_error, last_health_status,
		       last_health_checked_at, created_at, updated_at
		FROM public_routes
		WHERE hostname = $1
	`
	err := d.QueryRow(query, hostname).Scan(
		&r.ID, &r.Hostname, &r.PublicID, &appInstanceID, &r.AppTemplateCode, &nodeID,
		&r.ServiceName, &r.TargetScheme, &r.TargetHost, &r.TargetPort, &r.TargetURL,
		&r.RouteKind, &r.TLSMode, &r.Status, &r.LastError, &r.LastHealthStatus,
		&lastHealthCheckedAt, &r.CreatedAt, &r.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("query public route %q: %w", hostname, err)
	}
	if appInstanceID.Valid {
		r.AppInstanceID = appInstanceID.String
	}
	if nodeID.Valid {
		n := nodeID.String
		r.NodeID = &n
	}
	if lastHealthCheckedAt.Valid {
		t := lastHealthCheckedAt.Time
		r.LastHealthCheckedAt = &t
	}
	return &r, nil
}

func (d *DB) UpdatePublicRoute(route *PublicRoute) error {
	if route == nil {
		return fmt.Errorf("public route is nil")
	}
	query := `
		UPDATE public_routes
		SET hostname = $1,
		    public_id = $2,
		    app_instance_id = $3,
		    app_template_code = $4,
		    node_id = $5,
		    service_name = $6,
		    target_scheme = $7,
		    target_host = $8,
		    target_port = $9,
		    target_url = $10,
		    route_kind = $11,
		    tls_mode = $12,
		    status = $13,
		    last_error = $14,
		    last_health_status = $15,
		    last_health_checked_at = $16,
		    updated_at = CURRENT_TIMESTAMP
		WHERE hostname = $1
	`
	var nodeID interface{}
	if route.NodeID != nil && *route.NodeID != "" {
		nodeID = *route.NodeID
	}
	var appInstanceID interface{}
	if route.AppInstanceID != "" {
		appInstanceID = route.AppInstanceID
	}
	var lastHealthCheckedAt interface{}
	if route.LastHealthCheckedAt != nil {
		lastHealthCheckedAt = *route.LastHealthCheckedAt
	}
	res, err := d.Exec(
		query,
		route.Hostname,
		route.PublicID,
		appInstanceID,
		route.AppTemplateCode,
		nodeID,
		route.ServiceName,
		route.TargetScheme,
		route.TargetHost,
		route.TargetPort,
		route.TargetURL,
		route.RouteKind,
		route.TLSMode,
		route.Status,
		route.LastError,
		route.LastHealthStatus,
		lastHealthCheckedAt,
	)
	if err != nil {
		return fmt.Errorf("update public route %q: %w", route.Hostname, err)
	}
	if rows, rerr := res.RowsAffected(); rerr == nil && rows == 0 {
		return fmt.Errorf("update public route %q: no rows affected", route.Hostname)
	}
	return nil
}

func (d *DB) DeletePublicRoute(hostname string) error {
	_, err := d.Exec("DELETE FROM public_routes WHERE hostname = $1", hostname)
	if err != nil {
		return fmt.Errorf("delete public route %q: %w", hostname, err)
	}
	return nil
}

func (d *DB) DeletePublicRouteByKind(kind string) error {
	_, err := d.Exec("DELETE FROM public_routes WHERE route_kind = $1", kind)
	if err != nil {
		return fmt.Errorf("delete public routes by kind %q: %w", kind, err)
	}
	return nil
}

func (d *DB) DeletePublicRouteByKindAndNotHostname(kind, hostname string) error {
	_, err := d.Exec("DELETE FROM public_routes WHERE route_kind = $1 AND hostname != $2", kind, hostname)
	if err != nil {
		return fmt.Errorf("delete public routes by kind %q except %q: %w", kind, hostname, err)
	}
	return nil
}

func (d *DB) UpdatePublicRouteStatus(hostname, status, lastError, lastHealth string, checkedAt *time.Time) error {
	query := `
		UPDATE public_routes
		SET status = $2,
		    last_error = $3,
		    last_health_status = $4,
		    last_health_checked_at = $5,
		    updated_at = CURRENT_TIMESTAMP
		WHERE hostname = $1
	`
	var checked interface{}
	if checkedAt != nil {
		checked = *checkedAt
	}
	_, err := d.Exec(query, hostname, status, lastError, lastHealth, checked)
	if err != nil {
		return fmt.Errorf("update public route %q status: %w", hostname, err)
	}
	return nil
}

// --- Admin Users CRUD ---
