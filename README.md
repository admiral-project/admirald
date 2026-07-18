# admirald

Control plane for the Admiral PaaS platform.

`admirald` is the central API service that manages platform state, validates operations, coordinates provisioning, dispatches tasks to worker nodes, and maintains auditability.

The RPM installs the `admirald` binary and the `admirald.service` unit.

## Responsibilities

- Expose the Admiral HTTP API
- Register and manage worker nodes
- Register application definitions and tiers
- Manage customer application instances (provision, pause, resume, deprovision)
- Coordinate backups and restores
- Insert durable tasks into PostgreSQL-backed queue for `admiral-fleet` workers
- Receive task results and update platform state
- Maintain audit logs
- Enforce basic security and authorization (Rate limiting, HMAC sessions)
- Background maintenance (Session cleaning, Node health monitoring, Route reconciliation)

## Quick start

```bash
export ADMIRAL_DATABASE_URL=postgres://admiral:password@localhost:5432/admiral?sslmode=require
export ADMIRAL_ADMIN_TOKEN=dev-token
export ADMIRAL_TOKEN_PEPPER=change-me-in-production
export ADMIRAL_SECRETS_KEY=change-me-in-production
export ADMIRAL_TLS_CERT_FILE=/etc/admiral/tls/admirald.pem
export ADMIRAL_TLS_KEY_FILE=/etc/admiral/tls/admirald-key.pem
export ADMIRAL_QUEUE_DATABASE_URL=postgres://queue:password@localhost:5432/admiral_queue?sslmode=require
export ADMIRAL_ED25519_PRIVATE_KEY=$(cat /etc/admiral/signing.key)
export ADMIRAL_TASK_ENCRYPTION_KEY=64-character-random-hex-string

admirald
```

`admirald` requires PostgreSQL for both the main platform database and the durable queue. SQLite is not supported, and the queue database should be a separate PostgreSQL database or schema from the main control-plane database.

Configuration can also be provided via `/etc/admirald.ini`.

## Architecture

`admirald` does not execute containers directly. It delegates all local execution to `admiral-fleet` agents via a PostgreSQL-backed durable queue.

## API

- `GET /health` — Health check (admin auth)
- `/api/v1/*` — Platform API (admin token or node token auth)
    - `/api/v1/nodes` — Node registration and management
    - `/api/v1/apps` — Application definition management (harbor token)
    - `/api/v1/customer-apps` — Instance lifecycle management (harbor token)
    - `/api/v1/harbor_ping` — Harbor connectivity check (harbor token)
    - `/api/v1/fleet/*` — Worker node callbacks and health reporting
- `/api/admin/*` — Administrative API (session auth)
    - `/api/admin/auth/*` — Session management and password changes
    - `/api/admin/users` — User management
    - `/api/admin/backups` — Backup and restore operations
    - `/api/admin/settings/*` — System settings (storage, etc.)

## Dependencies

- Go 1.26.5+
- PostgreSQL 16 for persistent state
- PostgreSQL-backed durable queue for async task dispatch
- Caddy with admin API for public HTTP routing
