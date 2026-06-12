# admirald

Control plane for the Admiral PaaS platform.

`admirald` is the central API service that manages platform state, validates operations, coordinates provisioning, dispatches tasks to worker nodes, and maintains auditability.

## Responsibilities

- Expose the Admiral HTTP API
- Register and manage worker nodes
- Register application definitions and tiers
- Manage customer application instances (provision, pause, resume, deprovision)
- Coordinate backups and restores
- Insert durable tasks into PostgreSQL-backed queue for `admiral-fleet` workers
- Receive task results and update platform state
- Maintain audit logs
- Enforce basic security and authorization

## Quick start

```bash
export ADMIRAL_DATABASE_URL=postgres://admiral:password@localhost:5432/admiral?sslmode=disable
export ADMIRAL_SHARED_TOKEN=dev-token
export ADMIRAL_SECRETS_KEY=change-me-in-production
export ADMIRAL_TLS_CERT_FILE=/etc/admiral/tls/admirald.pem
export ADMIRAL_TLS_KEY_FILE=/etc/admiral/tls/admirald-key.pem
export ADMIRAL_QUEUE_DATABASE_URL=postgres://queue:password@localhost:5432/admiral_queue?sslmode=disable

admirald
```

## Architecture

`admirald` does not execute containers directly. It delegates all local execution to `admiral-fleet` agents via a PostgreSQL-backed durable queue.

See [docs/app-definition-v1.md](../docs/app-definition-v1.md) for the app definition format and [docs/alpha-release-gate.md](../docs/alpha-release-gate.md) for validation criteria.

## API

- `GET /health` — health check
- `/api/v1/*` — platform API (token auth)
- `/api/admin/*` — administrative API (session auth)

## Dependencies

- PostgreSQL 16 for persistent state
- PostgreSQL-backed durable queue for async task dispatch
- Caddy with admin API for public HTTP routing
