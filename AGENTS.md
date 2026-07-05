# admirald

`admirald` es el control plane de Admiral y la fuente de verdad del sistema.

Hace:

- expone la API central.
- valida solicitudes.
- mantiene estado de apps, nodos, instancias, operaciones y backups.
- crea tareas para `admiral-fleet`.
- recibe resultados y audita acciones.

No hace:

- ejecutar Podman directamente.
- manipular contenedores remotos.
- contener lógica de negocio propia de portales o UI.

Reglas:

- estado global en `admirald`.
- operaciones largas o destructivas deben ser auditable.
- PostgreSQL es la persistencia principal.
- la cola duradera de tareas usa una base separada.

## Pre-commit

Ejecutar estos comandos antes de cada commit:

```bash
go mod tidy
gofmt -w .
go vet ./...
go build ./...
go test ./...
```
