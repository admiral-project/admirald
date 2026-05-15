admirald

Definición de producto

admirald es el núcleo operativo de Admiral. Es el servicio central encargado de exponer la API principal de la plataforma, mantener el estado del sistema, validar solicitudes, coordinar tareas y ordenar a los workers admiral-fleet la ejecución de operaciones sobre aplicaciones contenerizadas.

admirald actúa como el control plane de Admiral.

No debe enfocarse en ejecutar directamente contenedores, sino en decidir, coordinar, registrar y auditar las acciones necesarias para administrar el ciclo de vida de las aplicaciones SaaS.

Propósito principal

Permitir que Admiral pueda administrar aplicaciones SaaS de forma segura, consistente y auditable mediante una API central que coordina nodos, aplicaciones, clientes, tiers, pods, backups y operaciones.

Responsabilidades principales

admirald debe encargarse de:

Exponer una API interna para los demás componentes.
Registrar y administrar nodos workers.
Registrar definiciones de aplicaciones.
Registrar tiers disponibles por aplicación.
Crear solicitudes de provisionamiento.
Coordinar el despliegue de apps en nodos.
Coordinar backups.
Coordinar pausa y reanudación de apps.
Coordinar cambio de tier o recursos.
Coordinar desaprovisionamiento.
Mantener el estado técnico de cada app.
Mantener el estado de las operaciones.
Publicar tareas hacia admiral-fleet.
Recibir resultados de ejecución desde admiral-fleet.
Registrar logs de auditoría.
Aplicar reglas básicas de seguridad y autorización.
Integrarse con billing como fuente de decisiones operativas.
Lo que admirald sí debe hacer

admirald debe:

Ser la fuente de verdad del estado de la plataforma.
Saber qué apps existen.
Saber qué cliente posee cada app.
Saber en qué nodo corre cada app.
Saber qué tier tiene asignado cada app.
Saber qué operaciones están pendientes, en ejecución, finalizadas o fallidas.
Validar si una acción es permitida antes de ejecutarla.
Crear tareas para los workers.
Procesar respuestas de los workers.
Exponer endpoints para admiral-harbor, admiral-flagship y admiralctl.
Mantener una bitácora auditable de operaciones relevantes.
Lo que admirald no debe hacer

admirald no debe:

Ejecutar directamente podman.
Manipular directamente contenedores en nodos remotos.
Contener lógica específica de cada aplicación SaaS.
Administrar UI de cliente.
Administrar UI administrativa.
Procesar pagos directamente si se usa un proveedor externo.
Convertirse en un Kubernetes alternativo.
Tomar decisiones complejas de scheduling en el MVP.
Implementar autoscaling sofisticado en las primeras versiones.
Funciones mínimas del MVP

Para una primera versión, admirald debería incluir:

Gestión de nodos
Registrar nodo.
Listar nodos.
Ver estado de nodo.
Activar/desactivar nodo.
Asociar nodo a una zona o grupo simple.
Gestión de aplicaciones
Registrar definición YAML de app.
Validar definición YAML.
Listar apps disponibles.
Ver detalle de app.
Registrar tiers por app.
Activar/desactivar app del catálogo.
Gestión de instancias de cliente
Crear instancia de app contratada.
Provisionar instancia.
Pausar instancia.
Reanudar instancia.
Cambiar tier.
Desaprovisionar instancia.
Consultar estado de instancia.
Gestión de operaciones
Crear operación.
Consultar operación.
Listar operaciones.
Marcar operación como pendiente, en ejecución, exitosa o fallida.
Registrar errores de operación.
Gestión de backups
Solicitar backup.
Listar backups.
Registrar metadata de backup.
Asociar backup a una instancia de app.
Exponer información para descarga segura.
Comunicación con fleet
Crear tareas para admiral-fleet.
Enviar tareas por RabbitMQ.
Recibir resultados.
Manejar reintentos básicos.
Marcar tareas fallidas después de cierto número de intentos.
Interfaces principales

admirald debe exponer una API HTTP interna.

Ejemplos de recursos:

/api/v1/nodes
/api/v1/apps
/api/v1/app-definitions
/api/v1/tiers
/api/v1/customer-apps
/api/v1/operations
/api/v1/backups
/api/v1/fleet-tasks

También debe integrarse con RabbitMQ para mensajería asíncrona:

admirald -> RabbitMQ -> admiral-fleet
admiral-fleet -> RabbitMQ/API -> admirald
Estados que debe administrar
Estado de app contratada
pending_payment
pending_provision
provisioning
active
paused
suspended
resizing
backup_running
failed
deprovisioning
deprovisioned
cancelled
Estado de operación
pending
queued
running
succeeded
failed
cancelled
Estado de nodo
registered
active
draining
inactive
unreachable
maintenance
Requerimientos técnicos
Lenguaje: Go.
API HTTP REST.
Base de datos: PostgreSQL.
Cola de mensajes: RabbitMQ.
Cache opcional: Redis.
Configuración por archivo YAML/TOML/env vars.
Logs estructurados.
Migraciones de base de datos.
Autenticación por tokens internos.
Auditoría de operaciones críticas.
Preparado para empaquetarse como RPM.
Servicio administrado por systemd.
Criterio de éxito

admirald será exitoso si permite que Admiral tenga un centro de control confiable capaz de recibir solicitudes de negocio, convertirlas en operaciones técnicas y coordinar su ejecución sobre nodos workers de forma segura, simple y auditable.
