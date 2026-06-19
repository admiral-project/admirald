# Informe de Auditoría de Seguridad: admirald

## 1. Resumen Ejecutivo
`admirald` presenta una postura de seguridad robusta, siguiendo prácticas modernas de desarrollo en Go. Se destaca el uso correcto de consultas parametrizadas para prevenir inyecciones SQL, el uso de Argon2id para el hash de contraseñas y la implementación de una defensa en profundidad en la comunicación con los nodos mediante validación de IP de WireGuard.

## 2. Autenticación y Gestión de Sesiones
*   **Protección contra Ataques de Tiempo**: El middleware `AdminAuthMiddleware` utiliza `crypto/subtle.ConstantTimeCompare` para validar el token de administración estático, eliminando fugas de información por canal lateral.
*   **Seguridad de Sesiones**: Las sesiones administrativas se gestionan mediante tokens HMAC-SHA256. Se implementan correctamente tiempos de expiración (24h) y de inactividad (30m).
*   **Tokens de Nodos**: La autenticación de nodos utiliza `bcrypt` para el almacenamiento de hashes de tokens, lo cual es adecuado para la validación de secretos de larga duración.
*   **Clave HMAC Efímera**: Por defecto, el servidor genera una clave HMAC volátil en memoria para las sesiones si no se configura `ADMIRAL_SESSION_HMAC_KEY`. Esta es una elección de diseño segura que invalida todas las sesiones activas en caso de reinicio del servicio.

## 3. Criptografía y Gestión de Secretos
*   **Hash de Contraseñas**: Se utiliza **Argon2id** (3 iteraciones, 64MB memoria, 4 hilos), cumpliendo con los estándares actuales de resistencia contra ataques de fuerza bruta por GPU.
*   **Cifrado en Reposo**: Los secretos de las aplicaciones de los clientes se cifran utilizando **AES-256-GCM** en `internal/secrets/`. Este modo proporciona tanto confidencialidad como integridad (cifrado autenticado).
*   **Generación de Aleatoriedad**: Se utiliza correctamente `crypto/rand` (CSPRNG) para la generación de sales, nonces y tokens.

## 4. Validación de Entradas e Inyección
*   **SQL Injection**: Todas las interacciones con PostgreSQL en `internal/database/` utilizan consultas parametrizadas. No se encontraron instancias de concatenación de strings en queries SQL.
*   **Inyección de Comandos**: El validador `ValidateRunArgs` en `pkg/admiral/validation.go` inspecciona los comandos de las aplicaciones en busca de metacaracteres peligrosos del shell (`;`, `&`, `|`, `$()`, etc.).
*   **Path Traversal**: Se implementan verificaciones de secuencias `..` en las rutas de backup y restauración para prevenir accesos no autorizados al sistema de archivos del host.
*   **Límites de Carga (DoS)**: El middleware `MaxBody` se aplica sistemáticamente para limitar el tamaño de los payloads JSON (1 MiB) y YAML (5 MiB), previniendo el agotamiento de memoria.

## 5. Control de Acceso y Red
*   **Validación de IP de Nodo**: `NodeAuthMiddleware` verifica que las peticiones de los nodos provengan de su IP de WireGuard registrada, proporcionando una capa adicional de seguridad sobre el token de acceso.
*   **Limpieza de Headers**: El middleware de autenticación elimina headers sensibles suministrados por el cliente (como `X-Admiral-Admin-User`) antes de procesar la petición, evitando la suplantación de identidad en los logs de auditoría.

## 6. Mejoras Implementadas Durante la Auditoría

### Mayor Entropía en Tokens
Se ha aumentado la entropía de los IDs generados de 8 bytes a 16 bytes (128 bits), reduciendo drásticamente la probabilidad de colisiones en tokens de sesión y otros identificadores sensibles.

### Rate Limiting en API Administrativa
Se ha aplicado el `adminLimiter` a los endpoints de la API administrativa para mitigar ataques de fuerza bruta y denegación de servicio a nivel de aplicación.

### Detección Robusta de IP de Cliente
Se ha mejorado la función de detección de IP para manejar correctamente direcciones con puerto y formatos IPv6.
