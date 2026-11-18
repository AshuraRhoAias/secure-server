# 🔐 secure-server

> **secure-server** es una API REST en Node.js (Express 5 + MySQL/MariaDB) para guardar y servir datos sensibles, con una **interfaz web de operación** (Next.js) para administradores. Los campos sensibles se cifran con AES-256-GCM (formato `v4`), los archivos se cifran por archivo y por bloques (en disco local o en un bucket S3), cada petición pasa por detección de inyecciones, límites y bloqueos **cuyo estado vive en MySQL**, y las claves se rotan con migración de datos.
>
> 📘 **Detalle, operación y límites honestos: [`docs/SEGURIDAD.md`](docs/SEGURIDAD.md)** · bitácora de auditoría y mejoras: [`docs/ReadmeLogsMejoras.md`](docs/ReadmeLogsMejoras.md) · interfaz web: [`web/README.md`](web/README.md) · pruebas: `npm run test:all` (MariaDB; ver `test/helpers/env.js`).

## 🧭 Descripción del proyecto

| Capa | Qué hace | Dónde está |
|------|----------|------------|
| **Entrada** | helmet, CORS cerrado en producción, compresión, registro de accesos, parseo JSON, trazas (`X-Request-Id`) y métricas | `src/index.js`, `src/observability/` |
| **Protección** | Bloqueo progresivo de IP, detección de inyecciones (bloquea en rutas críticas), límites de peticiones y análisis de anomalías, todo en tablas MySQL | `src/middleware/protection.middleware.js`, `src/security/` |
| **Autenticación** | JWT HS256 de **15 min** ligado a una sesión en BD + refresh token opaco con rotación y detección de reutilización; MFA (TOTP, passkeys/WebAuthn, códigos de recuperación); SSO por OpenID Connect y SAML 2.0 | `src/security/secure-auth.service.js`, `src/security/mfa.service.js`, `src/security/webauthn.service.js`, `src/sso/` |
| **Autorización** | Roles `user` / `auditor` / `operator` / `admin` con permisos explícitos leídos de la BD en cada petición; acciones sensibles con **aprobación de dos administradores** | `src/security/permissions.js`, `src/middleware/role.middleware.js`, `src/security/admin-approvals.service.js` |
| **APIs** | Cada `*.routes.js` se monta solo en `/api/<nombre>`; definición completa en [`docs/openapi.json`](docs/openapi.json) | `src/api/routes/`, `src/api/controllers/` |
| **Datos** | Consultas siempre con parámetros; campos sensibles AES-256-GCM v4 (HKDF); réplica de lectura opcional para análisis | `src/config/database.js`, `src/crypto/` |
| **Archivos** | Imágenes, vídeo, audio, PDF y texto: tipo por contenido, antivirus (ClamAV), imágenes recodificadas, PDF sin contenido activo, cifrados por archivo; en `FILES_DIR` o en **S3** | `src/files/` |
| **Claves** | Rotación con migración de datos y backups cifrados; KMS (archivo, Vault, AWS) para secretos y claves de archivo | `src/crypto/`, `scripts/rotateKeys.js`, `scripts/kms.js` |
| **Operación** | Alertas automáticas, panel, métricas Prometheus, trazas OTLP, **novedades en vivo (SSE)**, exportación y borrado de datos personales | `src/security/alerts.service.js`, `src/observability/` |
| **Escala** | Cluster (un proceso por núcleo, reinicio en caliente), un solo líder para las tareas periódicas, varias réplicas detrás de un balanceador ([`deploy/`](deploy/)) | `src/cluster.js`, `src/tasks/leader.js`, `Dockerfile` |
| **Interfaz web** | Next.js + React, solo administradores: BFF con cookie `httpOnly` (los tokens nunca llegan al navegador), passkeys, SSO, datos en vivo | `web/` |

### Flujo de una petición

```
Cliente ── (opcional) interfaz web: navegador ⇄ BFF Next.js (cookie httpOnly) ⇄ API con Bearer
  │
  ▼
trazas · métricas · helmet · CORS · compression · express.json          (src/index.js)
  │
  ▼
autoProtect()  ── IP bloqueada → 403 · inyección en ruta crítica → 403/400 · límite → 429
  │
  ▼
registerRoutes()  ── verifyJWT (salvo router.access = 'public' | 'custom') → 401
  │
  ▼
router  ──  requirePermission(...) → 403  ·  validate.body/query/params → 400
  │
  ▼
controller  ──  db.query() · cifrado · audit.log() · security_events
  │
  ▼
manejador de errores global (4xx del cliente se respetan; el resto → 500 sin detalles)
```

### Endpoints

Generada desde [`docs/openapi.json`](docs/openapi.json) (`npm run docs:endpoints -- --write`; `test/test_api.js` falla si se desincroniza). «JWT» significa sesión válida; cada ruta de `/api/system` exige además su permiso (`src/security/permissions.js`).

<!-- endpoints:inicio -->
| Grupo | Método | Ruta | Acceso | Descripción |
|---|---|---|---|---|
| Sistema | GET | `/health` | público | Estado del proceso (no usa la BD) |
| Sistema | GET | `/health/ready` | público | Preparación para balanceadores: 200 solo si esta instancia puede atender (BD alcanzable, no en cierre ni mantenimiento) |
| Autenticación | POST | `/api/auth/register` | público | Registro |
| Autenticación | POST | `/api/auth/login` | público | Login (paso 1). Con MFA devuelve mfaRequired y mfaToken |
| Autenticación | POST | `/api/auth/login/mfa` | público | Login (paso 2): segundo factor |
| Autenticación | POST | `/api/auth/logout` | JWT | Cierra la sesión |
| Autenticación | GET | `/api/auth/profile` | JWT | Perfil descifrado |
| Autenticación | POST | `/api/auth/refresh` | público | Renueva el token de acceso con el refresh token (rota) |
| Autenticación | POST | `/api/auth/logout-all` | JWT | Cierra todas las sesiones del usuario (opcionalmente menos la actual) |
| Autenticación | GET | `/api/auth/sessions` | JWT | Sesiones abiertas del usuario |
| Autenticación | DELETE | `/api/auth/sessions/{id}` | JWT | Cierra una sesión concreta del usuario |
| Autenticación | POST | `/api/auth/password` | JWT | Cambia la propia contraseña (cierra las demás sesiones; quita el cambio obligatorio) |
| MFA | GET | `/api/auth/mfa` | JWT | Estado del MFA |
| MFA | POST | `/api/auth/mfa/setup` | JWT | Inicia el alta de MFA (secreto + QR) |
| MFA | POST | `/api/auth/mfa/enable` | JWT | Activa MFA con un código válido; entrega los códigos de recuperación |
| MFA | POST | `/api/auth/mfa/disable` | JWT | Desactiva MFA (contraseña + segundo factor) |
| MFA | POST | `/api/auth/mfa/recovery-codes` | JWT | Regenera los códigos de recuperación (contraseña + segundo factor) |
| MFA | POST | `/api/auth/login/webauthn/options` | público | Login con passkey (paso 2, A): opciones con el reto |
| MFA | POST | `/api/auth/login/webauthn` | público | Login con passkey (paso 2, B): la firma |
| MFA | GET | `/api/auth/webauthn/credentials` | JWT | Passkeys registradas del usuario (sin claves) |
| MFA | POST | `/api/auth/webauthn/register/options` | JWT | Registrar passkey (A): opciones; exige contraseña (+ segundo factor si ya hay) |
| MFA | POST | `/api/auth/webauthn/register` | JWT | Registrar passkey (B): respuesta del autenticador; la primera entrega códigos de recuperación |
| MFA | DELETE | `/api/auth/webauthn/credentials/{id}` | JWT | Quitar una passkey; exige contraseña (+ segundo factor) |
| SSO | GET | `/api/sso/status` | público | ¿Está configurado el SSO? |
| SSO | GET | `/api/sso/login` | público | Inicia el login OIDC (redirige al proveedor; ?format=json devuelve la URL) |
| SSO | GET | `/api/sso/callback` | público | Retorno del proveedor OIDC (code + state) |
| SSO | GET | `/api/saml/status` | público | ¿SAML activado? |
| SSO | GET | `/api/saml/metadata` | público | Metadatos SAML del proveedor de servicio (entityID, URL ACS, certificado) |
| SSO | GET | `/api/saml/login` | público | Inicia el login SAML: 302 al IdP (o JSON con ?format=json) |
| SSO | POST | `/api/saml/acs` | público | ACS: recibe la respuesta firmada del IdP y abre sesión (amr "saml") |
| SSO | POST | `/api/sso/exchange` | público | Canjea el código de entrega de un login SSO (OIDC o SAML) por los tokens. Lo usa el BFF de la interfaz web, servidor a servidor: un solo uso, 60 s, exige el verificador |
| Notas | GET | `/api/notes` | JWT | Lista tus notas |
| Notas | POST | `/api/notes` | JWT | Crea una nota |
| Notas | GET | `/api/notes/{id}` | JWT | Lee una nota tuya |
| Notas | PUT | `/api/notes/{id}` | JWT | Edita title y/o content |
| Notas | DELETE | `/api/notes/{id}` | JWT | Borra una nota tuya |
| Archivos | GET | `/api/files` | JWT | Lista tus archivos (cursor) |
| Archivos | POST | `/api/files` | JWT | Sube UN archivo (multipart, campo file) |
| Archivos | GET | `/api/files/quota` | JWT | Tu uso y límites |
| Archivos | GET | `/api/files/{id}` | JWT | Metadatos |
| Archivos | DELETE | `/api/files/{id}` | JWT | Borra fila y archivo |
| Archivos | GET | `/api/files/{id}/download` | JWT | Descarga (Range y HEAD) |
| Administración | GET | `/api/system/status` | JWT | Estado del sistema |
| Administración | GET | `/api/system/logs` | JWT | Logs de seguridad (cifrados en BD) |
| Administración | GET | `/api/system/rotation` | JWT | Estado de claves, mantenimiento y backups |
| Administración | GET | `/api/system/blocked-ips` | JWT | IP bloqueadas |
| Administración | DELETE | `/api/system/blocked-ips/{ip}` | JWT | Desbloquea una IP |
| Administración | GET | `/api/system/security-events` | JWT | Tabla de análisis de anomalías |
| Administración | GET | `/api/system/security-summary` | JWT | Resumen de eventos |
| Administración | POST | `/api/system/accounts/unlock` | JWT | Libera una cuenta bloqueada por intentos fallidos |
| Administración | POST | `/api/system/accounts/mfa-reset` | JWT | Solicita reiniciar el MFA de un usuario (otro admin debe aprobarlo) |
| Administración | POST | `/api/system/integrity-check` | JWT | Fuerza la verificación de integridad |
| Administración | POST | `/api/system/rotate-keys` | JWT | 501: la rotación se lanza con npm run rotate-keys |
| Administración | POST | `/api/system/test-communications` | JWT | Prueba los canales de alerta |
| Administración | GET | `/api/system/approvals` | JWT | Solicitudes de aprobación (filtro opcional por estado) |
| Administración | POST | `/api/system/approvals/{id}/approve` | JWT | Aprueba (y ejecuta) una solicitud: no puede ser quien la pidió |
| Administración | POST | `/api/system/approvals/{id}/reject` | JWT | Rechaza una solicitud (o la cancela si la pidió el mismo admin) |
| Administración | GET | `/api/system/alerts` | JWT | Alertas de seguridad automáticas (solo admin) |
| Administración | POST | `/api/system/alerts/evaluate` | JWT | Evalúa las reglas de alerta ahora (solo admin) |
| Administración | POST | `/api/system/alerts/{id}/ack` | JWT | Reconoce una alerta (solo admin) |
| Administración | POST | `/api/system/alerts/{id}/resolve` | JWT | Resuelve una alerta (solo admin) |
| Administración | GET | `/api/system/dashboard` | JWT | Panel de operación: alertas, eventos, sesiones, archivos, estado (solo admin) |
| Administración | GET | `/api/system/users/{id}/export` | JWT | Exporta, descifrados, todos los datos de un usuario (solo admin; queda auditado) |
| Administración | POST | `/api/system/users/{id}/erase` | JWT | Solicita borrar los datos de un usuario (otro admin debe aprobarlo) |
| Administración | POST | `/api/system/users/{id}/revoke-sessions` | JWT | Cierra todas las sesiones de un usuario (solo admin) |
| Administración | POST | `/api/system/sessions/revoke-all` | JWT | Interruptor de emergencia: cierra TODAS las sesiones de TODOS (solo admin) |
| Administración | GET | `/api/system/stream` | JWT | Novedades en vivo (Server-Sent Events): eventos de seguridad, alertas nuevas y resumen de alertas (solo admin). Reconecta con Last-Event-ID |
| Administración | GET | `/api/system/users` | JWT | Lista paginada de usuarios (sin hashes ni secretos) |
| Administración | POST | `/api/system/users` | JWT | Crea un usuario con contraseña temporal (rol admin: aprobación de otro administrador) |
| Administración | POST | `/api/system/users/{id}/role` | JWT | Cambia el rol de un usuario y cierra sus sesiones (subir a admin: aprobación de otro administrador) |
| Administración | GET | `/api/system/settings` | JWT | Configuración efectiva (sin secretos) agrupada, con origen, límites y quién la cambió |
| Administración | PUT | `/api/system/settings/{key}` | JWT | Cambia en caliente un ajuste del catálogo (si reduce la seguridad: aprobación de otro administrador) |
| Administración | DELETE | `/api/system/settings/{key}` | JWT | Vuelve un ajuste al valor del entorno (si eso reduce la seguridad: aprobación de otro administrador) |
| Observabilidad | GET | `/api/metrics` | JWT | Métricas Prometheus (solo admin; opcionalmente un token de servicio METRICS_TOKEN) |
<!-- endpoints:fin -->

> `/api/notes` es una API **de ejemplo funcional**: sirve de plantilla para las tuyas (ver [Cómo crear una API nueva](#cómo-crear-una-api-nueva)).

### Puesta en marcha rápida

Requisitos: **Node.js ≥ 22** y MariaDB 10.11 / MySQL 8 (o Docker). Instalador guiado: [`docs/INSTALL.md`](docs/INSTALL.md).

```bash
npm install
# 1. Crea la BD y aplica el esquema (instalaciones nuevas: ya incluye las migraciones 001-017)
mysql -u <usuario> -p <base_de_datos> < database/schema.sql
#    …si vienes de una versión anterior: aplica en orden las migraciones que te falten de database/migrations/ (docs/SEGURIDAD.md §8)
# 2. Configura .env (plantilla comentada: .env.example) y arranca (un proceso por núcleo)
npm run start:cluster
# 3. Convierte a un usuario ya registrado en administrador (para /api/system/* y la interfaz web)
npm run set-role -- --user-id 1 --role admin
# 4. Pruebas
npm run test:api          # sin base de datos
npm run test:all          # con MariaDB
```

**Con Docker** (varias réplicas detrás de nginx, MariaDB y SeaweedFS como S3): ver [`deploy/docker-compose.yml`](deploy/docker-compose.yml) y `docs/SEGURIDAD.md` §23.

---

## 📋 Índice
0. [Descripción del proyecto](#descripción-del-proyecto)
1. [Referencia de la API y cómo crear APIs nuevas](#referencia-de-la-api-y-cómo-crear-apis-nuevas)
2. [Defensa contra exfiltración por ICMP](#defensa-contra-exfiltración-por-icmp)
3. [Rotación de claves, migración de datos y backups](#rotación-de-claves-migración-de-datos-y-backups)
4. [Despliegue y comandos útiles](#despliegue-y-comandos-útiles)
5. [Características de seguridad](#características-de-seguridad)

> La guía de instalación paso a paso original (con el código de agosto de 2025) está en [`docs/historico/GUIA-ORIGINAL.md`](docs/historico/GUIA-ORIGINAL.md) como **referencia histórica**: describe un diseño anterior (triple cifrado con la misma clave, JWT de 5 días, estado en memoria…). La fuente de verdad es el código y esta página.

---

## 🧩 Referencia de la API y cómo crear APIs nuevas

### Probar el sistema con curl

```bash
# 1. Registro
curl -X POST http://localhost:3000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"ana","email":"ana@example.com","password":"una-clave-larga","deviceInfo":{}}'

# 2. Login → guarda el token de la respuesta
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"ana","password":"una-clave-larga","deviceInfo":{}}' | jq -r .token)

# 3. Usar una API protegida
curl -X POST http://localhost:3000/api/notes \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"Mi primera nota","content":"Se guarda cifrada"}'

curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/notes
```

Todas las respuestas siguen el mismo formato: `{ "success": true, ... }` o
`{ "success": false, "message": "...", "code": "VALIDATION_ERROR" }`. Códigos habituales:
`400` datos inválidos, `401` token ausente/inválido, `403` sin permisos o IP bloqueada,
`404` no existe (o no es tuyo), `429` rate limit, `503` migración pendiente.

### Cómo funciona el cargador de rutas

`src/api/routes/index.js` busca todos los archivos `*.routes.js` de esa carpeta y monta cada uno en
`/api/<nombre-del-archivo>`. **No hace falta tocar `src/index.js`.**

| `router.access` | Efecto |
|-----------------|--------|
| *(sin definir)* o `'protected'` | JWT obligatorio (`verifyJWT`). **Es el valor por defecto: seguro por omisión.** |
| `'public'` | Sin login (por ejemplo, un endpoint de estado público). |
| `'custom'` | El router gestiona su propia autenticación (lo usa `/api/auth`, que mezcla rutas públicas y protegidas). |

La protección global (`autoProtect`: IPs bloqueadas, anomalías, rate limiting) se aplica siempre, también a las rutas públicas.

### Herramientas que puedes reutilizar

| Herramienta | Para qué | Uso |
|-------------|----------|-----|
| `req.user` | Usuario autenticado: `{ id, username, sessionId, riskLevel }` | `req.user.id` |
| `roleMiddleware.requireRole('admin')` | Restringir por rol (se consulta la BD, no el token) | `router.use(roleMiddleware.requireRole('admin'))` |
| `validate.body / query / params` | Validar y limpiar la entrada; descarta campos no declarados | `validate.body({ title: { type: 'string', required: true, max: 200 } })` |
| `tripleEncryptor.encrypt / decrypt` | Cifrar antes de guardar, descifrar al leer | `tripleEncryptor.encrypt(texto)` |
| `audit.log(evento, detalles, { req, severity, riskScore })` | Registrar la acción, cifrada, en `security_logs` | `await audit.log('TASK_CREATED', { id }, { req })` |
| `protectionMiddleware.highSecurity()` | Rate limit estricto (10 req/min) para operaciones sensibles | `router.post('/x', protectionMiddleware.highSecurity(), handler)` |
| `db.query(sql, params)` | Consultas parametrizadas; devuelve `[filas]` (o `[ResultSetHeader]` en INSERT/UPDATE/DELETE) | `const [rows] = await db.query('SELECT …', [id])` |

Tipos que acepta `validate`: `string`, `email`, `number`, `integer`, `boolean` y `enum` (con `values`); opciones `required`, `min`, `max`, `default`.
En `validate.query` el resultado limpio queda en `req.validated.query` (en Express 5 `req.query` es de solo lectura); en `validate.body` se reemplaza `req.body`.

### Cómo crear una API nueva

Ejemplo: una API de **tareas** (`/api/tasks`). La API de notas (`notes.routes.js` + `notes.controller.js`) es la referencia completa y funcional.

**1. Tabla en la base de datos** — crea un archivo en `database/migrations/` y añade la misma tabla a `database/schema.sql`. Los datos sensibles van en columnas `*_encrypted` (`longtext`), y la tabla cuelga de `users` con `ON DELETE CASCADE`:

```sql
CREATE TABLE IF NOT EXISTS `user_tasks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `title_encrypted` longtext NOT NULL,
  `done` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_tasks_user_id` (`user_id`),
  CONSTRAINT `user_tasks_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

**1b. Registra la columna cifrada** en `src/crypto/encrypted-columns.js` (si no, la próxima rotación de claves la dejaría ilegible):

```js
user_tasks: { primaryKey: 'id', columns: ['title_encrypted'] },
```

**2. Controlador** — `src/api/controllers/tasks.controller.js`. Reglas de oro: filtra **siempre** por `user_id = req.user.id`, cifra lo sensible, audita las escrituras y devuelve 404 (no 403) cuando algo no es del usuario:

```js
const db = require('../../config/database');
const tripleEncryptor = require('../../crypto/tripleEncryptor');
const audit = require('../../services/audit.service');

class TasksController {
    constructor() {
        this.create = this.create.bind(this);   // se usan como handlers de Express
        this.list = this.list.bind(this);
    }

    async create(req, res) {
        const { title } = req.body;                       // ya validado por validate.body
        const [result] = await db.query(
            'INSERT INTO user_tasks (user_id, title_encrypted) VALUES (?, ?)',
            [req.user.id, tripleEncryptor.encrypt(title)]
        );
        await audit.log('TASK_CREATED', { taskId: result.insertId }, { req });
        res.status(201).json({ success: true, task: { id: result.insertId, title, done: false } });
    }

    async list(req, res) {
        const [rows] = await db.query(
            'SELECT id, title_encrypted, done FROM user_tasks WHERE user_id = ? ORDER BY id DESC',
            [req.user.id]
        );
        res.json({
            success: true,
            tasks: rows.map(r => ({ id: r.id, title: tripleEncryptor.decrypt(r.title_encrypted), done: !!r.done }))
        });
    }
}

module.exports = new TasksController();
```

> En Express 5 los errores de funciones `async` se propagan solos al manejador global: no hace falta `try/catch` ni `asyncHandler` (solo si quieres una respuesta de error propia).

**3. Rutas** — `src/api/routes/tasks.routes.js`. El nombre del archivo define la URL:

```js
const express = require('express');
const router = express.Router();
const tasksController = require('../controllers/tasks.controller');
const validate = require('../utils/validate');

router.post('/',
    validate.body({ title: { type: 'string', required: true, min: 1, max: 200 } }),
    tasksController.create
);
router.get('/', tasksController.list);

// router.access = 'public';              // opcional: sin login
// router.use(roleMiddleware.requireRole('admin'));   // opcional: solo administradores

module.exports = router;
```

**4. Listo.** Reinicia el servidor: en el arranque verás `↳ /api/tasks (protected)`. Ya hereda JWT, rate limiting, detección de anomalías, cifrado y auditoría.

**5. Test** — añade casos a `test/test_api.js` (usa una BD simulada en memoria, así que no necesita MySQL) y ejecuta `npm run test:api`. Comprueba como mínimo: 401 sin token, validación 400, que otro usuario no ve tus datos y que en BD no queda texto plano.

### Checklist de seguridad para cada API nueva

- [ ] Cada consulta que toca datos de usuario filtra por `user_id = req.user.id`
- [ ] Todo dato sensible se guarda con `tripleEncryptor.encrypt` (nada de texto plano en BD)
- [ ] Cada columna cifrada está registrada en `src/crypto/encrypted-columns.js` (`npm run test:rotation` lo comprueba)
- [ ] Entrada validada con `validate.*` (límites de longitud incluidos)
- [ ] SQL siempre con parámetros `?` (nunca concatenar datos del usuario). Excepción: `LIMIT`/`OFFSET` se interpolan solo tras validarlos como enteros acotados
- [ ] Escrituras y borrados auditados con `audit.log`
- [ ] Operaciones administrativas detrás de `requireRole('admin')` y, si son sensibles, `highSecurity()`
- [ ] Las respuestas nunca incluyen claves, hashes ni datos de otros usuarios
- [ ] Rutas públicas (`router.access = 'public'`) solo cuando sea imprescindible

### Roles y administradores

Los usuarios nuevos tienen `role = 'user'`. Para dar acceso a `/api/system/*`:

```bash
npm run set-role -- --user-id 1 --role admin
```

El rol se consulta en la BD en cada petición: si lo quitas, el acceso desaparece al instante aunque el JWT siga vigente. Si olvidas aplicar la migración, las rutas con `requireRole` responden `503 MIGRATION_REQUIRED`.

---

## 🛰️ Defensa contra exfiltración por ICMP

### El ataque

Con `ping -c 1 -p <patrón> <ip>` el atacante rellena el payload del echo-request con un patrón de hasta **16 bytes** (32 caracteres hex; no 16 bits). Cada ping lleva un trozo del archivo y una máquina que escucha reconstruye el documento a partir de los payloads. Es lento, pero casi ningún firewall ni antivirus mira dentro del ICMP.

Un ping legítimo no se parece a eso: Linux/macOS/BSD rellenan con bytes incrementales (`0x10, 0x11, …`) y Windows con `abcdefghijklmnopqrstuvwabcdefghi`. Un payload que repite un patrón arbitrario y **cambia de un ping al siguiente** es la firma del canal encubierto.

### Qué se puede (y qué no) hacer desde Node

Una aplicación Node **no ve paquetes ICMP**: eso ocurre en el kernel. Por eso la defensa va en capas y la que de verdad corta el canal vive en el host, no en el código de la API:

| Capa | Qué hace | Dónde |
|------|----------|-------|
| **1. Prevención** | Un proceso comprometido no puede emitir ICMP, o solo hacia destinos de confianza y con tasa limitada | `scripts/icmp-firewall.sh`, `sysctl`, quitar `CAP_NET_RAW` |
| **2. Detección** | Analiza los payloads ICMP y alerta de patrones repetidos, patrones que cambian, alta entropía, tamaños anormales y replies alterados | `scripts/icmpMonitor.js`, `src/security/icmp-covert-channel.service.js` |
| **3. Respuesta** | Alerta camuflada por los canales existentes, evento cifrado en `security_logs`, bloqueo HTTP de IPs externas | `scripts/icmpMonitor.js` |
| **4. Postura** | `/api/system/status` informa de qué puede hacer el proceso en red; el servidor no puede lanzar procesos | `src/security/network-hardening.check.js` |

### Capa 1 — Prevención en el host

**a) Firewall (la medida más eficaz).** `scripts/icmp-firewall.sh` crea cadenas propias (`ICMP_GUARD_IN` / `ICMP_GUARD_OUT`) para IPv4 e IPv6:

- **Salida**: `echo-request` solo hacia `ICMP_ALLOWED_DESTS`, de tamaño estándar y máx. 6/min; el resto se registra (`ICMP_GUARD_DROP_OUT`) y se descarta. Con la lista vacía (por defecto) un servidor comprometido no puede emitir pings.
- **Entrada**: `echo-request` de tamaño estándar con límite de tasa (o descartados del todo con `ICMP_ALLOW_INBOUND_PING=0`); los `echo-reply` que no responden a un ping nuestro se descartan.

```bash
# 1. Ver qué haría (no modifica nada)
ICMP_ALLOWED_DESTS="1.1.1.1 8.8.8.8" npm run icmp-firewall
# 2. Aplicar (root). Idempotente: se puede ejecutar varias veces
sudo ICMP_ALLOWED_DESTS="1.1.1.1 8.8.8.8" npm run icmp-firewall -- --apply
# 3. Deshacer: quita solo sus cadenas, sin tocar el resto del firewall
sudo npm run icmp-firewall -- --remove
```

> Las reglas no persisten tras un reinicio: guárdalas con tu mecanismo habitual (`iptables-persistent`, `netfilter-persistent save`, un servicio systemd que ejecute el script…). Si la máquina enruta tráfico, replica las reglas en `FORWARD`.

**b) Sin capacidad de ICMP para el proceso.** El atacante necesita `CAP_NET_RAW` o que el kernel permita ping sin privilegios:

```bash
# Desactivar ping para usuarios sin privilegios (persistente)
echo 'net.ipv4.ping_group_range = 1 0' | sudo tee /etc/sysctl.d/90-icmp-guard.conf && sudo sysctl --system
```
```yaml
# docker-compose.yml
services:
  secure-server:
    user: "1000:1000"          # nunca root
    cap_drop: [ALL]            # o, como mínimo, NET_RAW
    read_only: true
```
```ini
# systemd: [Service]
User=secureserver
CapabilityBoundingSet=
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```

`GET /api/system/status` (admin) devuelve `security.networkPosture` con `capNetRaw`, `unprivilegedPing`, `runningAsRoot`, `hardened` y una lista de `recommendations`. Hasta que el host esté endurecido te dirá exactamente qué falta.

### Capa 2 — Detección: `icmp-monitor`

Captura echo-request/echo-reply con `tcpdump` y los analiza. **Debe correr como proceso aparte**, nunca dentro del servidor web, porque capturar exige root o `CAP_NET_RAW`:

```bash
sudo apt install tcpdump
sudo npm run icmp-monitor                                    # todas las interfaces
sudo npm run icmp-monitor -- --interface eth0
sudo npm run icmp-monitor -- --allowlist 10.0.0.9,10.0.0.10  # IPs de monitoreo legítimas
# Analizar una captura guardada, sin privilegios y sin tocar BD ni enviar alertas:
npm run icmp-monitor -- --file captura.txt --dry-run
```

| Señal | Qué significa | Nivel |
|-------|---------------|-------|
| `PATTERN_STEPPING` | ≥ 8 patrones distintos en 10 min entre las mismas IPs (≥ 20 → crítico): los datos "avanzan" ping a ping | high / critical |
| `SLOW_PATTERN_STEPPING` | ≥ 40 patrones distintos en 6 h (≥ 100 → crítico): exfiltración lenta para esquivar la ventana corta | high / critical |
| `HIGH_ENTROPY_PAYLOAD` | Payloads con aspecto de datos cifrados/comprimidos (túneles ICMP) | high / critical |
| `OVERSIZED_PAYLOAD` | Varios payloads no estándar de más de 128 bytes | high / critical |
| `MODIFIED_REPLY` | El echo-reply no refleja el payload del request (las pilas legítimas lo reflejan siempre) | high |
| `NON_STANDARD_FLOOD` | ≥ 60 pings no estándar por minuto | medium |

Cada alerta indica la dirección (`egress` = sale de esta máquina → **investiga el host**; `ingress` = entra), las razones, estadísticas y una muestra de patrones como evidencia. El mismo par de IPs no vuelve a alertar del mismo nivel hasta pasar 30 min.

Al detectar una alerta (sin `--dry-run`) el monitor la guarda cifrada en `security_logs` (visible en `GET /api/system/logs`) y envía una alerta camuflada por los canales configurados. Con `--autoblock` además bloquea en la capa HTTP las IPs externas (`ingress`) con alertas ≥ high. **Está desactivado por defecto** porque la IP de origen de un paquete ICMP se puede falsificar: un atacante podría hacer que bloquees a una IP inocente. **Nunca bloquea nada en `egress`**: la IP es la propia máquina y lo que hay que hacer es aislarla e investigar.

Servicio systemd para el monitor (usuario propio con solo la capacidad de captura):

```ini
[Service]
User=icmpmon
WorkingDirectory=/opt/secure-server
ExecStart=/usr/bin/node scripts/icmpMonitor.js --interface eth0
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
Restart=always
```

### Despliegue recomendado

1. `npm run icmp-firewall` (dry-run) y revisa las reglas con tus destinos reales.
2. Ejecuta `icmp-monitor` unos días con `--dry-run` y ajusta la `--allowlist` si alguna herramienta de monitoreo legítima genera alertas (algunas usan payloads propios).
3. Aplica el firewall (`--apply`) y activa el monitor como servicio.
4. Endurece el proceso (sin root, sin `NET_RAW`, `ping_group_range`) hasta que `networkPosture.hardened` sea `true`.

### Capa 4 — El servidor no puede lanzar `ping`

Para ejecutar `ping -p` desde el servidor, el atacante primero necesita ejecución de comandos. Por eso `src/` **no usa `child_process`** y un test (`npm run test:icmp`) falla si alguien lo añade. Única excepción, verificada por el mismo test: `src/crypto/kms.js` lanza `process.execPath` con el script fijo `kms-worker.js` (sin shell ni argumentos variables; los datos van por stdin) para mantener síncrono el arranque. Si algún día necesitas ejecutar un proceso, hazlo en un servicio aparte con sus propios permisos. El monitor (`scripts/`) sí lanza `tcpdump`, con argumentos fijos y sin shell.

### Límites que conviene conocer

- **Es heurístico.** Detecta el uso de `ping -p` y herramientas parecidas; no demuestra que no haya exfiltración. Un atacante que envíe pings con el payload estándar y codifique datos en otros campos (`id`/`seq`) o en los tiempos entre pings no queda cubierto por el análisis de payload; el firewall de la capa 1 sí limita ese canal por tasa y destino.
- **Solo ICMP.** La exfiltración por DNS, HTTP(S) u otros protocolos necesita su propia vigilancia de salida (un firewall con política de salida denegada por defecto es la base).
- **El ancho de banda del ataque es mínimo** (≤ 16 bytes por ping): con el firewall limitando a 6 pings/min hacia destinos de confianza, un archivo de 1 MB tardaría más de 7 días en salir… si el atacante tuviera a dónde enviarlo.
- **Qué está probado.** `npm run test:icmp` (24 tests, sin privilegios) cubre el análisis, el detector, el parser y el monitor sobre capturas sintéticas. El firewall se verificó en un namespace de red aislado con paquetes ICMP reales (pasa lo permitido, descarta tamaño excesivo y destinos no autorizados). **La captura en vivo con `tcpdump` y los payloads estándar de cada sistema operativo no se han probado contra tráfico real**: valida con una captura tuya (`--dry-run`) antes de confiar en las alertas.

---

## 🔄 Rotación de claves, migración de datos y backups

### ⚠️ Leer primero: las claves cambiaban cada día

Hasta ahora las claves de cifrado se derivaban de `BASE_SEED` **y de la fecha UTC de hoy**. Un dato cifrado un martes no se podía descifrar el miércoles (se comprobó: `Error en triple descifrado`), y los JWT dejaban de valer a medianoche aunque duraran 5 días. Para que cualquier rotación tenga sentido las claves tienen que ser **estables** hasta que decidas rotarlas. Ahora lo son si defines `KEY_EPOCH`:

| Variable | Qué es | ¿La cambia la rotación? |
|----------|--------|-------------------------|
| `KEY_EPOCH` | Etiqueta de la generación de claves (p. ej. `E20261101T020000Z`). **Su presencia activa el modo estable.** | Sí |
| `ENCRYPTION_SEED` | Semilla de la clave de cifrado de datos | Sí |
| `JWT_SEED` | Semilla del secreto de los JWT | Sí |
| `BASE_SEED` | Sal de `users.username_hash` (búsqueda de login) y parte de todas las claves | **No**: cambiarla invalidaría todos los hashes de login |

Sin `KEY_EPOCH` el sistema sigue en **modo legacy** (comportamiento anterior, claves diarias) para no romper instalaciones existentes. `npm run rotate-keys -- status` te dice en qué modo estás.

**Si ya tienes datos cifrados (modo legacy), migra así:**

```bash
# 1. Esquema: marcador de claves y columna de auditoría (esta última arregla además un bug, ver abajo)
mysql ... < database/migrations/002_crypto_meta.sql
mysql ... < database/migrations/003_security_logs_encrypted_timestamp.sql
# 2. Copia de seguridad de la BD y del .env con tus herramientas habituales (mysqldump...)
# 3. Ensayo: busca la clave de cada fila en los últimos 30 días SIN cambiar nada
npm run rotate-keys -- analyze --legacy-scan-days 30
# 4. Migración real a claves estables
npm run rotate-keys -- rotate --confirm --legacy-scan-days 30
```

Cada fila se prueba primero con las claves de la fecha de sus propias marcas de tiempo (±1 día) y después hacia atrás desde hoy. Si alguna fila se cifró con una clave anterior al rango, **toda la migración aborta sin cambiar nada** y te dice qué fila (`tabla.columna`, `id`) para que amplíes `--legacy-scan-days` o la repares.

> **Bug corregido de paso:** `security_logs.encrypted_timestamp` era `DATETIME` pero el código guarda ahí texto cifrado. En MySQL/MariaDB en modo estricto (el predeterminado) **cada evento de auditoría de `auth.controller` se perdía en silencio** (`Incorrect datetime value`; en una prueba con el servidor real se perdieron 26 eventos en unos minutos). La migración 003 lo pasa a `LONGTEXT`.

### Qué hace una rotación

```bash
npm run rotate-keys -- rotate --confirm
```

| # | Paso | Detalle |
|---|------|---------|
| 1 | **Cierre** | Lock de mantenimiento: todos los procesos del servidor responden `503` (incluido `/health`) y dejan de ejecutar tareas que escriben. Lock en la BD (`GET_LOCK`) contra rotaciones concurrentes. Todas las sesiones se expiran. Espera `--drain` s (10) a las peticiones en curso |
| 2 | **Backup previo** | Snapshot de **toda** la BD → comprimido → cifrado con la **clave anterior** → releído y verificado antes de seguir |
| 3 | **Backups viejos** | Los backups de meses anteriores se re-cifran con la **clave nueva** (sin descomprimirlos) |
| 4 | **Re-cifrado** | Todas las columnas de `encrypted-columns.js`, en **una transacción**: se descifra con la clave antigua y se cifra con la nueva **en memoria**; se verifica cada valor |
| 5 | **Confirmación en dos fases** | Lo que debe cambiar de sitio (backups, keyring, `.env`) se prepara en temporales **antes** del `COMMIT` y se renombra **después**. Un journal registra la fase |
| 6 | **Barrido y reapertura** | Un último pase re-cifra cualquier valor que un proceso rezagado escribiera con la clave antigua; el nuevo `.env` queda activo, se recargan las claves y se quita el lock |

El servidor (si está corriendo) se reabre solo: cada 5 s comprueba el lock y compara la huella de su clave en memoria con la de `crypto_meta`; si no coinciden recarga el `.env`, y si aun así no coinciden **se niega a atender** (`503 KEYS_OUT_OF_SYNC`) en lugar de escribir datos con una clave equivocada. En una prueba con el servidor real, durante una rotación de 12 s hubo `503` desde el cierre hasta ~3 s después de terminar el CLI, **0 respuestas 5xx**, y tras ella el mismo login, las notas anteriores y las nuevas funcionaron.

### Decisiones de diseño (y por qué no es exactamente lo que se describió)

**Sobre "cerrar la red y el PC".** Se implementan dos capas: el **modo mantenimiento** de la aplicación (503 a todo) y, opcionalmente, un **bloqueo de red** con `--lockdown-firewall`, que descarta las conexiones *entrantes nuevas* salvo loopback, conexiones ya establecidas y tus IPs de administración (`MAINTENANCE_ADMIN_IPS`). No se apaga ni se bloquea la máquina: sin acceso del administrador no se podría vigilar, completar ni deshacer la migración. El script se niega a aplicarse sin IPs de administración, y las reglas se quitan solas pasados `--firewall-ttl` minutos (120) aunque el proceso muera.

**Sobre "pasar a datos no cifrados y borrar los registros no cifrados".** El texto plano **nunca se escribe en disco ni en logs**: se descifra y se vuelve a cifrar en memoria, valor a valor. No hay nada que borrar después, que es más seguro que borrarlo: en SSD, sistemas de archivos con journaling o copias de seguridad del hosting, "borrar" un archivo no destruye su contenido. (Node no puede garantizar poner a cero los strings en memoria; el proceso es corto y no vuelca nada.) Además se retiraron de los logs valores que se imprimían en claro: fragmentos de la URL de la BD, contraseñas de email y tokens (`credential-builder`/`database`), y nombres de usuario (`auth.controller`, `secure-auth.service`).

**Sobre el backup "comprimido al máximo".** Se comprime con **brotli (calidad 11)** y **gzip (nivel 9)** y se guarda el que menos ocupe. No se usa ZIP ni RAR: ZIP/deflate comprime peor que brotli y RAR es un formato propietario sin soporte en Node. Dos detalles importantes:
- **Se comprime antes de cifrar**, porque el texto cifrado no se comprime (parece aleatorio).
- **No se usa `tripleEncryptor` para el archivo**: devuelve texto hex y cada nivel vuelve a pasar a hex la salida del anterior, así que la salida llega a ocupar ~8 veces la entrada. El archivo usa **una capa AES-256-GCM binaria** (28 bytes de sobrecarga) con la cabecera autenticada: cambiar un solo byte hace que falle el descifrado. En las pruebas, 2 000 filas repetitivas ocupan menos de la quinta parte comprimidas y cifradas, y la BD de ejemplo pasa de 10,4 KB a 1,4 KB.

**El backup guarda las columnas cifradas ya descifradas** (el archivo completo sí va comprimido y cifrado). Si dentro hubiera texto cifrado con la clave antigua, cada backup necesitaría esa clave para siempre, y "re-cifrarlo con la clave nueva" solo cambiaría la capa de fuera. Así, una sola clave abre cualquier backup.

### La cadena de backups

El backup de cada rotación (semanal por defecto; la tabla usa meses como ejemplo) se cifra con la clave que acaba de dejar de ser la vigente ("copia de esas claves"), y **al mes siguiente se re-cifra con la nueva**. Para poder hacerlo, la clave anterior se guarda en `backups/keyring.json`, **envuelta con la clave actual**:

| Tras la rotación de… | Backup de ene | Backup de feb | Backup de mar | Keyring (guarda…) |
|----------------------|---------------|---------------|---------------|-------------------|
| **Enero** (K0→K1) | clave **K0** | | | K0, envuelta con K1 |
| **Febrero** (K1→K2) | clave **K2** | clave **K1** | | K1, envuelta con K2 |
| **Marzo** (K2→K3) | clave **K3** | clave **K3** | clave **K2** | K2, envuelta con K3 |

Con **solo la clave actual** (más el keyring) se abre cualquier backup, y no queda ninguna clave antigua suelta en disco. Si rotas porque la clave anterior **se ha comprometido**, usa `--backup-key new`: el backup de este mes también se cifra con la clave nueva (de lo contrario seguiría abierto para quien tenga la antigua hasta el mes siguiente).

### Uso

```bash
npm run rotate-keys -- status                   # modo de claves, lock, journal, backups
npm run rotate-keys -- analyze                  # ensayo: ¿se puede descifrar todo? (no cambia nada)
npm run rotate-keys -- rotate --confirm         # rotación completa
npm run rotate-keys -- rotate --confirm --lockdown-firewall   # + bloqueo de red (root y MAINTENANCE_ADMIN_IPS)
npm run rotate-keys -- backups                  # lista de backups (tamaño, algoritmo, época, filas)
npm run rotate-keys -- verify backups/<archivo>.sbk
npm run rotate-keys -- restore backups/<archivo>.sbk --confirm RESTORE [--tables users,user_notes]
```

Opciones de `rotate`: `--no-write-env`, `--backup-key old|new`, `--drain N`, `--legacy-scan-days N`, `--keep-backups N` (en el CLI por defecto se conservan **todos**), `--firewall-ttl N`, `--no-notify`, `--env-file ruta`. La cabecera de `scripts/rotateKeys.js` las documenta.

**Rotación automática (semanal):** con `AUTO_ROTATION_ENABLED=true` el servidor descifra y vuelve a cifrar **todos** los datos con claves nuevas **cada domingo a las 02:00 (México)** dentro de su propio proceso (`KEY_ROTATION_CRON`, cron de 5 campos, y `KEY_ROTATION_TZ` lo cambian). Conserva **8 backups** (≈ 2 meses; `BACKUP_RETENTION=N`, 0 = todos). Se niega a programarla con una expresión cron inválida o con claves `legacy` (sin `KEY_EPOCH`). Requiere un `.env` escribible y **una sola instancia** con esa variable activa. Alternativa más conservadora: déjala en `false` y programa `npm run rotate-keys -- rotate --confirm` con cron/systemd.

**Mientras rota no entra ni sale nada:** las peticiones nuevas reciben `503 MAINTENANCE` (salvo `/health`, que dice "el proceso vive" para que un orquestador no reinicie el contenedor a mitad; `/health/ready` sí da 503); los streams en vivo se cierran al momento y cualquier otra conexión abierta (descargas o subidas largas) se corta a los 4 s (`MAINTENANCE_CUT_MS`), antes de que termine la espera de 10 s de la rotación. Hacia fuera: ni webhooks de alertas, ni evaluación de alertas, ni limpieza, ni correos; la única excepción es el aviso de que la rotación **falló** (texto fijo, sin detalles internos), porque si no nadie sabría que el servidor sigue cerrado. Las demás alertas se guardan en `NOTIFICATIONS_DIR` y no se reenvían. Con la rotación por CLI en Linux, `--lockdown-firewall` cierra además la red salvo `MAINTENANCE_ADMIN_IPS`.

**Qué supone rotar cada semana:** se cierran **todas las sesiones** (cambia la semilla de los JWT: todo el mundo vuelve a iniciar sesión), el servidor está cerrado lo que dure la rotación (75 s para una BD de 83 MB, ver abajo) y los **bytes de los archivos no se re-cifran**: solo se re-envuelve la clave de cada archivo.

**Claves en el panel del hosting (sin `.env` escribible):** usa `--no-write-env`. La rotación re-cifra los datos pero no toca el `.env`: deja las variables nuevas en `data/rotation/new-env-*.txt` (permisos 600) y **el servidor sigue cerrado**. Aplica `ENCRYPTION_SEED`, `JWT_SEED` y `KEY_EPOCH` en el panel, reinicia, ejecuta `npm run rotate-keys -- finish` (comprueba que coinciden con la BD antes de reabrir) y borra ese archivo.

`/api/system/rotate-keys` ya **no** lanza la rotación por HTTP (responde `501`): una operación que bloquea el servidor y reescribe el `.env` no debe depender de una petición web. `GET /api/system/rotation` (admin) muestra el estado y los backups, sin claves ni datos.

### Si algo falla

| Dónde falló | Estado | Qué ocurre |
|-------------|--------|------------|
| Antes del `COMMIT` (dato ilegible, disco lleno, error de BD…) | La BD **no cambió** | Rollback, se borran los temporales, se quita el lock y el servidor se reabre con las claves anteriores. El backup ya creado se conserva |
| `COMMIT` ambiguo (se pierde la respuesta) | Puede que la BD sí confirmara | **No** se deshace a ciegas: se pregunta a la BD por la huella; si confirmó, se trata como confirmado |
| Después del `COMMIT` | La BD ya usa las claves nuevas | Sigue **cerrado**; `npm run rotate-keys -- recover` termina de colocar los archivos y reabre |
| El proceso muere | Lock y journal quedan en `data/rotation/` | Sigue cerrado (el lock **no caduca solo**); `recover` decide según la huella de la BD si termina o deshace. Al arrancar, el servidor envía el aviso de rotación fallida si el proceso que la hacía ya no existe |
| El proceso se queda parado (equipo suspendido) | La BD corta sus conexiones: deshace la transacción y suelta el cerrojo | Al despertar la rotación falla y se deshace sin cambiar nada; antes de confirmar comprueba que **sigue teniendo** el cerrojo de la BD (si lo perdió, otras máquinas podrían haberse reabierto) |
| `recover` sin poder preguntar a la BD | No se sabe si confirmó | **No decide**: no borra las semillas nuevas (`.env.pending`) ni reabre; repetir cuando la BD responda |

Mantener el servidor cerrado ante la duda es deliberado: reabrirlo a medias de una migración corrompería datos.

### Restaurar un backup

`restore` sustituye el contenido de las tablas por el del backup (en una transacción), re-cifrando con la clave **actual**, aunque el backup sea de otra época. Bloquea el servidor mientras dura y cierra las sesiones. Omite `crypto_meta` y `user_sessions`. Usa `--tables` para restaurar solo algunas. Pruébalo con `verify` antes de necesitarlo de verdad.

### Si añades tablas o columnas cifradas

**Registra cada columna que guarde datos cifrados con `tripleEncryptor` en `src/crypto/encrypted-columns.js`.** La rotación solo re-cifra lo registrado: lo que falte quedaría cifrado con una clave que ya no existe (irrecuperable). `npm run test:rotation` falla si `database/schema.sql` tiene una columna de texto con "encrypted" en el nombre que no esté registrada. Esto está también en la guía "Cómo crear una API nueva".

### Límites y qué está probado

**Probado** (`npm run test:rotation`: 48 pruebas; se omiten si no hay BD, y entonces las suites salen "verdes" con pruebas omitidas: comprueba que `skipped` sea 0):
- Contra **MariaDB 10.11 y MySQL 8.0.46 reales** (las tres suites: 82/82 en cada motor, 0 omitidas): rotaciones encadenadas, backups por mes, fallos antes/durante/después del commit, `COMMIT` ambiguo, `recover`, migración legacy, restauración, guardián y CLI. Los tests se verificaron con mutaciones deliberadas.
- **`kill -9` en 44 instantes aleatorios** de la rotación (prueba manual de oct-2026; incluido justo tras el commit y durante la liberación del lock): en todos, tras `recover`, los datos íntegros y legibles, huella coherente, lock liberado y sin temporales sueltos.
- **En la suite automática** (`test/test_rotation.js`, proceso hijo real): muerte con la transacción abierta, justo tras el `COMMIT` de la BD (con el journal aún en `PREPARED`) y a mitad de colocar los archivos; rotación parada a la que la BD corta las conexiones; pérdida del cerrojo antes de confirmar; `recover` sin BD. Y el bloqueo de entradas y salidas durante el mantenimiento.
- **Escrituras concurrentes**: con el servidor real y 8 escritores durante la rotación (≈63 000 peticiones), 0 escrituras confirmadas perdidas o corruptas y 0 respuestas 5xx.
- **El job programado real** (`executeScheduledRotation`, semanal por defecto) y el servidor real (login, notas, endpoints de administrador).

**Rendimiento medido** (no estimado): una BD de **83 MB** (30 000 filas, 70 000 valores cifrados) tardó **75 s** en rotar, con el servidor cerrado todo ese tiempo, y el proceso llegó a **593 MB de RAM** (≈7 veces el tamaño de la BD, porque el snapshot y su compresión van en memoria). Extrapolando de forma lineal, 1 GB de datos serían ≈15 min de cierre y ≈7 GB de RAM: **este diseño sirve para bases de datos de decenas o pocos cientos de MB**, no para bases grandes. Con carga concurrente el tiempo se multiplica (58 s en lugar de 5 s en una BD pequeña).

**No probado:**
- Bases de datos grandes (>100 MB), y varias máquinas reales compartiendo la BD (solo se probó el mecanismo con el lock de la BD, no un despliegue multi-host).
- Que el firewall de mantenimiento bloquee tráfico externo real (se verificó que las reglas se aplican, son idempotentes y se retiran en un entorno de red aislado).
- La ejecución automática con el reloj real (domingo 02:00): se prueba el job y el planificador, no la espera hasta el domingo. La fecha de la próxima ejecución no se calcula: `node-cron` 4.2 la da mal para expresiones semanales.
- El flujo `--no-write-env` con un panel de hosting real (se probó con las variables aplicadas a mano en el test).

**Cosas a tener en cuenta:**
- **Ningún proceso con un `.env` distinto debe escribir en la misma BD** (un script lanzado con otras claves, o con claves legacy): deja datos que la rotación no puede descifrar. La rotación aborta sin cambiar nada y el mensaje indica el registro; si es regenerable (`server_integrity`) se puede borrar, si no, hay que restaurarlo.
- **Varias máquinas**: el guardián ve también el lock de la BD (`GET_LOCK`), así que todas se cierran durante la rotación; las que no tengan las claves nuevas después se quedan en `503 KEYS_OUT_OF_SYNC`. Aun así, lo recomendable es una sola instancia con `AUTO_ROTATION_ENABLED=true`.
- `recover` se niega si hay una rotación en curso (comprueba que el pid del lock siga vivo en esa máquina) y no toca locks de otro host sin `--force`.
- **Corregido después:** en `production` la conexión a la BD verifica el certificado (`DB_SSL=verify` por defecto) y ya no cae en silencio a una conexión sin cifrar (ver `docs/SEGURIDAD.md` §1).
- El límite de 10 peticiones/min **por IP** en login/registro (y en las operaciones de `highSecurity`) es **un único contador compartido**: varios usuarios detrás de la misma IP (una oficina, un NAT) se bloquean entre sí, y un atacante puede dejar sin login a toda esa IP. Es comportamiento previo.

---

## 🚀 Despliegue y comandos útiles

### Producción

- **Imagen**: `Dockerfile` (solo dependencias de producción, usuario sin privilegios, `HEALTHCHECK` real con `npm run health-check`). Varias réplicas: [`deploy/docker-compose.yml`](deploy/docker-compose.yml) (nginx + MariaDB + SeaweedFS como S3), probado en el CI (job `compose`).
- **Sin Docker**: `npm ci --omit=dev` y `npm run start:cluster` bajo systemd/PM2 (nunca `npm run dev` en producción: se niega con `NODE_ENV=production`).
- **Configuración**: solo por variables de entorno o un `.env` fuera del repositorio (plantilla: `.env.example`); secretos envueltos con el KMS (`npm run kms -- migrate-env`).
- **Delante**: TLS en el balanceador, `TRUST_PROXY`, sondas a `/health/ready`, y la interfaz web en otra máquina o detrás de VPN/SSO (`web/README.md`).

### Comandos

```bash
npm run health-check                      # ¿esta instancia está lista? (consulta /health/ready)
npm run rotate-keys -- status             # rotación de claves (ver la sección de rotación)
npm run rotate-keys -- rotate --confirm
npm run kms -- status                     # secretos envueltos con el KMS
npm run events:partition -- status        # particionado mensual de security_events (opcional)
npm run files:backup                      # copias de FILES_DIR (con FILES_STORAGE=s3: versionado del bucket)
npm run set-role -- --user-id 1 --role admin
npm run security-audit                    # auditoría de configuración (puntuación calculada, no declarada)
npm run lint:security                     # análisis estático (0 avisos)
npm run test:all                          # todas las pruebas (MariaDB)
npm run coverage                          # cobertura con umbral
npm run test:icmp && npm run icmp-firewall   # defensa ICMP (firewall en modo ensayo)
```

---

## 🔐 Características de seguridad

✅ **Cifrado autenticado AES-256-GCM** (`v4`, clave por HKDF) en campos; **cifrado por archivo y por bloques** con clave propia; KMS opcional  
✅ **Rotación de claves con migración de datos**, backups (semanales) comprimidos y cifrados, recuperación ante fallos  
✅ **Estado de seguridad en MySQL** (bloqueos, límites, intentos, eventos): sobrevive a reinicios y lo comparten todas las réplicas  
✅ **Sesiones cortas** (JWT 15 min) con refresh rotatorio, detección de reutilización y «cerrar todas»  
✅ **MFA**: TOTP, passkeys (WebAuthn) y códigos de recuperación; **SSO** OpenID Connect y SAML 2.0  
✅ **Roles finos** y **aprobación de dos administradores** para acciones sensibles  
✅ **Archivos seguros**: tipo por contenido, antivirus, imágenes recodificadas, PDF sin contenido activo; disco local o S3  
✅ **Detección de inyecciones** (bloqueo en rutas críticas) sobre consultas siempre parametrizadas  
✅ **Operación**: alertas automáticas, panel, métricas, trazas, novedades en vivo, datos personales exportables y borrables  
✅ **Interfaz web** solo para administradores con BFF: los tokens nunca llegan al JavaScript del navegador  
✅ **Escalabilidad**: cluster, líder único, varias réplicas, réplica de lectura y particionado de eventos (opcionales)  
✅ **Defensa contra exfiltración por ICMP** (`ping -p`): firewall, detector de patrones y postura de red  
✅ **CI endurecido**: CodeQL, gitleaks, SBOM, ZAP, Semgrep con reglas propias, fuzzing, cobertura y pruebas de extremo a extremo en tres navegadores  

Lo que **no** está y los límites de cada pieza: [`docs/SEGURIDAD.md` §22](docs/SEGURIDAD.md#22-límites-y-pendientes-sin-humo).
