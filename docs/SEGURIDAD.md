# Seguridad, archivos y análisis de anomalías

Guía de lo que cambió en esta versión, cómo funciona, cómo se opera y **qué NO cubre**. Todo lo que
aquí se afirma está comprobado por las pruebas del repositorio (`npm run test:all`, contra MariaDB
real); donde algo no se puede garantizar desde el código, se dice.

- [1. Qué cambió](#1-qué-cambió)
- [2. Cifrado v4](#2-cifrado-v4)
- [3. El estado de seguridad vive en tablas](#3-el-estado-de-seguridad-vive-en-tablas)
- [4. Anti-inyección](#4-anti-inyección)
- [5. API de archivos](#5-api-de-archivos)
- [6. Analizar anomalías después](#6-analizar-anomalías-después)
- [7. Variables de entorno](#7-variables-de-entorno)
- [8. Migrar una instalación existente](#8-migrar-una-instalación-existente)
- [9. Rendimiento medido](#9-rendimiento-medido)
- [10. MFA y SSO](#10-mfa-y-sso)
- [11. KMS: secretos envueltos](#11-kms-secretos-envueltos)
- [12. Antivirus](#12-antivirus)
- [13. Copias de `FILES_DIR`](#13-copias-de-files_dir)
- [14. Pentest, análisis estático y certificaciones](#14-pentest-análisis-estático-y-certificaciones)
- [15. Sesiones cortas con renovación y «cerrar todas»](#15-sesiones-cortas-con-renovación-y-cerrar-todas)
- [16. Roles finos y aprobación de dos administradores](#16-roles-finos-y-aprobación-de-dos-administradores)
- [17. Passkeys (WebAuthn) y SAML 2.0](#17-passkeys-webauthn-y-saml-20)
- [18. Archivos: imágenes recodificadas, PDF sin contenido activo y claves de archivo en el KMS](#18-archivos-imágenes-recodificadas-pdf-sin-contenido-activo-y-claves-de-archivo-en-el-kms)
- [19. Operación y observabilidad (solo admin)](#19-operación-y-observabilidad-solo-admin)
- [20. Pruebas, cobertura y fuzzing](#20-pruebas-cobertura-y-fuzzing)
- [21. CI y producción (sin nodemon)](#21-ci-y-producción-sin-nodemon)
- [22. Límites y pendientes (sin humo)](#22-límites-y-pendientes-sin-humo)

---

## 1. Qué cambió

| Antes | Ahora |
|---|---|
| "Triple cifrado" con **la misma clave** en las 3 capas | Un solo **AES-256-GCM** (formato `v4`) con clave derivada por HKDF; lo antiguo sigue leyéndose |
| Los 3 niveles volcaban a consola IV, etiqueta, hash de clave y trozos de texto cifrado | **No se escribe nada** de eso en ningún log |
| El **bloqueo de cuenta nunca funcionaba** (guardaba `usuario_IP`, consultaba `usuario`) | Funciona, en la base de datos, también para usuarios inexistentes |
| Límite de peticiones, IP bloqueadas, intentos y anomalías en `Map`/`Set` **en memoria** | Todo en **tablas MySQL**: sobrevive a reinicios, se comparte entre procesos y se puede consultar |
| Sin `trust proxy`: detrás de un proxy todos los usuarios eran "la misma IP" | `TRUST_PROXY`; IPv6 se agrupa por /64 |
| TLS a la BD con `rejectUnauthorized: false` y caída silenciosa a sin cifrar | Se verifica el certificado en producción; sin caída silenciosa |
| Riesgo de login contaba los fallos de **toda la plataforma** | Cuenta los de **ese usuario** |
| El login respondía más rápido si el usuario no existía | Siempre una comparación bcrypt |
| JWT sin fijar algoritmo | `HS256` fijado y token ligado a su sesión |
| Sin API de archivos | `/api/files` (imágenes, vídeo, audio, PDF, texto), cifrada en disco |
| Scripts `maximize-score.js` / `final-boost-to-100.js` / `quick-fix.js` | Eliminados (inflaban un "100/100" auto-declarado; `quick-fix.js` además reescribía el código con la versión antigua) |
| `npm audit` (producción): 3 vulnerabilidades | **0** (`geoip-lite` 2.0.3) |

---

## 2. Cifrado v4

Formato de cada campo cifrado en BD: `v4:<base64(iv[12] | etiqueta[16] | texto cifrado)>`.

- **AES-256-GCM**, IV aleatorio de 96 bits por mensaje, AAD fijo que liga el mensaje a este formato.
  Un bit alterado ⇒ el descifrado falla (probado en IV, etiqueta y datos).
- **Clave de campo derivada con HKDF-SHA256** de la clave maestra (`info = secure-server/v4/field-encryption`).
- **Compatibilidad**: lo cifrado con el formato de tres capas sigue descifrándose. La **próxima rotación
  de claves** (`npm run rotate-keys`) lo re-cifra todo en v4 (probado con la rotación real).
- Límite a tener presente: con IV aleatorio de 96 bits conviene no pasar de ~2³² mensajes con la misma
  clave. La rotación periódica existe, entre otras cosas, para eso.

> **Por qué solo una capa.** Las tres capas anteriores usaban la misma clave. Apilar cifrados con la
> misma clave no suma seguridad: quien tiene la clave descifra las tres. Una capa autenticada, bien
> hecha, es más simple, más rápida y no menos segura.

**Lo que sigue sin resolver el código**: la clave maestra se deriva de semillas en el entorno
(`BASE_SEED`, `ENCRYPTION_SEED`, `KEY_EPOCH`). Quien comprometa el servidor y lea el entorno, tiene las
claves. Para separar eso hace falta un KMS/HSM (AWS KMS, Vault…) y es una decisión de infraestructura.

---

## 3. El estado de seguridad vive en tablas

Nada de lo que decide si dejas pasar una petición está en memoria del proceso.

| Tabla | Para qué |
|---|---|
| `security_events` | **Tabla de análisis**: una fila por evento sospechoso (en claro, consultable con SQL; sin contraseñas ni tokens) |
| `rate_limit_counters` | Contadores por ventana, atómicos entre procesos (`INSERT … ON DUPLICATE KEY UPDATE`) |
| `login_attempts` | Intentos de login (éxito/fallo) por hash de usuario e IP |
| `blocked_ips` | Bloqueos, **progresivos**: 1 h, 2 h, 4 h… hasta 7 días |
| `security_logs` | Auditoría **cifrada** (lo confidencial) |

**Orden de comprobaciones de cada petición** (`src/middleware/protection.middleware.js`):

1. IP bloqueada → `403 IP_BLOCKED`
2. Límite global por IP (ventana deslizante de 60 s) → `429`; si se multiplica por 3 → bloqueo
3. Rutas de escáner (`/.env`, `/wp-admin`, `/.git/`…) → se registran; 5 seguidas → bloqueo
4. Firmas de inyección → rechazo + evento + "strike"; 5 strikes en 10 min → bloqueo
5. Ráfaga de `401`/`403` desde una IP (30 en 10 min) → bloqueo
6. `/health` no toca la BD (un balanceador puede comprobar que el proceso vive)

**Falla cerrado**: si la BD de seguridad no responde, la API contesta `503`, no deja pasar sin comprobar.

**Bloqueo de cuenta** (diseñado para que NO se pueda usar contra el dueño de la cuenta):

1. **Por (usuario, origen)**: 5 fallos desde una misma IP (o /64 en IPv6) en 15 min bloquean *esa combinación*
   (`429 ACCOUNT_LOCKED` con `Retry-After`, aunque la contraseña sea correcta). Quien ataca desde una IP solo
   se bloquea a sí mismo; el dueño, desde su sitio, sigue entrando.
2. **Global por usuario**: 20 fallos sumando todos los orígenes (ataque distribuido) bloquean a los orígenes
   **desconocidos** de ese usuario. Un **origen de confianza** (login correcto desde él en los últimos 30 días) no
   se ve afectado, y un login legítimo reinicia el contador.
3. Un **administrador** puede liberar la cuenta (`POST /api/system/accounts/unlock`); esa liberación no convierte
   a nadie en origen de confianza.

Mientras algo está bloqueado no se registran más intentos (si no, el bloqueo se prolongaría para siempre). Se
comporta igual con usuarios que no existen. Muchos fallos desde una IP contra usuarios distintos (*credential
stuffing*) ⇒ bloqueo de la IP. Los códigos TOTP erróneos cuentan como fallos; acertar la contraseña de una cuenta con
MFA **no** reinicia el contador (si lo hiciera, quien la conoce podría probar códigos sin límite).
*Residual honesto*: si un ataque distribuido se dirige a una cuenta y su dueño entra por primera vez desde un
origen nuevo, esperará como máximo 15 min o pedirá la liberación a un administrador.

**Qué deja de hacer el detector antiguo**: se eliminaron "cambio de país" y "cambio de navegador" *por
IP* (una IP no cambia de país). Su versión con sentido, **por usuario**, está en el login
(`NEW_COUNTRY`, `NEW_DEVICE`, `IMPOSSIBLE_TRAVEL` → `security_events`).

**Limpieza** (`src/tasks/securityHousekeeping.js`, cada 10 min): borra contadores de >24 h, eventos más
viejos que `SECURITY_EVENTS_RETENTION_DAYS` (90), intentos de login de >30 días, sesiones caducadas y
temporales de subida huérfanos. Es mantenimiento, no estado de seguridad: reiniciar no abre nada.
Tope anti-inundación: como máximo `SECURITY_EVENTS_MAX_PER_MINUTE` (30) eventos por (IP, tipo) y minuto;
lo que excede deja una única fila `EVENTS_THROTTLED`.

---

## 4. Anti-inyección

Tres capas, de la más fuerte a la más débil:

1. **Prevención (lo que realmente impide la inyección SQL).** Toda consulta usa parámetros `?` y
   `mysql2.execute`, es decir, **sentencias preparadas en el servidor**: los valores viajan aparte del
   SQL y nunca se interpretan como SQL. `multipleStatements` está desactivado. Lo único que no admite
   parámetros (`LIMIT`/`OFFSET`) pasa por `sqlInt()`, que devuelve un entero o lanza una excepción.
   Una prueba (`no hay SQL con interpolación`) **recorre todo `src/` y falla** si alguien construye SQL
   con `${…}` que no sea `sqlInt()`/`sqlPlaceholders()`.
2. **Validación estricta.** `validate.body/query/params`: tipos, longitudes, enteros acotados, campos
   desconocidos descartados; `sanitize.middleware.js` rechaza `__proto__`/`constructor`/`prototype`,
   bytes NUL y anidamiento o tamaño desmesurados.
3. **Detección (señal y defensa en profundidad)** — `src/security/injection-detector.js`. Normaliza
   (decodifica `%xx` dos veces, Unicode `ＵＮＩＯＮ`, comentarios `UNION/**/SELECT`, `/*!50000UNION*/`) y
   aplica reglas de SQL, XSS, recorrido de rutas, comandos, JNDI/Log4Shell, CRLF, NUL y operadores
   NoSQL. Resistente a ReDoS (probado con entradas de megabytes).

Qué se **rechaza** y qué solo se **registra**:

| Dónde aparece | Severidad alta (`UNION SELECT`, `<script>`, `../`…) | Media (`select … from`, `javascript:`) |
|---|---|---|
| URL, query, params, cabeceras | **403** + evento + strike | solo evento |
| Cuerpo JSON | **400** + evento + strike (`INJECTION_BODY_MODE=block`) | solo evento |
| Cuerpo: `../` y comandos | solo evento (el servidor nunca usa el cuerpo como ruta ni comando) | — |

**Falsos positivos.** Texto normal ("Please select the file from the list", "O'Brien & Sons",
`a < b`) no se rechaza (probado). Pero una nota que contenga literalmente `' OR '1'='1` o
`<script>` **sí** se rechaza en modo `block`. Si tu app guarda código o artículos técnicos, pon
`INJECTION_BODY_MODE=log`: sigue registrando todo, pero ya no rechaza por el cuerpo — y la inyección
sigue siendo imposible por la capa 1 (hay una prueba que lo demuestra con el detector en ese modo).

**Lo que no hace**: no es un WAF, no sustituye a la capa 1 y no protege a quien *muestre* los datos:
el XSS se evita escapando al pintar en el cliente (la API responde `application/json` + `nosniff`).

---

## 5. API de archivos

`/api/files` — requiere JWT. Guarda **imágenes, vídeo, audio, PDF y texto**, cifrados en disco.

| Método | Ruta | Descripción |
|---|---|---|
| `POST` | `/api/files` | Sube **un** archivo (`multipart/form-data`, campo `file`). `201` con `id`, `name`, `mimeType`, `size`, `sha256` |
| `GET` | `/api/files?limit=&before=&category=` | Lista tus archivos, paginación por cursor (`nextBefore`) |
| `GET` | `/api/files/quota` | Tu uso y tus límites |
| `GET` | `/api/files/:id` | Metadatos |
| `GET` | `/api/files/:id/download[?inline=true]` | Descarga (soporta `Range` y `HEAD`) |
| `DELETE` | `/api/files/:id` | Borra fila **y** archivo del disco |

```bash
# subir
curl -H "Authorization: Bearer $TOKEN" -F "file=@foto.jpg" http://localhost:3000/api/files
# descargar (o con Range, para saltar en un vídeo)
curl -H "Authorization: Bearer $TOKEN" -o foto.jpg http://localhost:3000/api/files/1/download
curl -H "Authorization: Bearer $TOKEN" -H "Range: bytes=1000000-1999999" http://localhost:3000/api/files/2/download
```

**Cómo se reconoce el tipo.** Por los **primeros bytes del contenido** (*magic bytes*), nunca por la
extensión ni por el `Content-Type` que declara el cliente. La extensión debe coincidir con el
contenido (un JPEG llamado `.png` se rechaza).

| Categoría | Formatos | Máx. por defecto |
|---|---|---|
| image | JPEG, PNG, GIF, WebP, AVIF, HEIC | 25 MB |
| audio | MP3, M4A, WAV, OGG/Opus, FLAC, AAC | 100 MB |
| video | MP4, MOV, 3GP, WebM, MKV, AVI | 512 MB |
| document | PDF | 50 MB |
| text | `.txt` `.csv` `.md` `.json` `.log` (UTF-8 válido, sin NUL) | 5 MB |

**Se rechaza** (`415`/`400`/`413`, sin dejar fila ni archivo, y **queda un evento** `FILE_REJECTED`):

- ejecutables (PE, ELF, Mach-O, clases Java), scripts `#!`, comprimidos y ofimáticos (ZIP/DOCX/JAR, gzip, RAR, 7z);
- SVG, HTML, XML, PHP… **aunque se llamen `.txt`** (texto con etiquetas activas);
- nombres con extensión prohibida **en cualquier segmento** (`foto.php.jpg`, `a.exe`, `a.svg`…);
- nombres con `../`, `..\`, SQL, `<script>`, `${jndi:…}`; el nombre se limpia (sin ruta, sin controles,
  sin el carácter bidi `U+202E` que invierte la extensión visible, sin nombres reservados de Windows);
- tipo desconocido, extensión que no coincide con el contenido, tamaño por encima del máximo del
  **tipo real**, más de un archivo, campo distinto de `file`.

**Cómo se guardan.**

- Disco: `FILES_DIR/files/<aa>/<uuid>.enc`. El nombre en disco es un **UUID del servidor**: nada del
  usuario forma parte de la ruta. Permisos `0700`/`0600`. `FILES_DIR` debe estar **fuera** de cualquier
  carpeta que sirva un servidor web.
- Cada archivo se cifra **en streaming** (nunca entero en memoria) con su **propia clave aleatoria** de
  256 bits, en bloques de 64 KiB con **AES-256-GCM** y autenticación por bloque. Se autentica cada
  bloque *antes* de entregarlo; quitar, reordenar o alterar bloques se detecta (probado). El nombre
  original y la clave del archivo (envuelta con la clave maestra) van cifrados en la BD.
- **Rotación de claves**: solo hay que re-envolver las claves de archivo (están en `encrypted-columns.js`);
  **los bytes de los archivos no se tocan** (probado con la rotación real). Rotar no cuesta gigabytes.
- **Descarga**: `attachment` por defecto; `?inline=true` solo para imagen/audio/vídeo (PDF y texto
  siempre como descarga). Siempre `X-Content-Type-Options: nosniff`,
  `Content-Security-Policy: default-src 'none'; sandbox`, `Cache-Control: private, no-store, no-transform`.
  El `Content-Type` lo fija el servidor según el contenido verificado al subir.
- **Cuotas y límites**: `UPLOAD_USER_QUOTA_MB` (1 GB), `UPLOAD_MAX_FILES_PER_USER`, subidas por minuto y
  usuario. La cuota se comprueba dentro de una transacción con la fila del usuario bloqueada: subidas
  simultáneas no se la saltan (probado con 8 en paralelo).
- Una subida cortada a medias, un disco no escribible o un fallo de BD **no dejan nada** (ni fila ni
  archivo) y no tumban el proceso.
- Si alguien altera un archivo en disco, la descarga se corta y queda un evento **crítico**
  `FILE_INTEGRITY_FAILURE`.

**Lo que NO hace (importante):**

- **No es un antivirus.** Verifica que el archivo *es* lo que dice y que no es ejecutable/activo, pero
  un PDF malicioso o una imagen que explote un fallo de un visor siguen siendo archivos válidos. Si
  necesitas escaneo de malware, integra ClamAV u otro motor antes de `storage.commit`.
- No elimina metadatos (EXIF con GPS en fotos) ni recodifica imágenes.
- No incluye los archivos en los backups de BD: **haz copia de `FILES_DIR`** (siguen cifrados) junto
  con la de la base de datos; sin las dos no se pueden restaurar.
- Solo cuenta el tamaño al terminar la subida; un usuario con varias subidas simultáneas grandes puede
  ocupar disco temporal hasta que acaben o se corten (limitado por `UPLOAD_RATE_PER_MIN`).

---

## 6. Analizar anomalías después

Dos formas: por **API** (solo `role = admin`) o directamente por **SQL**.

```
GET /api/system/security-events?hours=24&type=INJECTION_ATTEMPT&rule=SQLI_UNION&severity=high&ip=1.2.3.4&userId=7&limit=100&before=<id>
GET /api/system/security-summary?hours=24
```

El resumen devuelve eventos por tipo y severidad, IPs más activas, reglas más disparadas, línea
temporal por hora e IPs bloqueadas activas. Tipos de evento: `INJECTION_ATTEMPT`, `RATE_LIMITED`,
`SCANNER_PATH`, `LOGIN_FAILED`, `LOGIN_BLOCKED`, `LOGIN_ANOMALY`, `IMPOSSIBLE_TRAVEL`, `IP_BLOCKED`,
`AUTH_FAILURE_BURST`, `FILE_REJECTED`, `FILE_INTEGRITY_FAILURE`, `EVENTS_THROTTLED`.

```sql
-- ¿Quién probó inyecciones en las últimas 24 h, y con qué?
SELECT ip_address, COUNT(*) AS intentos, GROUP_CONCAT(DISTINCT rule) AS reglas, MAX(created_at) AS ultimo
FROM security_events
WHERE event_type = 'INJECTION_ATTEMPT' AND created_at > NOW() - INTERVAL 24 HOUR
GROUP BY ip_address ORDER BY intentos DESC;

-- Cuentas con más fallos de login (por hash, el nombre real no se guarda en claro)
SELECT username_hash, COUNT(*) AS fallos, COUNT(DISTINCT ip_address) AS ips
FROM login_attempts WHERE success = 0 AND created_at > NOW() - INTERVAL 1 DAY
GROUP BY username_hash ORDER BY fallos DESC LIMIT 20;

-- IPs bloqueadas ahora mismo
SELECT ip_address, reason, blocked_until, block_count FROM blocked_ips WHERE blocked_until > NOW();

-- Logins raros: país nuevo, dispositivo nuevo, viaje imposible
SELECT created_at, user_id, ip_address, country, event_type, rule, risk_score
FROM security_events WHERE event_type IN ('IMPOSSIBLE_TRAVEL', 'LOGIN_ANOMALY') ORDER BY id DESC LIMIT 50;

-- Archivos rechazados, por motivo
SELECT rule, COUNT(*) AS total FROM security_events WHERE event_type = 'FILE_REJECTED' GROUP BY rule ORDER BY total DESC;

-- Actividad por hora (¿hay un pico?)
SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00') AS hora, severity, COUNT(*) AS total
FROM security_events WHERE created_at > NOW() - INTERVAL 3 DAY GROUP BY hora, severity ORDER BY hora;
```

---

## 7. Variables de entorno

Todas opcionales. Plantilla comentada en `.env.example`.

| Variable | Por defecto | Qué hace |
|---|---|---|
| `TRUST_PROXY` | — | Saltos de proxy delante (`1`, `2`, `loopback`, CIDR). **Defínela si hay proxy** |
| `PROTECTION_ALLOWLIST` | — | IPs que nunca se bloquean solas (el loopback ya está exento) |
| `DB_SSL` | `verify` en producción, `off` fuera | `verify` · `no-verify` · `off` |
| `DB_SSL_CA` | — | Ruta o PEM de la CA de la BD |
| `DB_POOL_SIZE` / `DB_QUEUE_LIMIT` | `10` / `500` | Conexiones y cola (acotada: bajo avalancha se rechaza) |
| `RATE_LIMIT_GLOBAL_PER_MIN` | `600` | Peticiones por IP y minuto |
| `SENSITIVE_RATE_LIMIT_PER_MIN` | `10` | Login/registro/tareas admin por IP y minuto |
| `INJECTION_STRIKES_TO_BLOCK` | `5` | Rechazos por inyección (10 min) antes de bloquear la IP |
| `INJECTION_BODY_MODE` | `critical` | `critical` (rechaza solo en `INJECTION_BLOCK_PATHS`) · `block` (en todas) · `log` (solo registra); ver §4 y §18 |
| `SCANNER_HITS_TO_BLOCK` / `AUTH_FAILURES_TO_BLOCK` | `5` / `30` | Umbrales de bloqueo |
| `MAX_FAILED_ATTEMPTS` / `LOCKOUT_WINDOW_SECONDS` | `5` / `900` | Bloqueo de cuenta |
| `LOGIN_IP_FAILURES_TO_BLOCK` | `20` | Fallos de login desde una IP antes de bloquearla |
| `ACCESS_TOKEN_MINUTES` / `REFRESH_IDLE_DAYS` / `SESSION_ABSOLUTE_DAYS` | `15` / `7` / `30` | Vida del JWT de acceso, inactividad máxima y tope absoluto de la sesión (§15). Sustituyen a `SESSION_TTL_HOURS` |
| `REFRESH_REUSE_GRACE_SECONDS` | `10` | Ventana en la que dos renovaciones simultáneas no se toman por un robo (§15) |
| `ADMIN_APPROVALS_REQUIRED` / `ADMIN_APPROVAL_TTL_HOURS` | `2` / `24` | Administradores que deben aprobar una acción crítica y caducidad de la solicitud (§16) |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGINS` / `WEBAUTHN_RP_NAME` / `WEBAUTHN_USER_VERIFICATION` | — / — / — / `preferred` | Passkeys; sin `RP_ID` y `ORIGINS` quedan desactivadas (§17) |
| `SAML_*` | — | SAML 2.0 (§17) |
| `IMAGE_SANITIZE` / `IMAGE_JPEG_QUALITY` / `IMAGE_MAX_PIXELS` / `IMAGE_SANITIZE_PASSTHROUGH` | `on` / `90` / `100000000` / — | Recodificación de imágenes (§18) |
| `PDF_ACTIVE_CONTENT` / `PDF_MAX_INFLATED_MB` / `SANITIZE_MAX_CONCURRENT` | `reject` / `64` / `4` | Inspección de PDF y concurrencia del saneador (§18) |
| `INJECTION_BLOCK_PATHS` | `/api/auth,/api/system,/api/sso` | Prefijos donde un hallazgo en el cuerpo SÍ rechaza la petición (§18) |
| `KMS_DATA_KEYS` / `KMS_DATA_KEY_CACHE_SECONDS` / `KMS_TIMEOUT_MS` | `false` / `300` / `30000` | Claves de archivo envueltas por el KMS (§18) |
| `ALERT_*`, `ALERTS_DISABLED`, `METRICS_TOKEN`, `OTEL_*`, `HOUSEKEEPING_INTERVAL_MINUTES` | ver §19 | Operación y observabilidad |
| `FUZZ_RUNS` / `FUZZ_SEED` | `100` / aleatoria | Solo pruebas: iteraciones y semilla del fuzzing (§20) |
| `SECURITY_EVENTS_RETENTION_DAYS` | `90` | Retención de `security_events` |
| `SECURITY_EVENTS_MAX_PER_MINUTE` | `30` | Tope de eventos por (IP, tipo) y minuto |
| `JSON_BODY_LIMIT` | `1mb` | Tamaño máximo de un cuerpo JSON |
| `FILES_DIR` | `./storage` | Dónde se guardan los archivos cifrados |
| `UPLOAD_MAX_{IMAGE,AUDIO,VIDEO,DOCUMENT,TEXT}_MB` | 25/100/512/50/5 | Máximo por categoría |
| `UPLOAD_USER_QUOTA_MB` / `UPLOAD_MAX_FILES_PER_USER` | `1024` / `5000` | Cuota por usuario |
| `UPLOAD_RATE_PER_MIN` / `DOWNLOAD_RATE_PER_MIN` | `20` / `600` | Por usuario y minuto |
| `REQUEST_TIMEOUT_MS` | `600000` | Tiempo máximo de una petición (subidas grandes) |

---

## 8. Migrar una instalación existente

1. `git pull && npm install`.
2. Aplica las migraciones **en orden** (las tres son idempotentes salvo la 006, ver su cabecera):
   ```bash
   mysql -u USER -p DB < database/migrations/004_security_analysis_tables.sql
   mysql -u USER -p DB < database/migrations/005_user_files.sql
   mysql -u USER -p DB < database/migrations/006_users_username_hash_unique.sql
   ```
   (Instalaciones nuevas: `database/schema.sql` ya lo incluye todo.) Si la 006 falla con
   *Duplicate entry*, hay usuarios duplicados que resolver antes (la consulta está en su cabecera).
3. **Si hay un proxy delante**, define `TRUST_PROXY` (sin él, todos los usuarios comparten IP).
4. **En producción** la conexión a la BD verifica el certificado. Si tu BD no usa TLS, pon
   `DB_SSL=off` *a conciencia* (el servidor avisa en el arranque).
5. Opcional pero recomendable: `npm run rotate-keys -- --confirm` para pasar todos los datos
   antiguos a v4 (el formato antiguo sigue funcionando mientras tanto).
6. Reinicia. Para ver el estado: `GET /api/system/status` (admin).

Nada de esto cierra sesiones ni invalida datos existentes; las contraseñas bcrypt no cambian.

---

## 9. Rendimiento medido

Misma máquina para todo (contenedor de 4 vCPU), `benchmarks/loadtest.js`, una sola IP cliente,
usuario con 300 notas (cada `GET /api/notes?limit=20` descifra 40 campos). **Una corrida por
celda: son órdenes de magnitud, no cifras de catálogo.**

| | `/health` (30 000 pet., 100 conex.) | `GET /api/notes?limit=20` (3 000 pet., 20 conex.) |
|---|---|---|
| Código anterior, protección desactivada | 2 459 req/s | 220 req/s · p50 88 ms |
| Código nuevo, protección desactivada | 2 981 req/s | 430 req/s · p50 45 ms |
| Código nuevo, **protección activa en MySQL** | 2 543 req/s | 350 req/s · p50 55 ms |

Lectura honesta: la protección en MySQL cuesta ~19 % de rendimiento en rutas con BD frente a
desactivarla, y aun así el conjunto es más rápido que el código anterior *sin* protección (se quitaron
decenas de `console.log` por operación de cifrado y el doble descifrado de verificación).
`/health` no usa la BD de seguridad, por eso apenas cambia. Cada petición protegida hace ~3
consultas por clave primaria; sube `DB_POOL_SIZE` si tu BD lo permite.

**Escalado horizontal**: ahora sí es posible (el estado es compartido). Varias instancias detrás de un
balanceador comparten límites, bloqueos y eventos; solo `FILES_DIR` debe ser **almacenamiento
compartido** (NFS/EFS/volumen) o todas las instancias deben ver el mismo disco. El cuello de botella
pasa a ser la base de datos.

---

## 10. MFA y SSO

### MFA (TOTP + códigos de recuperación)

Compatible con Google Authenticator, Microsoft Authenticator, Authy, 1Password, Bitwarden… (RFC 6238, verificado con los
vectores del RFC en `test_mfa.js`).

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/api/auth/mfa` | Estado (activo, alta pendiente, códigos de recuperación restantes) |
| `POST` | `/api/auth/mfa/setup` | Genera el secreto, la URL `otpauth://` y un QR |
| `POST` | `/api/auth/mfa/enable` `{otp}` | Activa MFA con un código válido y entrega **10 códigos de recuperación** (una sola vez) |
| `POST` | `/api/auth/login/mfa` `{mfaToken, otp \| recoveryCode}` | Segundo paso del login |
| `POST` | `/api/auth/mfa/disable` · `/mfa/recovery-codes` `{password, otp \| recoveryCode}` | Exigen contraseña **y** segundo factor |
| `POST` | `/api/system/accounts/mfa-reset` `{username}` | Admin: dispositivo perdido y sin códigos |

Login con MFA en dos pasos: `POST /api/auth/login` con la contraseña correcta devuelve `{mfaRequired: true, mfaToken}`
(**sin sesión**); `POST /api/auth/login/mfa` lo canjea por el token. El reto dura 5 min y **no vale como sesión**.

- El secreto TOTP va cifrado (v4) y la rotación de claves lo re-cifra; los códigos de recuperación solo se guardan como hash.
- Un código no se puede reutilizar (el paso de 30 s aceptado se guarda con un `UPDATE` atómico: 5 peticiones simultáneas con el
  mismo código ⇒ pasa una). Ventana de ±1 paso.
- `MFA_REQUIRED_FOR_ADMINS=true`: un administrador solo opera si inició sesión con segundo factor (o por SSO).
- Cada sesión lleva `amr` (`pwd`, `otp`, `recovery`, `sso`) para saber *cómo* se autenticó.

### SSO (OpenID Connect)

Authorization code + **PKCE**. Funciona con cualquier proveedor que publique `/.well-known/openid-configuration`
(Microsoft Entra ID, Okta, Auth0, Keycloak, Google Workspace…). Para SAML 2.0 ver el [§17](#17-passkeys-webauthn-y-saml-20).

| Variable | Qué hace |
|---|---|
| `SSO_ISSUER`, `SSO_CLIENT_ID`, `SSO_REDIRECT_URI` | Obligatorias (sin ellas `/api/sso/*` responde `404 SSO_NOT_CONFIGURED`). `SSO_REDIRECT_URI` = `https://tu-api/api/sso/callback` |
| `SSO_CLIENT_SECRET` | Cliente confidencial (recomendado) |
| `SSO_ALLOWED_EMAIL_DOMAINS` | Lista de dominios permitidos (`acme.com,partner.org`) |
| `SSO_AUTO_PROVISION` | `false` ⇒ solo entran los usuarios ya dados de alta |
| `SSO_REQUIRE_EMAIL_VERIFIED` | `false` para aceptar emails sin verificar (por defecto se exige) |
| `SSO_ADMIN_CLAIM` + `SSO_ADMIN_VALUE` | Rol admin según un claim (p. ej. `groups` = `secure-server-admins`); se retira al salir del grupo |
| `SSO_POST_LOGIN_URL` | Aplicación web: redirige a esa URL **fija** con el token en el fragmento (`#token=…`) |

Flujo: `GET /api/sso/login` (redirige al proveedor; `?format=json` devuelve la URL) → el usuario se autentica →
`GET /api/sso/callback?code&state` → sesión con `amr=['sso']`.

Lo que se comprueba (cada punto tiene prueba contra un proveedor simulado, `test_sso.js`, 29 pruebas): `state` de un solo
uso y con caducidad guardado **en la BD** (el callback puede caer en otra instancia); `nonce` ligado al `id_token`;
PKCE; que el documento de descubrimiento declare **el mismo issuer** (defensa contra *mix-up*); firma con las claves del
proveedor y **solo algoritmos asimétricos** (se rechazan `none` y `HS256` con el secreto del cliente); `iss`, `aud`/`azp`, `exp`, `sub`;
HTTPS obligatorio en producción. **Nunca se enlaza por email con una cuenta local existente** (vector clásico de toma de cuentas): la
identidad SSO crea su propia cuenta, que no puede entrar con contraseña.

---

## 11. KMS: secretos envueltos

Los secretos del `.env` (semillas de las claves, contraseña de la BD, tokens…) pueden guardarse **cifrados por un KMS**:

```
ENCRYPTION_SEED=kms:aws:AQICAHj...     # en vez del valor en claro
```

| Proveedor (`KMS_PROVIDER`) | Qué es | Configuración |
|---|---|---|
| `file` | Clave de envoltura (KEK) en un archivo `0400` (secreto montado, systemd-creds, volumen aparte) | `KMS_KEK_FILE` |
| `vault` | HashiCorp Vault, motor Transit | `VAULT_ADDR` (https en producción), `VAULT_TOKEN`/`VAULT_TOKEN_FILE`, `VAULT_TRANSIT_KEY`, `VAULT_NAMESPACE` |
| `aws` | AWS KMS (clave simétrica; con CloudHSM si así se configura en AWS) | `KMS_KEY_ID`, `AWS_REGION`, credenciales AWS estándar; `KMS_ENDPOINT` opcional |

```bash
npm run kms -- status                 # prueba de ida y vuelta + variables ya envueltas
npm run kms -- migrate-env            # envuelve en el sitio las semillas y secretos del .env (deja .env.pre-kms: guárdalo fuera o bórralo)
echo -n "valor" | npm run kms -- wrap NOMBRE
npm run kms -- migrate-env --rewrap   # pasar de un KMS/KEK a otro
npm run kms -- unwrap-env             # salida de emergencia: .env en claro por stdout
```

- Al arrancar, el servidor descifra los valores `kms:` antes de derivar ninguna clave. **Si el KMS no responde, el proceso
  no arranca** (falla cerrado). Las claves derivadas son idénticas a las de las semillas en claro (probado).
- Cada valor se envuelve **junto con el nombre de su variable**: el blob de `JWT_SEED` no sirve como `ENCRYPTION_SEED`.
- La **rotación de claves** escribe las semillas nuevas ya envueltas (`.env.pending`) y otro proceso que recargue el `.env` las
  resuelve con el KMS (probado con la rotación real).
- El texto claro viaja por una tubería (stdin/stdout) entre el servidor y un proceso auxiliar, nunca por argumentos ni entorno.

**Qué protege y qué no.** Protege el robo del `.env`, de un backup o del repositorio: sin acceso al KMS (y a su política de
permisos) las semillas no sirven. **No** protege de quien ejecute código dentro del proceso ya arrancado, porque necesita la clave
en memoria para cifrar. Eso solo lo evita hacer cada cifrado dentro de un HSM (latencia y coste por petición) y es una decisión
de arquitectura. Vault y AWS KMS están probados contra servidores **simulados** del protocolo (el SDK oficial de AWS firma de
verdad con SigV4); la primera prueba contra el servicio real es tuya: `npm run kms -- status`.

---

## 12. Antivirus

ClamAV por el protocolo `INSTREAM`: los bytes se envían a `clamd` **mientras se cifran** (el archivo en claro nunca se
guarda) y el veredicto llega antes de dar la subida por buena. Malware ⇒ `422 MALWARE_DETECTED`, nada queda en disco ni BD,
evento **crítico** y *strike* (varios ⇒ bloqueo de la IP).

| Variable | Qué hace |
|---|---|
| `FILE_SCAN` | `off` (por defecto) · `optional` (si clamd falla, se acepta marcado `unscanned` y queda un evento) · **`required`** (si clamd falla, `503`: recomendado en producción) |
| `CLAMAV_HOST`/`CLAMAV_PORT` o `CLAMAV_SOCKET` | Dónde está clamd (`127.0.0.1:3310` por defecto) |
| `CLAMAV_TIMEOUT_MS`, `CLAMAV_MAX_BYTES` | Espera máxima (60 s) y `StreamMaxLength` de tu clamd (25 MB) |
| `FILE_SCAN_ON_OVERSIZE` | `reject` (por defecto) o `skip` (se guarda `skipped`) para archivos mayores que el límite |

Un archivo rechazado por **tipo** (ejecutable, SVG…) ni siquiera llega al antivirus. Cada archivo guarda su `scanStatus`
(`clean`, `skipped`, `unscanned`). Las firmas cambian cada día, así que **`npm run rescan-files`** vuelve a revisar lo ya
guardado (`-- --all`, `-- --delete-infected`, `-- --limit N`; código de salida 3 si hay malware).

Probado con un clamd simulado (caídas, silencio, errores, límites) **y con ClamAV real** (firmas locales de prueba, EICAR entero,
a caballo entre bloques y dentro de una imagen). **Límite honesto:** ClamAV detecta lo que sus firmas conocen; un malware nuevo
o hecho a medida pasa. Es una capa más, no una garantía. Mantén `freshclam` al día.

---

## 13. Copias de `FILES_DIR`

Los archivos ya están cifrados con clave propia, así que la copia no vuelve a cifrar nada: el destino solo ve bytes aleatorios
con nombres UUID y un índice sin nombres reales. Para restaurar hacen falta **las dos cosas**: los archivos (aquí) y la BD (con las claves
de cada archivo, envueltas); las copias de BD las hace la rotación de claves (`src/backup`).

```bash
export FILES_BACKUP_DIR=/mnt/copias/archivos        # fuera de FILES_DIR (disco aparte, NFS, bucket montado con rclone…)
npm run files:backup                                # incremental + cruza BD y disco
npm run files:verify                                # integridad de la copia y cobertura de la BD
npm run files:restore                               # restaura lo que falte, verificando el hash (-- --target DIR, --force, --all)
# cron:  17 3 * * *  cd /ruta/app && npm run -s files:backup >> /var/log/files-backup.log
```

- **Incremental**, con SHA-256 del texto cifrado y verificación tras copiar.
- **Retención**: lo que se borra en origen se conserva `FILES_BACKUP_RETENTION_DAYS` (30) y después se elimina.
- **Detecta pérdidas**: archivos que la BD cree tener y no existen, o con tamaño incorrecto (truncados), y huérfanos. Salida `2` ⇒ alerta.
- **Nunca sobrescribe una copia buena con un original dañado** (se señala como `changedInSource`); `restore` verifica el hash
  antes de colocar cada archivo y no pisa existentes sin `--force`.
- Probado con pérdida de archivos, truncado, copia dañada, **pérdida total de `FILES_DIR`** y restauración a otro directorio.

Para una copia en otra región/proveedor, sincroniza `FILES_BACKUP_DIR` con `rclone sync` (los datos siguen cifrados).
**Haz pruebas de restauración periódicas**: una copia que nunca se ha restaurado no es una copia.

---

## 14. Pentest, análisis estático y certificaciones

**Lo que el código no puede hacer:** un pentest externo lo hace un tercero independiente, y una certificación (SOC 2, ISO 27001…)
la emite un auditor sobre una *organización*. Aquí no se afirma ninguna de las dos cosas.

**Lo que sí hay, para llegar a ellos con la tarea hecha:**

- `docs/CONTROLES.md` — modelo de amenazas y matriz de controles (OWASP ASVS, SOC 2, ISO 27001) con estado real y evidencia.
- `docs/PENTEST-AUTOEVALUACION.md` — lo que ya se probó (sqlmap, análisis estático, ataques a SSO/MFA/archivos) y lo que **no**.
- `docs/openapi.json` — definición de la API para ZAP/Burp (una prueba garantiza que está al día con el código).
- `SECURITY.md` — política de divulgación de vulnerabilidades.
- CI (`.github/workflows`): pruebas con MariaDB y ClamAV reales, `npm run lint:security` (a cero avisos), `npm audit`, CodeQL,
  gitleaks, SBOM CycloneDX y un escaneo DAST con OWASP ZAP (informativo), más Dependabot. CodeQL excluye dos consultas, con justificación en `.github/codeql/codeql-config.yml`:
`js/missing-rate-limiting` (el limitador es propio y vive en MariaDB, CodeQL solo reconoce librerías como `express-rate-limit`) y
`js/file-access-to-http` (el token de Vault se lee de un archivo y se envía a Vault, que es su función). Quien añada una ruta nueva
debe protegerla con `protectionMiddleware` a mano: ahí CodeQL ya no avisará.

---

## 15. Sesiones cortas con renovación y «cerrar todas»

El JWT de acceso dura **15 minutos** (`ACCESS_TOKEN_MINUTES`): es lo único que puede robar quien lea una petición. Para que el
usuario **no tenga que iniciar sesión a cada rato**, el login entrega además un **refresh token** opaco (`rt_…`) con el que el
cliente pide un JWT nuevo sin volver a pedir la contraseña.

| Método | Ruta | Descripción |
|---|---|---|
| `POST` | `/api/auth/refresh` `{refreshToken}` | Público. Devuelve `token` + un **refresh token nuevo** (el anterior queda inservible) |
| `POST` | `/api/auth/logout` | Cierra la sesión actual |
| `POST` | `/api/auth/logout-all` `{keepCurrent?}` | **Cierra todas las sesiones** del usuario (opcionalmente conserva la actual) |
| `GET` | `/api/auth/sessions` | Lista de sesiones vivas (IP, navegador, país, cómo se autenticó, última actividad) |
| `DELETE` | `/api/auth/sessions/{id}` | Cierra una sesión concreta (solo las propias) |

Reglas (cada una con prueba en `test_sessions.js`):

- El refresh token **solo se guarda como hash** (SHA-256) y **rota en cada uso**. Si se presenta uno ya usado (señal de que fue
  copiado), **se revoca la sesión entera** y se registra un evento crítico `REFRESH_TOKEN_REUSE` (el atacante y la víctima quedan fuera;
  la víctima inicia sesión de nuevo).
- Dos pestañas que renuevan a la vez no son un robo: dentro de `REFRESH_REUSE_GRACE_SECONDS` (10) la segunda recibe `409 REFRESH_CONFLICT`
  y debe usar el token más reciente, sin revocar nada.
- La sesión caduca por **inactividad** (`REFRESH_IDLE_DAYS`, 7, se desliza con cada renovación) y por **tope absoluto**
  (`SESSION_ABSOLUTE_DAYS`, 30): pasado ese tiempo hay que autenticarse de nuevo, se renueve o no.
- Renovar desde un origen (IP) distinto deja un evento `SESSION_REFRESH_NEW_ORIGIN` para el análisis posterior.
- La fila de sesión **no se reactiva por efecto colateral** (`expires_at` sin `ON UPDATE`) y los JWT anteriores a este cambio
  (sin `v:2`) siguen valiendo hasta su caducidad.
- Admin: `POST /api/system/users/{id}/revoke-sessions` (cierra todas las de un usuario) y `POST /api/system/sessions/revoke-all` (cierra TODAS las de la plataforma: exige `reason` de 10+ caracteres y `confirm: "REVOKE-ALL-SESSIONS"`); ambas quedan auditadas.

**Cliente**: guarda el refresh token en un almacén seguro (no en `localStorage` si la web admite XSS), renueva al recibir `401` o
poco antes de que caduque el JWT, y serializa las renovaciones (una sola a la vez) para no provocar el `409`.

---

## 16. Roles finos y aprobación de dos administradores

| Rol | Puede |
|---|---|
| `user` | Su cuenta, notas y archivos |
| `auditor` | Solo lectura: estado, logs, eventos y resumen de seguridad |
| `operator` | Auditor + desbloquear cuentas e IP |
| `admin` | Todo, incluido lo que exige un **segundo administrador** |

Los permisos están en `src/security/permissions.js` (mapa explícito, **denegar por defecto**) y las rutas piden el permiso por
nombre (`requirePermission('…')`): un permiso mal escrito **falla al arrancar**, no deja la ruta abierta. El rol se lee de la BD en
**cada petición**, de modo que bajar a alguien de rol surte efecto de inmediato aunque su JWT siga vivo.
Para dar un rol: `npm run set-role -- --user-id <id> --role <user|auditor|operator|admin>`.

**Aprobación de dos administradores** (`admin_approvals`): el **reset de MFA** de un usuario y el **borrado de sus datos** no se
ejecutan al pedirlos. Un admin los solicita (`POST /api/system/accounts/mfa-reset`, `/users/{id}/erase`) y **otro administrador distinto** los aprueba (`POST /api/system/approvals/{id}/approve`)
o rechaza. Quien solicita **no puede aprobar la suya**; el paso de «pendiente» a «aprobada» es atómico (dos aprobaciones
simultáneas ejecutan la acción una vez); caducan a las 24 h; todo queda en la tabla (quién, cuándo, por qué, resultado).
El reset de MFA además **cierra todas las sesiones** del usuario. `ADMIN_APPROVALS_REQUIRED=1` ejecuta al momento (solo para instalaciones
con un único administrador: pierde la protección).

---

## 17. Passkeys (WebAuthn) y SAML 2.0

### Passkeys / llaves de seguridad (segundo factor)

Alternativa o complemento del TOTP (FIDO2: Touch ID, Windows Hello, YubiKey, passkeys del móvil).
Con `WEBAUTHN_RP_ID` (dominio, sin esquema ni puerto) y `WEBAUTHN_ORIGINS` (https en producción) definidos:

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/api/auth/webauthn/credentials` | Llaves registradas |
| `POST` | `/api/auth/webauthn/register/options` · `/register` | Alta de una llave (exige contraseña **y** un segundo factor ya existente) |
| `DELETE` | `/api/auth/webauthn/credentials/{id}` | Quitar una llave (misma exigencia) |
| `POST` | `/api/auth/login/webauthn/options` · `/login/webauthn` | Segundo paso del login, en lugar del código TOTP |

Retos de **un solo uso** en BD (5 min, ligados a usuario y propósito, consumidos con `DELETE` atómico); origen y RP ID **exactos**
(una respuesta firmada para otro sitio no vale: anti-phishing); **contador de firmas** con actualización optimista (llave clonada ⇒
rechazo y evento crítico `WEBAUTHN_CLONE_SUSPECTED`); solo *attestation* `none`. Una sesión robada **no puede añadir su propia llave**
para quedarse. Máximo 10 llaves por usuario. Probado con un autenticador de software que firma de verdad (`test_webauthn.js`, 24 pruebas).

### SAML 2.0 (proveedor de servicio)

Para organizaciones cuyo IdP solo habla SAML (Entra ID, Okta, ADFS, Keycloak, Google Workspace…).

| Ruta | Descripción |
|---|---|
| `GET /api/saml/metadata` | Metadatos del SP (entityID, URL ACS, certificado si firmas las solicitudes) |
| `GET /api/saml/login` | Redirige al IdP (`?format=json` devuelve la URL) |
| `POST /api/saml/acs` | Recibe la respuesta del IdP |
| `GET /api/saml/status` | Si está configurado |

| Variable | Qué hace |
|---|---|
| `SAML_IDP_SSO_URL`, `SAML_IDP_ENTITY_ID`, `SAML_IDP_CERT`, `SAML_CALLBACK_URL` | **Obligatorias**. `SAML_IDP_CERT` admite PEM o rutas separadas por comas (varias para rotar) |
| `SAML_SP_ENTITY_ID` | Nuestro entityID (por defecto, la URL de metadatos) |
| `SAML_REQUIRE_SIGNED` | `assertion` (por defecto) · `response` · `both`. **Nada sin firmar se acepta** |
| `SAML_EMAIL_ATTRIBUTE`, `SAML_ALLOWED_EMAIL_DOMAINS`, `SAML_AUTO_PROVISION` | Identidad y alta automática |
| `SAML_ADMIN_ATTRIBUTE` + `SAML_ADMIN_VALUE` | Rol admin según un atributo; se retira al salir del grupo |
| `SAML_CLOCK_SKEW_SECONDS`, `SAML_FORCE_AUTHN`, `SAML_POST_LOGIN_URL` | Tolerancia de reloj (60), reautenticación forzada, destino tras el login |
| `SAML_SP_PRIVATE_KEY` + `SAML_SP_CERT` | Firmar nuestras solicitudes (opcional) |
| `SAML_ALLOW_INSECURE_HTTP` | Solo desarrollo |

Reglas (prueba contra un IdP simulado que **firma XML de verdad**, `test_saml.js`, 22 pruebas): solo *SP-initiated* (la respuesta debe
contestar a una solicitud NUESTRA, guardada en BD y de un solo uso; el inicio *IdP-initiated* no se admite); firma con el certificado
configurado; **emisor, audiencia, destinatario (ACS), destino y estado** exactos; ventanas `NotBefore/NotOnOrAfter` con tolerancia
acotada; una aserción no se acepta dos veces; defensa contra *signature wrapping* y manipulación tras firmar. Como en OIDC,
**nunca se enlaza por email con una cuenta local existente**, y el IdP solo concede o retira `admin`.

---

## 18. Archivos: imágenes recodificadas, PDF sin contenido activo y claves de archivo en el KMS

**Imágenes** (JPEG, PNG, GIF, WebP): se **decodifican y recodifican** con `sharp` antes de cifrar. Así desaparecen EXIF (GPS, cámara),
perfiles ICC, miniaturas incrustadas, datos añadidos tras el final del archivo y las imágenes políglotas (JPEG válido que además es
otra cosa). Una imagen que no se puede decodificar se rechaza (`422 IMAGE_INVALID`); se limita el tamaño en píxeles
(`IMAGE_MAX_PIXELS`, anti «bomba de descompresión») y la concurrencia (`SANITIZE_MAX_CONCURRENT`). El archivo guarda su
`sanitize_status`: `reencoded` (imagen recodificada), `inspected` (PDF inspeccionado, sin modificar) o `none`. `IMAGE_SANITIZE_PASSTHROUGH` admite tipos sin saneador (p. ej. `heic`).

**PDF**: se rechazan los que contienen JavaScript, lanzadores, archivos incrustados, formularios que envían datos, multimedia,
XFA o cifrado (no inspeccionable). Se leen también los *object streams* comprimidos con Flate (donde se esconden las acciones) y se
descodifican los nombres ofuscados (`/J#61vaScript`). Un PDF que no se puede inspeccionar (filtros raros, bomba de descompresión,
`PDF_MAX_INFLATED_MB`) se **rechaza** (falla cerrado). `PDF_ACTIVE_CONTENT=allow` lo desactiva (no recomendado).
Orden del pipeline: tipo real → antivirus (sobre el original) → saneado → cifrado → disco. El texto en claro nunca se escribe.

**Detector de inyección**: en el **cuerpo** de las peticiones, un hallazgo solo **rechaza** en las rutas críticas
(`INJECTION_BLOCK_PATHS`, por defecto `/api/auth`, `/api/system` y `/api/sso`: login, registro, MFA, administración y SSO, donde nunca hay texto libre legítimo); en el resto (p. ej. una nota que habla de SQL) se **registra**
sin rechazar, con más contexto en `security_events`. La defensa real sigue siendo la capa 1 (parámetros), no el detector.

### Claves de archivo envueltas por el KMS (`KMS_DATA_KEYS=true`)

Por defecto la clave de cada archivo se guarda envuelta con la clave maestra del servidor. Con `KMS_DATA_KEYS=true` (y `KMS_PROVIDER`)
se envuelve **directamente con el KMS/HSM**: quien robe la base de datos *y* las semillas del servidor sigue sin poder abrir los
archivos, y cada descifrado queda en el registro de auditoría del KMS.

- Formato `kms1:<proveedor>:<blob>`, **ligado a `file:<storage_name>`**: copiar el blob a otra fila no abre nada.
- Se decide por lo **guardado**, no por la configuración: archivos `v4:` y `kms1:` conviven y se leen siempre.
- Caché en memoria acotada (500 claves, `KMS_DATA_KEY_CACHE_SECONDS`=300; `0` la desactiva): el KMS no es el cuello de botella.
- **Si el KMS no responde**, descargar da `503 FILE_KEY_UNAVAILABLE` (más un evento) y subir falla sin dejar fila ni archivo.
- La rotación de la clave maestra y el snapshot de backup **no tocan** las claves `kms1:` (no dependen de la maestra); **restaurar un
  backup exige acceso al mismo KMS**.
- Migración y vuelta atrás, repetibles y con simulación: `npm run kms -- migrate-files [--dry-run]`, `unmigrate-files`, `rewrap-files`
  (cambio de KMS o de clave de envoltura). Una fila ilegible se informa y no bloquea a las demás.

---

## 19. Operación y observabilidad (solo admin)

Todo lo de esta sección exige rol `admin` (permisos `alerts:*`, `dashboard:read`, `metrics:read`, `privacy:*`).

**Alertas automáticas** (`security_alerts`). Un evaluador (cada `ALERT_EVAL_INTERVAL_SECONDS`, 60) ejecuta reglas fijas sobre
`security_events`, cada una con una consulta parametrizada, y levanta una alerta al cruzar su umbral: cualquier **evento crítico**
(`EVENT_CRITICAL`: reutilización de refresh token, llave WebAuthn clonada, fallo de integridad de archivo…), ataque de login **distribuido**
(`ALERT_LOGIN_FAILURES` fallos desde `ALERT_LOGIN_FAILURE_IPS` IP), fuerza bruta contra **una cuenta** (`ALERT_ACCOUNT_FAILURES`), códigos
MFA erróneos (`ALERT_MFA_FAILURES`), oleada de inyecciones (`ALERT_INJECTION_ATTEMPTS`), pico de bloqueos de IP (`ALERT_IP_BLOCKS`),
antivirus no disponible, integridad del servidor, inundación de eventos y actividad administrativa sensible. Una sola alerta activa por
(regla, sujeto) aunque haya varias instancias; la alerta **avisa, no actúa** (no bloquea ni cierra nada por sí sola). Aviso externo por **webhook
firmado** (`X-Signature-256`, HMAC-SHA256 con `ALERT_WEBHOOK_SECRET`) a `ALERT_WEBHOOK_URL`, desde `ALERT_NOTIFY_MIN_SEVERITY` (por defecto `high`; https en
producción); un fallo de envío queda registrado en la propia alerta.

| Ruta | Descripción |
|---|---|
| `GET /api/system/alerts` · `POST /alerts/{id}/ack` · `/resolve` · `POST /alerts/evaluate` | Ver, reconocer, resolver, evaluar ya |
| `GET /api/system/dashboard` | Resumen JSON para el panel: alertas abiertas, eventos por severidad/hora, IP bloqueadas, sesiones, aprobaciones pendientes |
| `GET /api/system/approvals` | Aprobaciones pendientes (§16) |

**Métricas** (`GET /api/metrics`, formato Prometheus): peticiones y latencias por plantilla de ruta, eventos de seguridad,
sesiones, subidas, consultas SQL, alertas abiertas… con **cardinalidad acotada** (nunca URLs reales, usuarios ni IP en las etiquetas)
y sin datos personales. Un scraper no puede renovar un JWT de 15 minutos: si defines `METRICS_TOKEN` (≥ 32 caracteres) ese token vale
**solo** para esta ruta (comparación en tiempo constante; desactivado por defecto).

**Trazas**: contexto W3C (`traceparent`); cada respuesta lleva `X-Request-Id` y cada evento de seguridad guarda su `traceId`, de modo que
de un evento sospechoso se reconstruye todo lo que hizo esa petición. Exportación OTLP/HTTP opcional (`OTEL_EXPORTER_OTLP_ENDPOINT`,
muestreo `OTEL_TRACES_SAMPLER_ARG`=0.1); los spans llevan método, plantilla de ruta, estado y operación SQL, **nunca** query, cabeceras ni parámetros.

**Datos personales**: `GET /api/system/users/{id}/export` entrega, descifrado, todo lo que el sistema guarda del usuario (sin hashes,
secretos MFA ni claves de archivo). `POST /api/system/users/{id}/erase` lo borra (BD y disco) con **aprobación de un segundo
admin**; los eventos de seguridad se **anonimizan**, no se borran. Las copias de seguridad existentes siguen conteniendo esos datos
hasta que caduquen: díselo al usuario.

**Procedimientos**: `docs/RESPUESTA-INCIDENTES.md` (plan de respuesta: detectar, contener, erradicar, recuperar, comunicar, aprender) y
`docs/CUSTODIA-CLAVES.md` (quién guarda qué clave, doble custodia, rotación, recuperación).

---

## 20. Pruebas, cobertura y fuzzing

`npm run test:all` ejecuta 18 archivos contra MariaDB real, de uno en uno (comparten servidor). Cada suite nueva tiene su script
(`test:sessions`, `test:rbac`, `test:webauthn`, `test:saml`, `test:sanitize`, `test:ops`, `test:kms-files`, `test:fuzz`…).

**Cobertura** (c8, sobre `src/` y `scripts/`): `npm run coverage` mide toda la suite y escribe `coverage/` (HTML/LCOV/JSON);
`npm run coverage:check` aplica los umbrales de `.c8rc.json`. El CI falla si la cobertura baja de los umbrales y publica el resumen en
cada ejecución. La cobertura **mide qué código se ejecuta, no si las pruebas comprueban lo correcto**: úsala para encontrar lo no probado, no como nota.

**Fuzzing con propiedades** (`test_fuzz.js`, fast-check): entradas aleatorias, mutadas y patológicas contra lo que procesa datos hostiles.
Propiedades comprobadas: el detector de tipos nunca lanza y rechaza SIEMPRE ejecutables; nombres de archivo sin rutas, controles ni bidi y estables;
cifrado de campos y de archivos (cualquier rango; **cualquier byte alterado o truncado se detecta**); `parseRange` acotado; el detector de
inyección no tarda (sin ReDoS) ni lanza, aguanta JSON de 5000 niveles y sigue detectando ataques con mayúsculas, comentarios y doble codificación;
`sqlInt`/`sqlFragment` solo producen texto seguro; un rol inventado no tiene ningún permiso; PDF ofuscados con `#hex`, bombas Flate e imágenes
corruptas se rechazan sin colgar; y **todas las rutas documentadas en `docs/openapi.json`**, con rol anónimo, usuario y admin, con ids, query y cuerpos hostiles
(JSON inválido, `text/plain`, multipart sin cierre), **nunca responden 5xx ni filtran trazas**.

El fuzzing ya encontró **dos fallos reales**, corregidos y con prueba fija: un `id` de sesión enorme daba 500 (`/api/auth/sessions/99999999999999999999`;
el validador aceptaba enteros no seguros) y un cuerpo multipart sin cierre **tumbaba el proceso** (busboy emite `error` directamente en el
stream del archivo). `npm run test:fuzz` usa 100 iteraciones (`FUZZ_RUNS`); `.github/workflows/fuzz.yml` corre 1500 cada noche, y una
ejecución fallida imprime la semilla (`FUZZ_SEED`) para repetirla.

Límite honesto: es *property-based testing*, no un fuzzer guiado por cobertura (AFL/libFuzzer) ni sustituye a un pentest.

---

## 21. CI y producción (sin nodemon)

- **`ci.yml`**: lint de seguridad (0 avisos), `check:prod-deps`, MariaDB y ClamAV reales, `npm run coverage` (toda la suite, fuzzing incluido, con
  umbral mínimo y artefacto `coverage`), `npm audit` de producción (alto), trabajo **`production-install`** (`npm ci --omit=dev`,
  comprueba que no hay nodemon ni herramientas de desarrollo en `node_modules`, que `npm run dev` se niega con `NODE_ENV=production` y que el servidor
  carga sus módulos) y **`dependency-review`** en los pull requests (rechaza dependencias nuevas con vulnerabilidades altas o licencias GPL/AGPL).
  Permisos `contents: read`, cancelación de ejecuciones obsoletas y *timeouts*.
- **`security.yml`**: ESLint security, CodeQL, gitleaks, SBOM CycloneDX y **DAST con OWASP ZAP que bloquea** si el informe contiene alertas de riesgo ALTO
  (si ZAP no llega a ejecutarse por infraestructura, no bloquea). **`fuzz.yml`**: fuzzing nocturno largo.
- **Todas las acciones están fijadas por SHA** de commit (con la versión en un comentario) y Dependabot propone las actualizaciones: una etiqueta como `@v4`
  puede moverse y ejecutar código distinto mañana.
- **nodemon solo en desarrollo**: está en `devDependencies`; `npm start` ejecuta `node src/index.js`; `npm run dev` pasa por `scripts/devGuard.js` y
  **se niega con `NODE_ENV=production`**; `install.js --production` (o `NODE_ENV=production`) instala con `--omit=dev`; y `npm run check:prod-deps`
  falla si una herramienta de desarrollo aparece en `dependencies`, en `start` o en un `require` de `src/`/`scripts/`.
  En producción: `npm ci --omit=dev` y un gestor de procesos (systemd, PM2, contenedor) en lugar de nodemon.

---

## 22. Límites y pendientes (sin humo)

Resuelto desde la versión anterior: MFA (TOTP, passkeys), SSO (OIDC y SAML), sesiones cortas con renovación y «cerrar todas», roles
finos con aprobación de dos administradores, KMS para secretos **y** para las claves de archivo, antivirus, recodificación de imágenes y
filtrado de PDF, alertas/métricas/trazas/datos personales para admin, cobertura, fuzzing y CI endurecido. Lo que **sigue sin estar** o tiene límites:

- **Multi-organización** (varios clientes aislados en una misma instalación): no existe.
- **HSM por operación**: la clave maestra de los campos cifrados sigue en memoria del proceso (ver §11). Con `KMS_DATA_KEYS` los **archivos** ya no dependen de ella.
- **Pentest externo y certificaciones** (ISO 27001, SOC 2…): dependen de terceros y de la organización (ver §14 y `docs/CONTROLES.md`). Que el código pase sus
  pruebas **no es** una certificación.
- **Saneado de archivos**: solo imágenes (recodificadas) y PDF (inspeccionados, no modificados). Audio, vídeo y texto conservan sus metadatos; el antivirus detecta
  lo conocido, no lo nuevo.
- **Detección por reglas**: bloquea lo conocido; un atacante que conozca las reglas puede evadirlas. Por eso la defensa real es la capa 1 (parámetros), no el detector.
- **Fuzzing**: pruebas con propiedades (§20), no un fuzzer guiado por cobertura; encuentra la clase de fallo común, no garantiza su ausencia. La **cobertura** mide ejecución, no corrección.
- **Proveedores simulados**: OIDC, SAML, WebAuthn, Vault y AWS KMS están probados contra simuladores que firman/cifran de verdad, **no contra un Entra ID, Okta o AWS reales**:
  prueba tu integración en un entorno de preproducción. Los workflows de CodeQL/gitleaks/ZAP/dependency-review no se han podido ejecutar fuera de GitHub; la primera ejecución puede pedir ajustes.
- **DoS volumétrico** de capa 7: hace falta un WAF/CDN delante.
- **Panel de administración**: hay API (`/api/system/dashboard`, alertas, aprobaciones) y métricas para Grafana; no hay interfaz web propia.
- **Mantenimiento**: `prom-client` avisa de que su paquete fue sustituido por `@prometheus-io/client`; migrar es trabajo pendiente (sin impacto de seguridad conocido).
- `.env` y `src/notifications/` estaban versionados. Se dejó de versionar `src/notifications/`; **`.env` no se ha tocado** (decisión
  del propietario). Sus valores sensibles coinciden con los de `.env.example` público (parecen de ejemplo), pero si algún día contiene
  secretos reales quedarán en el historial: usa `npm run kms -- migrate-env` y sácalo del repositorio.
