# Plan de respuesta a incidentes

Plantilla **operativa** para este sistema: usa los endpoints, tablas y comandos reales del repositorio. Rellena los huecos
`[...]` con tu organización antes de necesitarla. No es asesoramiento legal: los plazos de notificación dependen de tu
jurisdicción y de tus contratos (por ejemplo, en la UE el RGPD obliga a notificar a la autoridad de control en un máximo de 72 h
desde que se conoce una brecha de datos personales; confírmalo con tu DPO/asesor).

## 0. Antes de que pase

| Qué | Dónde |
|---|---|
| Quién responde (nombre, teléfono, suplente) | `[Responsable de seguridad]`, `[Suplente]`, `[Contacto legal/DPO]` |
| Dónde llegan los avisos | `ALERT_WEBHOOK_URL` (Slack/Teams/PagerDuty) y `ALERT_NOTIFY_MIN_SEVERITY`; ver `.env.example` |
| Quién puede aprobar acciones destructivas | Al menos **dos** administradores con MFA (`ADMIN_APPROVALS_REQUIRED=2`, `MFA_REQUIRED_FOR_ADMINS=true`) |
| Dónde se ve todo | `GET /api/system/dashboard`, `GET /api/system/alerts`, `GET /api/system/security-events`, métricas en `/api/metrics` |
| Copias probadas | `npm run files:verify`; copias de BD de la rotación de claves; **una restauración de prueba** cada trimestre |
| Claves y custodia | [`docs/CUSTODIA-CLAVES.md`](CUSTODIA-CLAVES.md) |

Todos los endpoints de administración exigen rol `admin` (el panel y las acciones de incidente, **solo admin**).

## 1. Detectar

Las alertas automáticas (`security_alerts`) se evalúan cada minuto sobre `security_events`:

| Alerta | Qué significa | Primera mirada |
|---|---|---|
| `EVENT_CRITICAL` | Algo marcado crítico: reutilización de refresh token (robo), malware, fallo de integridad de un archivo | Evento y `details.traceId` |
| `LOGIN_FAILURES_DISTRIBUTED` | Ataque de *credential stuffing* desde muchas IP | `topIps` del panel; ¿cuentas reales afectadas? |
| `ACCOUNT_UNDER_ATTACK` | Una cuenta recibe muchos fallos | ¿La contraseña está filtrada? Avisar al usuario |
| `MFA_CODE_GUESSING` | Alguien **ya conoce la contraseña** y prueba códigos MFA | Tratar como cuenta comprometida (sección 3) |
| `INJECTION_WAVE` | Oleada de payloads | Normalmente ruido; mirar si algún evento pasó de "registrado" a efecto |
| `ANTIVIRUS_UNAVAILABLE` | `clamd` caído: subidas rechazadas (`required`) o sin escanear (`optional`) | Restaurar `clamd`; revisar `npm run rescan-files` |
| `SERVER_INTEGRITY` | Falló la comprobación de integridad del servidor | Posible alteración del código: sección 4 |
| `SENSITIVE_ADMIN_ACTIVITY` | Un admin hizo algo delicado (aprobación, exportar datos, borrar, cerrar sesiones) | **Confirmar con la persona** que fue ella |

Reconoce la alerta (`POST /api/system/alerts/:id/ack`) para que el equipo sepa que alguien la está mirando; ciérrala
(`/resolve`) cuando termine. **Las alertas abiertas no se cierran solas.**

Para reconstruir una petición concreta: el `traceId` de un evento es el `X-Request-Id` de esa respuesta; con él se encuentran sus
trazas en tu colector (si exportas OTLP) y sus logs.

## 2. Clasificar (primeros 15 minutos)

1. ¿Hay datos personales de usuarios expuestos o modificados? (`GET /api/system/users/:id/export` ayuda a ver qué guardas de alguien).
2. ¿Hay acceso con privilegios ajeno? (sesiones activas de admins: `GET /api/system/dashboard` → `auth.activeSessions`).
3. ¿Sigue ocurriendo? (eventos nuevos en `security-events` en los últimos minutos).
4. Asigna severidad: **SEV1** datos expuestos o admin comprometido · **SEV2** cuenta(s) de usuario comprometida(s) · **SEV3** intento sin efecto.

Apunta la hora de **detección** y la de **conocimiento** (suele ser la que cuenta para los plazos legales).

## 3. Contener

Elige lo mínimo que pare el daño. Todo queda registrado en `security_events` y `audit`.

| Situación | Acción |
|---|---|
| Una cuenta de usuario comprometida | `POST /api/system/users/:id/revoke-sessions` `{reason}` (cierra sesiones y refresh) → pide al usuario cambiar la contraseña; si usa MFA y sospechas del dispositivo, reinicio de MFA con **dos admins** (`POST /api/system/accounts/mfa-reset`) |
| Sospecha de robo de tokens | Un `REFRESH_TOKEN_REUSE` ya revoca esa sesión solo. Si hay más: revocar las del usuario |
| **Cuenta de administrador** comprometida | Quitar el rol (`npm run set-role -- --user-id N --role user`; efecto inmediato, el rol se lee de la BD), revocar sus sesiones, revisar qué aprobó/solicitó en `admin_approvals` |
| Compromiso general o de la clave JWT | `POST /api/system/sessions/revoke-all` `{reason, confirm: "REVOKE-ALL-SESSIONS"}` (**todos** reinician sesión) y rotación de claves (sección 4) |
| IP o rango atacante | Los bloqueos son automáticos y progresivos; se ven en `GET /api/system/blocked-ips` y se levantan con `DELETE /api/system/blocked-ips/:ip`. No hay bloqueo manual de rangos: para eso, filtra en el WAF/CDN |
| Antivirus caído y subidas peligrosas | `FILE_SCAN=required` (rechaza si `clamd` falla) y reiniciar el servicio |
| Hay que parar el servicio | Modo mantenimiento de la rotación de claves (`src/maintenance`) o retirar del balanceador |

## 4. Erradicar y recuperar

- **Claves expuestas** (semillas, KEK, `.env` filtrado): rotar. `npm run rotate-keys -- status` / `analyze` / `rotate --confirm`;
  las semillas nuevas pueden escribirse envueltas por el KMS (`npm run kms -- migrate-env`). Rotar también la contraseña de la BD y
  los tokens de terceros. Detalle en `docs/SEGURIDAD.md` §11 y [`CUSTODIA-CLAVES.md`](CUSTODIA-CLAVES.md).
- **Código alterado** (`SERVER_INTEGRITY`): reconstruye desde un commit conocido y firmado; no "repares" el servidor comprometido.
- **Archivos dañados**: `npm run files:verify` y `npm run files:restore`. **Malware que se coló** (firmas nuevas): `npm run rescan-files -- --delete-infected`.
- **Datos borrados o alterados**: restaura la copia de BD más reciente buena + `files:restore`; comprueba cobertura BD↔disco.
- Comprueba que el vector está cerrado **antes** de levantar la restricción (misma alerta sin recurrencia durante el tiempo que decidas).

## 5. Datos personales y comunicación

- ¿Se vieron datos personales? Decide con tu DPO si es una brecha notificable y a quién (autoridad, afectados).
- **Derechos de las personas** (acceso, supresión) se atienden con:
  - `GET /api/system/users/:id/export` → JSON con el perfil, notas, metadatos de archivos, sesiones y eventos, descifrado. Queda auditado.
  - `POST /api/system/users/:id/erase` `{reason, confirmUsername}` → **otro** admin lo aprueba (`POST /api/system/approvals/:id/approve`). Borra cuenta, notas, archivos (BD y disco), sesiones y MFA; **anonimiza** (no borra) eventos de seguridad e intentos de login.
- **Lo que el borrado NO alcanza:** las copias de seguridad de la BD y de `FILES_DIR` que ya existen conservan esos datos hasta que
  caduquen por su retención (`FILES_BACKUP_RETENTION_DAYS`, copias de BD). Dilo al interesado y, si el plazo es largo, define cómo
  se purgan al restaurar (volver a ejecutar los borrados registrados en `admin_approvals`).
- `admin_approvals` conserva el historial (quién pidió, quién aprobó, motivo) y el **id** numérico del usuario borrado, ya sin vínculo con ninguna persona.
- Mensaje a usuarios: qué pasó, qué datos, qué hacer (cambiar contraseña, revisar sesiones en `GET /api/auth/sessions`, "cerrar todas" con `POST /api/auth/logout-all`), contacto. Sin culpar ni especular.

## 6. Después (en la semana siguiente)

1. Línea de tiempo: detección → contención → recuperación, con los `traceId` y alertas implicadas.
2. Causa raíz y qué control habría parado o detectado antes. Convierte lo aprendido en una prueba automática (`test_*.js`) o en una regla de alerta.
3. Ajusta umbrales (`ALERT_*`) si hubo ruido o silencio.
4. Revisa la lista de personas con rol `admin`/`operator`/`auditor` y quién aprueba qué.
5. Guarda el informe: `[ubicación]`.

## Ejercicio recomendado (cada 6 meses)

Simulacro de 1 hora: se "roba" un refresh token (reutilízalo y comprueba la alerta crítica), se pide un borrado de datos con
dos admins, se hace `revoke-all` en un entorno de pruebas y se restaura una copia. Anota lo que tardó y lo que faltaba.
