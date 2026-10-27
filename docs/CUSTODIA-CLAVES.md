# Custodia de claves y secretos

Quién guarda qué, cómo se rota y qué hacer si alguien se va o algo se pierde. Plantilla: completa los `[...]` con tu organización.
Los mecanismos técnicos (KMS, rotación) están en [`SEGURIDAD.md`](SEGURIDAD.md) §11 y en el README.

## 1. Inventario

| Secreto | Para qué | Dónde vive | Quién puede leerlo | Rotación |
|---|---|---|---|---|
| `ENCRYPTION_SEED` / `BASE_SEED` | Deriva la clave maestra de los datos (campos y claves de archivos) | `.env` **envuelto por el KMS** (`kms:...`) o, sin KMS, en claro en el servidor | `[Rol A]` | Anual y ante sospecha: `npm run rotate-keys` |
| `JWT_SEED` | Firma de sesiones (HS256) | Igual | `[Rol A]` | Anual y ante sospecha |
| KEK del KMS `file` (`KMS_KEK_FILE`) | Envuelve las semillas del `.env` | Archivo `0400` fuera del repositorio, en un volumen/secreto aparte | `[Rol B]` (y el proceso del servidor) | Anual: `kms migrate-env --rewrap` |
| Clave del KMS en Vault/AWS (`VAULT_TRANSIT_KEY`, `KMS_KEY_ID`) | Igual, en un servicio gestionado | El KMS; el acceso se controla con su política | Política IAM: solo el servicio + `[break-glass]` | La rotación nativa del KMS |
| Contraseña de la BD (`DB_FRAGMENT_*`) | Acceso a MariaDB | `.env` envuelto | `[Rol A]` | Semestral |
| `METRICS_TOKEN`, `ALERT_WEBHOOK_SECRET`, `SSO_CLIENT_SECRET`, `CLAMAV`... | Servicios auxiliares | `.env` envuelto | `[Rol A]` | Ante sospecha y cuando alguien con acceso se va |
| Claves de archivos (`key_encrypted`) | Una por archivo | BD, envueltas con la clave maestra | Nadie directamente | Se re-envuelven en cada rotación (sin re-cifrar archivos) |
| Copias de BD y de `FILES_DIR` | Recuperación | `[Destino de copias]` | `[Rol C]` | Retención `FILES_BACKUP_RETENTION_DAYS` y la de la BD |

Los roles de la aplicación (`admin`, `operator`, `auditor`) **no** dan acceso a estos secretos: se gestionan en la infraestructura.

## 2. Principios

1. **Ninguna persona sola** puede descifrar todo y a la vez borrar los rastros: la clave maestra y el acceso a las copias van a roles distintos.
2. **El `.env` en claro no se guarda en repositorios, tickets ni chats.** Con KMS, el `.env` solo contiene valores `kms:`.
3. Las semillas **no** se pegan en un terminal compartido: se pasan por stdin (`echo -n "valor" | npm run kms -- wrap NOMBRE`).
4. Acceso con registro: el KMS (Vault/AWS) audita cada `unwrap`; revisa ese log en las revisiones de acceso.
5. Revisión de accesos **trimestral**: quién puede leer cada fila de la tabla anterior.

## 3. Divulgación dividida de la clave de recuperación (opcional, recomendado)

Si necesitas una copia de la KEK fuera del sistema (continuidad ante pérdida), no la guardes entera en un sitio ni con una persona:
divídela (por ejemplo con Shamir 3-de-5, herramienta `ssss` o la de tu gestor de secretos) y reparte las partes a personas distintas
y lugares distintos. Documenta aquí dónde está cada parte: `[...]`. Prueba la recomposición **una vez al año**.

## 4. Rotación

| Cuándo | Procedimiento |
|---|---|
| Programada | `npm run rotate-keys -- status`, luego `analyze` (ensayo), luego `rotate --confirm`. Hace copia previa, re-cifra y deja las semillas nuevas listas (envueltas si hay KMS). |
| Ante sospecha de filtración | Igual, y además: contraseña de BD, tokens de terceros, y `POST /api/system/sessions/revoke-all` (ver el plan de incidentes) |
| Cambio de KEK / proveedor KMS | `npm run kms -- migrate-env --rewrap` (de un KMS a otro) y comprobar con `npm run kms -- status` |
| Una persona con acceso se va | Rotar todo lo que pudiera leer (fila por fila) el mismo día; quitar su acceso al KMS y a las copias |

Antes de cualquier rotación: copia verificada de BD y `npm run files:verify`. Después: prueba de login, de lectura de una nota y de descarga de un archivo.

## 5. Pérdida o corrupción

- **Pierdes la KEK del KMS `file` y no hay copia**: las semillas envueltas no se pueden recuperar. Recupera desde la copia dividida (sección 3) o desde un `.env.pre-kms` guardado fuera (si lo conservaste cifrado). Sin ninguna, los datos cifrados con esa clave maestra son **irrecuperables**: es la contrapartida del cifrado.
- **KMS no disponible**: el servidor **no arranca** (falla cerrado) en lugar de arrancar sin cifrado. Restaura el servicio KMS o usa el procedimiento *break-glass*: `[quién, cómo, cómo se audita]`.
- **Break-glass**: `npm run kms -- unwrap-env` imprime el `.env` en claro. Solo con dos personas presentes y registro del motivo; después, **rotar**.

## 6. Altas y bajas

| Evento | Pasos |
|---|---|
| Alta de administrador | Cuenta personal (nunca compartida) + MFA obligatorio (`MFA_REQUIRED_FOR_ADMINS=true`) + `npm run set-role -- --user-id N --role admin` + anotarlo aquí |
| Cambio de rol | `set-role` (el rol se lee de la BD en cada petición: efecto inmediato) |
| Baja | Quitar el rol, revocar sus sesiones (`revoke-sessions`), retirar accesos al KMS/servidores/copias y rotar los secretos que conocía |
