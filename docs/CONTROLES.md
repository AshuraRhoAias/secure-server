# Modelo de amenazas y matriz de controles

Para quien tenga que **evaluar** este sistema: un pentester, un auditor (SOC 2, ISO 27001) o el equipo de seguridad de un
cliente. Cada fila dice qué control existe, **dónde está** y **qué prueba lo comprueba**. Está escrito para que se pueda
verificar, no para dar buena imagen: lo que no está hecho figura como *No hecho*.

> **Esto NO es una certificación ni un informe de pentest.** Una certificación (SOC 2, ISO 27001, PCI DSS, HIPAA…) la emite un
> auditor acreditado sobre una **organización** y su operación durante un periodo; un repositorio de código no se certifica.
> Un pentest lo hace un tercero independiente. Lo que sí puede hacer el código es llegar a esos procesos con los controles
> técnicos ya implementados y con evidencia reproducible. Eso es lo que recoge este documento.

Leyenda: ✅ Implementado y probado · 🟡 Parcial · ❌ No hecho · 🏢 Depende de la organización (política/proceso, no de código)

---

## 1. Modelo de amenazas (STRIDE resumido)

Activos: credenciales y sesiones · datos de usuario cifrados en BD (notas, perfil) · archivos de usuario · claves de cifrado ·
tabla de eventos de seguridad. Fronteras de confianza: Internet → API; API → MySQL; API → disco de archivos; API → KMS/Vault/clamd/IdP.

| Amenaza | Vector | Mitigación | Estado |
|---|---|---|---|
| **S**poofing | Robo/adivinación de contraseña | bcrypt(12), bloqueo por usuario+origen y global, rate limit, MFA TOTP y passkeys (WebAuthn), SSO OIDC y SAML | ✅ |
| **S**poofing | Sesión robada | JWT de 15 min + refresh token con rotación y detección de reutilización (revoca la sesión), caducidad por inactividad (7 d) y absoluta (30 d), «cerrar todas las sesiones», `amr` por sesión; operaciones sensibles piden contraseña + 2.º factor | ✅ |
| **S**poofing | Confusión de algoritmo / token falsificado (JWT, id_token) | `HS256` fijado; id_token solo algoritmos asimétricos; nonce, state, PKCE | ✅ |
| **T**ampering | Inyección SQL / NoSQL / XSS / traversal / CRLF | Consultas parametrizadas, validación estricta, detector con strikes, prueba que impide SQL con interpolación | ✅ |
| **T**ampering | Alterar datos o archivos en reposo | AES-256-GCM autenticado (campos y bloques de archivo); alteración ⇒ error + evento crítico | ✅ |
| **R**epudiation | "Yo no lo hice" | Auditoría cifrada (`security_logs`) + tabla de análisis (`security_events`) con IP, usuario, regla | ✅ |
| **I**nformation disclosure | Fuga de datos de otro usuario | Todas las consultas filtran por `user_id`; pruebas de aislamiento | ✅ |
| **I**nformation disclosure | Robo del `.env` / backup / repositorio | Secretos envueltos por KMS (file/Vault/AWS); archivos con clave propia | 🟡 (ver §3, límite del proceso en marcha) |
| **I**nformation disclosure | Enumeración de usuarios | Mismo mensaje y mismo coste (bcrypt) exista o no el usuario; el bloqueo se comporta igual | 🟡 (el registro devuelve 409 si el usuario existe) |
| **D**enial of service | Fuerza bruta de login para bloquear a la víctima | Bloqueo por (usuario, origen); el global no afecta a orígenes de confianza; liberación por admin | 🟡 (ataque distribuido desde muchas IP + víctima desde un origen nuevo: espera ≤ 15 min) |
| **D**enial of service | Inundación de peticiones / eventos / subidas | Límites en BD por IP/usuario, tope de eventos, cuotas, cola de BD acotada, `requestTimeout`; cluster multiproceso con relevo de líder, `/health/ready` y cierre ordenado (`test_scale.js`) | 🟡 (L7 volumétrico requiere WAF/CDN delante; escala medida en una máquina de 4 vCPU) |
| **T**ampering / **S**poofing | Robo de la sesión del administrador desde el navegador (XSS, extensiones) | Interfaz web con BFF: tokens en cookie `httpOnly` cifrada que el JavaScript no puede leer; CSP con nonce; CSRF; lista cerrada de rutas (`web/`, e2e con Chromium) | ✅ (no protege de un navegador o equipo ya comprometido) |
| **E**levation of privilege | Pasar a admin | Rol leído de la BD en cada petición; permisos explícitos con denegación por defecto (`user`/`auditor`/`operator`/`admin`); `MFA_REQUIRED_FOR_ADMINS`; contaminación de prototipos bloqueada | ✅ |
| **E**levation of privilege | Un admin comprometido (o malintencionado) | Reset de MFA y borrado de datos exigen la aprobación de **otro** administrador (sin auto-aprobación, atómico, con caducidad); revocación masiva con confirmación; alertas automáticas | ✅ (con un solo admin hay que usar `ADMIN_APPROVALS_REQUIRED=1`, sin esa protección) |
| **E**levation of privilege | Sesión robada que añade su propia llave/dispositivo | Alta y baja de passkeys exigen contraseña + 2.º factor existente | ✅ |
| **T**ampering | Robo de la BD **y** de las semillas del servidor para abrir archivos | `KMS_DATA_KEYS`: la clave de cada archivo la envuelve el KMS/HSM, ligada al archivo | 🟡 (opcional; el KMS pasa a ser punto de fallo: caché y 503 controlado) |
| **T**ampering | Archivo «políglota» o con metadatos/GPS ocultos; PDF con JavaScript | Imágenes decodificadas y recodificadas (sharp); PDF con contenido activo rechazado, incluidos object streams comprimidos y nombres ofuscados | ✅ (solo imágenes y PDF) |
| **R**epudiation | Reutilización de refresh token / llave clonada | Eventos críticos `REFRESH_TOKEN_REUSE`, `WEBAUTHN_CLONE_SUSPECTED` + alerta automática `EVENT_CRITICAL` | ✅ |
| **E**levation of privilege | Subir un ejecutable/script | Tipo real por magic bytes, lista cerrada, antivirus, `attachment`+`nosniff`+CSP sandbox al servir | ✅ (el antivirus es opcional: `FILE_SCAN`) |

Fuera de modelo (la API no puede defenderlo sola): compromiso del servidor con ejecución de código, del proveedor de identidad,
del KMS, de la cuenta de GitHub o de la cadena de suministro más allá de `npm audit`/Dependabot/SBOM.

---

## 2. OWASP ASVS 4.0 (nivel 2) — por capítulo

| Capítulo | Estado | Qué hay (y dónde) | Qué falta |
|---|---|---|---|
| **V1** Arquitectura | 🟡 | Este documento; `docs/SEGURIDAD.md`; defensa en capas | Diagrama de flujo de datos formal, revisión periódica |
| **V2** Autenticación | ✅ | bcrypt(12) sin recortar la contraseña, 10–72 bytes (`auth.controller`); bloqueo (`secure-auth.service`); TOTP RFC 6238 con anti-reutilización y códigos de recuperación (`mfa.service`, `totp.js`); SSO OIDC (`sso/oidc.service`) | Comprobación de contraseñas filtradas (HIBP); WebAuthn/FIDO2 |
| **V3** Sesiones | ✅ | JWT HS256 de 15 min ligado a una fila de sesión; refresh token opaco con rotación y detección de reutilización; inactividad/tope absoluto; cerrar una/todas las sesiones; `amr`; reto MFA ≠ sesión (`test_sessions.js`, `test_mfa.js`, `test_security.js`) | Limitar el número de sesiones simultáneas |
| **V4** Control de acceso | ✅ | Propiedad por `user_id` en todas las consultas; RBAC con permisos explícitos y denegación por defecto (`permissions.js`, `test_rbac.js`); roles desde BD; aprobación de dos administradores; admin con MFA opcional | Multi-organización |
| **V5** Validación | ✅ | `validate.*` (tipos/longitudes/patrones), `sanitize.middleware`, detector, `sqlInt()`; prueba "no hay SQL con interpolación" | — |
| **V6** Criptografía | 🟡 | AES-256-GCM, HKDF, IV aleatorio, claves por archivo, rotación con migración, KMS | Clave maestra sigue derivada de semillas del entorno (KMS las protege en reposo, no en memoria); sin HSM por operación |
| **V7** Logs y errores | ✅ | `security_events` + `security_logs` cifrado; alertas automáticas por umbral (`security_alerts`), métricas Prometheus, trazas con `X-Request-Id`; sin secretos en logs (probado); errores genéricos al cliente | Envío a SIEM externo (hay webhook firmado, métricas Prometheus y trazas OTLP) |
| **V8** Protección de datos | 🟡 | Cifrado en reposo de campos y archivos; `Cache-Control: no-store` en API | Clasificación formal de datos; borrado/retención por política (existe retención de eventos) |
| **V9** Comunicaciones | 🟡 | HSTS, TLS a la BD verificado en producción, HTTPS exigido para IdP/Vault | La terminación TLS de la API es del proxy/balanceador (fuera del código) |
| **V10** Código malicioso | 🟡 | `lint:security`, CodeQL, gitleaks, Dependabot, SBOM, `npm audit` y `dependency-review` en CI; acciones fijadas por SHA; fuzzing con propiedades (`test_fuzz.js`); cobertura con umbral; nada de desarrollo (nodemon) en producción (`check:prod-deps`); sin `eval` | Firma de artefactos / SLSA |
| **V11** Lógica de negocio | 🟡 | Cuotas, límites por usuario, transacción de cuota bajo bloqueo de fila | Análisis de abuso específico del negocio |
| **V12** Archivos | ✅ | Tipo por contenido, extensiones prohibidas, ClamAV, imágenes recodificadas, PDF sin contenido activo, UUID en disco, descarga segura, cuotas (`test_files.js`, `test_av.js`, `test_sanitize.js`) | No sanea audio/vídeo/texto (conservan metadatos) |
| **V13** API | ✅ | `docs/openapi.json` (con prueba de que está al día), validación por esquema, límites, CORS cerrado en producción | Versionado de API |
| **V14** Configuración | 🟡 | Variables documentadas (`.env.example`), `trust proxy`, cabeceras (helmet), TLS BD | Hardening del SO/contenedor y gestión de la configuración: del despliegue |

---

## 3. Qué protege (y qué no) cada control criptográfico

| Control | Te protege de | NO te protege de |
|---|---|---|
| Cifrado de campos/archivos (AES-GCM) | Robo de la BD o del disco, lectura por un DBA sin la clave | Quien ejecute código dentro del proceso (tiene la clave en memoria) |
| Secretos envueltos por KMS | Robo del `.env`, de un backup, del repositorio | Lo mismo: el proceso arrancado descifra las semillas al iniciar |
| Rotación de claves | Clave antigua comprometida; límite de uso de una clave | Datos ya exfiltrados cifrados con la clave antigua y la clave |
| Copias de `FILES_DIR` | Pérdida de disco, borrado accidental o malicioso (retención) | Falta de la BD: sin las claves envueltas de la BD los archivos no se leen |

Una protección real frente a "compromiso del proceso" exige cifrar/descifrar **dentro** de un HSM o servicio externo en cada
operación (latencia y coste por petición) o confidential computing: decisión de arquitectura, no un parche de código.

---

## 4. SOC 2 (Trust Services Criteria) — qué aporta el código

SOC 2 evalúa **controles operados por la organización durante un periodo (Type II)**. El código solo cubre la parte técnica:

| Criterio | Aporta el código | Lo pone la organización 🏢 |
|---|---|---|
| CC6.1 Acceso lógico | Autenticación fuerte (MFA/SSO), roles, cifrado | Alta/baja de personas, revisiones de acceso, gestión de claves del KMS |
| CC6.2/6.3 Altas, bajas, mínimo privilegio | Roles desde BD, liberación/reinicio MFA por admin con auditoría | Procedimiento de onboarding/offboarding y evidencias |
| CC6.6 Frontera del sistema | Límites, bloqueo de IP, validación, CORS | Firewall/WAF/red, segmentación |
| CC6.7 Datos en tránsito | HSTS, TLS BD | TLS en el balanceador, gestión de certificados |
| CC6.8 Software malicioso | Antivirus en subidas, SAST/CodeQL, dependencias | Endpoint protection de los equipos |
| CC7.1–7.3 Detección y monitorización | `security_events`, resumen, alertas internas | Revisión periódica y respuesta a alertas, SIEM |
| CC7.4–7.5 Respuesta a incidentes | Bloqueo automático, rotación de claves, copias | Plan de respuesta, simulacros, comunicación |
| CC8.1 Gestión de cambios | CI con pruebas y análisis, PR | Revisión de código obligatoria, separación de entornos, aprobaciones |
| A1.2 Disponibilidad / copias | Copias de BD cifradas y de `FILES_DIR`, `verify`/`restore` | RTO/RPO, pruebas de restauración periódicas, alta disponibilidad |

## 5. ISO/IEC 27001:2022 Anexo A — qué aporta el código

| Control | Aporta el código | Organización 🏢 |
|---|---|---|
| A.5.15/5.18 Control de acceso | Roles, MFA, SSO, bloqueo, revisión por API de eventos | Política de acceso, revisiones |
| A.8.2/8.5 Autenticación y privilegios | MFA obligatorio para admins (opción), reautenticación en acciones sensibles | Gestión de privilegios |
| A.8.7 Protección contra malware | ClamAV, tipos permitidos | Políticas de endpoints |
| A.8.8 Vulnerabilidades técnicas | `npm audit`, Dependabot, CodeQL, SBOM | Proceso de parcheo con plazos |
| A.8.12/8.13 Fuga de datos / copias | Cifrado, copias, verificación | Política de retención y restauración |
| A.8.15/8.16 Registro y monitorización | `security_events`, `security_logs` | Revisión y retención por política |
| A.8.24 Criptografía | AES-GCM, HKDF, KMS, rotación | Política criptográfica, custodia de claves |
| A.8.25–8.29 Desarrollo seguro y pruebas | CI, SAST, pruebas de seguridad (396 pruebas automatizadas), OpenAPI | Ciclo de vida de desarrollo formal, pentest independiente |
| Resto (A.5.x políticas, A.6 personas, A.7 físico) | — | Íntegramente de la organización |

---

## 6. Para llegar a una certificación hace falta, además del código

1. Políticas escritas y aprobadas (seguridad, acceso, criptografía, copias, incidentes, proveedores, continuidad).
2. Registro de riesgos y declaración de aplicabilidad (ISO) / descripción del sistema (SOC 2).
3. Evidencias operativas durante meses: revisiones de acceso, tickets de cambios, restauraciones de copias, formación.
4. Un **pentest independiente** (alcance acordado, informe, retest de hallazgos). Este repositorio ofrece `docs/openapi.json`,
   el entorno reproducible de pruebas y `docs/PENTEST-AUTOEVALUACION.md` para acelerarlo.
5. Un auditor acreditado.

Nada de lo anterior se puede resolver desde el código: aquí no se afirma que el sistema esté certificado ni auditado.
