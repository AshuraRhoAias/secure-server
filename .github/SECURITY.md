# Política de seguridad

## Cómo avisar de una vulnerabilidad

**No abras un issue público.** Usa el aviso privado de GitHub: pestaña **Security → Report a vulnerability**
(el propietario del repositorio debe tenerlo activado en *Settings → Code security → Private vulnerability reporting*).

Incluye, si puedes: versión o commit, pasos para reproducirlo, impacto que ves y, si lo tienes, una prueba de concepto.
No hace falta que propongas la solución.

### Qué esperar (objetivos propuestos; el propietario debe confirmarlos o cambiarlos)

| Paso | Plazo objetivo |
|---|---|
| Acuse de recibo | 5 días hábiles |
| Valoración inicial (¿es reproducible? ¿gravedad?) | 10 días hábiles |
| Corrección de problemas críticos/altos | 30 días |
| Publicación coordinada del aviso | cuando exista corrección, acordando la fecha contigo |

### Alcance

Dentro: el código de este repositorio (API, scripts de operación, migraciones, configuración de ejemplo).
Fuera: ataques de denegación de servicio volumétricos, ingeniería social, y fallos de dependencias de terceros que no
se puedan alcanzar desde este código (repórtalos a su proyecto).

### Pruebas autorizadas

Puedes probar contra TU PROPIA instalación local o de pruebas. No pruebes contra instalaciones de terceros sin su permiso.
Mientras actúes de buena fe, no compartas datos de otros usuarios y nos des un plazo razonable para corregir, no emprenderemos
acciones contra ti.

## Versiones con soporte

Solo la rama `main`. Las correcciones de seguridad se publican allí.

## Qué ya está comprobado y cómo reproducirlo

- `npm run test:all` (necesita MySQL/MariaDB): pruebas de seguridad, sesiones, RBAC, MFA/WebAuthn, SSO/SAML, KMS, antivirus, archivos, operación y fuzzing.
- `npm run coverage`: la misma suite medida con c8 (umbral mínimo en CI). `npm run test:fuzz`: fuzzing con propiedades (`FUZZ_RUNS`, `FUZZ_SEED`).
- `npm run test:scale`: limitador, caché de bloqueos, líder, cluster (reparto, relevo, reinicio en caliente sin errores, cierre ordenado). `npm run bench:scale -- --env <archivo>`: antes/después de rendimiento.
- `cd web && npm test && npm run build && npm run test:e2e`: interfaz web (BFF, CSP, CSRF, sesión) con el API real y Chromium.
- `npm run check:prod-deps`: nada de desarrollo (nodemon, eslint, c8…) en producción.
- `npm run lint:security`: análisis estático (eslint-plugin-security), debe quedar a cero avisos.
- `npm audit --omit=dev`: dependencias de producción sin vulnerabilidades altas.
- `docs/openapi.json`: definición de la API para escáneres (ZAP, Burp); una prueba garantiza que está al día.
- `docs/CONTROLES.md`: modelo de amenazas y matriz de controles (OWASP ASVS, SOC 2, ISO 27001) con el estado REAL de cada uno.
- `docs/PENTEST-AUTOEVALUACION.md`: lo que se ha probado ya (sqlmap, análisis estático…) y, sobre todo, lo que NO.
