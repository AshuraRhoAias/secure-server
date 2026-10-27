# Interfaz web de operación y observabilidad

Next.js (App Router) + React + TypeScript. **Solo para administradores** de `secure-server`: panel, alertas, aprobaciones de dos
administradores, eventos de seguridad, IP bloqueadas, sesiones, datos personales, métricas y estado del sistema.

No es un cliente del API «a pelo»: lleva un **BFF** (backend-for-frontend) que guarda los tokens en el servidor.

```
Navegador ──(misma origen, cookie httpOnly cifrada)──▶ Next.js (BFF) ──(Bearer)──▶ API de secure-server ──▶ MariaDB
```

## Por qué es seguro (y comprobado)

| Control | Cómo | Prueba |
|---|---|---|
| Los tokens **nunca llegan al JavaScript** | Token de acceso y refresh token viven en una cookie `httpOnly`, `SameSite=Strict` (`__Host-` y `Secure` con HTTPS), cifrada con AES-256-GCM | `e2e`: `document.cookie`, `localStorage`, HTML y cuerpo de las respuestas no contienen ningún token |
| Renovación sin molestar | El BFF renueva el token (15 min) antes de que caduque, con **una sola** renovación por refresh token aunque lleguen 5 peticiones a la vez | `bff.test.ts`, `e2e` (token de 36 s, rota el refresh) |
| **No es un proxy abierto** | Lista cerrada de rutas y métodos (`src/lib/allowlist.ts`); nada de `rotate-keys`, perfil, notas… | `guards.test.ts`, `e2e` |
| **CSRF** | Cabecera `X-Ops-Csrf` + `Origin` propio + `Sec-Fetch-Site` + cookie `SameSite=Strict` | `guards.test.ts`, `e2e` |
| **CSP con nonce** por petición, sin `unsafe-inline`/`unsafe-eval` (ni `style-src-attr`), `frame-ancestors 'none'` | `src/proxy.ts` | `e2e`: un manejador o `<script>` inyectado no se ejecuta y se registra la violación |
| Solo administradores | Tras el login se comprueba una ruta exclusiva de admin; si no es admin, la sesión se cierra en el API | `e2e` |
| MFA | TOTP y códigos de recuperación (el reto de 5 min va en otra cookie httpOnly, no en la página) | `e2e` |
| IP real para los límites del API | `X-Forwarded-For` con el salto de confianza (`WEB_TRUST_PROXY_HOPS`), nunca lo que mande el navegador | `guards.test.ts`, `bff.test.ts` |

## Puesta en marcha

```bash
cd web
npm ci
npm run build
WEB_SESSION_SECRET="$(openssl rand -base64 48)" OPS_API_URL=https://api.ejemplo.com npm start   # puerto 3100
```

Desarrollo: `npm run dev` (necesita el mismo entorno). Desde la raíz del repositorio: `npm run web:build`, `npm run web:start`.

| Variable | Obligatoria | Qué hace |
|---|---|---|
| `OPS_API_URL` | sí | URL base del API. En producción debe ser `https://` (`OPS_API_ALLOW_HTTP=true` solo en redes internas de confianza) |
| `WEB_SESSION_SECRET` | sí | ≥ 32 caracteres aleatorios; cifra las cookies. `WEB_SESSION_SECRET_PREVIOUS` permite rotarla sin cerrar sesiones |
| `WEB_ORIGIN` | recomendada | Origen público (`https://ops.ejemplo.com`) para la comprobación CSRF si hay un proxy que reescribe `Host` |
| `WEB_COOKIE_SECURE` | no | `true` por defecto en producción (cookies `__Host-` + `Secure`). `false` solo para probar por HTTP |
| `WEB_TRUST_PROXY_HOPS` | no (1) | Proxies de confianza delante de esta app. `0` = expuesta directamente: se ignora `X-Forwarded-For` |
| `OPS_API_TIMEOUT_MS` | no (10000) | Tiempo máximo de cada llamada al API |

**En el API** (`secure-server`): define `TRUST_PROXY=1` (esta aplicación es un proxy delante de él) para que los límites y bloqueos por IP vean
la del cliente real, y no pongas esta interfaz en `ALLOWED_ORIGINS` (el navegador no habla con el API: no hay CORS que abrir).
Desactiva la telemetría de Next si quieres: `NEXT_TELEMETRY_DISABLED=1`.

**Despliegue**: ponla detrás de TLS (balanceador o proxy) y, mejor, en una red o con una VPN/SSO delante: es una herramienta de administración.

## Pruebas

```bash
npm run typecheck
npm test                  # vitest: cookies selladas, CSRF, lista cerrada, IP del cliente, BFF contra un API simulado, Prometheus
npm run build && npm run test:e2e   # API real + web real + Chromium (necesita MariaDB; Playwright 1.56)
```

## Límites

- Inicio de sesión con contraseña + TOTP/código de recuperación. **No** hay (todavía) inicio por passkey ni por SSO desde esta interfaz: se usan
  desde el API.
- Los datos se refrescan por sondeo (10–30 s), no por WebSocket. Para históricos y alertas de infraestructura, Prometheus/Grafana con `METRICS_TOKEN`.
- Con varios procesos del API (cluster), `Sistema` muestra el estado del proceso que atendió la petición; `Métricas` sí son las agregadas.
