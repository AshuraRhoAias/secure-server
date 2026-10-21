# Optimizaciones y endurecimiento (ronda 4)

Fecha: 2026-10-21. Todo medido en un contenedor de 4 vCPU / 16 GB, sin GPU.

## 1. Cifrado/descifrado mucho más veloz

El camino de cifrado se ejecuta en cada lectura y escritura. Dos cosas lo
frenaban enormemente y se corrigieron **sin cambiar el formato cifrado** (los
datos ya guardados siguen descifrándose igual):

- **Auto-test en cada cifrado.** `level3.encrypt()` descifraba el resultado en
  el acto para "validarlo" en CADA operación: duplicaba el trabajo. Ese auto-test
  ahora sólo corre al depurar.
- **Log por operación.** Cada nivel volcaba varias líneas por operación. Todo ese
  log pasó a un interruptor `CRYPTO_DEBUG` (apagado por defecto).

Medición (microbenchmark): **~9 600 pares cifrado+descifrado por segundo**, 0 fallos.
A/B sobre los mismos datos en `/api/notes`: ruta antigua 159 req/s → optimizada
345 req/s (~2.2×).

Para volver a ver el log detallado al depurar: `CRYPTO_DEBUG=true npm start`.

## 2. Caché del total de notas (COUNT)

`/api/notes` hacía un `COUNT(*)` por usuario en cada listado. Con 100k notas eso
costaba ~17 ms por petición (frente a <1 ms de la página en sí). Ahora el total
se cachea unos segundos por usuario y se invalida al crear/borrar notas del
propio usuario, así la paginación sigue siendo exacta para quien escribe.

Resultado en `/api/notes` con **100 000 notas**: de **8.3 req/s (p50 4.4 s)** en la
ronda 3 a **316 req/s (p50 78 ms)**. Ajustable con `NOTES_COUNT_TTL_MS` (def 5000).

## 3. Token web diario único por usuario (X-Client-Token)

Segundo factor de transporte, aparte del JWT. El servidor lo emite al iniciar
sesión y **todas las rutas protegidas lo exigen**: sin él la petición se rechaza
con 403.

- Es **único por usuario** y **cambia cada día** (UTC): `HMAC(secreto_servidor, "userId:FECHA")`.
- El cliente lo recibe en la respuesta de `POST /api/auth/login` (campos
  `clientToken` y `clientTokenExpiresAt`) y debe mandarlo en la cabecera
  **`X-Client-Token`** en cada petición.
- Si cruza la medianoche UTC, puede renovarlo sin re-login con
  `GET /api/auth/client-token` (o en `GET /api/auth/profile`). Se admite el token
  de ayer con una pequeña tolerancia para no cortar peticiones en el cambio de día.
- Códigos de rechazo: `CLIENT_TOKEN_REQUIRED` (falta), `INVALID_CLIENT_TOKEN`
  (equivocado, caducado o de otro usuario).

Ejemplo:
```bash
curl /api/notes -H "Authorization: Bearer <JWT>" -H "X-Client-Token: <clientToken>"
```
`X-Client-Token` está permitido en CORS (`allowedHeaders`).

## 4. Usar sólo la mitad del equipo

Al arrancar, el servidor detecta la capacidad real y se reserva **la mitad**
(ajustable con `CAPACITY_FRACTION`, def 0.5). De ese presupuesto salen:

- `connectionLimit` del pool MySQL (también forzable con `DB_POOL_SIZE`).
- `UV_THREADPOOL_SIZE` (hilos de libuv para crypto/fs).
- Trabajadores para cargas en paralelo.
- Memoria recomendada para el heap de V8.

Para aplicar también el tope de RAM del heap, arrancar con:
```bash
npm run start:half      # node --max-old-space-size=<mitad RAM> src/index.js
```
El arranque imprime el resumen: núcleos y RAM totales, y el presupuesto usado.

## 5. Fingerprint, geolocalizador y localizador de IP

- **IP real detrás de proxy:** `trust proxy` activado (configurable con
  `TRUST_PROXY`), así `req.ip` es la IP del cliente y no la del proxy.
- **Normalización de IP:** se quita el prefijo IPv4 mapeada en IPv6
  (`::ffff:1.2.3.4` → `1.2.3.4`) y `::1` → `127.0.0.1`, porque geoip-lite no
  resuelve la forma mapeada. Verificado: `8.8.8.8` → país `US`.
- **Huella estable:** se calcula un `fingerprintId` (hash de user-agent +
  accept-language + accept-encoding + navegador + SO) para detectar cambios de
  dispositivo de forma más fiable.
- **Geo enriquecida:** el fingerprint incluye país, ciudad, coordenadas y zona
  horaria cuando la IP es pública (las IP privadas/loopback dan `Unknown`, que es
  lo correcto).

Para comprobarlo, `login`, `profile` y `client-token` devuelven un objeto
`client` con `ip`, `fingerprintId`, `browser`, `os`, `device` y `geo`.
