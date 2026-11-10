# Imagen del API de secure-server (src/). La interfaz web (web/) tiene su propia forma de despliegue (web/README.md).
#
#   docker build -t secure-server .
#   docker run --env-file prod.env -p 3000:3000 secure-server          (la configuración llega SIEMPRE por variables de entorno)
#
# - Solo dependencias de PRODUCCIÓN (sin nodemon, eslint, c8…): npm ci --omit=dev en una etapa aparte.
# - Usuario sin privilegios (uid 10001), código y dependencias de solo lectura para ese usuario; solo son escribibles
#   storage/ (temporales de subida y archivos si FILES_STORAGE=local), data/ (estado de rotación) y backups/.
# - Sin secretos en la imagen: ni .env, ni claves (ver .dockerignore). ENV_FILE apunta a un archivo VACÍO: index.js exige que exista.
# - Arranca con el cluster (un worker por núcleo, WEB_CONCURRENCY) y una sonda de salud real (/health/ready).
# - Fija la imagen base por digest en producción (Dependabot la mantiene: .github/dependabot.yml, ecosistema docker).

FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    ENV_FILE=/app/config/empty.env \
    FILES_DIR=/app/storage \
    NOTIFICATIONS_DIR=/app/data/notifications \
    PORT=3000
WORKDIR /app
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app \
 && mkdir -p /app/config /app/storage /app/data /app/backups \
 && touch /app/config/empty.env \
 && chown -R app:app /app/storage /app/data /app/backups \
 && chmod 0700 /app/storage /app/data /app/backups
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY scripts ./scripts
COPY database ./database
USER app
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=3 CMD ["node", "scripts/healthCheck.js"]
CMD ["node", "src/cluster.js"]
