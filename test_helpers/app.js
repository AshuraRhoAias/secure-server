const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const mysql = require('mysql2/promise');
const { dbUrl, DB_NAME } = require('./env');

// Aplicación de pruebas: monta los MISMOS middlewares y rutas reales que src/index.js
// (protección con estado en MySQL, sanitización, cargador de rutas, manejador de errores).

async function prepareDatabase() {
    try {
        const root = await mysql.createConnection({
            host: dbUrl.hostname, port: Number(dbUrl.port) || 3306, user: dbUrl.username, password: dbUrl.password,
            multipleStatements: true, connectTimeout: 3000
        });
        await root.query(`DROP DATABASE IF EXISTS \`${DB_NAME}\`; CREATE DATABASE \`${DB_NAME}\` CHARACTER SET utf8mb4; USE \`${DB_NAME}\`;`);
        await root.query(fs.readFileSync(path.join(__dirname, '../database/schema.sql'), 'utf8'));
        await root.end();
        return true;
    } catch (error) {
        console.log(`ℹ️ Pruebas de integración omitidas: no hay base de datos (${error.code || error.message})`);
        return false;
    }
}

function buildApp() {
    const protection = require('../src/middleware/protection.middleware');
    const { sanitizeInput } = require('../src/middleware/sanitize.middleware');
    const { createErrorHandler } = require('../src/middleware/error.middleware');
    const { registerRoutes } = require('../src/api/routes');

    const app = express();
    app.set('trust proxy', true); // las pruebas simulan IPs distintas con X-Forwarded-For
    app.use(express.json({ limit: '1mb' }));
    app.use(express.urlencoded({ extended: false, limit: '1mb' }));
    app.use(protection.autoProtect());
    app.use(sanitizeInput());
    app.get('/health', (req, res) => res.json({ status: 'healthy' }));
    registerRoutes(app);
    app.use((req, res) => res.status(404).json({ success: false, message: 'Ruta no encontrada' }));
    app.use(createErrorHandler({ logError: () => {} }));
    return app;
}

async function startApp() {
    const server = http.createServer(buildApp());
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    return { server, base: `http://127.0.0.1:${port}`, port, close: () => new Promise(resolve => server.close(resolve)) };
}

// Cliente mínimo. `ip` se envía como X-Forwarded-For (el servidor de pruebas confía en él).
async function api(base, method, route, { token, ip, json, form, headers = {}, raw, redirect } = {}) {
    const init = { method, headers: { ...headers } };
    if (redirect) init.redirect = redirect;
    if (ip) init.headers['X-Forwarded-For'] = ip;
    if (token) init.headers.Authorization = `Bearer ${token}`;
    if (json !== undefined) {
        init.headers['Content-Type'] = 'application/json';
        init.body = typeof json === 'string' ? json : JSON.stringify(json);
    }
    if (form) init.body = form;
    if (raw) init.body = raw;

    const res = await fetch(base + route, init);
    const buffer = Buffer.from(await res.arrayBuffer());
    const text = buffer.toString('utf8');
    let body = null;
    try { body = JSON.parse(text); } catch { /* respuesta no JSON (descarga) */ }
    return { status: res.status, headers: res.headers, body, buffer, text };
}

// Petición HTTP "cruda": permite enviar una ruta tal cual (sin que el cliente normalice ".." ni %2e)
function rawRequest(port, { method = 'GET', path: rawPath, headers = {}, body }) {
    return new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, method, path: rawPath, headers }, (res) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
        });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

const PASSWORD = 'Contraseña-Segura-123';
let counter = 0;
const uniqueName = (prefix = 'user') => `${prefix}_${process.pid}_${Date.now().toString(36)}_${counter++}`;

async function registerAndLogin(base, { ip, username = uniqueName(), password = PASSWORD } = {}) {
    const reg = await api(base, 'POST', '/api/auth/register', { ip, json: { username, email: "usuario@example.com", password } });
    if (reg.status !== 201) throw new Error(`registro falló: ${reg.status} ${reg.text}`);
    const login = await api(base, 'POST', '/api/auth/login', { ip, json: { username, password } });
    if (login.status !== 200) throw new Error(`login falló: ${login.status} ${login.text}`);
    return { username, password, token: login.body.token, refreshToken: login.body.refreshToken, userId: reg.body.userId };
}

// IP de documentación (RFC 5737) distinta por prueba: así cada prueba tiene sus propios contadores
let ipCounter = 10;
const testIp = () => `203.0.113.${ipCounter++}`;

module.exports = { prepareDatabase, buildApp, startApp, api, rawRequest, registerAndLogin, uniqueName, testIp, PASSWORD };
