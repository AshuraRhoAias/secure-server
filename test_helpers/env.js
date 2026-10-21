// Entorno de las pruebas de integración (security / files). Debe requerirse ANTES de cargar cualquier
// módulo del proyecto: secure-env deriva las claves al cargarse.
//
// Usan una base de datos MySQL/MariaDB REAL (no dobles). Por defecto:
//
//   mysql://sec:sec_test_pw@127.0.0.1:3306/secure_platform_test_app      (cámbialo con TEST_APP_DB_URL)
//
// Preparación (una vez): CREATE DATABASE secure_platform_test_app; y un usuario con todos los permisos sobre ella.
// Si no hay base de datos disponible, las pruebas de integración se omiten.

const fs = require('fs');
const os = require('os');
const path = require('path');

const dbUrl = new URL(process.env.TEST_APP_DB_URL || 'mysql://sec:sec_test_pw@127.0.0.1:3306/secure_platform_test_app');
const DB_NAME = dbUrl.pathname.slice(1);

const filesDir = process.env.TEST_FILES_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'secure-files-'));

Object.assign(process.env, {
    NODE_ENV: 'test',
    BASE_SEED: 'base-seed-de-tests-app',
    ENCRYPTION_SEED: 'enc-seed-de-tests-app',
    JWT_SEED: 'jwt-seed-de-tests-app',
    KEY_EPOCH: 'APP-T0',
    DB_FRAGMENT_1: `mysql://${dbUrl.username}:${dbUrl.password}@`,
    DB_FRAGMENT_2: dbUrl.host,
    DB_FRAGMENT_3: `/${DB_NAME}`,
    DISABLE_EMAIL_NOTIFICATIONS: 'true',
    FILES_DIR: filesDir
});

// Las pruebas lanzan muchas peticiones desde pocas IP: se sube el límite global. Los tests de límites
// lo bajan a propósito (y un proceso hijo hereda ese valor, por eso solo se fija si no viene ya definido).
process.env.RATE_LIMIT_GLOBAL_PER_MIN ??= '100000';
process.env.SENSITIVE_RATE_LIMIT_PER_MIN ??= '100000';
process.env.UPLOAD_RATE_PER_MIN ??= '100000';
process.env.DOWNLOAD_RATE_PER_MIN ??= '100000';

module.exports = { dbUrl, DB_NAME, filesDir };
