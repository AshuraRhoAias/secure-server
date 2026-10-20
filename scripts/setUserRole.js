#!/usr/bin/env node
// Asigna un rol a un usuario existente (necesario para acceder a /api/system/*).
//
//   npm run set-role -- --user-id 1 --role admin
//
// Requiere haber ejecutado database/migrations/001_roles_and_notes.sql.

require('dotenv').config({ path: process.env.ENV_FILE || require('path').join(__dirname, '../.env') });

const VALID_ROLES = ['user', 'admin'];

function parseArgs(argv) {
    const args = {};
    for (let i = 0; i < argv.length; i++) {
        if (argv[i].startsWith('--')) args[argv[i].slice(2)] = argv[i + 1];
    }
    return args;
}

async function main() {
    const { 'user-id': userId, role } = parseArgs(process.argv.slice(2));

    if (!userId || !/^\d+$/.test(userId) || !VALID_ROLES.includes(role)) {
        console.error('Uso: npm run set-role -- --user-id <id> --role <user|admin>');
        process.exit(1);
    }

    const db = require('../src/config/database');

    try {
        const [result] = await db.query('UPDATE users SET role = ? WHERE id = ?', [role, Number(userId)]);

        if (result.affectedRows === 0) {
            console.error(`❌ No existe un usuario con id ${userId}`);
            process.exitCode = 1;
        } else {
            console.log(`✅ Usuario ${userId} ahora tiene el rol "${role}"`);
        }
    } catch (error) {
        if (error.code === 'ER_BAD_FIELD_ERROR') {
            console.error('❌ Falta la columna users.role. Ejecuta database/migrations/001_roles_and_notes.sql');
        } else {
            console.error('❌ Error asignando rol:', error.message);
        }
        process.exitCode = 1;
    } finally {
        await db.pool.end();
    }
}

main();
