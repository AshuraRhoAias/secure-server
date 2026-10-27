#!/usr/bin/env node
// Comprueba que NADA de desarrollo llega a producción (se ejecuta en CI y antes de desplegar: npm run check:prod-deps).
//   1. nodemon y demás herramientas de desarrollo están solo en devDependencies.
//   2. "start" arranca con node, no con nodemon, y "dev" pasa por el guardián.
//   3. El código de src/ y scripts/ no hace require de ninguna dependencia de desarrollo.
//   4. Con --installed: en node_modules NO hay herramientas de desarrollo (tras `npm ci --omit=dev`).

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const DEV_ONLY = ['nodemon', 'concurrently', 'eslint', 'eslint-plugin-security', 'globals', 'c8', 'fast-check'];
const problems = [];

for (const name of DEV_ONLY) {
    if (pkg.dependencies?.[name]) problems.push(`${name} está en dependencies: debe estar en devDependencies`);
}
if (/nodemon/.test(pkg.scripts?.start || '')) problems.push('"start" usa nodemon');
if (!/devGuard\.js/.test(pkg.scripts?.dev || '')) problems.push('"dev" debe pasar por scripts/devGuard.js antes de nodemon');
for (const [name, command] of Object.entries(pkg.scripts || {})) {
    if (/^(start|prestart|poststart|postinstall|install|preinstall|prepare)$/.test(name) && /nodemon/.test(command)) problems.push(`el script "${name}" usa nodemon`);
}

const walk = (dir, out = []) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const file = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(file, out); else if (entry.name.endsWith('.js')) out.push(file);
    }
    return out;
};
for (const dir of ['src', 'scripts']) {
    for (const file of walk(path.join(ROOT, dir))) {
        if (path.basename(file) === 'checkProductionDeps.js') continue;
        const text = fs.readFileSync(file, 'utf8');
        // Todos los require('…') del archivo; el nombre se compara por igualdad (sin construir expresiones regulares con datos)
        for (const [, spec] of text.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)) {
            const base = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0];
            if (DEV_ONLY.includes(base)) problems.push(`${path.relative(ROOT, file)} hace require de ${base} (solo desarrollo)`);
        }
    }
}

if (process.argv.includes('--installed')) {
    for (const name of DEV_ONLY) {
        if (fs.existsSync(path.join(ROOT, 'node_modules', name))) problems.push(`node_modules/${name} está instalado: usa "npm ci --omit=dev" en producción`);
    }
}

if (problems.length) {
    console.error('❌ Dependencias de desarrollo en producción:\n  - ' + problems.join('\n  - '));
    process.exit(1);
}
console.log('✅ Producción limpia: nada de desarrollo (nodemon, eslint, c8…) en dependencies, start ni en el código servido');
