#!/usr/bin/env node
// Tabla de endpoints del README, generada desde docs/openapi.json (que a su vez test_api.js comprueba contra el código).
//
//   npm run docs:endpoints            imprime la tabla
//   npm run docs:endpoints -- --write la sustituye en README.md entre los marcadores <!-- endpoints:inicio --> / <!-- endpoints:fin -->
//
// Así la tabla no puede volver a quedarse atrás: test_api.js falla si la del README no coincide con la generada.
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const START = '<!-- endpoints:inicio -->';
const END = '<!-- endpoints:fin -->';

function render(spec = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs/openapi.json'), 'utf8'))) {
    const groups = new Map();
    for (const [route, operations] of Object.entries(spec.paths)) {
        for (const [method, op] of Object.entries(operations)) {
            const tag = op.tags?.[0] || 'Otros';
            if (!groups.has(tag)) groups.set(tag, []);
            groups.get(tag).push({ method: method.toUpperCase(), route, op });
        }
    }
    const lines = ['| Grupo | Método | Ruta | Acceso | Descripción |', '|---|---|---|---|---|'];
    for (const [tag, list] of groups) {
        for (const { method, route, op } of list) {
            const access = Array.isArray(op.security) && op.security.length === 0 ? 'público' : 'JWT';
            const summary = String(op.summary || '').replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
            lines.push(`| ${tag} | ${method} | \`${route}\` | ${access} | ${summary} |`);
        }
    }
    return lines.join('\n');
}

function currentBlock(readme) {
    const a = readme.indexOf(START), b = readme.indexOf(END);
    return a >= 0 && b > a ? readme.slice(a + START.length, b).trim() : null;
}

if (require.main === module) {
    const table = render();
    if (process.argv.includes('--write')) {
        const file = path.join(ROOT, 'README.md');
        const readme = fs.readFileSync(file, 'utf8');
        const a = readme.indexOf(START), b = readme.indexOf(END);
        if (a < 0 || b < a) { console.error(`README.md no tiene los marcadores ${START} … ${END}`); process.exit(1); }
        fs.writeFileSync(file, `${readme.slice(0, a + START.length)}\n${table}\n${readme.slice(b)}`);
        console.log('README.md actualizado');
    } else {
        console.log(table);
    }
}

module.exports = { render, currentBlock, START, END };
