// `npm run dev` (nodemon) es SOLO para desarrollo: reinicia el proceso al cambiar archivos y no debe usarse en producción.
// Se ejecuta antes de nodemon (ver "dev" en package.json) y se niega si el entorno es de producción.
if (process.env.NODE_ENV === 'production') {
    console.error('❌ "npm run dev" (nodemon) no se usa en producción. Arranca con "npm start" (node src/index.js) bajo un gestor de procesos.');
    process.exit(1);
}
