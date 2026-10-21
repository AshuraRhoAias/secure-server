// Segundo proceso de servidor para las pruebas: demuestra que el estado de seguridad vive en la base de
// datos y no en la memoria de un proceso. Imprime "PORT <n>" cuando está listo.
require('./env');
const { startApp } = require('./app');

startApp().then(({ port }) => {
    console.log(`PORT ${port}`);
});
