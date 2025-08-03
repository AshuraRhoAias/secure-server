#!/usr/bin/env node

const disguiser = require('../src/crypto/disguiser');
const fs = require('fs');
const path = require('path');

class MessageDecryptor {
    constructor() {
        this.outputFile = path.join(__dirname, 'decrypted_keys.json');
        this.patterns = ['default', 'advanced', 'reverse'];
    }

    async decryptFromText(messageText, patternType = 'default') {
        try {
            console.log('🔓 Analizando mensaje camuflado...\n');

            // Intentar decodificar con diferentes patrones
            let decodedPattern = null;
            let usedPattern = patternType;

            if (patternType === 'auto') {
                for (const pattern of this.patterns) {
                    try {
                        decodedPattern = disguiser.decodePattern(messageText, pattern);
                        if (decodedPattern) {
                            usedPattern = pattern;
                            break;
                        }
                    } catch (error) {
                        continue;
                    }
                }
            } else {
                decodedPattern = disguiser.decodePattern(messageText, patternType);
            }

            if (!decodedPattern) {
                throw new Error('No se pudo decodificar el patrón del mensaje');
            }

            console.log('📋 Información extraída:');
            console.log(`   🔑 Patrón utilizado: ${usedPattern}`);
            console.log(`   📊 Índices de clave: [${decodedPattern.keyIndices?.join(', ') || 'N/A'}]`);
            console.log(`   🔐 Clave codificada: ${decodedPattern.encodedKey || 'N/A'}`);

            // Guardar resultado completo
            const result = {
                patternInfo: {
                    pattern: usedPattern,
                    keyIndices: decodedPattern.keyIndices,
                    encodedKey: decodedPattern.encodedKey
                },
                decodedAt: new Date().toISOString(),
                messagePreview: messageText.substring(0, 200) + '...'
            };

            await fs.promises.writeFile(this.outputFile, JSON.stringify(result, null, 2));
            console.log(`\n✅ Resultado guardado en: ${this.outputFile}`);

            return result;

        } catch (error) {
            console.error('❌ Error decifrando mensaje:', error.message);
            throw error;
        }
    }

    showUsage() {
        console.log(`
🔓 Descifrador de Mensajes Camuflados

Uso:
  node scripts/decryptMessage.js [opciones]

Opciones:
  --text "mensaje"     Descifrar texto directamente
  --file ruta/archivo  Descifrar desde archivo
  --pattern tipo       Tipo de patrón (default, advanced, reverse, auto)
  --help              Mostrar esta ayuda

Ejemplos:
  node scripts/decryptMessage.js --text "Cinco blogs han sido detectados..."
  node scripts/decryptMessage.js --file ./mensaje_recibido.txt
  node scripts/decryptMessage.js --text "..." --pattern auto
        `);
    }
}

// Ejecución desde línea de comandos
if (require.main === module) {
    const args = process.argv.slice(2);
    const decryptor = new MessageDecryptor();

    (async () => {
        try {
            if (args.includes('--help') || args.length === 0) {
                decryptor.showUsage();
                process.exit(0);
            }

            let messageText = '';
            let patternType = 'default';

            // Procesar argumentos
            for (let i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case '--text':
                        messageText = args[i + 1];
                        i++;
                        break;
                    case '--file':
                        const filePath = args[i + 1];
                        messageText = await fs.promises.readFile(filePath, 'utf8');
                        i++;
                        break;
                    case '--pattern':
                        patternType = args[i + 1];
                        i++;
                        break;
                }
            }

            if (!messageText) {
                throw new Error('Debe proporcionar un mensaje o archivo para descifrar');
            }

            const result = await decryptor.decryptFromText(messageText, patternType);
            console.log('\n🎉 Descifrado completado exitosamente');

        } catch (error) {
            console.error('\n❌ Error:', error.message);
            console.log('\n💡 Usa --help para ver las opciones disponibles');
            process.exit(1);
        }
    })();
}

module.exports = MessageDecryptor;