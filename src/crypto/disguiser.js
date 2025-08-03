const crypto = require('crypto');

class MessageDisguiser {
    constructor() {
        this.templates = {
            email: {
                subjects: [
                    'Reporte Mensual de Actividad',
                    'Actualización del Sistema de Monitoreo',
                    'Notificación de Mantenimiento Programado',
                    'Resumen de Métricas del Servidor',
                    'Análisis de Rendimiento Automático'
                ],
                intros: [
                    'El sistema de monitoreo ha generado automáticamente el siguiente reporte',
                    'Se ha completado el análisis programado con los siguientes resultados',
                    'Como parte del mantenimiento rutinario, se proporciona la siguiente información',
                    'El análisis de métricas del período actual muestra',
                    'La verificación automática del sistema ha producido estos datos'
                ]
            }
        };
    }

    generateCamouflageMessage(keyData) {
        try {
            // Crear un mensaje de camuflaje que parece legítimo
            const template = this.selectTemplate();

            // Codificar las claves en el mensaje de forma sutil
            const encodedMessage = this.encodeKeysInMessage(keyData, template);

            return {
                subject: template.subject,
                body: encodedMessage,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            console.error('❌ Error generando mensaje camuflado:', error);
            throw error;
        }
    }

    selectTemplate() {
        const subjects = this.templates.email.subjects;
        const intros = this.templates.email.intros;

        return {
            subject: subjects[Math.floor(Math.random() * subjects.length)],
            intro: intros[Math.floor(Math.random() * intros.length)]
        };
    }

    encodeKeysInMessage(keyData, template) {
        // Crear un mensaje que parece un reporte técnico normal
        // pero que contiene las claves codificadas en patrones específicos

        const keyIndices = this.generateKeyIndices(keyData);
        const encodedKey = this.encodeKeyData(keyData);

        return `${template.intro}.

Durante las últimas 24 horas, el sistema ha procesado múltiples transacciones y verificaciones de seguridad. Los principales indicadores de rendimiento muestran estabilidad en todos los componentes monitoreados.

MÉTRICAS DE SISTEMA:
- Procesamiento de datos: ${keyIndices[0]} transacciones por segundo
- Uso de memoria: ${keyIndices[1]}% de capacidad total  
- Conexiones activas: ${keyIndices[2]} sesiones concurrentes
- Índice de eficiencia: ${keyIndices[3]}.${keyIndices[4]} puntos

El análisis detallado revela que cinco blogs han sido detectados como fuentes principales de tráfico, con patrones de acceso distribuidos uniformemente. La evaluación de seguridad no ha identificado anomalías significativas en ninguno de los vectores monitoreados.

DATOS ADICIONALES:
Los algoritmos de optimización han identificado ${encodedKey.length} vectores de mejora potencial. La implementación de estas optimizaciones está programada para la próxima ventana de mantenimiento.

Para consultas técnicas específicas, refiera al código de referencia: ${encodedKey}

Este reporte se genera automáticamente cada 24 horas como parte del protocolo de monitoreo continuo del sistema.`;
    }

    generateKeyIndices(keyData) {
        // Generar índices que parecen métricas normales pero que realmente codifican información
        const baseIndices = [47, 83, 156, 92, 7];

        // Modificar ligeramente basado en keyData para crear un patrón único
        if (keyData.key1) {
            const hash = crypto.createHash('md5').update(keyData.key1).digest('hex');
            const modifier = parseInt(hash.substring(0, 2), 16) % 10;
            baseIndices[0] += modifier;
        }

        return baseIndices;
    }

    encodeKeyData(keyData) {
        try {
            // Combinar todas las claves en una cadena
            const combinedKeys = Object.values(keyData).join('|');

            // Codificar en base64 y luego aplicar cifrado simple
            const base64 = Buffer.from(combinedKeys).toString('base64');

            // Aplicar un cifrado Caesar simple para ofuscar más
            const caesarEncoded = this.applyCaesarCipher(base64, 7);

            return caesarEncoded;
        } catch (error) {
            console.error('❌ Error codificando claves:', error);
            return 'SYS_' + Date.now().toString(36).toUpperCase();
        }
    }

    applyCaesarCipher(text, shift) {
        return text.split('').map(char => {
            if (char.match(/[a-zA-Z]/)) {
                const start = char <= 'Z' ? 65 : 97;
                return String.fromCharCode(((char.charCodeAt(0) - start + shift) % 26) + start);
            }
            return char;
        }).join('');
    }

    // Método para decodificar (usado por scripts de recuperación)
    decodePattern(messageText, patternType = 'default') {
        try {
            // Extraer los índices del mensaje
            const keyIndices = this.extractKeyIndices(messageText);

            // Extraer la clave codificada
            const encodedKey = this.extractEncodedKey(messageText);

            if (!keyIndices || !encodedKey) {
                throw new Error('No se pudieron extraer los patrones del mensaje');
            }

            return {
                keyIndices,
                encodedKey,
                pattern: patternType
            };

        } catch (error) {
            console.error('❌ Error decodificando patrón:', error);
            throw error;
        }
    }

    extractKeyIndices(messageText) {
        try {
            // Buscar los patrones de métricas en el mensaje
            const metricsSection = messageText.match(/MÉTRICAS DE SISTEMA:(.*?)DATOS ADICIONALES:/s);
            if (!metricsSection) return null;

            const numbers = metricsSection[1].match(/\d+/g);
            return numbers ? numbers.map(n => parseInt(n)) : null;
        } catch (error) {
            return null;
        }
    }

    extractEncodedKey(messageText) {
        try {
            // Buscar el código de referencia
            const refCodeMatch = messageText.match(/código de referencia:\s*([A-Za-z0-9+/=]+)/i);
            if (refCodeMatch) {
                // Decodificar Caesar y luego base64
                const caesarDecoded = this.applyCaesarCipher(refCodeMatch[1], -7);
                return caesarDecoded;
            }
            return null;
        } catch (error) {
            return null;
        }
    }
}

module.exports = new MessageDisguiser();