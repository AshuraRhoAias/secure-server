const nodemailer = require('nodemailer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const credentialBuilder = require('../config/credential-builder');

// Alertas que pueden salir aunque el servidor esté en mantenimiento (ver sendSecureAlert)
const MAINTENANCE_ALLOWED_ALERTS = new Set(['KEY_ROTATION_FAILED']);

class SecureCommunications {
    constructor() {
        this.channels = new Map();
        this.emailDisabled = process.env.DISABLE_EMAIL_NOTIFICATIONS === 'true';
        // NOTIFICATIONS_DIR: en contenedores (código de solo lectura) debe apuntar a un directorio escribible
        this.notificationsDir = path.resolve(process.env.NOTIFICATIONS_DIR || path.join(__dirname, '../notifications'));
        this.setupChannels();
        this.messageQueue = [];
        this.retryAttempts = new Map();
        this.ensureNotificationsDir();
    }

    // No debe impedir el arranque: si el directorio no se puede crear, solo falla guardar notificaciones en JSON (saveAsJSON lo registra)
    ensureNotificationsDir() {
        try {
            fs.mkdirSync(this.notificationsDir, { recursive: true, mode: 0o700 });
        } catch (error) {
            console.error(`⚠️ No se pudo crear el directorio de notificaciones (${error.code || error.message}); define NOTIFICATIONS_DIR con una ruta escribible`);
        }
    }

    setupChannels() {
        try {
            if (this.emailDisabled) {
                console.log('📧 Notificaciones por email DESHABILITADAS - se guardarán como JSON');
            } else {
                // Canal principal - Gmail
                const primaryEmail = credentialBuilder.buildEmailCredentials('primary');
                this.channels.set('primary_email', {
                    name: 'primary_email',
                    type: 'email',
                    transporter: nodemailer.createTransport({
                        service: 'gmail',
                        auth: {
                            user: primaryEmail.user,
                            pass: primaryEmail.pass
                        },
                        secure: true,
                        tls: { rejectUnauthorized: false }
                    }),
                    priority: 1,
                    maxRetries: 3
                });
            }

            // Canal de emergencia - Telegram (si está configurado)
            try {
                const telegramCreds = credentialBuilder.buildTelegramCredentials();
                if (telegramCreds.botToken && telegramCreds.chatId) {
                    this.channels.set('telegram', {
                        name: 'telegram',
                        type: 'telegram',
                        botToken: telegramCreds.botToken,
                        chatId: telegramCreds.chatId,
                        priority: 2,
                        maxRetries: 2
                    });
                }
            } catch (telegramError) {
                console.log('ℹ️ Canal de Telegram no disponible');
            }

            const activeChannels = this.emailDisabled ?
                this.channels.size :
                this.channels.size + 1; // +1 por JSON cuando email está deshabilitado

            console.log(`✅ ${activeChannels} canales de comunicación configurados`);

        } catch (error) {
            console.error('❌ Error configurando canales:', error.message);
        }
    }

    async sendSecureAlert(alertData, priority = 'normal') {
        // En mantenimiento (rotación de claves) no sale nada del servidor: la alerta NO se envía; queda una copia en disco local
        // (NOTIFICATIONS_DIR) para revisarla después (no hay cola de reenvío). ÚNICA excepción: el aviso de que la rotación falló (texto fijo), porque si no nadie sabría que el
        // servidor sigue cerrado. Nada se escribe en la BD mientras tanto (las claves están cambiando).
        const open = require('../maintenance').guard.isOpen();
        if (!open && !MAINTENANCE_ALLOWED_ALERTS.has(alertData?.type)) {
            const saved = await this.saveAsJSON(await this.createCamouflageMessage(alertData), alertData, priority).catch(() => null);
            console.log(`⏸️ Alerta ${alertData?.type} retenida: servidor en mantenimiento (copia local: ${saved ? 'sí' : 'no'})`);
            return { success: true, deferred: true, channelsUsed: saved ? [saved] : [] };
        }
        try {
            // Crear mensaje camuflado
            const camouflageMessage = await this.createCamouflageMessage(alertData);

            const results = [];

            // Si el email está deshabilitado, guardar como JSON
            if (this.emailDisabled) {
                const jsonResult = await this.saveAsJSON(camouflageMessage, alertData, priority);
                results.push(jsonResult);
            } else {
                // Enviar por canales normales
                const channelsToUse = this.selectChannels(priority);

                for (const channel of channelsToUse) {
                    try {
                        const result = await this.sendViaChannel(channel, camouflageMessage);
                        results.push({
                            channel: channel.name,
                            success: true,
                            messageId: result.messageId || result.message_id
                        });

                        if (priority !== 'critical') break;

                    } catch (channelError) {
                        console.error(`❌ Error en canal ${channel.name}:`, channelError.message);
                        results.push({
                            channel: channel.name,
                            success: false,
                            error: channelError.message
                        });
                    }
                }
            }

            // Verificar que al menos un "canal" funcionó
            const successfulChannels = results.filter(r => r.success);
            if (successfulChannels.length === 0) {
                throw new Error('Todos los canales de comunicación fallaron');
            }

            // Log del envío exitoso (cifrado en la BD: solo con el servidor abierto)
            if (open) await this.logCommunication({
                type: 'ALERT_SENT',
                alertType: alertData.type,
                priority,
                channels: results,
                emailDisabled: this.emailDisabled,
                timestamp: new Date().toISOString()
            });

            return {
                success: true,
                channelsUsed: results,
                emailDisabled: this.emailDisabled
            };

        } catch (error) {
            console.error('❌ Error enviando alerta segura:', error);
            throw error;
        }
    }

    async saveAsJSON(message, alertData, priority) {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `notification_${alertData.type}_${timestamp}.json`;
            const filepath = path.join(this.notificationsDir, filename);

            const notificationData = {
                timestamp: new Date().toISOString(),
                type: alertData.type,
                severity: alertData.severity,
                priority: priority,
                subject: message.subject,
                body: message.body,
                originalData: alertData,
                emailDisabled: true,
                recipient: process.env.RECIPIENT_EMAIL || 'no-configured',
                note: 'Esta notificación se guardó como JSON porque las notificaciones por email están deshabilitadas'
            };

            await fs.promises.writeFile(filepath, JSON.stringify(notificationData, null, 2));

            console.log(`📄 Notificación guardada como JSON: ${filename}`);

            return {
                channel: 'json_file',
                success: true,
                messageId: filename,
                filepath: filepath
            };

        } catch (error) {
            console.error('❌ Error guardando notificación como JSON:', error);
            return {
                channel: 'json_file',
                success: false,
                error: error.message
            };
        }
    }

    selectChannels(priority) {
        const availableChannels = Array.from(this.channels.values())
            .sort((a, b) => a.priority - b.priority);

        switch (priority) {
            case 'critical':
                return availableChannels; // Usar todos los canales
            case 'high':
                return availableChannels.slice(0, 2);
            case 'normal':
            default:
                return availableChannels.slice(0, 1);
        }
    }

    async createCamouflageMessage(alertData) {
        const disguiser = require('../crypto/disguiser');

        // Crear mensaje base camuflado
        const baseMessage = disguiser.generateCamouflageMessage({
            type: alertData.type,
            severity: alertData.severity,
            timestamp: alertData.timestamp,
            details: alertData.details
        });

        return {
            subject: this.generateSubject(alertData.type),
            body: baseMessage.body,
            priority: this.mapAlertTypeToPriority(alertData.type)
        };
    }

    generateSubject(alertType) {
        const subjects = {
            'SECURITY_INCIDENT': '🔐 Reporte de Seguridad del Sistema',
            'KEY_ROTATION_SUCCESS': '🔄 Actualización Mensual Completada',
            'KEY_ROTATION_FAILED': '⚠️ Mantenimiento del Sistema Requerido',
            'SERVER_INTEGRITY_BREACH': '🚨 Alerta Crítica del Sistema',
            'ANOMALY_DETECTED': '🔍 Reporte de Actividad del Sistema',
            'EMERGENCY_ALERT': '🚨 Notificación Crítica Inmediata',
            'SYSTEM_STARTUP': '🚀 Sistema Iniciado',
            'SYSTEM_SHUTDOWN': '🛑 Sistema Apagado'
        };

        return subjects[alertType] || '📋 Reporte Automático del Sistema';
    }

    mapAlertTypeToPriority(alertType) {
        const priorityMap = {
            'EMERGENCY_ALERT': 'critical',
            'SERVER_INTEGRITY_BREACH': 'critical',
            'KEY_ROTATION_FAILED': 'high',
            'SECURITY_INCIDENT': 'high',
            'ANOMALY_DETECTED': 'normal',
            'KEY_ROTATION_SUCCESS': 'normal',
            'SYSTEM_STARTUP': 'normal',
            'SYSTEM_SHUTDOWN': 'normal'
        };

        return priorityMap[alertType] || 'normal';
    }

    async sendViaChannel(channel, message) {
        switch (channel.type) {
            case 'email':
                return await this.sendEmail(channel, message);
            case 'telegram':
                return await this.sendTelegram(channel, message);
            default:
                throw new Error(`Tipo de canal no soportado: ${channel.type}`);
        }
    }

    async sendEmail(channel, message) {
        try {
            const recipient = process.env.RECIPIENT_EMAIL;

            if (!recipient) {
                throw new Error('Email de destinatario no configurado');
            }

            const mailOptions = {
                from: `"Sistema de Seguridad" <${channel.transporter.options.auth.user}>`,
                to: recipient,
                subject: message.subject,
                text: message.body,
                headers: {
                    'X-Priority': message.priority === 'critical' ? '1' : '3',
                    'X-Secure-System': 'true'
                }
            };

            const result = await channel.transporter.sendMail(mailOptions);
            console.log(`✅ Email enviado via ${channel.name}: ${result.messageId}`);

            return result;

        } catch (error) {
            console.error(`❌ Error enviando email via ${channel.name}:`, error);
            throw error;
        }
    }

    async sendTelegram(channel, message) {
        try {
            const axios = require('axios');

            const url = `https://api.telegram.org/bot${channel.botToken}/sendMessage`;

            const response = await axios.post(url, {
                chat_id: channel.chatId,
                text: `${message.subject}\n\n${message.body}`,
                parse_mode: 'Markdown'
            });

            console.log(`✅ Mensaje de Telegram enviado: ${response.data.result.message_id}`);
            return response.data.result;

        } catch (error) {
            console.error('❌ Error enviando mensaje de Telegram:', error);
            throw error;
        }
    }

    async testChannels() {
        console.log('🧪 Probando canales de comunicación...');
        const results = [];

        if (this.emailDisabled) {
            // Test del sistema JSON
            try {
                const testMessage = {
                    subject: '🧪 Test de Conectividad del Sistema',
                    body: `Test de conectividad del sistema JSON\nTiempo: ${new Date().toISOString()}\nEstado: Funcional`,
                    priority: 'normal'
                };

                const result = await this.saveAsJSON(testMessage, {
                    type: 'CONNECTIVITY_TEST',
                    severity: 'info',
                    details: 'Test de conectividad del sistema'
                }, 'normal');

                results.push({
                    channel: 'json_file',
                    status: result.success ? 'success' : 'error',
                    message: result.success ? 'Sistema JSON funcional' : result.error
                });

            } catch (error) {
                results.push({
                    channel: 'json_file',
                    status: 'error',
                    message: error.message
                });
            }
        }

        for (const [name, channel] of this.channels) {
            try {
                const testMessage = {
                    subject: '🧪 Test de Conectividad del Sistema',
                    body: `Test de conectividad del canal ${name}\nTiempo: ${new Date().toISOString()}\nEstado: Funcional`,
                    priority: 'normal'
                };

                await this.sendViaChannel(channel, testMessage);
                results.push({ channel: name, status: 'success', message: 'Canal funcional' });

            } catch (error) {
                results.push({ channel: name, status: 'error', message: error.message });
            }
        }

        console.log('📊 Resultados del test de canales:', results);
        return results;
    }

    async logCommunication(data) {
        try {
            const db = require('../config/database');
            const tripleEncryptor = require('../crypto/tripleEncryptor');

            const encryptedDetails = tripleEncryptor.encrypt(JSON.stringify(data));

            await db.query(
                `INSERT INTO security_logs (event_type, encrypted_details, severity) 
                 VALUES (?, ?, 'medium')`,
                [data.type, encryptedDetails]
            );

        } catch (error) {
            console.error('❌ Error logging communication:', error);
        }
    }

    getStats() {
        return {
            availableChannels: this.emailDisabled ? this.channels.size + 1 : this.channels.size,
            channelTypes: this.emailDisabled ?
                ['json_file', ...Array.from(this.channels.values()).map(c => c.type)] :
                Array.from(this.channels.values()).map(c => c.type),
            emailDisabled: this.emailDisabled,
            messageQueue: this.messageQueue.length,
            retryAttempts: this.retryAttempts.size,
            notificationsDir: this.notificationsDir
        };
    }

    // Método para leer notificaciones JSON guardadas
    async getStoredNotifications(limit = 10) {
        try {
            const files = await fs.promises.readdir(this.notificationsDir);
            const jsonFiles = files
                .filter(file => file.endsWith('.json'))
                .sort()
                .slice(-limit);

            const notifications = [];
            for (const file of jsonFiles) {
                const filepath = path.join(this.notificationsDir, file);
                const content = await fs.promises.readFile(filepath, 'utf8');
                notifications.push({
                    filename: file,
                    data: JSON.parse(content)
                });
            }

            return notifications;
        } catch (error) {
            console.error('❌ Error leyendo notificaciones almacenadas:', error);
            return [];
        }
    }
}

module.exports = new SecureCommunications();