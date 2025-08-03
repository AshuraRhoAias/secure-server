const nodemailer = require('nodemailer');
const crypto = require('crypto');
const credentialBuilder = require('../config/credential-builder');

class SecureCommunications {
    constructor() {
        this.channels = new Map();
        this.setupChannels();
        this.messageQueue = [];
        this.retryAttempts = new Map();
    }

    setupChannels() {
        try {
            // Canal principal - Gmail
            const primaryEmail = credentialBuilder.buildEmailCredentials('primary');
            this.channels.set('primary_email', {
                name: 'primary_email',
                type: 'email',
                transporter: nodemailer.createTransporter({
                    service: 'gmail',
                    auth: {
                        user: primaryEmail.user,
                        pass: primaryEmail.pass
                    },
                    secure: true,
                    tls: { rejectUnauthorized: true }
                }),
                priority: 1,
                maxRetries: 3
            });

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

            console.log(`✅ ${this.channels.size} canales de comunicación configurados`);

        } catch (error) {
            console.error('❌ Error configurando canales:', error);
        }
    }

    async sendSecureAlert(alertData, priority = 'normal') {
        try {
            // Crear mensaje camuflado
            const camouflageMessage = await this.createCamouflageMessage(alertData);

            const results = [];
            const channelsToUse = this.selectChannels(priority);

            // Enviar por los canales seleccionados
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

            // Verificar que al menos un canal funcionó
            const successfulChannels = results.filter(r => r.success);
            if (successfulChannels.length === 0) {
                throw new Error('Todos los canales de comunicación fallaron');
            }

            // Log del envío exitoso
            await this.logCommunication({
                type: 'ALERT_SENT',
                alertType: alertData.type,
                priority,
                channels: results,
                timestamp: new Date().toISOString()
            });

            return {
                success: true,
                channelsUsed: results
            };

        } catch (error) {
            console.error('❌ Error enviando alerta segura:', error);
            throw error;
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
            'EMERGENCY_ALERT': '🚨 Notificación Crítica Inmediata'
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
            'KEY_ROTATION_SUCCESS': 'normal'
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
            availableChannels: this.channels.size,
            channelTypes: Array.from(this.channels.values()).map(c => c.type),
            messageQueue: this.messageQueue.length,
            retryAttempts: this.retryAttempts.size
        };
    }
}

module.exports = new SecureCommunications();