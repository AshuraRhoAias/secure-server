const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const db = require('../config/database');
const tripleEncryptor = require('../crypto/tripleEncryptor');
const totp = require('./totp');

// Autenticación en dos pasos (TOTP). Todo el estado está en la base de datos.
//
//  - El secreto TOTP se guarda cifrado (v4) y se registra en encrypted-columns.js, así que la rotación
//    de claves lo re-cifra como el resto.
//  - Un código no se puede reutilizar: el paso de 30 s aceptado se guarda con un UPDATE atómico
//    (`mfa_last_step < paso`), de modo que dos peticiones simultáneas con el mismo código no pasan las dos.
//  - Códigos de recuperación de un solo uso (10), solo se guarda su hash; se marcan como usados con
//    otro UPDATE atómico.

const ISSUER = () => process.env.MFA_ISSUER || 'Secure Server';
const RECOVERY_CODES = 10;

class MfaError extends Error {
    constructor(code, message, status = 400) {
        super(message);
        this.code = code;
        this.status = status;
    }
}

class MfaService {
    async getState(userId) {
        const [rows] = await db.query(
            'SELECT mfa_enabled, mfa_secret_encrypted, mfa_last_step FROM users WHERE id = ?', [userId]);
        return rows[0] || null;
    }

    async status(userId) {
        const state = await this.getState(userId);
        const [[codes]] = await db.query(
            'SELECT COUNT(*) AS remaining FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL', [userId]);
        return { enabled: Boolean(state?.mfa_enabled), pendingSetup: Boolean(state?.mfa_secret_encrypted && !state.mfa_enabled), recoveryCodesRemaining: Number(codes.remaining) };
    }

    // Paso 1 del alta: genera un secreto NUEVO (no activo todavía) y lo devuelve una sola vez
    async beginSetup(userId, account) {
        const state = await this.getState(userId);
        if (state?.mfa_enabled) throw new MfaError('MFA_ALREADY_ENABLED', 'La autenticación en dos pasos ya está activada', 409);

        const secret = totp.generateSecret();
        await db.query(
            'UPDATE users SET mfa_secret_encrypted = ?, mfa_enabled = 0, mfa_last_step = NULL WHERE id = ?',
            [tripleEncryptor.encrypt(secret), userId]
        );

        const otpauthUrl = totp.otpauthUrl({ secret, account, issuer: ISSUER() });
        return { secret, otpauthUrl, qrDataUrl: await QRCode.toDataURL(otpauthUrl, { margin: 1, width: 240 }) };
    }

    // Paso 2: el usuario demuestra que su app genera códigos válidos. Activa MFA y entrega los códigos de recuperación.
    async enable(userId, otp) {
        const state = await this.getState(userId);
        if (!state?.mfa_secret_encrypted) throw new MfaError('MFA_NOT_STARTED', 'Primero inicia el alta (POST /api/auth/mfa/setup)', 409);
        if (state.mfa_enabled) throw new MfaError('MFA_ALREADY_ENABLED', 'La autenticación en dos pasos ya está activada', 409);

        const secret = tripleEncryptor.decrypt(state.mfa_secret_encrypted);
        const check = totp.verifyTotp(secret, otp);
        if (!check.ok) throw new MfaError('INVALID_OTP', 'Código incorrecto', 401);

        const [result] = await db.query(
            'UPDATE users SET mfa_enabled = 1, mfa_last_step = ? WHERE id = ? AND mfa_enabled = 0', [check.step, userId]);
        if (result.affectedRows !== 1) throw new MfaError('MFA_ALREADY_ENABLED', 'La autenticación en dos pasos ya está activada', 409);

        return { recoveryCodes: await this.regenerateRecoveryCodes(userId) };
    }

    async regenerateRecoveryCodes(userId) {
        const codes = Array.from({ length: RECOVERY_CODES }, () => totp.generateRecoveryCode());
        await db.transaction(async (tx) => {
            await tx.query('DELETE FROM user_recovery_codes WHERE user_id = ?', [userId]);
            for (const code of codes) {
                await tx.query('INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (?, ?)', [userId, totp.hashRecoveryCode(code)]);
            }
        });
        return codes;
    }

    // Verifica un código TOTP O uno de recuperación. Devuelve { ok, method }.
    async verify(userId, { otp, recoveryCode }) {
        const state = await this.getState(userId);
        if (!state?.mfa_enabled || !state.mfa_secret_encrypted) return { ok: false };

        if (recoveryCode) {
            const [result] = await db.query(
                'UPDATE user_recovery_codes SET used_at = NOW() WHERE user_id = ? AND code_hash = ? AND used_at IS NULL',
                [userId, totp.hashRecoveryCode(recoveryCode)]
            );
            return result.affectedRows === 1 ? { ok: true, method: 'recovery' } : { ok: false };
        }

        const secret = tripleEncryptor.decrypt(state.mfa_secret_encrypted);
        const check = totp.verifyTotp(secret, otp, { lastStep: state.mfa_last_step });
        if (!check.ok) return { ok: false, replay: Boolean(check.replay) };

        // Atómico: solo uno de dos intentos simultáneos con el mismo código puede avanzar el paso
        const [result] = await db.query(
            'UPDATE users SET mfa_last_step = ? WHERE id = ? AND (mfa_last_step IS NULL OR mfa_last_step < ?)',
            [check.step, userId, check.step]
        );
        return result.affectedRows === 1 ? { ok: true, method: 'totp' } : { ok: false, replay: true };
    }

    // Desactivar exige contraseña (la comprueba el controlador) Y un segundo factor válido
    async disable(userId) {
        await db.transaction(async (tx) => {
            await tx.query('UPDATE users SET mfa_enabled = 0, mfa_secret_encrypted = NULL, mfa_last_step = NULL WHERE id = ?', [userId]);
            await tx.query('DELETE FROM user_recovery_codes WHERE user_id = ?', [userId]);
        });
    }

    async passwordMatches(userId, password) {
        const [rows] = await db.query('SELECT password_hash FROM users WHERE id = ?', [userId]);
        return rows.length > 0 && bcrypt.compare(String(password), rows[0].password_hash);
    }
}

module.exports = new MfaService();
module.exports.MfaError = MfaError;
