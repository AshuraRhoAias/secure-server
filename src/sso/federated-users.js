const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../config/database');
const tripleEncryptor = require('../crypto/tripleEncryptor');
const secureAuth = require('../security/secure-auth.service');
const { SsoError } = require('./errors');

// Usuario local de una identidad federada (OIDC o SAML).
//
//  - La identidad es (emisor, sujeto): sha256("<emisor>|<sujeto>"). Nunca se enlaza por email con una cuenta existente
//    (vector clásico de toma de cuentas: quien controle un email en el proveedor se haría con la cuenta local).
//  - Si no existe, se crea (si la configuración lo permite y el dominio del email está permitido) con una contraseña
//    imposible de adivinar: esa cuenta solo entra por el proveedor.
//  - El proveedor solo concede o retira 'admin'; los roles auditor/operator (asignados con set-role) no se degradan.

const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');

// claimedRole: 'admin' | 'user' | null (null = el rol se gestiona en la BD, el proveedor no opina)
async function resolveFederatedUser({ issuerKey, subject, email = '', claimedRole = null, autoProvision = true, allowedDomains = [], provisionedBy = 'sso' }) {
    const identityHash = sha256(`${issuerKey}|${subject}`);

    const [found] = await db.query(
        `SELECT u.id, u.username_encrypted, u.role FROM user_identities i JOIN users u ON u.id = i.user_id WHERE i.identity_hash = ?`,
        [identityHash]
    );
    if (found.length > 0) {
        await db.query('UPDATE user_identities SET last_login_at = NOW() WHERE identity_hash = ?', [identityHash]);
        const roleNow = found[0].role;
        const nextRole = claimedRole === 'admin' ? 'admin' : (roleNow === 'admin' ? 'user' : roleNow);
        if (claimedRole && nextRole !== roleNow) await db.query('UPDATE users SET role = ? WHERE id = ?', [nextRole, found[0].id]);
        return { id: found[0].id, username: tripleEncryptor.decrypt(found[0].username_encrypted), role: claimedRole ? nextRole : roleNow, provisioned: false };
    }

    if (!autoProvision) throw new SsoError('SSO_USER_NOT_PROVISIONED', 'Tu usuario no está dado de alta', { status: 403, rule: 'SSO_USER_NOT_PROVISIONED' });

    const mail = typeof email === 'string' ? email.toLowerCase() : '';
    if (allowedDomains.length > 0 && !allowedDomains.includes(mail.split('@')[1] || '')) {
        throw new SsoError('SSO_DOMAIN_NOT_ALLOWED', 'Tu dominio no tiene acceso', { status: 403, rule: 'SSO_DOMAIN_NOT_ALLOWED' });
    }

    const username = `sso_${identityHash.slice(0, 20)}`;
    const usernameHash = secureAuth.generateUsernameHash(username);
    const role = claimedRole || 'user';

    try {
        const created = await db.transaction(async (tx) => {
            const [result] = await tx.query(
                `INSERT INTO users (username_encrypted, username_hash, email_encrypted, password_hash, device_fingerprint,
                                    risk_level_encrypted, encrypted_metadata, encryption_version, role, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`,
                [
                    tripleEncryptor.encrypt(username), usernameHash, tripleEncryptor.encrypt(mail),
                    await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10),
                    '', tripleEncryptor.encrypt('low'),
                    tripleEncryptor.encrypt(JSON.stringify({ provisionedBy, issuer: issuerKey, at: new Date().toISOString() })),
                    'v4.0.0', role
                ]
            );
            await tx.query('INSERT INTO user_identities (user_id, issuer, identity_hash, last_login_at) VALUES (?, ?, ?, NOW())', [result.insertId, issuerKey.slice(0, 255), identityHash]);
            return result.insertId;
        });
        return { id: created, username, role, provisioned: true };
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return resolveFederatedUser({ issuerKey, subject, email, claimedRole, autoProvision, allowedDomains, provisionedBy }); // dos primeros logins a la vez: gana uno
        throw error;
    }
}

module.exports = { resolveFederatedUser, sha256 };
