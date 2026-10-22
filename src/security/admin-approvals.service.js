// Aprobación de dos administradores para acciones destructivas o de alto riesgo.
//
//   Admin A:  POST /api/system/accounts/mfa-reset { username, reason }  ->  202, queda PENDIENTE
//   Admin B:  POST /api/system/approvals/:id/approve                    ->  se ejecuta
//
// Reglas (todas con prueba en test_rbac.js):
//  - Quien solicita NO puede aprobar su propia solicitud. Otro administrador distinto, siempre.
//  - La transición pending -> approved es un UPDATE atómico: si dos administradores aprueban a la vez, ejecuta uno.
//  - La solicitud caduca (ADMIN_APPROVAL_TTL_HOURS, 24 h) y queda todo en admin_approvals: quién, cuándo, por qué, resultado.
//  - ADMIN_APPROVALS_REQUIRED=1 salta la segunda firma (instalaciones con UN administrador): se ejecuta al momento,
//    pero igualmente queda registrado. Por defecto es 2.
//
// Límite honesto: dos CUENTAS no son dos PERSONAS. Si una persona controla ambas, esto no la frena.

const db = require('../config/database');
const events = require('./security-events.service');

class ApprovalError extends Error {
    constructor(code, message, status = 400) {
        super(message);
        this.code = code;
        this.status = status;
    }
}

const intEnv = (name, fallback) => {
    const n = Number(process.env[name]);
    return Number.isInteger(n) && n > 0 ? n : fallback;
};

// action -> { describe, execute({ targetUserId, params, requestedBy, approvedBy }) }
const handlers = new Map();
function registerAction(action, handler) {
    handlers.set(action, handler);
}

const twoPersonRequired = () => intEnv('ADMIN_APPROVALS_REQUIRED', 2) >= 2;

async function runAction(row) {
    const handler = handlers.get(row.action);
    if (!handler) throw new ApprovalError('UNKNOWN_ACTION', `Acción desconocida: ${row.action}`, 500);
    return handler.execute({
        targetUserId: row.target_user_id,
        params: row.params ? JSON.parse(row.params) : {},
        requestedBy: row.requested_by,
        approvedBy: row.approved_by
    });
}

async function finish(id, row) {
    try {
        const result = await runAction(row);
        await db.query("UPDATE admin_approvals SET status = 'executed', executed_at = NOW(), result = ? WHERE id = ?", [JSON.stringify(result ?? {}), id]);
        await events.record({
            type: 'ADMIN_APPROVAL_EXECUTED', severity: 'high', riskScore: 40, userId: row.target_user_id,
            details: { approvalId: id, action: row.action, requestedBy: row.requested_by, approvedBy: row.approved_by }
        });
        return { status: 'executed', result: result ?? {} };
    } catch (error) {
        await db.query("UPDATE admin_approvals SET status = 'failed', executed_at = NOW(), result = ? WHERE id = ?", [JSON.stringify({ error: error.code || error.message }), id]);
        await events.record({
            type: 'ADMIN_APPROVAL_FAILED', severity: 'high', riskScore: 40, userId: row.target_user_id,
            details: { approvalId: id, action: row.action, error: error.code || error.message }
        });
        throw error;
    }
}

async function request({ action, targetUserId = null, params = {}, reason, requestedBy }) {
    if (!handlers.has(action)) throw new ApprovalError('UNKNOWN_ACTION', 'Acción desconocida');
    if (typeof reason !== 'string' || reason.trim().length < 10) {
        throw new ApprovalError('REASON_REQUIRED', 'Indica el motivo (mínimo 10 caracteres): queda en el registro de auditoría');
    }

    const ttl = intEnv('ADMIN_APPROVAL_TTL_HOURS', 24);
    const single = !twoPersonRequired();
    const [inserted] = await db.query(
        `INSERT INTO admin_approvals (action, target_user_id, params, reason, status, requested_by, approved_by, expires_at, decided_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR), ${single ? 'NOW()' : 'NULL'})`,
        [action, targetUserId, JSON.stringify(params), reason.trim().slice(0, 255), single ? 'approved' : 'pending',
            requestedBy, single ? requestedBy : null, ttl]
    );
    const id = inserted.insertId;

    await events.record({
        type: 'ADMIN_APPROVAL_REQUESTED', severity: 'high', riskScore: 30, userId: targetUserId,
        details: { approvalId: id, action, requestedBy, twoPerson: !single }
    });

    if (single) {
        const done = await finish(id, { action, target_user_id: targetUserId, params: JSON.stringify(params), requested_by: requestedBy, approved_by: requestedBy });
        return { id, ...done };
    }
    return { id, status: 'pending', expiresInHours: ttl };
}

async function approve(id, approverId) {
    // Atómico: solo pasa de pending a approved UNA vez, si no caducó y si el aprobador no es quien lo pidió
    const [claimed] = await db.query(
        `UPDATE admin_approvals SET status = 'approved', approved_by = ?, decided_at = NOW()
         WHERE id = ? AND status = 'pending' AND expires_at > NOW() AND requested_by <> ?`,
        [approverId, id, approverId]
    );

    const [rows] = await db.query('SELECT * FROM admin_approvals WHERE id = ?', [id]);
    const row = rows[0];
    if (!row) throw new ApprovalError('NOT_FOUND', 'Solicitud no encontrada', 404);

    if (claimed.affectedRows !== 1) {
        if (Number(row.requested_by) === Number(approverId) && row.status === 'pending') {
            await events.record({ type: 'ADMIN_SELF_APPROVAL_DENIED', severity: 'high', riskScore: 50, details: { approvalId: id, by: approverId } });
            throw new ApprovalError('SELF_APPROVAL', 'No puedes aprobar tu propia solicitud: tiene que hacerlo otro administrador', 403);
        }
        if (row.status === 'pending') throw new ApprovalError('EXPIRED', 'La solicitud caducó: vuelve a crearla', 410);
        throw new ApprovalError('NOT_PENDING', `La solicitud ya está en estado "${row.status}"`, 409);
    }

    return { id, action: row.action, ...(await finish(id, { ...row, approved_by: approverId })) };
}

async function reject(id, userId) {
    const [rows] = await db.query('SELECT requested_by FROM admin_approvals WHERE id = ?', [id]);
    if (!rows[0]) throw new ApprovalError('NOT_FOUND', 'Solicitud no encontrada', 404);
    const status = Number(rows[0].requested_by) === Number(userId) ? 'cancelled' : 'rejected';
    const [result] = await db.query(
        "UPDATE admin_approvals SET status = ?, approved_by = ?, decided_at = NOW() WHERE id = ? AND status = 'pending'",
        [status, userId, id]
    );
    if (result.affectedRows !== 1) throw new ApprovalError('NOT_PENDING', 'La solicitud ya no está pendiente', 409);
    await events.record({ type: `ADMIN_APPROVAL_${status.toUpperCase()}`, severity: 'medium', riskScore: 10, details: { approvalId: id, by: userId } });
    return { id, status };
}

async function list({ status = null, limit = 100 } = {}) {
    const tripleEncryptor = require('../crypto/tripleEncryptor');
    const [rows] = await db.query(
        `SELECT a.id, a.action, a.target_user_id, a.reason, a.status, a.requested_by, a.approved_by, a.requested_at,
                a.expires_at, a.decided_at, a.executed_at, a.expires_at < NOW() AS expired,
                t.username_encrypted AS target_name, r.username_encrypted AS requester_name
         FROM admin_approvals a
         LEFT JOIN users t ON t.id = a.target_user_id
         LEFT JOIN users r ON r.id = a.requested_by
         WHERE (? IS NULL OR a.status = ?)
         ORDER BY a.id DESC LIMIT ${Math.min(Math.max(Number(limit) || 100, 1), 500)}`,
        [status, status]
    );
    const name = (value) => { try { return value ? tripleEncryptor.decrypt(value) : null; } catch { return null; } };
    return rows.map(row => ({
        id: row.id,
        action: row.action,
        status: row.status === 'pending' && row.expired ? 'expired' : row.status,
        reason: row.reason,
        target: row.target_user_id ? { id: row.target_user_id, username: name(row.target_name) } : null,
        requestedBy: { id: row.requested_by, username: name(row.requester_name) },
        approvedBy: row.approved_by,
        requestedAt: row.requested_at,
        expiresAt: row.expires_at,
        decidedAt: row.decided_at,
        executedAt: row.executed_at
    }));
}

module.exports = { request, approve, reject, list, registerAction, twoPersonRequired, ApprovalError };
