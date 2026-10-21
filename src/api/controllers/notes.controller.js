const db = require('../../config/database');
const tripleEncryptor = require('../../crypto/tripleEncryptor');
const audit = require('../../services/audit.service');

const ENCRYPTION_VERSION = 'v3.1.0';

// Caché del total de notas por usuario. El COUNT(*) sobre tablas grandes es caro
// (medido: ~17 ms con 100k notas, frente a <1 ms de la propia página), y se
// repetía en CADA listado. Se cachea el total unos segundos y se invalida al
// crear/borrar notas del propio usuario, para que la paginación siga siendo
// exacta para quien escribe. Configurable con NOTES_COUNT_TTL_MS.
const COUNT_TTL_MS = parseInt(process.env.NOTES_COUNT_TTL_MS, 10) || 5000;

// Cada nota pertenece a un usuario: TODAS las consultas filtran por user_id
// para que nadie pueda leer o modificar notas ajenas.
class NotesController {
    constructor() {
        this.countCache = new Map(); // userId -> { total, at }
        this.create = this.create.bind(this);
        this.list = this.list.bind(this);
        this.getOne = this.getOne.bind(this);
        this.update = this.update.bind(this);
        this.remove = this.remove.bind(this);
    }

    async countForUser(userId) {
        const cached = this.countCache.get(userId);
        if (cached && (Date.now() - cached.at) < COUNT_TTL_MS) return cached.total;

        const [countRows] = await db.query('SELECT COUNT(*) AS total FROM user_notes WHERE user_id = ?', [userId]);
        const total = countRows[0].total;
        this.countCache.set(userId, { total, at: Date.now() });
        return total;
    }

    invalidateCount(userId) {
        this.countCache.delete(userId);
    }

    serialize(row) {
        return {
            id: row.id,
            title: tripleEncryptor.decrypt(row.title_encrypted),
            content: row.content_encrypted ? tripleEncryptor.decrypt(row.content_encrypted) : '',
            createdAt: row.created_at,
            updatedAt: row.updated_at
        };
    }

    async create(req, res) {
        const { title, content = '' } = req.body;

        const [result] = await db.query(
            `INSERT INTO user_notes (user_id, title_encrypted, content_encrypted, encryption_version)
             VALUES (?, ?, ?, ?)`,
            [req.user.id, tripleEncryptor.encrypt(title), tripleEncryptor.encrypt(content), ENCRYPTION_VERSION]
        );

        this.invalidateCount(req.user.id);
        await audit.log('NOTE_CREATED', { noteId: result.insertId }, { req });

        res.status(201).json({
            success: true,
            note: { id: result.insertId, title, content }
        });
    }

    async list(req, res) {
        // validate.query ya garantiza enteros dentro de rango. Se interpolan en el SQL
        // porque LIMIT con parámetros preparados falla en algunas versiones de MySQL 8.
        const { page: pageNum, limit: limitNum } = req.validated.query;
        const offset = (pageNum - 1) * limitNum;

        const [rows] = await db.query(
            `SELECT id, title_encrypted, content_encrypted, created_at, updated_at
             FROM user_notes WHERE user_id = ?
             ORDER BY created_at DESC, id DESC
             LIMIT ${limitNum} OFFSET ${offset}`,
            [req.user.id]
        );
        const total = await this.countForUser(req.user.id);

        res.json({
            success: true,
            notes: rows.map(row => this.serialize(row)),
            pagination: { page: pageNum, limit: limitNum, total, pages: Math.ceil(total / limitNum) }
        });
    }

    async findOwned(req) {
        const [rows] = await db.query(
            `SELECT id, title_encrypted, content_encrypted, created_at, updated_at
             FROM user_notes WHERE id = ? AND user_id = ?`,
            [req.params.id, req.user.id]
        );
        return rows[0] || null;
    }

    async getOne(req, res) {
        const row = await this.findOwned(req);
        if (!row) return this.notFound(res);

        res.json({ success: true, note: this.serialize(row) });
    }

    async update(req, res) {
        const row = await this.findOwned(req);
        if (!row) return this.notFound(res);

        const { title, content } = req.body;
        const fields = [];
        const params = [];

        if (title !== undefined) {
            fields.push('title_encrypted = ?');
            params.push(tripleEncryptor.encrypt(title));
        }
        if (content !== undefined) {
            fields.push('content_encrypted = ?');
            params.push(tripleEncryptor.encrypt(content));
        }
        if (fields.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Debes enviar title o content',
                code: 'VALIDATION_ERROR'
            });
        }

        params.push(req.params.id, req.user.id);
        await db.query(`UPDATE user_notes SET ${fields.join(', ')} WHERE id = ? AND user_id = ?`, params);

        await audit.log('NOTE_UPDATED', { noteId: Number(req.params.id) }, { req });

        const updated = await this.findOwned(req);
        res.json({ success: true, note: this.serialize(updated) });
    }

    async remove(req, res) {
        const [result] = await db.query(
            'DELETE FROM user_notes WHERE id = ? AND user_id = ?',
            [req.params.id, req.user.id]
        );
        if (result.affectedRows === 0) return this.notFound(res);

        this.invalidateCount(req.user.id);
        await audit.log('NOTE_DELETED', { noteId: Number(req.params.id) }, { req, severity: 'medium', riskScore: 10 });

        res.json({ success: true, message: 'Nota eliminada' });
    }

    notFound(res) {
        return res.status(404).json({
            success: false,
            message: 'Nota no encontrada',
            code: 'NOT_FOUND'
        });
    }
}

module.exports = new NotesController();
