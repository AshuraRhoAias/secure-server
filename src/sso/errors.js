// Error común de los inicios de sesión federados (OpenID Connect y SAML). El controlador lo convierte en una respuesta
// con código estable y registra el evento de seguridad con `rule`.
class SsoError extends Error {
    constructor(code, message, { status = 400, rule = code } = {}) {
        super(message);
        this.code = code;
        this.status = status;
        this.rule = rule;
    }
}

module.exports = { SsoError };
