// Esquemas cerrados (additionalProperties: false implícito en validarCuerpo) de cada entrada.
// Copian campos, tipos y límites de contracts/openapi.yaml; donde el contrato no define el
// cuerpo (rutas admin) se usan los nombres de columna del esquema SQL.

const CODIGO = { type: 'string', pattern: /^[0-9]{6,8}$/u };
/**
 * user_ref: 1 a 128 caracteres imprimibles (letras, marcas, números, puntuación, símbolos y el
 * espacio U+0020 solo en el interior). Se rechazan NUL, controles C0/C1, caracteres de formato
 * (bidi, U+200B…U+200F, U+2060…, BOM), separadores distintos del espacio, privados, sin asignar y
 * rellenos invisibles (U+034F, U+115F, U+1160, U+2800, U+3164, U+FFA0).
 */
export const PATRON_USER_REF = /^(?! )(?!.* $)(?:(?![\u034F\u115F\u1160\u2800\u3164\uFFA0])[\p{L}\p{M}\p{N}\p{P}\p{S} ])+$/u;
const USER_REF = { type: 'string', minLength: 1, maxLength: 128, pattern: PATRON_USER_REF };
/**
 * client_ip (opcional): IP del usuario final que la app integradora atiende. Aquí solo se filtra el
 * alfabeto; la validación estricta (IPv4 sin ceros a la izquierda o IPv6 sin zona) la hace
 * security/ip.js en el caso de uso, que responde 400 si no es una IP válida.
 */
const CLIENT_IP = { type: 'string', minLength: 2, maxLength: 45, pattern: /^[0-9A-Fa-f:.]{2,45}$/u };
const ENTERO_TEXTO = { type: 'string', pattern: /^[0-9]{1,9}$/u };

/** POST /api/v1/enrollments */
export const ESQUEMA_ENROLAR = {
  type: 'object',
  required: ['user_ref'],
  properties: {
    user_ref: USER_REF,
    account_label: { type: 'string', maxLength: 120 },
    algorithm: { type: 'string', enum: ['SHA256', 'SHA512', 'SHA1'] },
    digits: { type: 'integer', enum: [6, 8] },
    period: { type: 'integer', minimum: 15, maximum: 60 },
  },
};

/** POST /api/v1/enrollments/{id}/activate */
export const ESQUEMA_ACTIVAR = { type: 'object', required: ['code'], properties: { code: CODIGO, client_ip: CLIENT_IP } };

/** POST /api/v1/verify */
export const ESQUEMA_VERIFICAR = {
  type: 'object', required: ['user_ref', 'code'], properties: { user_ref: USER_REF, code: CODIGO, client_ip: CLIENT_IP },
};

/** POST /api/v1/tokens/validate */
export const ESQUEMA_VALIDAR_TOKEN = {
  type: 'object',
  required: ['token'],
  properties: { token: { type: 'string', minLength: 1, maxLength: 8192 }, consume_jti: { type: 'boolean' } },
};

/** POST /api/v1/enrollments/{id}/resync */
export const ESQUEMA_RESINCRONIZAR = {
  type: 'object', required: ['code_1', 'code_2'], properties: { code_1: CODIGO, code_2: CODIGO, client_ip: CLIENT_IP },
};

/** POST /api/v1/recovery (mismo patrón de user_ref que en verify). */
export const ESQUEMA_RECUPERAR = {
  type: 'object',
  required: ['user_ref', 'recovery_code'],
  properties: { user_ref: USER_REF, recovery_code: { type: 'string', minLength: 8, maxLength: 32 }, client_ip: CLIENT_IP },
};

/** DELETE /api/v1/enrollments/{id} (sin cuerpo). */
export const ESQUEMA_VACIO = { type: 'object', properties: {} };

/**
 * POST /admin/api/login { usuario, password, totp_code }. `totp_code` es opcional en el esquema
 * (como en el contrato) pero el caso de uso lo exige: sin él responde 401 genérico.
 */
export const ESQUEMA_ADMIN_LOGIN = {
  type: 'object',
  required: ['usuario', 'password'],
  properties: {
    usuario: { type: 'string', minLength: 1, maxLength: 64 },
    password: { type: 'string', minLength: 1, maxLength: 256 },
    totp_code: CODIGO,
  },
};

/** POST /admin/api/apps: con `id` actualiza la política; sin `id` registra una app nueva (requiere `nombre`). */
export const ESQUEMA_ADMIN_APP = {
  type: 'object',
  properties: {
    id: { type: 'string', minLength: 1, maxLength: 64 },
    nombre: { type: 'string', minLength: 2, maxLength: 120 },
    algoritmo: { type: 'string', enum: ['SHA256', 'SHA512', 'SHA1'] },
    digitos: { type: 'integer', enum: [6, 8] },
    periodo: { type: 'integer', minimum: 15, maximum: 60 },
    ventana: { type: 'integer', minimum: 0, maximum: 3 },
    max_intentos: { type: 'integer', minimum: 3, maximum: 15 },
    // El validador propio no tiene tipo number: el umbral se admite entero (columna REAL).
    umbral_riesgo_bloqueo: { type: 'integer', minimum: 40, maximum: 100 },
    modo_heuristica: { type: 'string', enum: ['monitorizacion', 'bloqueo'] },
    permitir_sha1: { type: 'boolean' },
    estado: { type: 'string', enum: ['activo', 'suspendido'] },
    // Derivación del user_ref desde la cédula (migración 002). Con 'hmac' y sin cedula_secreto el
    // servicio genera el secreto y lo devuelve una sola vez.
    user_ref_desde_cedula: { type: 'string', enum: ['ninguno', 'hmac'] },
    cedula_prefijo: { type: 'string', maxLength: 32, pattern: /^[A-Za-z0-9_.:-]{0,32}$/u },
    cedula_secreto: { type: 'string', minLength: 43, maxLength: 86, pattern: /^[A-Za-z0-9_-]{43,86}$/u },
  },
};

/**
 * GET /admin/api/enrollments?app_id&estado&limite[&cedula|&user_ref] (parámetros de consulta: texto).
 * `cedula` o `user_ref` (excluyentes) convierten el listado en búsqueda de soporte y exigen `app_id`.
 */
export const ESQUEMA_ADMIN_ENROLAMIENTOS = {
  type: 'object',
  properties: {
    app_id: { type: 'string', minLength: 1, maxLength: 64 },
    estado: { type: 'string', enum: ['pendiente', 'activo', 'suspendido', 'revocado'] },
    limite: ENTERO_TEXTO,
    cedula: { type: 'string', minLength: 6, maxLength: 24 },
    user_ref: USER_REF,
  },
};

/** POST /admin/api/admins { usuario, rol }: la contraseña y el TOTP los genera el servicio. */
export const ESQUEMA_ADMIN_CREAR_ADMIN = {
  type: 'object',
  required: ['usuario', 'rol'],
  properties: {
    usuario: { type: 'string', minLength: 3, maxLength: 32, pattern: /^[a-z0-9][a-z0-9._-]{2,31}$/u },
    rol: { type: 'string', enum: ['Administrador', 'Operador', 'Auditor'] },
  },
};

/** GET /admin/api/audit?desde&limite (desde = id numérico o fecha ISO). */
export const ESQUEMA_ADMIN_AUDITORIA = {
  type: 'object',
  properties: {
    desde: { type: 'string', minLength: 1, maxLength: 40, pattern: /^([0-9]{1,12}|[0-9]{4}-[0-9]{2}-[0-9]{2}[0-9T:.Z+-]*)$/u },
    limite: ENTERO_TEXTO,
  },
};

/** GET /admin/api/anomalies?riesgo_minimo&limite */
export const ESQUEMA_ADMIN_ANOMALIAS = {
  type: 'object',
  properties: { riesgo_minimo: { type: 'string', pattern: /^[0-9]{1,3}$/u }, limite: ENTERO_TEXTO },
};
