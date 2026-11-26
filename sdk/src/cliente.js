// Cliente del Servicio Soberano de Autenticación TOTP para sistemas integradores.
// Falla cerrado: los métodos devuelven un resultado aprobado SOLO ante una respuesta 2xx
// que cumple el contrato; cualquier otra cosa lanza ErrorTotp.

import { randomUUID } from 'node:crypto';
import { ErrorTotp, CODIGOS_LOCALES } from './errores.js';
import { validarBaseUrl, crearAgente, peticion } from './http.js';
import { crearCacheJwks } from './jwks.js';
import { verificarTokenLocal } from './local.js';

const CODIGO = /^[0-9]{6,8}$/;
// Mismo patrón que acepta el servicio (backend/src/api/servidor.js).
const CLAVE_IDEMPOTENCIA = /^[A-Za-z0-9_.:-]{8,128}$/;
const VERSION = '1.0.0';

/**
 * @typedef {object} OpcionesCliente
 * @property {string} baseUrl            URL del servicio, p. ej. https://localhost:8443
 * @property {string} clientId           X-Client-Id de la app integradora
 * @property {string} clientSecret       X-Client-Secret (nunca se registra ni se expone)
 * @property {number} [timeoutMs=3000]   plazo total por intento
 * @property {number} [reintentos=1]     reintentos ante error de red / tiempo agotado / 503
 * @property {string | Buffer} [ca]      CA propia en PEM (CA local del servicio)
 * @property {string} [issuer]           iss esperado en los JWT (para verificarTokenLocal)
 * @property {string} [audience]         aud esperado (por defecto, clientId)
 * @property {number} [ttlJwksMs=600000] vigencia de la caché JWKS
 * @property {(t: Traza) => void} [alTrazar] observador de llamadas (sin secretos)
 */

/**
 * @typedef {{ operacion: string, metodo: string, ruta: string, intento: number, status: number | null,
 *   ms: number, codigo?: string, idempotencyKey?: string }} Traza
 */

/** @param {OpcionesCliente} opciones */
export function crearClienteTotp(opciones) {
  const {
    baseUrl, clientId, clientSecret, timeoutMs = 3000, reintentos = 1, ca,
    issuer, audience, ttlJwksMs = 10 * 60 * 1000, alTrazar,
  } = opciones ?? /** @type {any} */ ({});

  const url = validarBaseUrl(baseUrl);
  if (typeof clientId !== 'string' || clientId.length === 0) {
    throw new ErrorTotp('clientId es obligatorio', { codigo: CODIGOS_LOCALES.CONFIGURACION });
  }
  if (typeof clientSecret !== 'string' || clientSecret.length === 0) {
    throw new ErrorTotp('clientSecret es obligatorio', { codigo: CODIGOS_LOCALES.CONFIGURACION });
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60000) {
    throw new ErrorTotp('timeoutMs debe estar entre 100 y 60000', { codigo: CODIGOS_LOCALES.CONFIGURACION });
  }
  if (!Number.isInteger(reintentos) || reintentos < 0 || reintentos > 3) {
    throw new ErrorTotp('reintentos debe estar entre 0 y 3', { codigo: CODIGOS_LOCALES.CONFIGURACION });
  }

  const agente = crearAgente(url, { ca });
  const base = url.href.replace(/\/+$/, '');
  const trazar = typeof alTrazar === 'function' ? (t) => { try { alTrazar(t); } catch { /* el observador no rompe el flujo */ } } : () => {};

  /**
   * Llamada con reintento idempotente. La misma Idempotency-Key viaja en todos los intentos.
   * @param {string} operacion @param {string} metodo @param {string} ruta
   * @param {{ cuerpo?: object, autenticar?: boolean, idempotencyKey?: string }} [o]
   */
  async function llamar(operacion, metodo, ruta, { cuerpo, autenticar = true, idempotencyKey } = {}) {
    const destino = new URL(base + ruta);
    /** @type {Record<string, string>} */
    const cabeceras = {
      Accept: 'application/json',
      'User-Agent': `sdk-totp-soberano/${VERSION}`,
    };
    if (autenticar) {
      cabeceras['X-Client-Id'] = clientId;
      cabeceras['X-Client-Secret'] = clientSecret;
    }
    if (idempotencyKey) {
      if (!CLAVE_IDEMPOTENCIA.test(idempotencyKey)) {
        throw new ErrorTotp('idempotencyKey debe tener 8-128 caracteres [A-Za-z0-9_.:-]', { codigo: CODIGOS_LOCALES.ENTRADA_INVALIDA, operacion });
      }
      cabeceras['Idempotency-Key'] = idempotencyKey;
    }
    const texto = cuerpo !== undefined ? JSON.stringify(cuerpo) : undefined;
    if (texto !== undefined) cabeceras['Content-Type'] = 'application/json';

    let ultimo;
    for (let intento = 1; intento <= reintentos + 1; intento++) {
      const t0 = performance.now();
      try {
        const res = await peticion({ url: destino, metodo, cabeceras, cuerpo: texto, timeoutMs, agente, operacion });
        const ms = Math.round(performance.now() - t0);
        const datos = parsearJson(res.cuerpo);
        if (res.status >= 200 && res.status < 300) {
          trazar({ operacion, metodo, ruta, intento, status: res.status, ms, idempotencyKey });
          if (datos === undefined) {
            throw new ErrorTotp('Respuesta del servicio no es JSON', { status: res.status, codigo: CODIGOS_LOCALES.RESPUESTA_INVALIDA, operacion });
          }
          return datos;
        }
        const error = errorDeRespuesta(res, datos, operacion);
        trazar({ operacion, metodo, ruta, intento, status: res.status, ms, codigo: error.codigo, idempotencyKey });
        throw error;
      } catch (e) {
        const error = e instanceof ErrorTotp ? e : new ErrorTotp('Error inesperado del SDK', { codigo: CODIGOS_LOCALES.ERROR_RED, operacion, causa: e });
        if (error.status === null) {
          trazar({ operacion, metodo, ruta, intento, status: null, ms: Math.round(performance.now() - t0), codigo: error.codigo, idempotencyKey });
        }
        ultimo = error;
        const reintentable = error.status === null && error.codigo !== CODIGOS_LOCALES.RESPUESTA_INVALIDA
          ? true
          : error.status === 503;
        if (!reintentable || intento > reintentos) throw error;
        await pausa(100 + Math.floor(Math.random() * 150));
      }
    }
    throw ultimo;
  }

  const jwksCache = crearCacheJwks({ obtener: () => cliente.jwks(), ttlMs: ttlJwksMs });

  const cliente = {
    /** GET /health */
    async salud() {
      return llamar('salud', 'GET', '/health', { autenticar: false });
    },

    /**
     * POST /api/v1/enrollments — crea un enrolamiento PENDIENTE (10 min).
     * @param {string} userRef identificador opaco del usuario en su sistema (no use nombres ni documentos)
     * @param {{ etiquetaCuenta?: string, algoritmo?: 'SHA1'|'SHA256'|'SHA512', digitos?: 6|8, periodo?: number, idempotencyKey?: string }} [o]
     */
    async enrolar(userRef, { etiquetaCuenta, algoritmo, digitos, periodo, idempotencyKey } = {}) {
      exigirUserRef(userRef, 'enrolar');
      const cuerpo = { user_ref: userRef };
      if (etiquetaCuenta !== undefined) cuerpo.account_label = String(etiquetaCuenta).slice(0, 120);
      if (algoritmo !== undefined) cuerpo.algorithm = algoritmo;
      if (digitos !== undefined) cuerpo.digits = digitos;
      if (periodo !== undefined) cuerpo.period = periodo;
      const r = await llamar('enrolar', 'POST', '/api/v1/enrollments', { cuerpo, idempotencyKey: idempotencyKey ?? randomUUID() });
      exigir(r, ['enrollment_id', 'otpauth_uri', 'qr_svg'], 'enrolar');
      return {
        enrollmentId: r.enrollment_id,
        estado: r.estado,
        algoritmo: r.algoritmo,
        digitos: r.digitos,
        periodo: r.periodo,
        otpauthUri: r.otpauth_uri,
        qrSvg: r.qr_svg,
        expiraEn: r.expires_at,
        claveManual: claveDeOtpauth(r.otpauth_uri),
      };
    },

    /**
     * POST /api/v1/enrollments/{id}/activate — valida el primer código y entrega 10 códigos de recuperación.
     * @param {string} enrollmentId @param {string} codigo
     */
    async activar(enrollmentId, codigo, { idempotencyKey } = {}) {
      exigirId(enrollmentId, 'activar');
      exigirCodigo(codigo, 'activar');
      const r = await llamar('activar', 'POST', `/api/v1/enrollments/${encodeURIComponent(enrollmentId)}/activate`, {
        cuerpo: { code: codigo }, idempotencyKey: idempotencyKey ?? randomUUID(),
      });
      exigir(r, ['enrollment_id', 'recovery_codes'], 'activar');
      if (r.estado !== 'activo' || !Array.isArray(r.recovery_codes)) invalida('activar');
      return {
        enrollmentId: r.enrollment_id, estado: r.estado, activadoEn: r.activated_at, codigosRecuperacion: [...r.recovery_codes],
      };
    },

    /**
     * POST /api/v1/verify — verifica un código TOTP. Si no se pasa idempotencyKey se genera una
     * y se reutiliza en el reintento. Devuelve { aprobado: true, token, … } o lanza ErrorTotp.
     * @param {string} userRef @param {string} codigo @param {{ idempotencyKey?: string }} [o]
     */
    async verificar(userRef, codigo, { idempotencyKey } = {}) {
      exigirUserRef(userRef, 'verificar');
      exigirCodigo(codigo, 'verificar');
      const clave = idempotencyKey ?? randomUUID();
      const r = await llamar('verificar', 'POST', '/api/v1/verify', { cuerpo: { user_ref: userRef, code: codigo }, idempotencyKey: clave });
      // Falla cerrado: solo verified === true estricto y un token con forma de JWT aprueban.
      if (!r || r.verified !== true || typeof r.token !== 'string' || r.token.split('.').length !== 3) invalida('verificar');
      return {
        aprobado: /** @type {const} */ (true),
        token: r.token,
        jti: r.jti,
        kid: r.kid,
        expiraEn: r.expires_at,
        derivaPasos: r.drift_steps,
        riesgo: r.risk ?? null,
        idempotencyKey: clave,
      };
    },

    /**
     * POST /api/v1/tokens/validate — autenticidad, vigencia y consumo único del jti.
     * @param {string} token @param {{ consumirJti?: boolean }} [o]
     */
    async validarToken(token, { consumirJti = true } = {}) {
      if (typeof token !== 'string' || token.length === 0 || token.length > 8192) {
        throw new ErrorTotp('Token inválido', { codigo: CODIGOS_LOCALES.ENTRADA_INVALIDA, operacion: 'validarToken' });
      }
      const r = await llamar('validarToken', 'POST', '/api/v1/tokens/validate', { cuerpo: { token, consume_jti: consumirJti } });
      if (!r || typeof r.valid !== 'boolean') invalida('validarToken');
      return {
        valido: r.valid === true, sub: r.sub, aud: r.aud, jti: r.jti, kid: r.kid, amr: r.amr, exp: r.exp, motivo: r.reason ?? null,
      };
    },

    /**
     * POST /api/v1/enrollments/{id}/resync — corrige la deriva con dos códigos consecutivos.
     * @param {string} enrollmentId @param {string} codigo1 @param {string} codigo2
     */
    async resincronizar(enrollmentId, codigo1, codigo2) {
      exigirId(enrollmentId, 'resincronizar');
      exigirCodigo(codigo1, 'resincronizar');
      exigirCodigo(codigo2, 'resincronizar');
      const r = await llamar('resincronizar', 'POST', `/api/v1/enrollments/${encodeURIComponent(enrollmentId)}/resync`, {
        cuerpo: { code_1: codigo1, code_2: codigo2 }, idempotencyKey: randomUUID(),
      });
      if (!r || r.resynced !== true) invalida('resincronizar');
      return { resincronizado: true, derivaPasos: r.drift_steps };
    },

    /**
     * POST /api/v1/recovery — consume un código de recuperación; obliga a re-enrolar.
     * @param {string} userRef @param {string} codigoRecuperacion
     */
    async recuperar(userRef, codigoRecuperacion) {
      exigirUserRef(userRef, 'recuperar');
      if (typeof codigoRecuperacion !== 'string' || codigoRecuperacion.length < 8 || codigoRecuperacion.length > 32) {
        throw new ErrorTotp('Código de recuperación con formato inválido', { codigo: CODIGOS_LOCALES.ENTRADA_INVALIDA, operacion: 'recuperar' });
      }
      const r = await llamar('recuperar', 'POST', '/api/v1/recovery', {
        cuerpo: { user_ref: userRef, recovery_code: codigoRecuperacion }, idempotencyKey: randomUUID(),
      });
      if (!r || r.recovered !== true) invalida('recuperar');
      return { recuperado: true, debeReenrolar: r.must_reenroll === true, codigosRestantes: r.remaining_codes };
    },

    /**
     * DELETE /api/v1/enrollments/{id} — revoca definitivamente el factor.
     * @param {string} enrollmentId
     */
    async revocar(enrollmentId) {
      exigirId(enrollmentId, 'revocar');
      const r = await llamar('revocar', 'DELETE', `/api/v1/enrollments/${encodeURIComponent(enrollmentId)}`, { idempotencyKey: randomUUID() });
      if (!r || r.estado !== 'revocado') invalida('revocar');
      return { enrollmentId: r.enrollment_id, estado: r.estado, revocadoEn: r.revoked_at };
    },

    /** GET /.well-known/jwks.json (público, sin credenciales). */
    async jwks() {
      const r = await llamar('jwks', 'GET', '/.well-known/jwks.json', { autenticar: false });
      if (!r || !Array.isArray(r.keys)) invalida('jwks');
      return r;
    },

    /**
     * Verificación offline con la caché JWKS del cliente (TTL, refresco en kid desconocido,
     * copia vencida si el servicio no responde). Nunca lanza.
     * @param {string} token @param {{ issuer?: string, audience?: string, ahora?: number }} [o]
     */
    async verificarTokenLocal(token, o = {}) {
      return verificarTokenLocal(token, {
        jwks: jwksCache, issuer: o.issuer ?? issuer, audience: o.audience ?? audience ?? clientId, ahora: o.ahora,
      });
    },

    /** Caché JWKS interna (diagnóstico / precarga). */
    jwksCache,

    /** Libera los sockets keep-alive. */
    cerrar() {
      agente.destroy();
    },

    // Evita que console.log(cliente) muestre algo más que la configuración pública.
    [Symbol.for('nodejs.util.inspect.custom')]() {
      return `ClienteTotp { baseUrl: '${base}', clientId: '${clientId}', clientSecret: '[oculto]' }`;
    },
    toJSON() {
      return { baseUrl: base, clientId, clientSecret: '[oculto]' };
    },
  };
  return cliente;
}

// ---------- utilidades ----------

const pausa = (ms) => new Promise((r) => setTimeout(r, ms));

/** @param {Buffer} cuerpo */
function parsearJson(cuerpo) {
  if (!cuerpo || cuerpo.length === 0) return undefined;
  try {
    return JSON.parse(cuerpo.toString('utf8'));
  } catch {
    return undefined;
  }
}

/** Traduce una respuesta no-2xx a ErrorTotp (acepta GenericError y el formato de los mocks). */
function errorDeRespuesta(res, datos, operacion) {
  const d = datos && typeof datos === 'object' ? datos : {};
  const codigo = typeof d.error === 'string' ? d.error
    : typeof d.errorCode === 'string' ? d.errorCode
      : res.status === 503 ? 'SERVICE_UNAVAILABLE' : `HTTP_${res.status}`;
  let reintentarEn = Number.isFinite(d.retry_after_seconds) ? d.retry_after_seconds
    : Number.isFinite(d.retryAfterSeconds) ? d.retryAfterSeconds : null;
  if (reintentarEn === null && res.cabeceras['retry-after'] && /^\d+$/.test(res.cabeceras['retry-after'])) {
    reintentarEn = Number(res.cabeceras['retry-after']);
  }
  const mensaje = typeof d.message === 'string' && d.message.length < 300 ? d.message : `El servicio respondió ${res.status}`;
  return new ErrorTotp(mensaje, { status: res.status, codigo, reintentarEn, operacion });
}

function invalida(operacion) {
  throw new ErrorTotp('La respuesta del servicio no cumple el contrato', { codigo: CODIGOS_LOCALES.RESPUESTA_INVALIDA, operacion });
}

function exigir(r, campos, operacion) {
  if (!r || typeof r !== 'object' || campos.some((c) => r[c] === undefined || r[c] === null)) invalida(operacion);
}

function exigirCodigo(codigo, operacion) {
  if (typeof codigo !== 'string' || !CODIGO.test(codigo)) {
    throw new ErrorTotp('El código debe tener entre 6 y 8 dígitos', { codigo: CODIGOS_LOCALES.ENTRADA_INVALIDA, operacion });
  }
}

function exigirUserRef(userRef, operacion) {
  if (typeof userRef !== 'string' || userRef.length < 2 || userRef.length > 160) {
    throw new ErrorTotp('userRef debe tener entre 2 y 160 caracteres', { codigo: CODIGOS_LOCALES.ENTRADA_INVALIDA, operacion });
  }
}

function exigirId(id, operacion) {
  if (typeof id !== 'string' || id.length === 0 || id.length > 128) {
    throw new ErrorTotp('enrollmentId inválido', { codigo: CODIGOS_LOCALES.ENTRADA_INVALIDA, operacion });
  }
}

/** Extrae la clave Base32 del URI otpauth:// para el alta manual (plan B si no hay cámara). */
export function claveDeOtpauth(uri) {
  try {
    const u = new URL(uri);
    if (u.protocol !== 'otpauth:') return null;
    const s = u.searchParams.get('secret');
    return s && /^[A-Z2-7]+=*$/i.test(s) ? s.toUpperCase().replace(/=+$/, '') : null;
  } catch {
    return null;
  }
}
