// Servidor HTTPS propio (node:https / node:http), sin frameworks.
// Responsabilidades: cabeceras de seguridad, CORS estricto, límites de tasa antes de cualquier
// operación costosa, lectura acotada de cuerpos JSON, autenticación de apps integradoras,
// sesiones de la consola admin con CSRF y RBAC, rutas de salud/métricas, estáticos y
// "falla cerrado" (cualquier excepción en un caso de uso responde 503, nunca 200).

import { createServer as crearServidorHttp } from 'node:http';
import { createServer as crearServidorHttps } from 'node:https';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { realpath, stat } from 'node:fs/promises';
import { extname, join, resolve, sep } from 'node:path';
import { performance } from 'node:perf_hooks';

import { cabecerasSeguridad, crearLimitador, errorGenerico, normalizarIp, politicaPermisosPara, validarCuerpo } from '../security/index.js';
import { ESQUEMA_ADMIN_LOGIN } from '../application/use-cases/esquemas.js';
import { crearRouter } from './router.js';

// ------------------------------------------------------------------ constantes

const LIMITE_CUERPO_BYTES = 16 * 1024;
export const NOMBRE_COOKIE_SESION = 'sst_admin';
const DURACION_SESION_MS = 30 * 60 * 1000;
const DURACION_MAXIMA_SESION_MS = 8 * 60 * 60 * 1000;
const MAX_SESIONES = 1000;
const TTL_CACHE_APPS_MS = 30 * 1000;
const MAX_CACHE_APPS = 1000;

const CABECERAS_CORS_PERMITIDAS = 'Content-Type, X-Client-Id, X-Client-Secret, Idempotency-Key, X-CSRF-Token';
const METODOS_CORS = 'GET, POST, DELETE, OPTIONS';
const METODOS_QUE_MODIFICAN = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const RE_CLIENT_ID = /^[A-Za-z0-9_.-]{1,128}$/;
const RE_SECRETO = /^[\x21-\x7e]{1,256}$/;
const RE_IDEMPOTENCIA = /^[A-Za-z0-9_.:-]{8,128}$/;

/** CSP de los estáticos (PWA y consola): todo propio, imágenes data: para el QR. */
const CSP_ESTATICOS = [
  "default-src 'self'", "img-src 'self' data:", "style-src 'self'", "script-src 'self'", "connect-src 'self'",
  "manifest-src 'self'", "worker-src 'self'", "font-src 'self'", "frame-ancestors 'none'", "object-src 'none'",
  "base-uri 'none'", "form-action 'self'",
].join('; ');

const TIPOS_MIME = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
});

/** Errores genéricos adicionales al catálogo de security/errores.js (mismo formato GenericError). */
const ERRORES_HTTP = Object.freeze({
  403: { error: 'FORBIDDEN', message: 'Acceso denegado.' },
  404: { error: 'NOT_FOUND', message: 'Recurso no encontrado.' },
  405: { error: 'METHOD_NOT_ALLOWED', message: 'Método no permitido.' },
  408: { error: 'REQUEST_TIMEOUT', message: 'Tiempo de espera agotado.' },
  413: { error: 'PAYLOAD_TOO_LARGE', message: 'Solicitud demasiado grande.' },
  415: { error: 'UNSUPPORTED_MEDIA_TYPE', message: 'Tipo de contenido no admitido.' },
});

/** Cabeceras que un caso de uso no puede sobrescribir. */
const CABECERAS_RESERVADAS = new Set([
  ...Object.keys(cabecerasSeguridad()).map((c) => c.toLowerCase()),
  'set-cookie', 'content-length', 'content-type', 'transfer-encoding', 'connection',
  'access-control-allow-origin', 'access-control-allow-credentials',
]);

// ------------------------------------------------------------------ utilidades

/** Error de control de flujo con respuesta HTTP asociada. */
class ErrorHttp extends Error {
  /** @param {number} status @param {Record<string, string>} [cabeceras] */
  constructor(status, cabeceras = {}) {
    super(`HTTP ${status}`);
    this.status = status;
    this.cabeceras = cabeceras;
  }
}

/** @param {number} status @returns {{ status: number, cuerpo: object, cabeceras: Record<string, string> }} */
function respuestaError(status) {
  if (ERRORES_HTTP[status]) return { status, cuerpo: { ...ERRORES_HTTP[status] }, cabeceras: {} };
  if (status === 400) return errorGenerico('entrada');
  if (status === 401) return errorGenerico('credenciales');
  return errorGenerico('no_disponible');
}

/** IP del socket en claro, sin el prefijo IPv4 mapeado. No se confía en X-Forwarded-For. */
function ipDe(req) {
  const ip = req.socket?.remoteAddress ?? '';
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

function esLocal(ip) {
  return ip === '127.0.0.1' || ip === '::1';
}

/** Comparación en tiempo constante de dos textos. */
function igualSeguro(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/** @param {string | undefined} cabecera */
function leerCookies(cabecera) {
  /** @type {Record<string, string>} */
  const cookies = Object.create(null);
  if (typeof cabecera !== 'string' || cabecera.length > 4096) return cookies;
  for (const parte of cabecera.split(';')) {
    const i = parte.indexOf('=');
    if (i <= 0) continue;
    const nombre = parte.slice(0, i).trim();
    if (nombre && !(nombre in cookies)) cookies[nombre] = parte.slice(i + 1).trim();
  }
  return cookies;
}

/** Valor de cabecera simple (rechaza cabeceras repetidas convertidas en arreglo). */
function cabecera(req, nombre) {
  const v = req.headers[nombre];
  return typeof v === 'string' ? v : undefined;
}

/** Query string a objeto plano acotado (primer valor de cada clave). */
function consultaDe(url) {
  /** @type {Record<string, string>} */
  const q = {};
  let n = 0;
  for (const [k, v] of url.searchParams) {
    if (++n > 20) break;
    if (k.length > 64 || v.length > 256 || Object.hasOwn(q, k) || k === '__proto__') continue;
    q[k] = v;
  }
  return q;
}

/**
 * Lee el cuerpo con límite de tamaño y tiempo.
 * @param {import('node:http').IncomingMessage} req @param {{ limite: number, timeoutMs: number }} op
 * @returns {Promise<Buffer>}
 */
function leerCuerpo(req, { limite, timeoutMs }) {
  return new Promise((resolver, rechazar) => {
    const largo = Number(req.headers['content-length']);
    if (Number.isFinite(largo) && largo > limite) {
      rechazar(new ErrorHttp(413));
      return;
    }
    /** @type {Buffer[]} */
    const trozos = [];
    let total = 0;
    let terminado = false;
    const fin = (error, valor) => {
      if (terminado) return;
      terminado = true;
      clearTimeout(temporizador);
      req.off('data', alDato);
      req.off('end', alFin);
      req.off('error', alError);
      if (error) {
        req.pause();
        rechazar(error);
      } else resolver(valor);
    };
    const alDato = (trozo) => {
      total += trozo.length;
      if (total > limite) fin(new ErrorHttp(413));
      else trozos.push(trozo);
    };
    const alFin = () => fin(null, Buffer.concat(trozos, total));
    const alError = () => fin(new ErrorHttp(400));
    const temporizador = setTimeout(() => fin(new ErrorHttp(408)), timeoutMs);
    req.on('data', alDato);
    req.on('end', alFin);
    req.on('error', alError);
  });
}

function tieneCuerpo(req) {
  const largo = req.headers['content-length'];
  return req.headers['transfer-encoding'] !== undefined || (largo !== undefined && largo !== '0');
}

/** true si el Content-Type es application/json (charset, si viene, debe ser utf-8). */
function esJson(req) {
  const ct = cabecera(req, 'content-type');
  if (!ct) return false;
  const [tipo, ...params] = ct.split(';').map((s) => s.trim().toLowerCase());
  if (tipo !== 'application/json') return false;
  for (const p of params) {
    if (p.startsWith('charset=') && !['utf-8', 'utf8', '"utf-8"'].includes(p.slice(8))) return false;
  }
  return true;
}

function esObjetoPlano(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// ------------------------------------------------------------------ servidor

/**
 * @typedef {{ info: Function, warn: Function, error: Function }} Registro
 * @typedef {{ prefijo: string, carpeta: string }} Estatico
 * @typedef {{
 *   global?: ReturnType<typeof crearLimitador>, porApp?: ReturnType<typeof crearLimitador>,
 *   porOrigen?: ReturnType<typeof crearLimitador>, login?: ReturnType<typeof crearLimitador>,
 * }} Limitadores
 *   global: por IP TCP, antes de autenticar (anti-DDoS; alto porque un portal integrador concentra
 *   a todos sus ciudadanos en una sola IP). porApp: por app autenticada. porOrigen: por (app, origen
 *   del usuario final) en las rutas que comprueban credenciales (verify, recovery, activate, resync);
 *   el origen es `client_ip` si la app lo envía y, si no, la IP TCP de la app.
 */

/**
 * Crea el servidor HTTP(S) con todas las rutas montadas. No llama a listen().
 * @param {{
 *   casos: Record<string, Function>,
 *   metricas: { registrarPeticion: Function, registrarErrorBaseDatos: Function, registrarChequeoSalud: Function,
 *     registrarLimiteTasa: Function, formatoTexto: () => string },
 *   limitadores?: Limitadores,
 *   cors?: { origenes: string[] },
 *   salud?: () => unknown,
 *   info?: () => { dbDriver: string, activeKeyId: string, heuristicsMode: string },
 *   puede?: (rol: string, accion: string) => boolean,
 *   tls?: { cert: string | Buffer, key: string | Buffer, ca?: string | Buffer } | null,
 *   certificadoCa?: string | null,
 *   registro?: Registro,
 *   estaticos?: Estatico[],
 *   redirigirRaiz?: string | null,
 *   ahora?: () => number,
 *   opciones?: { limiteCuerpo?: number, timeoutCuerpoMs?: number, requestTimeoutMs?: number,
 *     headersTimeoutMs?: number, keepAliveTimeoutMs?: number, ttlCacheAppsMs?: number },
 * }} dependencias
 * @returns {import('node:http').Server & { api: { sesiones: Map<string, any>, invalidarCacheApps: () => void, rutas: string[] } }}
 */
export function crearServidor({
  casos,
  metricas,
  limitadores = {},
  cors = { origenes: [] },
  salud = () => true,
  info = () => ({ dbDriver: 'sqlite', activeKeyId: '', heuristicsMode: 'local' }),
  puede,
  tls = null,
  certificadoCa = null,
  registro = console,
  estaticos = [],
  sitioPublico = null,
  redirigirRaiz = '/app/',
  ahora = () => Date.now(),
  opciones = {},
}) {
  if (!casos || typeof casos !== 'object') throw new Error('Se requieren los casos de uso');
  if (!metricas) throw new Error('Se requieren las métricas');

  const limiteCuerpo = opciones.limiteCuerpo ?? LIMITE_CUERPO_BYTES;
  const timeoutCuerpoMs = opciones.timeoutCuerpoMs ?? 10_000;
  const ttlCacheAppsMs = opciones.ttlCacheAppsMs ?? TTL_CACHE_APPS_MS;
  const limGlobal = limitadores.global ?? crearLimitador({ capacidad: 6000, ventanaMs: 60_000 });
  const limApp = limitadores.porApp ?? crearLimitador({ capacidad: 3000, ventanaMs: 60_000 });
  const limOrigen = limitadores.porOrigen ?? crearLimitador({ capacidad: 60, ventanaMs: 60_000 });
  const limLogin = limitadores.login ?? crearLimitador({ capacidad: 10, ventanaMs: 5 * 60_000 });
  const origenes = new Set((cors?.origenes ?? []).map((o) => o.replace(/\/$/, '')));
  // RBAC: si no se inyecta, falla cerrado (se niega todo).
  const autorizar = typeof puede === 'function' ? puede : typeof casos.puede === 'function' ? casos.puede : () => false;

  // Pimienta en memoria (nunca persiste): las IP solo existen como HMAC dentro del proceso.
  const pimientaMemoria = randomBytes(32);
  const anonimizar = (texto) => createHmac('sha256', pimientaMemoria).update(texto).digest('base64url').slice(0, 32);

  /** @type {Map<string, { admin: any, csrf: string, expira: number, creada: number }>} */
  const sesiones = new Map();
  /** @type {Map<string, { app: any, expira: number }>} */
  const cacheApps = new Map();

  // ---------------------------------------------------------------- sesiones admin

  function crearSesion(admin) {
    const t = ahora();
    for (const [id, s] of sesiones) if (s.expira <= t) sesiones.delete(id);
    while (sesiones.size >= MAX_SESIONES) sesiones.delete(sesiones.keys().next().value);
    const id = randomBytes(32).toString('base64url');
    const { password_hash: _omitido, ...publico } = admin ?? {};
    const { csrf_token: csrfPropuesto, ...adminSesion } = publico;
    const csrf = typeof csrfPropuesto === 'string' && csrfPropuesto.length >= 32 ? csrfPropuesto : randomBytes(32).toString('base64url');
    const sesion = { admin: adminSesion, csrf, expira: t + DURACION_SESION_MS, creada: t };
    sesiones.set(id, sesion);
    return { id, sesion };
  }

  /** Busca la sesión de la cookie y la renueva (expiración deslizante con tope absoluto). */
  function sesionDe(req) {
    const id = leerCookies(cabecera(req, 'cookie'))[NOMBRE_COOKIE_SESION];
    if (!id || id.length > 64) return null;
    const s = sesiones.get(id);
    if (!s) return null;
    const t = ahora();
    if (s.expira <= t || t - s.creada > DURACION_MAXIMA_SESION_MS) {
      sesiones.delete(id);
      return null;
    }
    s.expira = t + DURACION_SESION_MS;
    return { id, sesion: s };
  }

  const cookieSesion = (id, maxAge) =>
    `${NOMBRE_COOKIE_SESION}=${id}; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=${maxAge}`;

  // ---------------------------------------------------------------- autenticación de apps

  async function autenticarApp(req) {
    const clientId = cabecera(req, 'x-client-id');
    const secreto = cabecera(req, 'x-client-secret');
    if (!clientId || !secreto || !RE_CLIENT_ID.test(clientId) || !RE_SECRETO.test(secreto)) return null;
    const clave = anonimizar(`${clientId}\n${secreto}`);
    const t = ahora();
    const enCache = cacheApps.get(clave);
    if (enCache && enCache.expira > t) return enCache.app;
    cacheApps.delete(clave);
    const app = await casos.autenticarApp(clientId, secreto);
    if (!app || (app.estado !== undefined && app.estado !== 'activo')) return null;
    if (ttlCacheAppsMs > 0) {
      while (cacheApps.size >= MAX_CACHE_APPS) cacheApps.delete(cacheApps.keys().next().value);
      cacheApps.set(clave, { app, expira: t + ttlCacheAppsMs });
    }
    return app;
  }

  // ---------------------------------------------------------------- rutas

  const router = crearRouter();

  /** Invoca un caso de uso por nombre; si no existe, falla cerrado. */
  const caso = (nombre) => async (entrada, ctx) => {
    if (typeof casos[nombre] !== 'function') throw new Error(`Caso de uso no disponible: ${nombre}`);
    return casos[nombre](entrada, ctx);
  };

  // --- sistema
  router.agregar('GET', '/health', async () => {
    const i = info();
    return {
      status: 200,
      cuerpo: { status: 'ok', timestamp: new Date(ahora()).toISOString(), dbDriver: i.dbDriver, activeKeyId: i.activeKeyId, heuristicsMode: i.heuristicsMode },
    };
  }, { tipo: 'publica' });

  router.agregar('GET', '/health/ready', async () => {
    try {
      const r = await Promise.race([
        Promise.resolve().then(() => salud()),
        new Promise((_, rechazar) => setTimeout(() => rechazar(new Error('tiempo agotado')), 2000).unref()),
      ]);
      if (r === false) throw new Error('salud() devolvió false');
      metricas.registrarChequeoSalud(true);
      return { status: 200, cuerpo: { status: 'ok', timestamp: new Date(ahora()).toISOString(), database: 'ok' } };
    } catch {
      metricas.registrarChequeoSalud(false);
      metricas.registrarErrorBaseDatos();
      return errorGenerico('no_disponible');
    }
  }, { tipo: 'publica' });

  // Exposición en texto para un recolector local (Prometheus en el mismo host): solo loopback.
  // La cookie de sesión tiene Path=/admin, así que la consola usa GET /admin/api/metrics (RBAC).
  // IMPORTANTE: si se coloca un proxy inverso local delante del servicio, todas las peticiones
  // llegarán desde 127.0.0.1 y esta comprobación dejaría /metrics abierto a cualquiera: en ese caso
  // /metrics debe bloquearse en el propio proxy (p. ej. denegar la ruta salvo al recolector).
  router.agregar('GET', '/metrics', async () => ({
    status: 200, texto: metricas.formatoTexto(), tipoContenido: 'text/plain; version=0.0.4; charset=utf-8',
  }), { tipo: 'loopback' });

  // Certificado PÚBLICO de la CA propia (solo lectura), para instalarlo en teléfonos y equipos de la red.
  // Solo se ofrece si el despliegue lo configura (TLS_CA_PUBLIC_PATH); nunca contiene llaves privadas.
  router.agregar('GET', '/ca.crt', async () => (certificadoCa
    ? {
      status: 200,
      texto: certificadoCa,
      tipoContenido: 'application/x-x509-ca-cert',
      cabeceras: { 'Content-Disposition': 'attachment; filename="ca-servicio-totp.crt"' },
    }
    : respuestaError(404)), { tipo: 'publica' });

  router.agregar('GET', '/.well-known/jwks.json', async () => caso('jwks')(), { tipo: 'publica', cacheJwks: true });

  // --- API v1 de integradores (X-Client-Id / X-Client-Secret)
  const api = (metodo, plantilla, nombre, entrada, extra = {}) =>
    router.agregar(metodo, plantilla, async (p) => caso(nombre)(entrada(p), p.ctx), { tipo: 'api', ...extra });

  api('POST', '/api/v1/enrollments', 'enrolar', (p) => p.cuerpo, { cuerpo: true });
  // porOrigen: rutas que comprueban un código y aceptan `client_ip` (límite por app y usuario final).
  api('POST', '/api/v1/enrollments/:id/activate', 'activar', (p) => ({ id: p.params.id, cuerpo: p.cuerpo }), { cuerpo: true, porOrigen: true });
  api('POST', '/api/v1/enrollments/:id/resync', 'resincronizar', (p) => ({ id: p.params.id, cuerpo: p.cuerpo }), { cuerpo: true, porOrigen: true });
  api('DELETE', '/api/v1/enrollments/:id', 'revocar', (p) => ({ id: p.params.id, cuerpo: {} }));
  // Vinculación de dispositivos (issue #47): consultar y desvincular (revoca el enrolamiento).
  api('GET', '/api/v1/enrollments/:id/device', 'dispositivo', (p) => ({ id: p.params.id }));
  api('DELETE', '/api/v1/enrollments/:id/device', 'desvincularDispositivo', (p) => ({ id: p.params.id, cuerpo: {} }));
  api('POST', '/api/v1/verify', 'verificar', (p) => p.cuerpo, { cuerpo: true, porOrigen: true });
  api('POST', '/api/v1/tokens/validate', 'validarToken', (p) => p.cuerpo, { cuerpo: true });
  api('POST', '/api/v1/recovery', 'recuperar', (p) => p.cuerpo, { cuerpo: true, porOrigen: true });

  // --- consola admin (cookie de sesión + CSRF + RBAC)
  router.agregar('POST', '/admin/api/login', async (p) => {
    // Esquema cerrado del contrato, validado en el borde antes de cualquier trabajo costoso.
    const v = validarCuerpo(p.cuerpo, ESQUEMA_ADMIN_LOGIN);
    if (!v.ok) return errorGenerico('entrada');
    const r = await caso('adminLogin')(v.valor, p.ctx);
    if (!r || r.status !== 200 || !r.admin) {
      // Nunca se emite sesión sin admin explícito; un 200 sin admin es un fallo.
      return r && r.status >= 400 ? r : errorGenerico('credenciales');
    }
    const previa = sesionDe(p.req);
    if (previa) sesiones.delete(previa.id); // evita fijación de sesión
    const { id, sesion } = crearSesion(r.admin);
    limLogin.reiniciar(`login:${p.ipHash}`);
    return {
      status: 200,
      cuerpo: { usuario: sesion.admin.usuario, rol: sesion.admin.rol, csrf_token: sesion.csrf },
      cookie: cookieSesion(id, DURACION_SESION_MS / 1000),
    };
  }, { tipo: 'login', cuerpo: true });

  router.agregar('GET', '/admin/api/session', async (p) => ({
    status: 200, cuerpo: { usuario: p.sesion.admin.usuario, rol: p.sesion.admin.rol, csrf_token: p.sesion.csrf },
  }), { tipo: 'admin' });

  router.agregar('POST', '/admin/api/logout', async (p) => {
    sesiones.delete(p.sesionId);
    return { status: 200, cuerpo: { ok: true }, cookie: cookieSesion('', 0) };
  }, { tipo: 'admin', cuerpo: true });

  const admin = (metodo, plantilla, nombre, permiso, entrada, extra = {}) =>
    router.agregar(metodo, plantilla, async (p) => caso(nombre)(entrada(p), p.ctx), { tipo: 'admin', permiso, ...extra });

  admin('GET', '/admin/api/apps', 'adminListarApps', 'apps.leer', (p) => p.query);
  admin('POST', '/admin/api/apps', 'adminActualizarApp', 'apps.escribir', (p) => p.cuerpo, { cuerpo: true, invalidaApps: true });
  admin('GET', '/admin/api/enrollments', 'adminListarEnrolamientos', 'enrolamientos.leer', (p) => p.query);
  admin('POST', '/admin/api/keys/rotate', 'adminRotarLlaves', 'llaves.rotar', (p) => p.cuerpo, { cuerpo: true });
  admin('GET', '/admin/api/audit', 'adminAuditoria', 'auditoria.leer', (p) => p.query);
  admin('GET', '/admin/api/audit/verify-chain', 'adminVerificarCadena', 'auditoria.verificar', (p) => p.query);
  admin('GET', '/admin/api/anomalies', 'adminAnomalias', 'anomalias.leer', (p) => p.query);
  admin('GET', '/admin/api/metrics', 'adminMetricas', 'metricas.leer', (p) => p.query);
  // --- consola admin: gestión (llaves, enrolamientos, apps y administradores)
  admin('GET', '/admin/api/keys', 'adminListarLlaves', 'llaves.leer', (p) => p.query);
  const conId = (p) => ({ id: p.params.id, cuerpo: p.cuerpo });
  admin('POST', '/admin/api/enrollments/:id/suspend', 'adminSuspenderEnrolamiento', 'enrolamientos.gestionar', conId, { cuerpo: true });
  admin('POST', '/admin/api/enrollments/:id/reactivate', 'adminReactivarEnrolamiento', 'enrolamientos.gestionar', conId, { cuerpo: true });
  admin('POST', '/admin/api/enrollments/:id/revoke', 'adminRevocarEnrolamiento', 'enrolamientos.gestionar', conId, { cuerpo: true });
  // El secreto anterior deja de valer al instante: se vacía la caché de autenticación de apps.
  admin('POST', '/admin/api/apps/:id/secret', 'adminRegenerarSecretoApp', 'apps.secreto', conId, { cuerpo: true, invalidaApps: true });
  admin('GET', '/admin/api/admins', 'adminListarAdministradores', 'admins.leer', (p) => p.query);
  admin('POST', '/admin/api/admins', 'adminCrearAdministrador', 'admins.escribir', (p) => p.cuerpo, { cuerpo: true });
  // Deshabilitar una cuenta cierra también sus sesiones abiertas en este proceso.
  admin('POST', '/admin/api/admins/:id/disable', 'adminDeshabilitarAdministrador', 'admins.escribir', conId, { cuerpo: true, cierraSesionesDe: true });

  // ---------------------------------------------------------------- estáticos

  const montajes = estaticos.map((e) => ({ prefijo: e.prefijo.replace(/\/$/, ''), carpeta: resolve(e.carpeta) }));
  const carpetaSitio = sitioPublico ? resolve(sitioPublico) : null;
  const PAGINAS_SITIO = Object.freeze({
    '/': 'index.html',
    '/instalar-certificado': 'instalar-certificado.html',
    '/estado': 'estado.html',
  });

  async function servirArchivoDesde(req, res, carpetaRaiz, archivoRel, pathname, estado) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      enviar(req, res, estado, { ...respuestaError(405), cabeceras: { Allow: 'GET, HEAD' } });
      return true;
    }
    const noEncontrado = () => enviar(req, res, estado, respuestaError(404));
    try {
      const raiz = await realpath(carpetaRaiz);
      const ruta = join(raiz, archivoRel);
      const info = await stat(ruta);
      const real = await realpath(ruta);
      if (!info.isFile() || (real !== raiz && !real.startsWith(raiz + sep))) throw new Error();
      res.setHeader('Content-Security-Policy', CSP_ESTATICOS);
      res.setHeader('Permissions-Policy', politicaPermisosPara(pathname));
      res.setHeader('Cache-Control', 'no-cache');
      res.removeHeader('Pragma');
      res.setHeader('Content-Type', TIPOS_MIME[extname(real).toLowerCase()] ?? 'application/octet-stream');
      res.setHeader('Content-Length', info.size);
      res.setHeader('Last-Modified', info.mtime.toUTCString());
      estado.status = 200;
      res.writeHead(200);
      if (req.method === 'HEAD') {
        res.end();
        return true;
      }
      const flujo = createReadStream(real);
      flujo.on('error', () => res.destroy());
      flujo.pipe(res);
    } catch {
      noEncontrado();
    }
    return true;
  }

  /** @returns {Promise<boolean>} true si respondió */
  async function servirEstatico(req, res, pathname, estado) {
    const montaje = montajes.find((m) => pathname === m.prefijo || pathname.startsWith(`${m.prefijo}/`));
    if (!montaje) return false;
    estado.plantilla = `${montaje.prefijo}/*`;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      enviar(req, res, estado, { ...respuestaError(405), cabeceras: { Allow: 'GET, HEAD' } });
      return true;
    }
    const noEncontrado = () => enviar(req, res, estado, respuestaError(404));
    let raiz;
    try {
      raiz = await realpath(montaje.carpeta);
      if (!(await stat(raiz)).isDirectory()) throw new Error();
    } catch {
      noEncontrado();
      return true;
    }
    if (pathname === montaje.prefijo) {
      enviarRedireccion(req, res, estado, `${montaje.prefijo}/`, 301);
      return true;
    }
    const relativo = pathname.slice(montaje.prefijo.length + 1);
    const partes = [];
    for (const seg of relativo.split('/')) {
      let d;
      try {
        d = decodeURIComponent(seg);
      } catch {
        noEncontrado();
        return true;
      }
      // Sin recorrido de rutas, sin barras codificadas, sin NUL y sin archivos ocultos.
      if (d === '' ) continue;
      if (d === '.' || d === '..' || /[/\\\0]/.test(d) || d.startsWith('.')) {
        noEncontrado();
        return true;
      }
      partes.push(d);
    }
    let ruta = join(raiz, ...partes);
    try {
      let info = await stat(ruta);
      if (info.isDirectory()) {
        if (!pathname.endsWith('/')) {
          enviarRedireccion(req, res, estado, `${pathname}/`, 301);
          return true;
        }
        ruta = join(ruta, 'index.html'); // índice por defecto; nunca se listan directorios
        info = await stat(ruta);
      }
      const real = await realpath(ruta); // enlaces simbólicos no pueden escapar de la raíz
      if (!info.isFile() || (real !== raiz && !real.startsWith(raiz + sep))) throw new Error();
      res.setHeader('Content-Security-Policy', CSP_ESTATICOS);
      res.setHeader('Permissions-Policy', politicaPermisosPara(pathname)); // cámara solo en /app/ (lector QR)
      res.setHeader('Cache-Control', 'no-cache');
      res.removeHeader('Pragma');
      res.setHeader('Content-Type', TIPOS_MIME[extname(real).toLowerCase()] ?? 'application/octet-stream');
      res.setHeader('Content-Length', info.size);
      res.setHeader('Last-Modified', info.mtime.toUTCString());
      estado.status = 200;
      res.writeHead(200);
      if (req.method === 'HEAD') {
        res.end();
        return true;
      }
      const flujo = createReadStream(real);
      flujo.on('error', () => res.destroy());
      flujo.pipe(res);
    } catch {
      noEncontrado();
    }
    return true;
  }

  // ---------------------------------------------------------------- respuesta

  function enviar(req, res, estado, { status, cuerpo, cabeceras = {}, texto, tipoContenido, cookie }) {
    if (res.headersSent || res.writableEnded) return;
    estado.status = status;
    for (const [nombre, valor] of Object.entries(cabeceras ?? {})) {
      if (typeof valor !== 'string' && typeof valor !== 'number') continue;
      if (!/^[A-Za-z0-9-]{1,64}$/.test(nombre) || CABECERAS_RESERVADAS.has(nombre.toLowerCase())) continue;
      res.setHeader(nombre, String(valor));
    }
    if (cookie) res.setHeader('Set-Cookie', cookie);
    let carga = '';
    if (texto !== undefined) {
      carga = String(texto);
      res.setHeader('Content-Type', tipoContenido ?? 'text/plain; charset=utf-8');
    } else if (cuerpo !== undefined && status !== 204) {
      carga = JSON.stringify(cuerpo);
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
    }
    res.setHeader('Content-Length', Buffer.byteLength(carga));
    res.writeHead(status);
    res.end(req.method === 'HEAD' ? undefined : carga);
  }

  function enviarRedireccion(req, res, estado, destino, status = 302) {
    res.setHeader('Location', destino);
    enviar(req, res, estado, { status, cuerpo: undefined });
  }

  /** Normaliza la salida de un caso de uso; cualquier forma inesperada se trata como fallo (503). */
  function normalizarResultado(r) {
    if (!r || typeof r !== 'object' || !Number.isInteger(r.status) || r.status < 200 || r.status > 599) {
      throw new Error('Resultado de caso de uso inválido');
    }
    return r;
  }

  // ---------------------------------------------------------------- CORS

  /** @returns {'ninguno' | 'permitido' | 'rechazado'} */
  function evaluarCors(req) {
    const origen = cabecera(req, 'origin');
    if (origen === undefined) return 'ninguno';
    const host = cabecera(req, 'host');
    if (host && (origen === `https://${host}` || origen === `http://${host}`)) return 'ninguno'; // mismo origen
    return origenes.has(origen) ? 'permitido' : 'rechazado';
  }

  // ---------------------------------------------------------------- manejador principal

  async function manejar(req, res) {
    const inicio = performance.now();
    const estado = { plantilla: 'no_encontrada', status: 0 };
    res.on('finish', () => {
      try {
        metricas.registrarPeticion({ ruta: estado.plantilla, status: estado.status || res.statusCode, duracionMs: performance.now() - inicio });
      } catch { /* las métricas nunca tumban una respuesta */ }
    });
    for (const [k, v] of Object.entries(cabecerasSeguridad())) res.setHeader(k, v);

    let url;
    try {
      if (typeof req.url !== 'string' || !req.url.startsWith('/')) throw new Error();
      url = new URL(req.url, 'http://servicio.local');
    } catch {
      enviar(req, res, estado, respuestaError(400));
      return;
    }
    const pathname = url.pathname;
    const ip = ipDe(req);
    const ipHash = anonimizar(`ip:${ip}`);

    // 1. Límite global por IP TCP antes de cualquier operación costosa (anti-DDoS, capacidad alta).
    const esVerificacion = req.method === 'POST' && pathname === '/api/v1/verify';
    const rechazoPorLimite = () => {
      try { metricas.registrarLimiteTasa({ verificacion: esVerificacion }); } catch { /* sin métricas */ }
    };
    const rg = limGlobal.consumir(`g:${ipHash}`);
    if (!rg.permitido) {
      rechazoPorLimite();
      enviar(req, res, estado, errorGenerico('limite', { reintentarEnSegundos: Math.max(1, rg.reintentarEnMs / 1000) }));
      return;
    }

    // 2. CORS estricto por lista blanca.
    const corsEstado = evaluarCors(req);
    if (corsEstado === 'permitido') {
      res.setHeader('Access-Control-Allow-Origin', cabecera(req, 'origin'));
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
    }
    if (req.method === 'OPTIONS') {
      estado.plantilla = 'preflight';
      if (corsEstado !== 'permitido') {
        enviar(req, res, estado, respuestaError(403));
        return;
      }
      res.setHeader('Access-Control-Allow-Methods', METODOS_CORS);
      res.setHeader('Access-Control-Allow-Headers', CABECERAS_CORS_PERMITIDAS);
      res.setHeader('Access-Control-Max-Age', '600');
      enviar(req, res, estado, { status: 204 });
      return;
    }
    if (corsEstado === 'rechazado') {
      enviar(req, res, estado, respuestaError(403));
      return;
    }

    // 3. Raíz, páginas públicas y estáticos.
    if (carpetaSitio && Object.hasOwn(PAGINAS_SITIO, pathname)) {
      estado.plantilla = pathname;
      await servirArchivoDesde(req, res, carpetaSitio, PAGINAS_SITIO[pathname], pathname, estado);
      return;
    }
    if (pathname === '/' && redirigirRaiz && (req.method === 'GET' || req.method === 'HEAD')) {
      estado.plantilla = '/';
      enviarRedireccion(req, res, estado, redirigirRaiz, 302);
      return;
    }
    if (await servirEstatico(req, res, pathname, estado)) return;

    // 4. Enrutado.
    const r = router.resolver(req.method ?? 'GET', pathname);
    if (r.tipo === 'no_encontrada') {
      enviar(req, res, estado, respuestaError(404));
      return;
    }
    if (r.tipo === 'metodo_no_permitido') {
      estado.plantilla = r.plantilla;
      enviar(req, res, estado, { ...respuestaError(405), cabeceras: { Allow: r.permitidos.join(', ') } });
      return;
    }
    const { ruta, params } = r;
    estado.plantilla = ruta.plantilla;
    const op = ruta.opciones;

    try {
      // 5. Límites específicos que no requieren trabajo costoso.
      if (op.tipo === 'login') {
        const rl = limLogin.consumir(`login:${ipHash}`);
        if (!rl.permitido) throw Object.assign(new ErrorHttp(429), { reintentarMs: rl.reintentarEnMs });
      }

      // 6. Cuerpo: solo application/json, acotado en tamaño y tiempo.
      let cuerpo = {};
      if (op.cuerpo) {
        if (tieneCuerpo(req)) {
          if (!esJson(req)) throw new ErrorHttp(415);
          const bruto = await leerCuerpo(req, { limite: limiteCuerpo, timeoutMs: timeoutCuerpoMs });
          if (bruto.length > 0) {
            try {
              cuerpo = JSON.parse(bruto.toString('utf8'));
            } catch {
              throw new ErrorHttp(400);
            }
            if (!esObjetoPlano(cuerpo)) throw new ErrorHttp(400);
          }
        }
      } else if (tieneCuerpo(req)) {
        await leerCuerpo(req, { limite: limiteCuerpo, timeoutMs: timeoutCuerpoMs }); // se descarta
      }

      // 7. Idempotencia.
      const claveIdem = cabecera(req, 'idempotency-key');
      if (claveIdem !== undefined && !RE_IDEMPOTENCIA.test(claveIdem)) throw new ErrorHttp(400);

      /** @type {Record<string, any>} */
      const ctx = { ip };
      if (claveIdem !== undefined) ctx.idempotencyKey = claveIdem;
      const peticion = { req, cuerpo, params, query: consultaDe(url), ctx, ipHash, sesion: null, sesionId: null };

      // 8. Autenticación según el tipo de ruta.
      if (op.tipo === 'api') {
        const app = await autenticarApp(req);
        if (!app) throw new ErrorHttp(401);
        const idApp = String(app.id ?? app.client_id);
        const ra = limApp.consumir(`app:${idApp}`);
        if (!ra.permitido) throw Object.assign(new ErrorHttp(429), { reintentarMs: ra.reintentarEnMs });
        if (op.porOrigen) {
          // Origen = client_ip válido del cuerpo o, si falta (o es inválido: el caso de uso dará 400), la IP TCP.
          const origen = normalizarIp(cuerpo.client_ip) ?? ip;
          const ro = limOrigen.consumir(`o:${anonimizar(`${idApp}:${origen}`)}`);
          if (!ro.permitido) throw Object.assign(new ErrorHttp(429), { reintentarMs: ro.reintentarEnMs });
        }
        ctx.app = app;
      } else if (op.tipo === 'loopback') {
        if (!esLocal(ip)) throw new ErrorHttp(403);
      } else if (op.tipo === 'admin') {
        const s = sesionDe(req);
        if (!s) throw new ErrorHttp(401);
        if (METODOS_QUE_MODIFICAN.has(req.method) && !igualSeguro(cabecera(req, 'x-csrf-token'), s.sesion.csrf)) {
          throw new ErrorHttp(403);
        }
        if (op.permiso && !autorizar(s.sesion.admin.rol, op.permiso)) throw new ErrorHttp(403);
        ctx.admin = s.sesion.admin;
        peticion.sesion = s.sesion;
        peticion.sesionId = s.id;
        peticion.renovarCookie = cookieSesion(s.id, DURACION_SESION_MS / 1000);
      }

      // 9. Caso de uso (falla cerrado).
      let resultado;
      try {
        resultado = normalizarResultado(await ruta.manejador(peticion));
      } catch (error) {
        registro.error?.(`Fallo en ${req.method} ${ruta.plantilla}: ${error?.name ?? 'Error'}: ${error?.message ?? ''}`);
        resultado = errorGenerico('no_disponible');
      }
      if (op.invalidaApps && resultado.status < 300) cacheApps.clear();
      if (op.cierraSesionesDe && resultado.status < 300) {
        const idCerrado = resultado.cuerpo?.admin?.id;
        for (const [idSesion, s] of sesiones) if (idCerrado && s.admin.id === idCerrado) sesiones.delete(idSesion);
      }
      if (!resultado.cookie && peticion.renovarCookie && sesiones.has(peticion.sesionId)) {
        resultado = { ...resultado, cookie: peticion.renovarCookie };
      }
      if (op.cacheJwks && resultado.status === 200) {
        res.setHeader('Cache-Control', 'public, max-age=300');
        res.removeHeader('Pragma');
      }
      enviar(req, res, estado, resultado);
    } catch (error) {
      if (error instanceof ErrorHttp) {
        if (error.status === 429) {
          rechazoPorLimite();
          enviar(req, res, estado, errorGenerico('limite', { reintentarEnSegundos: Math.max(1, (error.reintentarMs ?? 1000) / 1000) }));
        } else {
          if (error.status === 413 || error.status === 408) res.setHeader('Connection', 'close');
          enviar(req, res, estado, { ...respuestaError(error.status), cabeceras: error.cabeceras });
          if (error.status === 413 || error.status === 408) res.on('finish', () => req.socket?.destroySoon?.());
        }
        return;
      }
      registro.error?.(`Fallo inesperado en ${req.method} ${ruta.plantilla}: ${error?.message ?? ''}`);
      enviar(req, res, estado, errorGenerico('no_disponible'));
    }
  }

  /** Envoltura final: nada que lance aquí puede dejar la petición colgada. */
  function alPedir(req, res) {
    manejar(req, res).catch((error) => {
      registro.error?.(`Fallo del servidor: ${error?.message ?? ''}`);
      if (!res.headersSent) {
        res.statusCode = 503;
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.end(JSON.stringify(errorGenerico('no_disponible').cuerpo));
      } else res.destroy();
    });
  }

  const opcionesServidor = {
    requestTimeout: opciones.requestTimeoutMs ?? 15_000,
    headersTimeout: opciones.headersTimeoutMs ?? 10_000,
    keepAliveTimeout: opciones.keepAliveTimeoutMs ?? 5_000,
    maxHeaderSize: 16 * 1024,
  };
  const servidor = tls
    ? crearServidorHttps({ ...opcionesServidor, cert: tls.cert, key: tls.key, ca: tls.ca, minVersion: 'TLSv1.3' }, alPedir)
    : crearServidorHttp(opcionesServidor, alPedir);
  servidor.requestTimeout = opcionesServidor.requestTimeout;
  servidor.headersTimeout = opcionesServidor.headersTimeout;
  servidor.keepAliveTimeout = opcionesServidor.keepAliveTimeout;
  servidor.maxHeadersCount = 64;
  servidor.maxRequestsPerSocket = 200;
  servidor.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    else socket.destroy();
  });

  return Object.assign(servidor, {
    api: {
      sesiones,
      invalidarCacheApps: () => cacheApps.clear(),
      rutas: router.listar(),
    },
  });
}
