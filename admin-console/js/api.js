// Cliente de la API administrativa (/admin/api/*). Mismo origen, cookie HttpOnly de sesión,
// cabecera X-CSRF-Token en métodos que modifican. Normaliza las respuestas para que las
// vistas no dependan de variantes de nombres (snake_case / camelCase).
// Emite eventos globales de resiliencia: sesión expirada, permisos, límite de tasa,
// servicio no disponible y estado de la conexión.

import { esMock, mockFetch } from './mock.js';

export { esMock };

/** Bus de eventos de la capa de red. */
export const eventosApi = new EventTarget();
const emitir = (tipo, detalle) => eventosApi.dispatchEvent(new CustomEvent(tipo, { detail: detalle }));

const TIEMPO_MAXIMO_MS = 12_000;
let csrfToken = null;

export function fijarCsrf(token) { csrfToken = token || null; }

/** Operaciones opcionales que dependen de la versión de la API (todas disponibles desde el #21). */
export const capacidades = Object.freeze({ accionesEnrolamiento: true });

/** Error de la API con estado HTTP y cuerpo normalizado. */
export class ErrorApi extends Error {
  /** @param {number} status @param {any} cuerpo @param {string} [mensaje] */
  constructor(status, cuerpo, mensaje) {
    super(mensaje ?? cuerpo?.message ?? `Error ${status}`);
    this.status = status;
    this.cuerpo = cuerpo;
    this.codigo = cuerpo?.error ?? cuerpo?.errorCode ?? null;
    this.reintentarEn = Number(cuerpo?.retry_after_seconds ?? cuerpo?.retryAfterSeconds) || null;
  }
}

/** Mensajes genéricos por estado (no se muestran mensajes técnicos del servidor). */
export function mensajeDeError(e) {
  if (!(e instanceof ErrorApi)) return 'Se produjo un error inesperado.';
  switch (e.status) {
    case 0: return 'No hay conexión con el servicio.';
    case 400: return 'La solicitud no es válida. Revisa los datos.';
    case 401: return 'Tu sesión no es válida. Vuelve a iniciar sesión.';
    case 403: return 'No tienes permisos para realizar esta acción.';
    case 404: return 'El recurso solicitado no existe.';
    case 405: return 'La API no expone esta operación.';
    // Los 409 de la consola traen un motivo fijo del servidor (nunca datos de la entrada).
    case 409: return e.codigo === 'CONFLICT' && typeof e.cuerpo?.message === 'string' ? e.cuerpo.message : 'La operación entra en conflicto con el estado actual.';
    case 429: return `Demasiadas solicitudes. Reintenta en ${e.reintentarEn ?? 30} s.`;
    case 503: return 'Servicio no disponible temporalmente.';
    default: return e.status >= 500 ? 'Error interno del servicio.' : 'No se pudo completar la operación.';
  }
}

/**
 * Petición base.
 * @param {string} metodo @param {string} ruta
 * @param {{ cuerpo?: any, texto?: boolean, sinEventosSesion?: boolean, aceptarEstados?: number[] }} [opciones]
 */
async function peticion(metodo, ruta, { cuerpo, texto = false, sinEventosSesion = false, aceptarEstados = [] } = {}) {
  const cabeceras = { Accept: texto ? 'text/plain' : 'application/json' };
  if (cuerpo !== undefined) cabeceras['Content-Type'] = 'application/json';
  if (metodo !== 'GET' && metodo !== 'HEAD' && csrfToken) cabeceras['X-CSRF-Token'] = csrfToken;
  const opciones = {
    method: metodo,
    headers: cabeceras,
    body: cuerpo === undefined ? undefined : JSON.stringify(cuerpo),
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    signal: AbortSignal.timeout ? AbortSignal.timeout(TIEMPO_MAXIMO_MS) : undefined,
  };

  let respuesta;
  try {
    respuesta = esMock ? await mockFetch(ruta, opciones) : await fetch(ruta, opciones);
  } catch (e) {
    emitir('conexion', { ok: false });
    throw new ErrorApi(0, null, e?.name === 'TimeoutError' ? 'Tiempo de espera agotado.' : 'Sin conexión.');
  }
  emitir('conexion', { ok: true });

  let datos = null;
  const tipo = respuesta.headers.get('Content-Type') ?? '';
  try {
    if (texto && !tipo.includes('json')) datos = await respuesta.text();
    else if (respuesta.status !== 204) datos = tipo.includes('json') ? await respuesta.json() : await respuesta.text();
  } catch { datos = null; }

  if (respuesta.ok || aceptarEstados.includes(respuesta.status)) {
    if (respuesta.status !== 503) emitir('disponible', { ok: true });
    return { status: respuesta.status, datos, cabeceras: respuesta.headers };
  }

  const err = new ErrorApi(respuesta.status, typeof datos === 'object' ? datos : null);
  if (respuesta.status === 429 || respuesta.status === 503) {
    const cab = Number(respuesta.headers.get('Retry-After'));
    err.reintentarEn = err.reintentarEn ?? (Number.isFinite(cab) && cab > 0 ? cab : respuesta.status === 429 ? 30 : 15);
  }
  if (respuesta.status === 401 && !sinEventosSesion) emitir('sesion-expirada', {});
  else if (respuesta.status === 429) emitir('limite', { segundos: err.reintentarEn });
  else if (respuesta.status === 503) emitir('disponible', { ok: false, segundos: err.reintentarEn });
  else if (respuesta.status !== 401) emitir('disponible', { ok: true });
  throw err;
}

const get = (ruta, op) => peticion('GET', ruta, op).then((r) => r.datos);
const post = (ruta, cuerpo, op) => peticion('POST', ruta, { ...op, cuerpo }).then((r) => r.datos);

// --------------------------------------------------------------------- utilidades de normalización
const primero = (o, ...claves) => {
  for (const c of claves) if (o && o[c] !== undefined && o[c] !== null) return o[c];
  return undefined;
};
const lista = (datos, ...claves) => (Array.isArray(datos) ? datos : primero(datos, ...claves, 'items', 'data') ?? []);
const aBool = (v) => v === true || v === 1 || v === '1' || v === 'true';

function normalizarSesion(d) {
  if (!d) return null;
  return {
    usuario: primero(d, 'usuario', 'user', 'username') ?? 'admin',
    rol: primero(d, 'rol', 'role') ?? 'Auditor',
    csrf_token: primero(d, 'csrf_token', 'csrfToken', 'csrf') ?? null,
    expira_en: primero(d, 'expira_en', 'expires_at', 'expiresAt') ?? null,
  };
}

function normalizarApp(a) {
  return {
    id: primero(a, 'id', 'app_id'),
    nombre: primero(a, 'nombre', 'name') ?? '(sin nombre)',
    client_id: primero(a, 'client_id', 'clientId') ?? '—',
    algoritmo: primero(a, 'algoritmo', 'algorithm') ?? 'SHA256',
    digitos: Number(primero(a, 'digitos', 'digits') ?? 6),
    periodo: Number(primero(a, 'periodo', 'period', 'stepSeconds') ?? 30),
    ventana: Number(primero(a, 'ventana', 'window', 'driftWindow') ?? 1),
    max_intentos: Number(primero(a, 'max_intentos', 'maxFailedAttempts') ?? 5),
    umbral_riesgo_bloqueo: Number(primero(a, 'umbral_riesgo_bloqueo', 'anomalyBlockThreshold') ?? 75),
    modo_heuristica: primero(a, 'modo_heuristica', 'heuristicsMode') ?? 'bloqueo',
    permitir_sha1: aBool(primero(a, 'permitir_sha1', 'allowSha1')),
    estado: primero(a, 'estado', 'status') ?? 'activo',
    user_ref_desde_cedula: primero(a, 'user_ref_desde_cedula') ?? 'ninguno',
    cedula_prefijo: primero(a, 'cedula_prefijo') ?? '',
    created_at: primero(a, 'created_at', 'createdAt'),
    updated_at: primero(a, 'updated_at', 'updatedAt'),
  };
}

function normalizarAdmin(a) {
  return {
    id: primero(a, 'id'),
    usuario: primero(a, 'usuario') ?? '—',
    rol: primero(a, 'rol') ?? 'Auditor',
    activo: aBool(primero(a, 'activo')),
    totp_estado: primero(a, 'totp_estado') ?? 'sin_totp',
    created_at: primero(a, 'created_at', 'createdAt'),
  };
}

function normalizarEnrolamiento(e) {
  return {
    id: primero(e, 'id', 'enrollment_id'),
    app_id: primero(e, 'app_id', 'appId'),
    app_nombre: primero(e, 'app_nombre', 'app_name', 'app'),
    user_ref_hash: primero(e, 'user_ref_hash', 'userRefHash', 'externalUserId') ?? '—',
    estado: primero(e, 'estado', 'status') ?? 'pendiente',
    algoritmo: primero(e, 'algoritmo', 'algorithm'),
    digitos: primero(e, 'digitos', 'digits'),
    periodo: primero(e, 'periodo', 'period'),
    drift_steps: Number(primero(e, 'drift_steps', 'driftSteps') ?? 0),
    failed_attempts: Number(primero(e, 'failed_attempts', 'failedAttempts') ?? 0),
    locked_until: primero(e, 'locked_until', 'lockedUntil'),
    created_at: primero(e, 'created_at', 'createdAt'),
    activated_at: primero(e, 'activated_at', 'activatedAt'),
    revoked_at: primero(e, 'revoked_at', 'revokedAt'),
    last_used_at: primero(e, 'last_used_at', 'lastUsedAt'),
  };
}

function normalizarAlerta(a) {
  const riesgo = primero(a, 'risk', 'riskAssessment') ?? {};
  const razones = primero(a, 'reasons', 'razones', 'reasons_json') ?? primero(riesgo, 'reasons') ?? [];
  return {
    id: primero(a, 'id'),
    cuenta: primero(a, 'userRefHash', 'externalUserId', 'user_ref_hash'),
    ip_hash: primero(a, 'ipHash', 'ip_hash'),
    puntaje: Number(primero(a, 'riskScore', 'risk_score', 'score') ?? primero(riesgo, 'riskScore', 'score') ?? 0),
    nivel: String(primero(a, 'level', 'nivel') ?? primero(riesgo, 'level') ?? 'LOW').toUpperCase(),
    accion: String(primero(a, 'action', 'accion') ?? primero(riesgo, 'action') ?? 'ALLOW').toUpperCase(),
    razones: Array.isArray(razones) ? razones : [],
    app: primero(a, 'app', 'app_client_id', 'client_id'),
    inferencia_ms: primero(a, 'inferenceMs', 'inference_ms') ?? primero(riesgo, 'inferenceMs', 'inference_ms'),
    fecha: primero(a, 'createdAt', 'created_at', 'ts'),
  };
}

function normalizarLlave(k, activa) {
  const kid = primero(k, 'kid');
  const estado = primero(k, 'estado', 'status') ?? (kid === activa ? 'activa' : 'solo_verificacion');
  return { kid, estado, alg: primero(k, 'alg') ?? 'EdDSA', crv: primero(k, 'crv') ?? 'Ed25519', created_at: primero(k, 'created_at', 'createdAt'), rotated_at: primero(k, 'rotated_at', 'rotatedAt') };
}

function normalizarEvento(e) {
  return {
    id: Number(primero(e, 'id')),
    ts: primero(e, 'ts', 'timestamp'),
    actor: primero(e, 'actor') ?? '—',
    accion: primero(e, 'accion', 'action') ?? '—',
    objetivo: primero(e, 'objetivo', 'target') ?? null,
    detalle: e?.detalle ?? e?.detail ?? null,
    prev_hash: primero(e, 'prev_hash', 'prevHash'),
    hash: primero(e, 'hash'),
  };
}

/** Convierte el texto Prometheus de GET /metrics en la misma forma que la instantánea JSON. */
export function parsearPrometheus(texto) {
  const muestras = [];
  for (const linea of String(texto).split('\n')) {
    if (!linea || linea.startsWith('#')) continue;
    const m = linea.match(/^([a-zA-Z_:][\w:]*)(?:\{(.*)\})?\s+(\S+)/);
    if (!m) continue;
    const etiquetas = {};
    if (m[2]) for (const p of m[2].matchAll(/(\w+)="((?:[^"\\]|\\.)*)"/g)) etiquetas[p[1]] = p[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    muestras.push({ nombre: m[1], etiquetas, valor: Number(m[3]) });
  }
  const valor = (n) => muestras.find((x) => x.nombre === n)?.valor;
  const resultados = {};
  for (const x of muestras.filter((y) => y.nombre === 'totp_verifications_total')) resultados[x.etiquetas.resultado] = x.valor;
  const latenciaPorRuta = {};
  for (const x of muestras.filter((y) => y.nombre === 'totp_http_request_duration_ms')) {
    const r = (latenciaPorRuta[x.etiquetas.ruta] ??= { total: 0, errores5xx: 0, p50Ms: null, p95Ms: null });
    if (x.etiquetas.quantile === '0.5') r.p50Ms = Number.isFinite(x.valor) ? x.valor : null;
    if (x.etiquetas.quantile === '0.95') r.p95Ms = Number.isFinite(x.valor) ? x.valor : null;
  }
  for (const x of muestras.filter((y) => y.nombre === 'totp_http_requests_total')) if (latenciaPorRuta[x.etiquetas.ruta]) latenciaPorRuta[x.etiquetas.ruta].total = x.valor;
  return {
    uptimeSegundos: valor('totp_uptime_seconds'),
    totales: { verificaciones: Object.values(resultados).reduce((a, b) => a + (b || 0), 0) },
    disponibilidadPct: valor('totp_availability_percent'),
    resultadosVerificacion: resultados,
    latenciaPorRuta,
    inferencia: { mediaMs: valor('totp_anomaly_inference_ms_avg') },
    desfaseRelojMs: valor('totp_clock_skew_ms'),
  };
}

// --------------------------------------------------------------------- operaciones
export const api = {
  async sesion() {
    return normalizarSesion(await get('/admin/api/session', { sinEventosSesion: true }));
  },
  async iniciarSesion(usuario, password, codigo) {
    // El servidor valida un esquema cerrado con el campo `totp_code` (contracts/openapi.yaml).
    return normalizarSesion(await post('/admin/api/login', { usuario, password, totp_code: codigo }, { sinEventosSesion: true }));
  },
  async cerrarSesion() {
    try { await post('/admin/api/logout', undefined, { sinEventosSesion: true }); } catch { /* la sesión local se descarta igualmente */ }
  },

  /** Resumen del panel a partir del resumen del detector de anomalías. */
  async tablero() {
    const d = await get('/admin/api/anomalies');
    return {
      politica: d?.policy ?? null,
      resumen: d?.summary ?? {},
      alertas: lista(d, 'alerts', 'alertas').map(normalizarAlerta),
    };
  },
  /** Métricas en JSON (/metrics en texto queda reservado a la red local del servidor). */
  async metricas() {
    return (await get('/admin/api/metrics')) ?? {};
  },
  /** /health/ready: devuelve el cuerpo aunque el estado sea 503 (degradado). */
  async salud() {
    const r = await peticion('GET', '/health/ready', { aceptarEstados: [503] });
    const d = r.datos && typeof r.datos === 'object' ? r.datos : {};
    let checks = d.checks ?? d.componentes ?? null;
    if (!checks) {
      // Forma plana ({ status, database: 'ok' }): cada clave con valor de estado es un chequeo.
      const planos = Object.entries(d).filter(([k, v]) => k !== 'status' && typeof v === 'string' && /^(ok|error|fallo|degradado)$/.test(v));
      checks = planos.length ? Object.fromEntries(planos) : null;
    }
    return { listo: r.status === 200 && (d.status ?? 'ok') === 'ok', status: d.status ?? (r.status === 200 ? 'ok' : 'degradado'), checks, datos: d };
  },

  async apps() {
    return lista(await get('/admin/api/apps'), 'apps', 'aplicaciones').map(normalizarApp);
  },
  /** POST /admin/api/apps con `id`: actualiza la política (sin `id` registraría una app nueva). */
  async actualizarApp(id, cambios) {
    const cuerpo = { id, ...cambios };
    if ('umbral_riesgo_bloqueo' in cuerpo) cuerpo.umbral_riesgo_bloqueo = Math.round(cuerpo.umbral_riesgo_bloqueo);
    const d = await post('/admin/api/apps', cuerpo);
    return normalizarApp(d?.app ?? d ?? cuerpo);
  },
  /**
   * POST /admin/api/apps sin `id`: registra la app. Devuelve las credenciales que el servidor
   * entrega UNA sola vez (client_secret y, si la app deriva el user_ref desde la cédula, el secreto de derivación).
   */
  async registrarApp(datos) {
    const d = await post('/admin/api/apps', datos);
    return { app: normalizarApp(d?.app ?? {}), client_id: d?.client_id, client_secret: d?.client_secret, cedula_secreto: d?.cedula_secreto ?? null };
  },
  /** POST /admin/api/apps/{id}/secret: nuevo client_secret (el anterior deja de valer al instante). */
  async regenerarSecreto(id) {
    const d = await post(`/admin/api/apps/${encodeURIComponent(id)}/secret`, {});
    return { app: normalizarApp(d?.app ?? {}), client_id: d?.client_id, client_secret: d?.client_secret };
  },

  async enrolamientos(filtros = {}) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(filtros)) if (v) q.set(k, v);
    const d = await get(`/admin/api/enrollments${q.size ? `?${q}` : ''}`);
    return lista(d, 'enrollments', 'enrolamientos').map(normalizarEnrolamiento);
  },
  /**
   * Búsqueda de soporte: por cédula (si la app deriva el user_ref desde ella) o por user_ref exacto.
   * El servidor audita cada búsqueda sin guardar la cédula en claro.
   * @param {{ app_id: string, cedula?: string, user_ref?: string }} criterio
   */
  async buscarEnrolamientos(criterio) {
    return this.enrolamientos(criterio);
  },
  /**
   * Ciclo de vida desde la consola (Administrador y Operador): activo ↔ suspendido, → revocado (final).
   * @param {'suspend' | 'reactivate' | 'revoke'} accion
   */
  async accionEnrolamiento(id, accion) {
    const d = await post(`/admin/api/enrollments/${encodeURIComponent(id)}/${accion}`, {});
    return normalizarEnrolamiento(d?.enrollment ?? d);
  },

  /** Cuentas de la consola (solo Administrador). */
  async administradores() {
    return lista(await get('/admin/api/admins'), 'admins').map(normalizarAdmin);
  },
  /** Crea una cuenta: devuelve UNA sola vez la contraseña, la URI otpauth y el QR SVG de su TOTP. */
  async crearAdministrador(usuario, rol) {
    const d = await post('/admin/api/admins', { usuario, rol });
    return { admin: normalizarAdmin(d?.admin ?? {}), password: d?.password, otpauth_uri: d?.otpauth_uri, qr_svg: d?.qr_svg };
  },
  async deshabilitarAdministrador(id) {
    const d = await post(`/admin/api/admins/${encodeURIComponent(id)}/disable`, {});
    return normalizarAdmin(d?.admin ?? {});
  },

  async anomalias() {
    const d = await get('/admin/api/anomalies');
    return {
      modo: d?.modo ?? d?.mode ?? 'local',
      umbrales: d?.umbrales ?? d?.thresholds ?? { alerta: 60, bloqueo: 75 },
      resumen: d?.summary ?? d?.resumen ?? {},
      alertas: lista(d, 'alerts', 'alertas').map(normalizarAlerta),
    };
  },

  /** Inventario de llaves de firma (GET /admin/api/keys, permiso llaves.leer; sin material privado). */
  async llaves() {
    const d = await get('/admin/api/keys');
    const activa = primero(d, 'active_kid', 'activeKid', 'activeKeyId') ?? null;
    return { activa, llaves: lista(d, 'keys', 'llaves').map((k) => normalizarLlave(k, activa)), fuente: 'admin' };
  },
  async rotarLlave() {
    return post('/admin/api/keys/rotate', {});
  },

  /** Página de la bitácora por cursor de id (exclusivo). */
  async auditoria({ desde = 0, limite = 25 } = {}) {
    const d = await get(`/admin/api/audit?desde=${encodeURIComponent(desde)}&limite=${encodeURIComponent(limite)}`);
    const eventos = lista(d, 'eventos', 'events', 'registros').map(normalizarEvento).sort((a, b) => a.id - b.id);
    return { eventos, total: primero(d, 'total') ?? null };
  },
  async verificarCadena() {
    const d = await get('/admin/api/audit/verify-chain');
    return {
      intacta: aBool(primero(d, 'intact', 'intacta')),
      registros: Number(primero(d, 'checked_records', 'checkedRecords') ?? 0),
      rotaEnId: primero(d, 'broken_at_id', 'brokenAtId') ?? null,
      ultimoHash: primero(d, 'last_hash', 'lastHash') ?? null,
    };
  },
};
