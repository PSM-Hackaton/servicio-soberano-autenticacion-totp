// Modo demostración (?mock=1): simula la API administrativa en el navegador a partir de los
// archivos de admin-console/mocks/ (copias de contracts/mocks/ más datos de la consola).
// Estado en memoria; la sesión simulada vive en sessionStorage para sobrevivir a recargas.
//
// Parámetros de demostración en la URL:
//   rol=Administrador|Operador|Auditor   abre la consola con una sesión ya iniciada
//   simular=503|429|offline              fuerza el banner de resiliencia correspondiente
//   truncar=1                            elimina el último registro de la bitácora
//   alterar=<id>                         modifica el detalle del registro <id> (rompe la cadena)

import { PERMISOS } from './rbac.js';
import { calcularHash, HASH_GENESIS } from './cadena.js';

const parametros = new URLSearchParams(location.search);
export const esMock = parametros.get('mock') === '1';

const CLAVE_SESION = 'consola.demo.sesion';
const DURACION_SESION_MS = 15 * 60 * 1000;
const cache = new Map();
let estado = null;

async function cargar(nombre) {
  if (!cache.has(nombre)) {
    cache.set(nombre, fetch(new URL(`../mocks/${nombre}`, import.meta.url), { cache: 'no-store' }).then((r) => {
      if (!r.ok) throw new Error(`No se pudo cargar el mock ${nombre}`);
      return r.json();
    }));
  }
  return structuredClone(await cache.get(nombre));
}

async function inicializar() {
  if (estado) return estado;
  const [apps, enrol, anomalias, llaves, auditoria, metricas, salud, tablero, jwks, cadena, bloqueo, administradores] = await Promise.all([
    cargar('consola-apps.json'), cargar('consola-enrolamientos.json'), cargar('consola-anomalias.json'),
    cargar('consola-llaves.json'), cargar('consola-auditoria.json'), cargar('consola-metricas.json'),
    cargar('consola-salud.json'), cargar('admin-dashboard.json'), cargar('jwks.json'), cargar('audit-chain.json'),
    cargar('verify-anomaly-blocked.json'), cargar('consola-administradores.json'),
  ]);
  const eventos = auditoria.eventos;
  const alterar = Number(parametros.get('alterar'));
  if (alterar) {
    const fila = eventos.find((e) => e.id === alterar);
    if (fila) fila.detalle = '{"resultado":"manipulado"}';
  }
  if (parametros.get('truncar') === '1') eventos.pop();
  // La alerta del contrato (admin-dashboard.json) se enriquece con la evaluación de verify-anomaly-blocked.json.
  const alertaContrato = tablero.alerts?.[0];
  if (alertaContrato) {
    const existente = anomalias.alerts.find((a) => a.id === 'alrt-008');
    if (existente) existente.inferenceMs = bloqueo.riskAssessment?.inferenceMs ?? existente.inferenceMs;
  }
  estado = {
    apps: apps.apps, enrolamientos: enrol.enrollments, anomalias, llaves, eventos, metricas, salud, tablero, jwks, cadena, tick: 0,
    admins: administradores.admins, demoAlta: administradores.demo_alta,
  };
  return estado;
}

function leerSesion() {
  try {
    const s = JSON.parse(sessionStorage.getItem(CLAVE_SESION) ?? 'null');
    if (s && Date.parse(s.expira_en) > Date.now()) return s;
  } catch { /* sin almacenamiento */ }
  const rol = parametros.get('rol');
  if (rol && PERMISOS['panel.ver'].includes(rol)) return guardarSesion(nuevaSesion(rol.toLowerCase(), rol));
  return null;
}
function nuevaSesion(usuario, rol) {
  const aleatorio = crypto.getRandomValues(new Uint8Array(16));
  return { usuario, rol, csrf_token: [...aleatorio].map((b) => b.toString(16).padStart(2, '0')).join(''), expira_en: new Date(Date.now() + DURACION_SESION_MS).toISOString() };
}
function guardarSesion(s) {
  try { sessionStorage.setItem(CLAVE_SESION, JSON.stringify(s)); } catch { /* sin almacenamiento */ }
  return s;
}
function borrarSesion() {
  try { sessionStorage.removeItem(CLAVE_SESION); } catch { /* sin almacenamiento */ }
}

const json = (status, cuerpo, cabeceras = {}) => new Response(cuerpo === null ? null : JSON.stringify(cuerpo), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cabeceras },
});
const error = (status, codigo, mensaje, extra = {}) => json(status, { error: codigo, message: mensaje, ...extra }, extra.retry_after_seconds ? { 'Retry-After': String(extra.retry_after_seconds) } : {});
const espera = (t) => new Promise((r) => setTimeout(r, t));
const aleatorioB64 = (n) => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(n)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const aleatorioHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');
/** Campos de demostración (cédula y user_ref ficticios) que nunca salen en las respuestas simuladas. */
const sinDemo = ({ cedula_demo: _c, user_ref_demo: _u, ...e }) => e;
/** Misma regla que backend/src/core/identidad/cedula.js (V o E, 6 a 9 dígitos, sin ceros a la izquierda). */
function cedulaCanonica(texto) {
  const m = /^([VvEe])[- ]?([1-9][0-9]{0,2}(?:\.[0-9]{3}){1,2}|[1-9][0-9]{5,8})$/.exec(String(texto ?? '').trim());
  if (!m) return null;
  const n = m[2].replaceAll('.', '');
  return n.length >= 6 && n.length <= 9 ? `${m[1].toUpperCase()}${n}` : null;
}
/** Huella ficticia para la bitácora simulada: nunca se registra la cédula en claro. */
async function huellaDemo(texto) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`demo:${texto}`));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
const conflicto = (mensaje) => error(409, 'CONFLICT', mensaje);

/** Número aleatorio en [0, 1) del CSPRNG del navegador (datos simulados del modo demostración). */
function azar() {
  return crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32;
}

/** Avanza las métricas simuladas para que el refresco periódico muestre actividad. */
function avanzarMetricas(m) {
  estado.tick++;
  const ultimo = m.serie[m.serie.length - 1];
  const ok = 16 + Math.round(azar() * 14);
  const fallido = 1 + Math.round(azar() * 3);
  const bloqueado = azar() < 0.3 ? 1 : 0;
  m.serie.push({ ts: new Date(Date.parse(ultimo.ts) + 75000).toISOString(), ok, fallido, bloqueado, p95Ms: Math.round((18 + azar() * 12) * 10) / 10, p50Ms: Math.round((6 + azar() * 4) * 10) / 10 });
  m.serie.shift();
  m.resultadosVerificacion.ok += ok;
  m.resultadosVerificacion.invalid_code += fallido;
  m.resultadosVerificacion.rate_limited += bloqueado;
  m.totales.verificaciones += ok + fallido + bloqueado;
  m.totales.peticiones += (ok + fallido + bloqueado) * 2;
  m.uptimeSegundos += 15;
}

function registrarAuditoria(actor, accion, objetivo, detalle) {
  const anterior = estado.eventos[estado.eventos.length - 1];
  const fila = { id: (anterior?.id ?? 0) + 1, ts: new Date().toISOString(), actor, accion, objetivo, detalle: detalle ? JSON.stringify(detalle, Object.keys(detalle).sort()) : null, prev_hash: anterior?.hash ?? HASH_GENESIS, hash: '' };
  return calcularHash(fila.prev_hash, fila).then((h) => { fila.hash = h; estado.eventos.push(fila); });
}

async function verificarCadenaCompleta() {
  let esperado = HASH_GENESIS;
  let total = 0;
  for (const fila of estado.eventos) {
    total++;
    if (fila.prev_hash !== esperado || (await calcularHash(fila.prev_hash, fila)) !== fila.hash) {
      return { intact: false, checked_records: total, broken_at_id: fila.id, last_hash: null };
    }
    esperado = fila.hash;
  }
  return { intact: true, checked_records: total, broken_at_id: null, last_hash: total ? esperado : null };
}

/**
 * Sustituto de fetch para el modo demostración.
 * @param {string} url @param {RequestInit} [opciones]
 * @returns {Promise<Response>}
 */
export async function mockFetch(url, opciones = {}) {
  await inicializar();
  await espera(120 + azar() * 160);
  const destino = new URL(url, location.href);
  const ruta = destino.pathname;
  const metodo = (opciones.method ?? 'GET').toUpperCase();
  const cuerpo = typeof opciones.body === 'string' ? JSON.parse(opciones.body) : {};
  const simular = parametros.get('simular');

  if (simular === 'offline') throw new TypeError('Failed to fetch');

  // ---- sesión
  if (ruta === '/admin/api/login' && metodo === 'POST') {
    const { usuario = '', password = '' } = cuerpo;
    const codigo = cuerpo.totp_code ?? cuerpo.codigo ?? '';
    if (!usuario || !password || !/^[0-9]{6}([0-9]{2})?$/.test(codigo) || codigo === '000000') {
      return error(401, 'LOGIN_FAILED', 'Credenciales o código no válidos.');
    }
    const u = String(usuario).toLowerCase();
    const rol = u.startsWith('aud') ? 'Auditor' : u.startsWith('oper') ? 'Operador' : 'Administrador';
    const sesion = guardarSesion(nuevaSesion(u, rol));
    await registrarAuditoria(`admin:${u}`, 'admin.login', u, { rol });
    return json(200, sesion);
  }
  if (ruta === '/admin/api/logout' && metodo === 'POST') {
    borrarSesion();
    return json(200, { ok: true });
  }
  if (ruta === '/health/ready' || ruta === '/health') {
    if (simular === '503') return json(503, { status: 'degradado', checks: { base_datos: 'error', llaves_firma: 'ok', detector_anomalias: 'ok', reloj: 'ok' } });
    return json(200, { ...estado.salud, timestamp: new Date().toISOString() });
  }
  if (ruta === '/.well-known/jwks.json') return json(200, estado.jwks);

  const sesion = leerSesion();
  if (ruta === '/admin/api/session') return sesion ? json(200, sesion) : error(401, 'UNAUTHENTICATED', 'Sesión no válida.');
  if (!sesion) return error(401, 'UNAUTHENTICATED', 'Sesión no válida.');
  // Renovación deslizante de la sesión simulada.
  guardarSesion({ ...sesion, expira_en: new Date(Date.now() + DURACION_SESION_MS).toISOString() });

  if (simular === '503') return error(503, 'SERVICE_UNAVAILABLE', 'Servicio no disponible temporalmente.', { retry_after_seconds: 15 });
  if (simular === '429') return error(429, 'RATE_LIMITED', 'Demasiadas solicitudes.', { retry_after_seconds: 20 });

  if (metodo !== 'GET') {
    const csrf = new Headers(opciones.headers).get('X-CSRF-Token');
    if (csrf !== sesion.csrf_token) return error(403, 'CSRF', 'Solicitud no permitida.');
  }
  const exigir = (permiso) => (PERMISOS[permiso].includes(sesion.rol) ? null : error(403, 'FORBIDDEN', 'Acceso denegado.'));

  // ---- panel y métricas
  if (ruta === '/admin/api/metrics') {
    avanzarMetricas(estado.metricas);
    return json(200, estado.metricas);
  }

  // ---- aplicaciones
  if (ruta === '/admin/api/apps' && metodo === 'GET') return exigir('apps.ver') ?? json(200, { apps: estado.apps });
  if (ruta === '/admin/api/apps' && metodo === 'POST' && cuerpo.id === undefined) {
    const prohibido = exigir('apps.editar');
    if (prohibido) return prohibido;
    const nombre = String(cuerpo.nombre ?? '').trim();
    const hmac = cuerpo.user_ref_desde_cedula === 'hmac';
    if (nombre.length < 2 || nombre.length > 120 || (!hmac && cuerpo.cedula_prefijo)) return error(400, 'INVALID_REQUEST', 'Solicitud inválida.');
    const ahora = new Date().toISOString();
    const app = {
      id: crypto.randomUUID(), nombre, client_id: `app_${aleatorioHex(16)}`, algoritmo: 'SHA256', digitos: 6, periodo: 30, ventana: 1,
      max_intentos: 5, umbral_riesgo_bloqueo: 75, modo_heuristica: 'bloqueo', permitir_sha1: false, estado: 'activo',
      user_ref_desde_cedula: hmac ? 'hmac' : 'ninguno', cedula_prefijo: hmac ? (cuerpo.cedula_prefijo ?? '') : '', created_at: ahora, updated_at: ahora,
    };
    estado.apps.push(app);
    await registrarAuditoria(`admin:${sesion.usuario}`, 'app.registrada', app.id, { nombre, client_id: app.client_id, user_ref_desde_cedula: app.user_ref_desde_cedula });
    const respuesta = { app, client_id: app.client_id, client_secret: aleatorioB64(32) };
    if (hmac) respuesta.cedula_secreto = aleatorioB64(32);
    return json(201, respuesta, { 'Cache-Control': 'no-store' });
  }
  const mSecreto = ruta.match(/^\/admin\/api\/apps\/([^/]+)\/secret$/);
  if (mSecreto && metodo === 'POST') {
    const prohibido = exigir('apps.secreto');
    if (prohibido) return prohibido;
    const app = estado.apps.find((a) => a.id === decodeURIComponent(mSecreto[1]));
    if (!app) return error(404, 'NOT_FOUND', 'Recurso no encontrado.');
    app.updated_at = new Date().toISOString();
    await registrarAuditoria(`admin:${sesion.usuario}`, 'app.secreto_regenerado', app.id, { client_id: app.client_id });
    return json(200, { app, client_id: app.client_id, client_secret: aleatorioB64(32) }, { 'Cache-Control': 'no-store' });
  }
  if (ruta === '/admin/api/apps' && metodo === 'POST') {
    const prohibido = exigir('apps.editar');
    if (prohibido) return prohibido;
    const { id, ...politica } = cuerpo;
    const app = estado.apps.find((a) => a.id === id);
    if (!app) return error(404, 'NOT_FOUND', 'Recurso no encontrado.');
    if ((politica.algoritmo ?? app.algoritmo) === 'SHA1' && !(politica.permitir_sha1 ?? app.permitir_sha1)) return error(400, 'BAD_REQUEST', 'Solicitud no válida.');
    Object.assign(app, politica, { updated_at: new Date().toISOString() });
    await registrarAuditoria(`admin:${sesion.usuario}`, 'app.politica_actualizada', app.id, politica);
    return json(200, { app });
  }

  // ---- enrolamientos
  if (ruta === '/admin/api/enrollments' && metodo === 'GET') {
    const prohibido = exigir('enrolamientos.ver');
    if (prohibido) return prohibido;
    const filtroEstado = destino.searchParams.get('estado');
    const filtroApp = destino.searchParams.get('app_id');
    const cedula = destino.searchParams.get('cedula');
    const userRef = destino.searchParams.get('user_ref');
    if (cedula !== null || userRef !== null) {
      // Búsqueda de soporte: mismas reglas que el servidor (app_id obligatorio, criterios excluyentes).
      if ((cedula !== null && userRef !== null) || !filtroApp) return error(400, 'INVALID_REQUEST', 'Solicitud inválida.');
      const app = estado.apps.find((a) => a.id === filtroApp);
      if (!app) return error(404, 'NOT_FOUND', 'Recurso no encontrado.');
      const canonica = cedula !== null ? cedulaCanonica(cedula) : null;
      if (cedula !== null && !canonica) return error(400, 'INVALID_REQUEST', 'Solicitud inválida.');
      if (canonica && app.user_ref_desde_cedula !== 'hmac') return conflicto('La aplicación no declara cómo deriva el user_ref desde la cédula.');
      const lista = estado.enrolamientos.filter((e) => e.app_id === app.id && (!filtroEstado || e.estado === filtroEstado)
        && (canonica ? e.cedula_demo === canonica : e.user_ref_demo === userRef));
      await registrarAuditoria(`admin:${sesion.usuario}`, 'enrolamientos.busqueda', app.id, canonica
        ? { criterio: 'cedula', cedula_hmac: await huellaDemo(canonica), resultados: lista.length }
        : { criterio: 'user_ref', user_ref_hash: await huellaDemo(userRef), resultados: lista.length });
      return json(200, { enrollments: lista.map(sinDemo) });
    }
    const lista = estado.enrolamientos.filter((e) => (!filtroEstado || e.estado === filtroEstado) && (!filtroApp || e.app_id === filtroApp));
    return json(200, { enrollments: lista.map(sinDemo) });
  }
  const mEnr = ruta.match(/^\/admin\/api\/enrollments\/([^/]+)\/(suspend|reactivate|revoke)$/);
  if (mEnr && metodo === 'POST') {
    const [, id, accion] = mEnr;
    const prohibido = exigir(accion === 'revoke' ? 'enrolamientos.revocar' : 'enrolamientos.suspender');
    if (prohibido) return prohibido;
    const e = estado.enrolamientos.find((x) => x.id === decodeURIComponent(id));
    if (!e) return error(404, 'NOT_FOUND', 'Recurso no encontrado.');
    // Transiciones del servidor: activo ↔ suspendido; activo | suspendido → revocado (final).
    const desde = { suspend: ['activo'], reactivate: ['suspendido'], revoke: ['activo', 'suspendido'] }[accion];
    if (!desde.includes(e.estado)) return conflicto('La transición de estado no es válida.');
    if (accion === 'reactivate' && estado.enrolamientos.some((x) => x !== e && x.app_id === e.app_id && x.user_ref_hash === e.user_ref_hash && x.estado === 'activo')) {
      return conflicto('El usuario ya tiene otro enrolamiento activo en la aplicación.');
    }
    const previo = e.estado;
    e.estado = accion === 'suspend' ? 'suspendido' : accion === 'reactivate' ? 'activo' : 'revocado';
    if (accion === 'revoke') {
      e.revoked_at = new Date().toISOString();
      // Revocar el enrolamiento desvincula su dispositivo (issue #47), igual que en el servidor.
      if (e.device && !e.device.unlinked_at) e.device.unlinked_at = e.revoked_at;
    }
    await registrarAuditoria(`admin:${sesion.usuario}`, `enrolamiento.${accion === 'suspend' ? 'suspendido' : accion === 'reactivate' ? 'reactivado' : 'revocado'}`, e.id, { app_id: e.app_id, estado_previo: previo, motivo: 'consola' });
    return json(200, { enrollment: sinDemo(e) });
  }

  // ---- administradores (solo Administrador)
  if (ruta === '/admin/api/admins' && metodo === 'GET') return exigir('admins.ver') ?? json(200, { admins: estado.admins });
  if (ruta === '/admin/api/admins' && metodo === 'POST') {
    const prohibido = exigir('admins.editar');
    if (prohibido) return prohibido;
    const usuario = String(cuerpo.usuario ?? '');
    if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(usuario) || !['Administrador', 'Operador', 'Auditor'].includes(cuerpo.rol)) return error(400, 'INVALID_REQUEST', 'Solicitud inválida.');
    if (estado.admins.some((a) => a.usuario === usuario)) return conflicto('El usuario ya existe.');
    const admin = { id: crypto.randomUUID(), usuario, rol: cuerpo.rol, activo: true, created_at: new Date().toISOString(), totp_estado: 'activo' };
    estado.admins.push(admin);
    await registrarAuditoria(`admin:${sesion.usuario}`, 'admin.creado', admin.id, { usuario, rol: admin.rol });
    // Demostración: URI y QR ficticios pregenerados (mocks/consola-administradores.json); la contraseña sí es aleatoria.
    const uri = estado.demoAlta.otpauth_uri.replace('operadora.demo', encodeURIComponent(usuario));
    return json(201, { admin, password: aleatorioB64(18), otpauth_uri: uri, qr_svg: estado.demoAlta.qr_svg }, { 'Cache-Control': 'no-store' });
  }
  const mAdm = ruta.match(/^\/admin\/api\/admins\/([^/]+)\/disable$/);
  if (mAdm && metodo === 'POST') {
    const prohibido = exigir('admins.editar');
    if (prohibido) return prohibido;
    const a = estado.admins.find((x) => x.id === decodeURIComponent(mAdm[1]));
    if (!a) return error(404, 'NOT_FOUND', 'Recurso no encontrado.');
    if (a.usuario === sesion.usuario) return conflicto('No puede deshabilitar su propia cuenta.');
    if (!a.activo) return conflicto('La cuenta ya está deshabilitada.');
    if (a.rol === 'Administrador' && estado.admins.filter((x) => x.activo && x.rol === 'Administrador').length <= 1) {
      return conflicto('No se puede deshabilitar al último Administrador activo.');
    }
    a.activo = false;
    await registrarAuditoria(`admin:${sesion.usuario}`, 'admin.deshabilitado', a.id, { usuario: a.usuario, rol: a.rol });
    return json(200, { admin: a });
  }

  // ---- detector de anomalías
  if (ruta === '/admin/api/anomalies') {
    const prohibido = exigir('anomalias.ver');
    return prohibido ?? json(200, estado.anomalias);
  }

  // ---- llaves
  if (ruta === '/admin/api/keys' && metodo === 'GET') return exigir('llaves.ver') ?? json(200, estado.llaves);
  if (ruta === '/admin/api/keys/rotate' && metodo === 'POST') {
    const prohibido = exigir('llaves.rotar');
    if (prohibido) return prohibido;
    const ahora = new Date();
    const previo = estado.llaves.active_kid;
    const d = ahora.toISOString().slice(0, 10).replace(/-/g, '');
    const n = estado.llaves.keys.filter((k) => k.kid.startsWith(`key-${d}`)).length + 1;
    const nuevo = `key-${d}-${String(n).padStart(2, '0')}`;
    for (const k of estado.llaves.keys) if (k.estado === 'activa') { k.estado = 'solo_verificacion'; k.rotated_at = ahora.toISOString(); }
    estado.llaves.keys.unshift({ kid: nuevo, estado: 'activa', alg: 'EdDSA', crv: 'Ed25519', created_at: ahora.toISOString(), rotated_at: null });
    estado.llaves.active_kid = nuevo;
    estado.salud.activeKeyId = nuevo;
    await registrarAuditoria(`admin:${sesion.usuario}`, 'llaves.rotadas', nuevo, { previous_kid: previo });
    return json(200, { new_kid: nuevo, previous_kid: previo, rotated_at: ahora.toISOString() });
  }

  // ---- auditoría
  if (ruta === '/admin/api/audit/verify-chain') {
    const prohibido = exigir('auditoria.verificar');
    if (prohibido) return prohibido;
    return json(200, await verificarCadenaCompleta());
  }
  if (ruta === '/admin/api/audit') {
    const prohibido = exigir('auditoria.ver');
    if (prohibido) return prohibido;
    const desde = Number(destino.searchParams.get('desde') ?? 0);
    const limite = Math.min(500, Number(destino.searchParams.get('limite') ?? 25));
    const filas = estado.eventos.filter((e) => e.id > desde).slice(0, limite);
    return json(200, { eventos: filas, siguiente: filas.length === limite ? filas[filas.length - 1].id : null });
  }

  return error(404, 'NOT_FOUND', 'Recurso no encontrado.');
}
