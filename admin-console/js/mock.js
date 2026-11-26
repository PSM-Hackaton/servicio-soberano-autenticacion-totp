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
  const [apps, enrol, anomalias, llaves, auditoria, metricas, salud, tablero, jwks, cadena, bloqueo] = await Promise.all([
    cargar('consola-apps.json'), cargar('consola-enrolamientos.json'), cargar('consola-anomalias.json'),
    cargar('consola-llaves.json'), cargar('consola-auditoria.json'), cargar('consola-metricas.json'),
    cargar('consola-salud.json'), cargar('admin-dashboard.json'), cargar('jwks.json'), cargar('audit-chain.json'),
    cargar('verify-anomaly-blocked.json'),
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
  estado = { apps: apps.apps, enrolamientos: enrol.enrollments, anomalias, llaves, eventos, metricas, salud, tablero, jwks, cadena, tick: 0 };
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

/** Avanza las métricas simuladas para que el refresco periódico muestre actividad. */
function avanzarMetricas(m) {
  estado.tick++;
  const ultimo = m.serie[m.serie.length - 1];
  const ok = 16 + Math.round(Math.random() * 14);
  const fallido = 1 + Math.round(Math.random() * 3);
  const bloqueado = Math.random() < 0.3 ? 1 : 0;
  m.serie.push({ ts: new Date(Date.parse(ultimo.ts) + 75000).toISOString(), ok, fallido, bloqueado, p95Ms: Math.round((18 + Math.random() * 12) * 10) / 10, p50Ms: Math.round((6 + Math.random() * 4) * 10) / 10 });
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
  await espera(120 + Math.random() * 160);
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
    const lista = estado.enrolamientos.filter((e) => (!filtroEstado || e.estado === filtroEstado) && (!filtroApp || e.app_id === filtroApp));
    return json(200, { enrollments: lista, total: lista.length });
  }
  const mEnr = ruta.match(/^\/admin\/api\/enrollments\/([^/]+)\/(suspend|reactivate|revoke)$/);
  if (mEnr && metodo === 'POST') {
    const [, id, accion] = mEnr;
    const prohibido = exigir(accion === 'revoke' ? 'enrolamientos.revocar' : 'enrolamientos.suspender');
    if (prohibido) return prohibido;
    const e = estado.enrolamientos.find((x) => x.id === decodeURIComponent(id));
    if (!e) return error(404, 'NOT_FOUND', 'Recurso no encontrado.');
    if (e.estado === 'revocado') return error(409, 'CONFLICT', 'El enrolamiento ya está revocado.');
    e.estado = accion === 'suspend' ? 'suspendido' : accion === 'reactivate' ? 'activo' : 'revocado';
    if (accion === 'revoke') e.revoked_at = new Date().toISOString();
    await registrarAuditoria(sesion.usuario, `enrolamiento.${accion === 'suspend' ? 'suspender' : accion === 'reactivate' ? 'reactivar' : 'revocar'}`, e.id, { estado: e.estado });
    return json(200, e);
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
