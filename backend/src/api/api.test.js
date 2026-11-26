// Pruebas del servidor HTTP propio con casos de uso FALSOS (no dependen de application/use-cases).

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { crearServidor, NOMBRE_COOKIE_SESION } from './servidor.js';
import { crearRouter } from './router.js';
import { crearLimitador } from '../security/index.js';
import { crearMetricas } from '../audit/index.js';

// ---------------------------------------------------------------- dobles

const APP = { id: 'app-1', nombre: 'Portal', client_id: 'app_portal', estado: 'activo' };
const SECRETO = 'secreto-correcto';
const ADMINS = {
  jefa: { id: 'a1', usuario: 'jefa', rol: 'Administrador', password_hash: 'NO-DEBE-SALIR' },
  mirón: { id: 'a2', usuario: 'auditor1', rol: 'Auditor', password_hash: 'x' },
};
const PERMISOS = {
  Administrador: new Set(['apps.leer', 'apps.escribir', 'enrolamientos.leer', 'llaves.rotar', 'auditoria.leer', 'auditoria.verificar', 'anomalias.leer', 'metricas.leer']),
  Auditor: new Set(['auditoria.leer', 'auditoria.verificar', 'anomalias.leer', 'metricas.leer']),
};
const puede = (rol, accion) => PERMISOS[rol]?.has(accion) ?? false;

function casosFalsos() {
  /** @type {{ nombre: string, entrada: any, ctx: any }[]} */
  const llamadas = [];
  const registrar = (nombre, respuesta) => async (entrada, ctx) => {
    llamadas.push({ nombre, entrada, ctx });
    return typeof respuesta === 'function' ? respuesta(entrada, ctx) : respuesta;
  };
  const casos = {
    llamadas,
    enrolar: registrar('enrolar', { status: 201, cuerpo: { enrollment_id: 'e1', estado: 'pendiente' } }),
    activar: registrar('activar', (e) => ({ status: 200, cuerpo: { enrollment_id: e.id, estado: 'activo' } })),
    verificar: registrar('verificar', () => { throw new Error('base caída'); }),
    validarToken: registrar('validarToken', { status: 200, cuerpo: { valid: false, reason: 'formato' } }),
    resincronizar: registrar('resincronizar', { status: 200, cuerpo: { resynced: true, drift_steps: 0 } }),
    recuperar: registrar('recuperar', { status: 200, cuerpo: { recovered: true } }),
    revocar: registrar('revocar', (e) => ({ status: 200, cuerpo: { enrollment_id: e.id, estado: 'revocado' } })),
    jwks: async () => ({ status: 200, cuerpo: { keys: [{ kty: 'OKP', crv: 'Ed25519', kid: 'k1', use: 'sig', alg: 'EdDSA', x: 'abc' }] } }),
    autenticarApp: async (id, secreto) => (id === APP.client_id && secreto === SECRETO ? APP : null),
    adminLogin: registrar('adminLogin', ({ usuario, password, totp_code: codigo }) => {
      const a = Object.values(ADMINS).find((x) => x.usuario === usuario);
      if (!a || password !== 'clave' || codigo !== '123456') return { status: 401, cuerpo: { error: 'UNAUTHORIZED', message: 'Credenciales inválidas.' } };
      return { status: 200, cuerpo: { usuario: a.usuario, rol: a.rol }, admin: a };
    }),
    adminListarApps: registrar('adminListarApps', { status: 200, cuerpo: { apps: [] } }),
    adminActualizarApp: registrar('adminActualizarApp', { status: 201, cuerpo: { ok: true } }),
    adminListarEnrolamientos: registrar('adminListarEnrolamientos', { status: 200, cuerpo: { enrollments: [] } }),
    adminRotarLlaves: registrar('adminRotarLlaves', { status: 200, cuerpo: { new_kid: 'k2', previous_kid: 'k1', rotated_at: 'x' } }),
    adminAuditoria: registrar('adminAuditoria', { status: 200, cuerpo: { eventos: [] } }),
    adminVerificarCadena: registrar('adminVerificarCadena', { status: 200, cuerpo: { intact: true, checked_records: 0, last_hash: null } }),
    adminAnomalias: registrar('adminAnomalias', { status: 200, cuerpo: { alertas: [] } }),
    adminMetricas: registrar('adminMetricas', { status: 200, cuerpo: {} }),
  };
  return casos;
}

// ---------------------------------------------------------------- utilidades

/** @returns {Promise<{ status: number, cabeceras: import('node:http').IncomingHttpHeaders, texto: string, json: any }>} */
function pedir(puerto, { metodo = 'GET', ruta = '/', cabeceras = {}, cuerpo, localAddress } = {}) {
  return new Promise((resolver, rechazar) => {
    const datos = cuerpo === undefined ? undefined : typeof cuerpo === 'string' || Buffer.isBuffer(cuerpo) ? cuerpo : JSON.stringify(cuerpo);
    const h = { ...cabeceras };
    if (datos !== undefined && !('content-type' in h)) h['content-type'] = 'application/json';
    if (datos !== undefined && !('content-length' in h) && !h['transfer-encoding']) h['content-length'] = Buffer.byteLength(datos);
    const req = request({ host: '127.0.0.1', port: puerto, method: metodo, path: ruta, headers: h, localAddress }, (res) => {
      const trozos = [];
      res.on('data', (t) => trozos.push(t));
      res.on('end', () => {
        const texto = Buffer.concat(trozos).toString('utf8');
        let json = null;
        try { json = JSON.parse(texto); } catch { /* no es JSON */ }
        resolver({ status: res.statusCode, cabeceras: res.headers, texto, json });
      });
    });
    req.on('error', rechazar);
    if (datos !== undefined) req.write(datos);
    req.end();
  });
}

const credenciales = { 'x-client-id': APP.client_id, 'x-client-secret': SECRETO };

function levantar(opciones = {}) {
  const casos = opciones.casos ?? casosFalsos();
  const metricas = crearMetricas();
  const errores = [];
  const servidor = crearServidor({
    casos,
    metricas,
    puede,
    cors: { origenes: ['https://localhost:5173'] },
    salud: opciones.salud ?? (() => true),
    info: () => ({ dbDriver: 'sqlite', activeKeyId: 'k1', heuristicsMode: 'local' }),
    registro: { info() {}, warn() {}, error: (m) => errores.push(m) },
    limitadores: opciones.limitadores,
    estaticos: opciones.estaticos ?? [],
    certificadoCa: opciones.certificadoCa ?? null,
  });
  return new Promise((resolver) => {
    servidor.listen(0, '127.0.0.1', () => resolver({ servidor, puerto: servidor.address().port, casos, metricas, errores }));
  });
}

// ---------------------------------------------------------------- enrutador

describe('router', () => {
  test('parámetros, 404 y 405', () => {
    const r = crearRouter();
    const h = () => {};
    r.agregar('POST', '/api/v1/enrollments/:id/activate', h).agregar('DELETE', '/api/v1/enrollments/:id', h);
    r.agregar('GET', '/a/fijo', h).agregar('GET', '/a/:x', h);
    const ok = r.resolver('POST', '/api/v1/enrollments/abc-123/activate');
    assert.equal(ok.tipo, 'ok');
    assert.equal(ok.params.id, 'abc-123');
    assert.equal(r.resolver('GET', '/a/fijo').ruta.plantilla, '/a/fijo');
    assert.equal(r.resolver('GET', '/a/otro').params.x, 'otro');
    assert.equal(r.resolver('GET', '/nada').tipo, 'no_encontrada');
    const m = r.resolver('GET', '/api/v1/enrollments/abc');
    assert.equal(m.tipo, 'metodo_no_permitido');
    assert.deepEqual(m.permitidos, ['DELETE']);
    assert.equal(r.resolver('DELETE', '/api/v1/enrollments/a%2Fb').tipo, 'no_encontrada');
    assert.throws(() => r.agregar('GET', '/a/fijo', h), /duplicada/);
  });
});

// ---------------------------------------------------------------- servidor

describe('servidor HTTP', () => {
  /** @type {Awaited<ReturnType<typeof levantar>>} */
  let s;
  let dirEstaticos;
  before(async () => {
    dirEstaticos = mkdtempSync(join(tmpdir(), 'estaticos-'));
    mkdirSync(join(dirEstaticos, 'app'));
    writeFileSync(join(dirEstaticos, 'app', 'index.html'), '<!doctype html><title>PWA</title>');
    writeFileSync(join(dirEstaticos, 'app', 'sw.js'), 'self.addEventListener("fetch",()=>{});');
    writeFileSync(join(dirEstaticos, 'app', '.oculto'), 'no');
    writeFileSync(join(dirEstaticos, 'secreto.txt'), 'NO-DEBE-SERVIRSE');
    s = await levantar({
      estaticos: [
        { prefijo: '/app', carpeta: join(dirEstaticos, 'app') },
        { prefijo: '/consola', carpeta: join(dirEstaticos, 'no-existe') },
      ],
    });
  });
  after(() => {
    s.servidor.close();
    s.servidor.closeAllConnections();
    rmSync(dirEstaticos, { recursive: true, force: true });
  });

  test('cabeceras de seguridad en todas las respuestas (incluido 404)', async () => {
    for (const ruta of ['/health', '/no-existe']) {
      const r = await pedir(s.puerto, { ruta });
      assert.equal(r.cabeceras['x-content-type-options'], 'nosniff');
      assert.equal(r.cabeceras['x-frame-options'], 'DENY');
      assert.match(r.cabeceras['strict-transport-security'], /max-age=/);
      assert.match(r.cabeceras['content-security-policy'], /frame-ancestors 'none'/);
      assert.equal(r.cabeceras['cache-control'], 'no-store');
    }
  });

  test('GET /health según contrato', async () => {
    const r = await pedir(s.puerto, { ruta: '/health' });
    assert.equal(r.status, 200);
    assert.equal(r.json.status, 'ok');
    assert.equal(r.json.dbDriver, 'sqlite');
    assert.equal(r.json.activeKeyId, 'k1');
    assert.equal(r.json.heuristicsMode, 'local');
    assert.ok(r.json.timestamp);
  });

  test('GET /health/ready 200 y /.well-known/jwks.json', async () => {
    assert.equal((await pedir(s.puerto, { ruta: '/health/ready' })).status, 200);
    const j = await pedir(s.puerto, { ruta: '/.well-known/jwks.json' });
    assert.equal(j.status, 200);
    assert.equal(j.json.keys[0].kid, 'k1');
  });

  test('404 y 405 genéricos', async () => {
    const r404 = await pedir(s.puerto, { ruta: '/api/v1/desconocida' });
    assert.equal(r404.status, 404);
    assert.deepEqual(Object.keys(r404.json).sort(), ['error', 'message']);
    const r405 = await pedir(s.puerto, { metodo: 'GET', ruta: '/api/v1/verify' });
    assert.equal(r405.status, 405);
    assert.equal(r405.cabeceras.allow, 'POST');
    assert.equal(r405.json.error, 'METHOD_NOT_ALLOWED');
  });

  test('sin credenciales o con secreto incorrecto → 401 genérico', async () => {
    const sin = await pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: { user_ref: 'u1' } });
    assert.equal(sin.status, 401);
    const mal = await pedir(s.puerto, {
      metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: { user_ref: 'u1' },
      cabeceras: { 'x-client-id': APP.client_id, 'x-client-secret': 'otro' },
    });
    assert.equal(mal.status, 401);
    assert.deepEqual(sin.json, mal.json);
  });

  test('rutas v1 se mapean a sus casos de uso con ctx (app, ip, idempotencyKey)', async () => {
    const e = await pedir(s.puerto, {
      metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: { user_ref: 'u1' },
      cabeceras: { ...credenciales, 'idempotency-key': 'clave-idem-0001' },
    });
    assert.equal(e.status, 201);
    const llamada = s.casos.llamadas.findLast((l) => l.nombre === 'enrolar');
    assert.deepEqual(llamada.entrada, { user_ref: 'u1' });
    assert.equal(llamada.ctx.app.id, APP.id);
    assert.equal(llamada.ctx.ip, '127.0.0.1');
    assert.equal(llamada.ctx.idempotencyKey, 'clave-idem-0001');

    const a = await pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/enrollments/e-42/activate', cuerpo: { code: '123456' }, cabeceras: credenciales });
    assert.equal(a.status, 200);
    assert.equal(a.json.enrollment_id, 'e-42');
    assert.deepEqual(s.casos.llamadas.findLast((l) => l.nombre === 'activar').entrada, { id: 'e-42', cuerpo: { code: '123456' } });

    const d = await pedir(s.puerto, { metodo: 'DELETE', ruta: '/api/v1/enrollments/e-42', cabeceras: credenciales });
    assert.equal(d.status, 200);
    assert.equal(d.json.estado, 'revocado');

    for (const ruta of ['/api/v1/tokens/validate', '/api/v1/recovery', '/api/v1/enrollments/e-1/resync']) {
      assert.equal((await pedir(s.puerto, { metodo: 'POST', ruta, cuerpo: {}, cabeceras: credenciales })).status, 200, ruta);
    }
  });

  test('Idempotency-Key con formato inválido → 400', async () => {
    const r = await pedir(s.puerto, {
      metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: { user_ref: 'u1' }, cabeceras: { ...credenciales, 'idempotency-key': 'x' },
    });
    assert.equal(r.status, 400);
  });

  test('JSON inválido → 400; arreglo → 400; tipo de contenido distinto → 415', async () => {
    const r = await pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: '{"user_ref":', cabeceras: credenciales });
    assert.equal(r.status, 400);
    assert.equal(r.json.error, 'INVALID_REQUEST');
    assert.equal((await pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: '[1]', cabeceras: credenciales })).status, 400);
    const t = await pedir(s.puerto, {
      metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: 'user_ref=u1', cabeceras: { ...credenciales, 'content-type': 'text/plain' },
    });
    assert.equal(t.status, 415);
  });

  test('cuerpo mayor de 16 KB → 413 (con y sin Content-Length)', async () => {
    const grande = JSON.stringify({ user_ref: 'x'.repeat(20 * 1024) });
    const r = await pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: grande, cabeceras: credenciales });
    assert.equal(r.status, 413);
    const c = await pedir(s.puerto, {
      metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: grande, cabeceras: { ...credenciales, 'transfer-encoding': 'chunked' },
    });
    assert.equal(c.status, 413);
  });

  test('excepción en caso de uso → 503 genérico, sin detalles', async () => {
    const r = await pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/verify', cuerpo: { user_ref: 'u1', code: '123456' }, cabeceras: credenciales });
    assert.equal(r.status, 503);
    assert.equal(r.json.error, 'SERVICE_UNAVAILABLE');
    assert.doesNotMatch(r.texto, /base caída/);
    assert.ok(s.errores.some((m) => m.includes('/api/v1/verify')));
  });

  test('métricas registran la plantilla de ruta, no la ruta concreta', async () => {
    await pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/enrollments/e-99/activate', cuerpo: { code: '1' }, cabeceras: credenciales });
    const rutas = Object.keys(s.metricas.instantanea().latenciaPorRuta);
    assert.ok(rutas.some((r) => r.includes(':id')), rutas.join(','));
    assert.ok(!rutas.some((r) => r.includes('e-99')));
  });

  test('GET /metrics desde localhost', async () => {
    const r = await pedir(s.puerto, { ruta: '/metrics' });
    assert.equal(r.status, 200);
    assert.match(r.cabeceras['content-type'], /text\/plain/);
    assert.match(r.texto, /totp_http_requests_total/);
  });

  test('GET /metrics es solo loopback: otra IP recibe 403 aunque traiga sesión de admin', async () => {
    const login = await pedir(s.puerto, { metodo: 'POST', ruta: '/admin/api/login', cuerpo: { usuario: 'jefa', password: 'clave', totp_code: '123456' } });
    const cookie = login.cabeceras['set-cookie'][0].split(';')[0];
    // 127.0.0.2 es otra dirección de origen: el servidor solo acepta 127.0.0.1 y ::1.
    const ajena = await pedir(s.puerto, { ruta: '/metrics', localAddress: '127.0.0.2', cabeceras: { cookie } });
    assert.equal(ajena.status, 403);
    assert.doesNotMatch(ajena.texto, /totp_http_requests_total/);
    const consola = await pedir(s.puerto, { ruta: '/admin/api/metrics', localAddress: '127.0.0.2', cabeceras: { cookie } });
    assert.equal(consola.status, 200);
  });

  test('login admin: solo `totp_code`; el alias `codigo` se rechaza (esquema cerrado)', async () => {
    const antes = s.casos.llamadas.filter((l) => l.nombre === 'adminLogin').length;
    const r = await pedir(s.puerto, { metodo: 'POST', ruta: '/admin/api/login', cuerpo: { usuario: 'jefa', password: 'clave', codigo: '123456' } });
    assert.equal(r.status, 400);
    assert.equal(r.json.error, 'INVALID_REQUEST');
    assert.equal(s.casos.llamadas.filter((l) => l.nombre === 'adminLogin').length, antes, 'no llega al caso de uso');
  });

  test('CORS: origen permitido, preflight y origen rechazado', async () => {
    const ok = await pedir(s.puerto, { ruta: '/health', cabeceras: { origin: 'https://localhost:5173' } });
    assert.equal(ok.cabeceras['access-control-allow-origin'], 'https://localhost:5173');
    assert.equal(ok.cabeceras.vary, 'Origin');

    const pre = await pedir(s.puerto, {
      metodo: 'OPTIONS', ruta: '/api/v1/verify',
      cabeceras: { origin: 'https://localhost:5173', 'access-control-request-method': 'POST' },
    });
    assert.equal(pre.status, 204);
    assert.match(pre.cabeceras['access-control-allow-headers'], /X-Client-Id/);

    const malo = await pedir(s.puerto, { ruta: '/health', cabeceras: { origin: 'https://atacante.example' } });
    assert.equal(malo.status, 403);
    assert.equal(malo.cabeceras['access-control-allow-origin'], undefined);
    const preMalo = await pedir(s.puerto, {
      metodo: 'OPTIONS', ruta: '/api/v1/verify', cabeceras: { origin: 'https://atacante.example', 'access-control-request-method': 'POST' },
    });
    assert.equal(preMalo.status, 403);
  });

  test('consola admin: login, cookie, sesión, CSRF obligatorio, RBAC y logout', async () => {
    const malo = await pedir(s.puerto, { metodo: 'POST', ruta: '/admin/api/login', cuerpo: { usuario: 'jefa', password: 'mal', totp_code: '123456' } });
    assert.equal(malo.status, 401);
    assert.equal(malo.cabeceras['set-cookie'], undefined);
    assert.equal((await pedir(s.puerto, { metodo: 'POST', ruta: '/admin/api/login', cuerpo: { usuario: 'jefa', extra: 1 } })).status, 400);

    const login = await pedir(s.puerto, { metodo: 'POST', ruta: '/admin/api/login', cuerpo: { usuario: 'jefa', password: 'clave', totp_code: '123456' } });
    assert.equal(login.status, 200);
    assert.equal(login.json.usuario, 'jefa');
    assert.equal(login.json.rol, 'Administrador');
    assert.ok(login.json.csrf_token.length >= 32);
    assert.doesNotMatch(login.texto, /NO-DEBE-SALIR/);
    const setCookie = login.cabeceras['set-cookie'][0];
    for (const atributo of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/admin']) assert.ok(setCookie.includes(atributo), atributo);
    const cookie = setCookie.split(';')[0];
    assert.ok(cookie.startsWith(`${NOMBRE_COOKIE_SESION}=`));
    const entradaLogin = s.casos.llamadas.findLast((l) => l.nombre === 'adminLogin').entrada;
    assert.deepEqual(entradaLogin, { usuario: 'jefa', password: 'clave', totp_code: '123456' });

    const sesion = await pedir(s.puerto, { ruta: '/admin/api/session', cabeceras: { cookie } });
    assert.equal(sesion.status, 200);
    assert.equal(sesion.json.csrf_token, login.json.csrf_token);
    assert.equal((await pedir(s.puerto, { ruta: '/admin/api/session' })).status, 401);

    const listado = await pedir(s.puerto, { ruta: '/admin/api/apps', cabeceras: { cookie } });
    assert.equal(listado.status, 200);
    const ctxAdmin = s.casos.llamadas.findLast((l) => l.nombre === 'adminListarApps').ctx.admin;
    assert.equal(ctxAdmin.usuario, 'jefa');
    assert.equal(ctxAdmin.password_hash, undefined);

    const sinCsrf = await pedir(s.puerto, { metodo: 'POST', ruta: '/admin/api/keys/rotate', cuerpo: {}, cabeceras: { cookie } });
    assert.equal(sinCsrf.status, 403);
    const csrfMalo = await pedir(s.puerto, { metodo: 'POST', ruta: '/admin/api/keys/rotate', cuerpo: {}, cabeceras: { cookie, 'x-csrf-token': 'x' } });
    assert.equal(csrfMalo.status, 403);
    const conCsrf = await pedir(s.puerto, {
      metodo: 'POST', ruta: '/admin/api/keys/rotate', cuerpo: {}, cabeceras: { cookie, 'x-csrf-token': login.json.csrf_token },
    });
    assert.equal(conCsrf.status, 200);
    assert.equal(conCsrf.json.new_kid, 'k2');

    const salir = await pedir(s.puerto, { metodo: 'POST', ruta: '/admin/api/logout', cabeceras: { cookie, 'x-csrf-token': login.json.csrf_token } });
    assert.equal(salir.status, 200);
    assert.match(salir.cabeceras['set-cookie'][0], /Max-Age=0/);
    assert.equal((await pedir(s.puerto, { ruta: '/admin/api/apps', cabeceras: { cookie } })).status, 401);
  });

  test('RBAC: un Auditor no puede rotar llaves ni ver apps (403)', async () => {
    const login = await pedir(s.puerto, { metodo: 'POST', ruta: '/admin/api/login', cuerpo: { usuario: 'auditor1', password: 'clave', totp_code: '123456' } });
    assert.equal(login.status, 200);
    const cookie = login.cabeceras['set-cookie'][0].split(';')[0];
    const csrf = login.json.csrf_token;
    assert.equal((await pedir(s.puerto, { ruta: '/admin/api/apps', cabeceras: { cookie } })).status, 403);
    assert.equal((await pedir(s.puerto, { metodo: 'POST', ruta: '/admin/api/keys/rotate', cuerpo: {}, cabeceras: { cookie, 'x-csrf-token': csrf } })).status, 403);
    assert.equal((await pedir(s.puerto, { ruta: '/admin/api/audit/verify-chain', cabeceras: { cookie } })).status, 200);
    assert.equal((await pedir(s.puerto, { ruta: '/admin/api/anomalies', cabeceras: { cookie } })).status, 200);
  });

  test('estáticos: índice por defecto, MIME, no-cache, CSP propia y redirecciones', async () => {
    const raiz = await pedir(s.puerto, { ruta: '/' });
    assert.equal(raiz.status, 302);
    assert.equal(raiz.cabeceras.location, '/app/');
    const sinBarra = await pedir(s.puerto, { ruta: '/app' });
    assert.equal(sinBarra.status, 301);
    const indice = await pedir(s.puerto, { ruta: '/app/' });
    assert.equal(indice.status, 200);
    assert.match(indice.cabeceras['content-type'], /text\/html/);
    assert.equal(indice.cabeceras['cache-control'], 'no-cache');
    assert.match(indice.cabeceras['content-security-policy'], /worker-src 'self'/);
    assert.match(indice.cabeceras['content-security-policy'], /img-src 'self' data:/);
    const sw = await pedir(s.puerto, { ruta: '/app/sw.js' });
    assert.equal(sw.status, 200);
    assert.match(sw.cabeceras['content-type'], /javascript/);
    assert.equal((await pedir(s.puerto, { ruta: '/app/.oculto' })).status, 404);
    assert.equal((await pedir(s.puerto, { ruta: '/consola/' })).status, 404); // carpeta inexistente
    assert.equal((await pedir(s.puerto, { metodo: 'POST', ruta: '/app/index.html', cuerpo: {} })).status, 405);
  });

  test('Permissions-Policy: cámara solo para la PWA en /app/; API y consola con camera=()', async () => {
    const restricciones = ['microphone=()', 'geolocation=()', 'payment=()', 'usb=()', 'interest-cohort=()'];
    for (const ruta of ['/app/', '/app/sw.js']) {
      const r = await pedir(s.puerto, { ruta });
      assert.equal(r.status, 200, ruta);
      const pp = r.cabeceras['permissions-policy'];
      assert.match(pp, /(^|, )camera=\(self\)/, ruta);
      for (const x of restricciones) assert.ok(pp.includes(x), `${ruta}: ${x}`);
    }
    for (const ruta of ['/health', '/admin/api/session', '/api/v1/verify', '/consola/', '/no-existe']) {
      const pp = (await pedir(s.puerto, { ruta })).cabeceras['permissions-policy'];
      assert.match(pp, /(^|, )camera=\(\)/, ruta);
      assert.doesNotMatch(pp, /camera=\(self\)/, ruta);
      for (const x of restricciones) assert.ok(pp.includes(x), `${ruta}: ${x}`);
    }
  });

  test('estáticos: recorrido de rutas bloqueado', async () => {
    for (const ruta of [
      '/app/../secreto.txt', '/app/%2e%2e/secreto.txt', '/app/..%2fsecreto.txt', '/app/..%5csecreto.txt',
      '/app/%2e%2e%2f%2e%2e%2fsecreto.txt', '/app/index.html%00.js', '/app//../secreto.txt',
    ]) {
      const r = await pedir(s.puerto, { ruta });
      assert.notEqual(r.status, 200, ruta);
      assert.doesNotMatch(r.texto, /NO-DEBE-SERVIRSE/, ruta);
    }
  });
});

describe('servidor HTTP: salud caída y límites de tasa', () => {
  test('/health/ready → 503 y registra error de base de datos cuando salud() falla', async () => {
    const s = await levantar({ salud: () => { throw new Error('SQLITE_BUSY'); } });
    try {
      const r = await pedir(s.puerto, { ruta: '/health/ready' });
      assert.equal(r.status, 503);
      assert.equal(r.json.error, 'SERVICE_UNAVAILABLE');
      assert.equal(s.metricas.instantanea().totales.erroresBaseDatos, 1);
    } finally {
      s.servidor.close();
      s.servidor.closeAllConnections();
    }
  });

  test('límite global por IP → 429 con Retry-After antes de autenticar', async () => {
    let autenticaciones = 0;
    const casos = casosFalsos();
    const original = casos.autenticarApp;
    casos.autenticarApp = async (...a) => { autenticaciones++; return original(...a); };
    const s = await levantar({ casos, limitadores: { global: crearLimitador({ capacidad: 3, ventanaMs: 60_000 }) } });
    try {
      for (let i = 0; i < 3; i++) await pedir(s.puerto, { ruta: '/health' });
      const r = await pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/verify', cuerpo: {}, cabeceras: credenciales });
      assert.equal(r.status, 429);
      assert.ok(Number(r.cabeceras['retry-after']) >= 1);
      assert.equal(r.json.error, 'TOO_MANY_REQUESTS');
      assert.equal(autenticaciones, 0);
    } finally {
      s.servidor.close();
      s.servidor.closeAllConnections();
    }
  });

  test('/health/ready: volver a estar bien tras un fallo cuenta una reconexión', async () => {
    let caida = true;
    const s = await levantar({ salud: () => { if (caida) throw new Error('SQLITE_BUSY'); return true; } });
    try {
      assert.equal((await pedir(s.puerto, { ruta: '/health/ready' })).status, 503);
      caida = false;
      assert.equal((await pedir(s.puerto, { ruta: '/health/ready' })).status, 200);
      assert.equal((await pedir(s.puerto, { ruta: '/health/ready' })).status, 200);
      const m = s.metricas.instantanea();
      assert.equal(m.totales.reconexiones, 1);
      assert.match(s.metricas.formatoTexto(), /totp_db_reconnections_total 1/);
    } finally {
      s.servidor.close();
      s.servidor.closeAllConnections();
    }
  });

  test('429 del limitador en verify cuenta como rate_limited', async () => {
    const casos = casosFalsos();
    casos.verificar = async () => ({ status: 401, cuerpo: { error: 'UNAUTHORIZED', message: 'x' } });
    const s = await levantar({ casos, limitadores: { porApp: crearLimitador({ capacidad: 1, ventanaMs: 60_000 }) } });
    try {
      const verificar = () => pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/verify', cuerpo: { user_ref: 'u1', code: '123456' }, cabeceras: credenciales });
      assert.equal((await verificar()).status, 401);
      assert.equal((await verificar()).status, 429);
      assert.equal((await pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: { user_ref: 'u1' }, cabeceras: credenciales })).status, 429);
      const m = s.metricas.instantanea();
      assert.equal(m.resultadosVerificacion.rate_limited, 1, 'solo el 429 de verify es un resultado de verificación');
      assert.equal(m.totales.limitadas, 2, 'todos los 429 por límite se cuentan');
    } finally {
      s.servidor.close();
      s.servidor.closeAllConnections();
    }
  });

  test('límite por app → 429', async () => {
    const s = await levantar({ limitadores: { porApp: crearLimitador({ capacidad: 2, ventanaMs: 60_000 }) } });
    try {
      const pedirEnrol = () => pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: { user_ref: 'u' }, cabeceras: credenciales });
      assert.equal((await pedirEnrol()).status, 201);
      assert.equal((await pedirEnrol()).status, 201);
      const r = await pedirEnrol();
      assert.equal(r.status, 429);
      assert.ok(r.cabeceras['retry-after']);
    } finally {
      s.servidor.close();
      s.servidor.closeAllConnections();
    }
  });

  test('límite por (app, origen): client_ip distintos detrás de la misma IP TCP no se frenan entre sí', async () => {
    const casos = casosFalsos();
    casos.verificar = async () => ({ status: 401, cuerpo: { error: 'VERIFICATION_FAILED', message: 'x' } });
    const s = await levantar({ casos, limitadores: { porOrigen: crearLimitador({ capacidad: 3, ventanaMs: 60_000 }) } });
    try {
      const verificar = (clientIp) => pedir(s.puerto, {
        metodo: 'POST', ruta: '/api/v1/verify', cabeceras: credenciales,
        cuerpo: { user_ref: 'u1', code: '123456', ...(clientIp ? { client_ip: clientIp } : {}) },
      });
      // Un mismo ciudadano (client_ip) agota su cupo…
      for (let i = 0; i < 3; i++) assert.equal((await verificar('203.0.113.7')).status, 401);
      const r = await verificar('203.0.113.7');
      assert.equal(r.status, 429);
      assert.equal(r.json.error, 'TOO_MANY_REQUESTS');
      assert.ok(Number(r.cabeceras['retry-after']) >= 1);
      // …sin afectar a otros ciudadanos del mismo portal (misma IP TCP) ni a la forma canónica de otra IP.
      for (let i = 0; i < 3; i++) assert.equal((await verificar(`203.0.113.${20 + i}`)).status, 401);
      assert.equal((await verificar('2001:db8::1')).status, 401);
      assert.equal((await verificar('2001:DB8:0:0:0:0:0:1')).status, 401);
      assert.equal((await verificar('2001:db8::1')).status, 401);
      assert.equal((await verificar('2001:db8::1')).status, 429, 'IPv6 equivalentes comparten cupo');
      // Sin client_ip, el origen es la IP TCP de la app: todos sus usuarios comparten cupo.
      for (let i = 0; i < 3; i++) assert.equal((await verificar()).status, 401);
      assert.equal((await verificar()).status, 429);
      // Las rutas sin client_ip (enrolar, validar token) no consumen el cupo por origen.
      assert.equal((await pedir(s.puerto, { metodo: 'POST', ruta: '/api/v1/enrollments', cuerpo: { user_ref: 'u' }, cabeceras: credenciales })).status, 201);
    } finally {
      s.servidor.close();
      s.servidor.closeAllConnections();
    }
  });

  test('límite por origen también en recovery, activate y resync', async () => {
    const s = await levantar({ limitadores: { porOrigen: crearLimitador({ capacidad: 1, ventanaMs: 60_000 }) } });
    try {
      const rutas = [
        ['/api/v1/recovery', { user_ref: 'u1', recovery_code: 'AAAA-BBBB', client_ip: '198.51.100.1' }],
        ['/api/v1/enrollments/e1/activate', { code: '123456', client_ip: '198.51.100.2' }],
        ['/api/v1/enrollments/e1/resync', { code_1: '123456', code_2: '654321', client_ip: '198.51.100.3' }],
      ];
      for (const [ruta, cuerpo] of rutas) {
        assert.equal((await pedir(s.puerto, { metodo: 'POST', ruta, cuerpo, cabeceras: credenciales })).status, 200, ruta);
        assert.equal((await pedir(s.puerto, { metodo: 'POST', ruta, cuerpo, cabeceras: credenciales })).status, 429, ruta);
      }
    } finally {
      s.servidor.close();
      s.servidor.closeAllConnections();
    }
  });
});

describe('servidor HTTP: descarga del certificado público de la CA', () => {
  const PEM = '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n';

  test('GET /ca.crt sirve el certificado configurado como application/x-x509-ca-cert', async () => {
    const s = await levantar({ certificadoCa: PEM });
    try {
      const r = await pedir(s.puerto, { ruta: '/ca.crt' });
      assert.equal(r.status, 200);
      assert.equal(r.cabeceras['content-type'], 'application/x-x509-ca-cert');
      assert.match(r.cabeceras['content-disposition'] ?? '', /attachment; filename="ca-servicio-totp\.crt"/);
      assert.equal(r.texto, PEM);
      const h = await pedir(s.puerto, { metodo: 'HEAD', ruta: '/ca.crt' });
      assert.equal(h.status, 200);
      assert.equal(h.texto, '');
      const p = await pedir(s.puerto, { metodo: 'POST', ruta: '/ca.crt', cuerpo: {} });
      assert.equal(p.status, 405);
    } finally {
      s.servidor.close();
    }
  });

  test('sin certificado configurado responde 404', async () => {
    const s = await levantar();
    try {
      assert.equal((await pedir(s.puerto, { ruta: '/ca.crt' })).status, 404);
    } finally {
      s.servidor.close();
    }
  });
});

describe('arranque real (main.js)', () => {
  test('/health informa el modo de heurística configurado (local | monitorizacion | mock)', async () => {
    const { iniciar } = await import('../main.js');
    const { validarConfig } = await import('../infrastructure/config/config.js');
    const silencio = { info() {}, warn() {}, error() {} };
    for (const modo of ['monitorizacion', 'mock', 'local']) {
      const config = validarConfig({
        HOST: '127.0.0.1', PORT: '0', TLS_MODE: 'off', SQLITE_DB_PATH: ':memory:', HEURISTICS_MODE: modo,
        MASTER_KEY_VERSION: 'v1', MASTER_KEY_V1_HEX: 'ab'.repeat(32),
        USER_REF_PEPPER: 'p'.repeat(43), DAILY_IP_PEPPER_SEED: 'q'.repeat(43),
      });
      const svc = await iniciar({ config, registro: silencio, senales: false });
      try {
        const r = await pedir(svc.puerto, { ruta: '/health' });
        assert.equal(r.status, 200);
        assert.equal(r.json.heuristicsMode, modo);
      } finally {
        await svc.detener('prueba');
      }
    }
  });
});
