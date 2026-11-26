// Pruebas HTTP de punta a punta de las rutas de gestión de la consola contra el servicio real
// (main.js con SQLite en memoria y TLS desactivado): login con contraseña + TOTP, cookie, CSRF y RBAC.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';

import { iniciar } from '../main.js';
import { validarConfig } from '../infrastructure/config/config.js';
import { generateTotp } from '../core/totp/totp.js';
import { base32Decode } from '../core/totp/base32.js';
import { hashSecretoAsync } from '../security/index.js';

const SILENCIO = { info() {}, warn() {}, error() {} };
const PASSWORD = 'clave-de-prueba-larga';

function pedir(puerto, { metodo = 'GET', ruta = '/', cabeceras = {}, cuerpo } = {}) {
  return new Promise((resolver, rechazar) => {
    const datos = cuerpo === undefined ? undefined : JSON.stringify(cuerpo);
    const h = { ...cabeceras };
    if (datos !== undefined) {
      h['content-type'] = 'application/json';
      h['content-length'] = Buffer.byteLength(datos);
    }
    const req = request({ host: '127.0.0.1', port: puerto, method: metodo, path: ruta, headers: h }, (res) => {
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

/** Código TOTP del paso siguiente al último usado (evita el anti replay entre logins seguidos). */
function codigoSiguiente(semilla, usados) {
  let t = Date.now();
  while (usados.has(Math.floor(t / 30_000))) t += 30_000;
  usados.add(Math.floor(t / 30_000));
  return generateTotp(semilla, t, { algoritmo: 'SHA256', digitos: 6, periodo: 30 });
}

/** Crea un administrador con TOTP activo directamente sobre el servicio (como la semilla). */
async function crearAdminDirecto(svc, usuario, rol) {
  let consola = svc.repos.apps.listar().find((a) => a.nombre === 'Consola Administrativa');
  if (!consola) {
    const alta = await svc.casos.adminActualizarApp({ nombre: 'Consola Administrativa' }, { admin: { id: 's', usuario: 'semilla', rol: 'Administrador' } });
    consola = svc.repos.apps.buscarPorId(alta.cuerpo.app.id);
  }
  const ctxApp = { app: consola, ip: '127.0.0.1' };
  const enrol = await svc.casos.enrolar({ user_ref: `admin:${usuario}`, account_label: usuario }, ctxApp);
  const semilla = base32Decode(new URL(enrol.cuerpo.otpauth_uri).searchParams.get('secret'));
  const usados = new Set([Math.floor(Date.now() / 30_000)]);
  const act = await svc.casos.activar({
    id: enrol.cuerpo.enrollment_id,
    cuerpo: { code: generateTotp(semilla, Date.now(), { algoritmo: 'SHA256', digitos: 6, periodo: 30 }) },
  }, ctxApp);
  assert.equal(act.status, 200);
  const admin = svc.repos.admins.crear({
    usuario, password_hash: await hashSecretoAsync(PASSWORD), rol, totp_enrollment_id: enrol.cuerpo.enrollment_id,
  });
  return { admin, semilla, usados };
}

/** Inicia sesión y devuelve cookie + csrf. */
async function entrar(puerto, usuario, semilla, usados, password = PASSWORD) {
  const r = await pedir(puerto, { metodo: 'POST', ruta: '/admin/api/login', cuerpo: { usuario, password, totp_code: codigoSiguiente(semilla, usados) } });
  assert.equal(r.status, 200, `login ${usuario}: ${r.texto}`);
  return { cookie: r.cabeceras['set-cookie'][0].split(';')[0], csrf: r.json.csrf_token, json: r.json };
}

describe('consola: rutas de gestión contra el servicio real', () => {
  /** @type {Awaited<ReturnType<typeof iniciar>>} */
  let svc;
  /** @type {Record<string, { cookie: string, csrf: string }>} */
  const sesiones = {};

  before(async () => {
    const config = validarConfig({
      HOST: '127.0.0.1', PORT: '0', TLS_MODE: 'off', SQLITE_DB_PATH: ':memory:', HEURISTICS_MODE: 'mock',
      MASTER_KEY_VERSION: 'v1', MASTER_KEY_V1_HEX: 'cd'.repeat(32),
      USER_REF_PEPPER: 'p'.repeat(43), DAILY_IP_PEPPER_SEED: 'q'.repeat(43),
    });
    svc = await iniciar({ config, registro: SILENCIO, senales: false });
    for (const [usuario, rol] of [['jefa', 'Administrador'], ['ope', 'Operador'], ['aud', 'Auditor']]) {
      const { semilla, usados } = await crearAdminDirecto(svc, usuario, rol);
      sesiones[rol] = await entrar(svc.puerto, usuario, semilla, usados);
    }
  });
  after(async () => { await svc.detener('prueba'); });

  const como = (rol, op) => pedir(svc.puerto, {
    ...op,
    cabeceras: { cookie: sesiones[rol].cookie, ...(op.metodo && op.metodo !== 'GET' ? { 'x-csrf-token': sesiones[rol].csrf } : {}), ...op.cabeceras },
  });

  test('GET /admin/api/keys: inventario sin material privado para los tres roles', async () => {
    const rotar = await como('Administrador', { metodo: 'POST', ruta: '/admin/api/keys/rotate', cuerpo: {} });
    assert.equal(rotar.status, 200);
    for (const rol of ['Administrador', 'Operador', 'Auditor']) {
      const r = await como(rol, { ruta: '/admin/api/keys' });
      assert.equal(r.status, 200, rol);
      assert.equal(r.json.active_kid, rotar.json.new_kid);
      assert.equal(r.json.keys.length, 2);
      assert.equal(r.json.keys.find((k) => k.kid === rotar.json.previous_kid).estado, 'solo_verificacion');
      assert.doesNotMatch(r.texto, /private|PRIVATE|BEGIN/);
    }
    assert.equal((await pedir(svc.puerto, { ruta: '/admin/api/keys' })).status, 401);
    assert.equal((await como('Auditor', { ruta: '/admin/api/keys?x=1' })).status, 400);
  });

  test('POST /admin/api/enrollments/:id/{suspend,reactivate,revoke}: CSRF, RBAC, 404 y 409', async () => {
    const alta = await como('Administrador', { metodo: 'POST', ruta: '/admin/api/apps', cuerpo: { nombre: 'Portal de prueba' } });
    assert.equal(alta.status, 201);
    const app = svc.repos.apps.buscarPorId(alta.json.app.id);
    const ctxApp = { app, ip: '127.0.0.1' };
    const enrol = await svc.casos.enrolar({ user_ref: 'ciudadana-http' }, ctxApp);
    const semilla = base32Decode(new URL(enrol.cuerpo.otpauth_uri).searchParams.get('secret'));
    const act = await svc.casos.activar({ id: enrol.cuerpo.enrollment_id, cuerpo: { code: generateTotp(semilla, Date.now(), { algoritmo: 'SHA256', digitos: 6, periodo: 30 }) } }, ctxApp);
    assert.equal(act.status, 200);
    const ruta = (accion) => `/admin/api/enrollments/${enrol.cuerpo.enrollment_id}/${accion}`;

    const sinCsrf = await pedir(svc.puerto, { metodo: 'POST', ruta: ruta('suspend'), cabeceras: { cookie: sesiones.Operador.cookie }, cuerpo: {} });
    assert.equal(sinCsrf.status, 403, 'sin X-CSRF-Token');
    assert.equal((await como('Auditor', { metodo: 'POST', ruta: ruta('suspend'), cuerpo: {} })).status, 403, 'Auditor');
    const s = await como('Operador', { metodo: 'POST', ruta: ruta('suspend') });
    assert.equal(s.status, 200, s.texto);
    assert.equal(s.json.enrollment.estado, 'suspendido');
    assert.equal((await como('Operador', { metodo: 'POST', ruta: ruta('suspend'), cuerpo: {} })).status, 409);
    assert.equal((await como('Administrador', { metodo: 'POST', ruta: ruta('reactivate'), cuerpo: {} })).json.enrollment.estado, 'activo');
    assert.equal((await como('Administrador', { metodo: 'POST', ruta: ruta('revoke'), cuerpo: {} })).json.enrollment.estado, 'revocado');
    assert.equal((await como('Administrador', { metodo: 'POST', ruta: ruta('reactivate'), cuerpo: {} })).status, 409, 'revocado es final');
    const no = await como('Administrador', { metodo: 'POST', ruta: '/admin/api/enrollments/00000000-0000-4000-8000-000000000000/revoke', cuerpo: {} });
    assert.equal(no.status, 404);
    assert.equal((await como('Administrador', { metodo: 'POST', ruta: ruta('revoke'), cuerpo: { extra: 1 } })).status, 400);
  });
});
