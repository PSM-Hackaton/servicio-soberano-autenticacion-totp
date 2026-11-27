// Prueba de punta a punta: ciudadano enrolado por el Portal de Trámites → la consola administrativa
// encuentra su enrolamiento escribiendo la cédula. Servicio real (backend/src/main.js, SQLite en
// memoria, TLS desactivado) + portal real; la app se registra como lo hace `npm run seed`
// (user_ref_desde_cedula = hmac, prefijo ptd-) y el portal recibe el cedula_secreto devuelto.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { iniciar } from '../../backend/src/main.js';
import { validarConfig } from '../../backend/src/infrastructure/config/config.js';
import { generateTotp } from '../../backend/src/core/totp/totp.js';
import { base32Decode } from '../../backend/src/core/totp/base32.js';
import { hashSecretoAsync } from '../../backend/src/security/index.js';
import { derivarUserRefDesdeCedula } from '../../sdk/src/index.js';
import { configuracion } from '../src/config.js';
import { crearPortal } from '../src/portal.js';
import { generarUsuarios, USUARIOS_DEMO } from '../src/usuarios.js';

const SILENCIO = { info() {}, warn() {}, error() {} };
const CLAVE_ADMIN = 'clave-de-prueba-larga';
const OPCIONES_TOTP = { algoritmo: 'SHA256', digitos: 6, periodo: 30 };
const SEMILLA_ACTOR = { admin: { id: 's', usuario: 'semilla', rol: 'Administrador' }, ip: '127.0.0.1' };

/** Navegador mínimo con cookies y token CSRF (formularios del portal). */
class Navegador {
  constructor(base) { this.base = base; this.cookies = new Map(); this.csrf = ''; }

  async pedir(ruta, { metodo = 'GET', campos } = {}) {
    const h = {};
    if (this.cookies.size) h.cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    let body;
    if (campos) {
      h['content-type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams({ _csrf: this.csrf, ...campos }).toString();
    }
    const res = await fetch(this.base + ruta, { method: metodo, headers: h, body, redirect: 'manual' });
    for (const c of res.headers.getSetCookie()) {
      const [par] = c.split(';');
      const i = par.indexOf('=');
      if (par.slice(i + 1)) this.cookies.set(par.slice(0, i), par.slice(i + 1)); else this.cookies.delete(par.slice(0, i));
    }
    const html = await res.text();
    if (res.status === 303) return this.pedir(res.headers.get('location'));
    const m = /name="_csrf" value="([^"]+)"/.exec(html);
    if (m) this.csrf = m[1];
    return { status: res.status, url: ruta, html };
  }
}

/** Llamada JSON a la API de la consola. */
async function consola(base, ruta, { metodo = 'GET', cuerpo, cookie, csrf } = {}) {
  const h = { 'content-type': 'application/json' };
  if (cookie) h.cookie = cookie;
  if (csrf) h['x-csrf-token'] = csrf;
  const res = await fetch(base + ruta, { method: metodo, headers: h, body: cuerpo === undefined ? undefined : JSON.stringify(cuerpo) });
  return { status: res.status, cabeceras: res.headers, json: await res.json().catch(() => null) };
}

let svc;
let portal;
let basePortal;
let baseServicio;
let dir;
let app;
let secretoCedula;

before(async () => {
  svc = await iniciar({
    config: validarConfig({
      HOST: '127.0.0.1', PORT: '0', TLS_MODE: 'off', SQLITE_DB_PATH: ':memory:', HEURISTICS_MODE: 'mock',
      MASTER_KEY_VERSION: 'v1', MASTER_KEY_V1_HEX: 'ef'.repeat(32),
      USER_REF_PEPPER: 'p'.repeat(43), DAILY_IP_PEPPER_SEED: 'q'.repeat(43),
    }),
    registro: SILENCIO,
    senales: false,
  });
  baseServicio = `http://127.0.0.1:${svc.puerto}`;
  // Igual que backend/scripts/semilla.js.
  const alta = await svc.casos.adminActualizarApp({ nombre: 'Portal de Trámites', user_ref_desde_cedula: 'hmac', cedula_prefijo: 'ptd-' }, SEMILLA_ACTOR);
  assert.equal(alta.status, 201);
  app = svc.repos.apps.buscarPorId(alta.cuerpo.app.id);
  secretoCedula = alta.cuerpo.cedula_secreto;

  dir = mkdtempSync(join(tmpdir(), 'portal-cedula-'));
  await generarUsuarios(join(dir, 'usuarios.json'), USUARIOS_DEMO);
  portal = await crearPortal({
    config: configuracion({
      TOTP_BASE_URL: baseServicio,
      TOTP_CLIENT_ID: alta.cuerpo.client_id,
      TOTP_CLIENT_SECRET: alta.cuerpo.client_secret,
      TOTP_CEDULA_SECRETO: secretoCedula,
      TOTP_CEDULA_PREFIJO: 'ptd-',
      PORTAL_USUARIOS: join(dir, 'usuarios.json'),
      PORTAL_TLS_CERT: join(dir, 'no-existe.crt'),
      PORTAL_TLS_KEY: join(dir, 'no-existe.key'),
    }),
  });
  basePortal = await portal.iniciar(0, '127.0.0.1');
});

after(async () => {
  await portal?.detener();
  await svc?.detener('prueba');
  if (dir) rmSync(dir, { recursive: true, force: true });
});

test('el portal deriva el user_ref con el formato hmac del servicio (SDK)', () => {
  assert.equal(portal.usuarios.origenSecreto, 'configurado');
  const ana = portal.usuarios.buscar('V10000001');
  assert.equal(ana.userRef, derivarUserRefDesdeCedula('V-10.000.001', secretoCedula, 'ptd-'));
  assert.match(ana.userRef, /^ptd-[A-Za-z0-9_-]{43}$/);
});

test('ciudadano enrolado por el portal → la consola encuentra su enrolamiento por cédula', async () => {
  // 1. Ana entra al portal con cédula + contraseña y activa su segundo factor.
  const nav = new Navegador(basePortal);
  await nav.pedir('/ingresar');
  const r = await nav.pedir('/ingresar', { metodo: 'POST', campos: { nacionalidad: 'V', cedula: '10.000.001', contrasena: 'Tramites-Demo-2026' } });
  assert.equal(r.url, '/enrolar', r.html.slice(0, 200));
  const otpauth = decodeURIComponent(/#add=([^"]+)"/.exec(r.html)[1].replaceAll('&amp;', '&'));
  const semilla = base32Decode(new URL(otpauth).searchParams.get('secret'));
  assert.doesNotMatch(otpauth, /10000001|10\.000\.001/, 'la cédula no viaja al servicio');
  const act = await nav.pedir('/enrolar/activar', { metodo: 'POST', campos: { codigo: generateTotp(semilla, Date.now(), OPCIONES_TOTP) } });
  assert.equal(act.url, '/enrolar/codigos');
  assert.equal((await nav.pedir('/enrolar/confirmar', { metodo: 'POST', campos: { guardados: 'si' } })).url, '/verificar');
  const factor = portal.usuarios.buscar('V10000001').factor;
  assert.ok(factor?.enrollmentId, 'el portal guardó el enrollment_id');

  // 2. Un operador de soporte entra a la consola (contraseña + TOTP) y busca por cédula.
  const consolaApp = (await svc.casos.adminActualizarApp({ nombre: 'Consola Administrativa' }, SEMILLA_ACTOR)).cuerpo.app;
  const ctxConsola = { app: svc.repos.apps.buscarPorId(consolaApp.id), ip: '127.0.0.1' };
  const enrolAdmin = await svc.casos.enrolar({ user_ref: 'admin:soporte', account_label: 'soporte' }, ctxConsola);
  const semillaAdmin = base32Decode(new URL(enrolAdmin.cuerpo.otpauth_uri).searchParams.get('secret'));
  const ahora = Date.now();
  assert.equal((await svc.casos.activar({ id: enrolAdmin.cuerpo.enrollment_id, cuerpo: { code: generateTotp(semillaAdmin, ahora, OPCIONES_TOTP) } }, ctxConsola)).status, 200);
  svc.repos.admins.crear({ usuario: 'soporte', password_hash: await hashSecretoAsync(CLAVE_ADMIN), rol: 'Operador', totp_enrollment_id: enrolAdmin.cuerpo.enrollment_id });
  const login = await consola(baseServicio, '/admin/api/login', {
    metodo: 'POST', cuerpo: { usuario: 'soporte', password: CLAVE_ADMIN, totp_code: generateTotp(semillaAdmin, ahora + 30_000, OPCIONES_TOTP) },
  });
  assert.equal(login.status, 200);
  const cookie = login.cabeceras.getSetCookie()[0].split(';')[0];

  for (const forma of ['V-10.000.001', 'v10000001', 'V 10000001']) {
    const q = `/admin/api/enrollments?app_id=${encodeURIComponent(app.id)}&cedula=${encodeURIComponent(forma)}`;
    const b = await consola(baseServicio, q, { cookie });
    assert.equal(b.status, 200, forma);
    assert.deepEqual(b.json.enrollments.map((e) => e.id), [factor.enrollmentId], forma);
    assert.equal(b.json.enrollments[0].estado, 'activo');
  }
  // Otro ciudadano no enrolado: sin resultados.
  const otro = await consola(baseServicio, `/admin/api/enrollments?app_id=${encodeURIComponent(app.id)}&cedula=V-10.000.002`, { cookie });
  assert.deepEqual(otro.json.enrollments, []);
});
