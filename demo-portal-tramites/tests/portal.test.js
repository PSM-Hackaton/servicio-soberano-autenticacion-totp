// Pruebas de extremo a extremo del Portal de Trámites con el SDK apuntando al servicio TOTP falso.
// Un "navegador" mínimo (fetch + cookies + CSRF) recorre el flujo como lo haría un ciudadano.

import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { crearServicioFalso } from '../../sdk/testing/servicio-falso.js';
import { configuracion, parsearEnv } from '../src/config.js';
import { crearPortal, ipCiudadano } from '../src/portal.js';
import { generarUsuarios, USUARIOS_DEMO } from '../src/usuarios.js';
import { normalizarCedula, formatearCedula, seudonimo } from '../src/cedula.js';

const CLAVE = 'Tramites-Demo-2026';

// Escenarios con su ciudadano ficticio (cédulas de prueba). Ana es la cuenta demo V-10.000.001.
const ESCENARIOS = ['malo', 'bloqueo', 'caido', 'lento', 'alterado', 'offline', 'recupera', 'ip'];
const CEDULAS = {
  'ana': 'V10000001',
  ...Object.fromEntries(ESCENARIOS.map((n, i) => [`prueba.${n}`, `V2000001${i}`])),
};
const ced = (alias) => CEDULAS[alias];
/** Campos del formulario de ingreso: la cédula se escribe con puntos, como lo haría un ciudadano. */
const ingreso = (alias, contrasena = CLAVE) => {
  const c = ced(alias);
  return { nacionalidad: c[0], cedula: formatearCedula(c).slice(2), contrasena };
};

class Navegador {
  constructor(base) { this.base = base; this.cookies = new Map(); this.csrf = null; this.html = ''; }

  async pedir(ruta, { metodo = 'GET', campos, cabeceras = {}, seguir = true } = {}) {
    const h = { ...cabeceras };
    if (this.cookies.size) h.cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    let body;
    if (campos) {
      h['content-type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams(campos).toString();
    }
    const res = await fetch(this.base + ruta, { method: metodo, headers: h, body, redirect: 'manual' });
    for (const c of res.headers.getSetCookie()) {
      const [par] = c.split(';');
      const i = par.indexOf('=');
      const v = par.slice(i + 1);
      if (v) this.cookies.set(par.slice(0, i), v); else this.cookies.delete(par.slice(0, i));
    }
    const texto = await res.text();
    if (res.status === 303 && seguir) return this.pedir(res.headers.get('location'));
    if ((res.headers.get('content-type') ?? '').includes('text/html')) {
      this.html = texto;
      const m = /name="_csrf" value="([^"]+)"/.exec(texto);
      if (m) this.csrf = m[1];
    }
    return { status: res.status, html: texto, url: ruta, location: res.headers.get('location'), cabeceras: res.headers };
  }

  get(ruta, o) { return this.pedir(ruta, o); }

  post(ruta, campos, o = {}) { return this.pedir(ruta, { metodo: 'POST', campos: { _csrf: this.csrf ?? '', ...campos }, ...o }); }
}

describe('Portal de Trámites con servicio TOTP falso', () => {
  let desfase = 0;
  /** Avanza el reloj TOTP del servicio falso (simula esperar al siguiente código). */
  const avanzar = (pasos = 1) => { desfase += pasos * 30_000; };
  const falso = crearServicioFalso({ reloj: () => Date.now() + desfase, maxFallos: 5, bloqueoSegundos: 90 });
  let portal;
  let base;
  let dir;

  before(async () => {
    const urlServicio = await falso.iniciar();
    dir = mkdtempSync(join(tmpdir(), 'portal-'));
    // Un ciudadano ficticio por escenario para que los estados (bloqueos, factores) no se mezclen.
    const extra = ESCENARIOS.map((n) => ({ cedula: ced(`prueba.${n}`), nombre: `Persona ${n}`, contrasena: CLAVE }));
    await generarUsuarios(join(dir, 'usuarios.json'), [...USUARIOS_DEMO, ...extra]);
    const config = configuracion({
      TOTP_BASE_URL: urlServicio,
      TOTP_CLIENT_ID: falso.clientId,
      TOTP_CLIENT_SECRET: falso.clientSecret,
      TOTP_TIMEOUT_MS: '500',
      PORTAL_USUARIOS: join(dir, 'usuarios.json'),
      PORTAL_TLS_CERT: join(dir, 'no-existe.crt'),
      PORTAL_TLS_KEY: join(dir, 'no-existe.key'),
    });
    portal = await crearPortal({ config });
    base = await portal.iniciar(0, '127.0.0.1');
  });

  after(async () => {
    await portal.detener();
    await falso.detener();
    rmSync(dir, { recursive: true, force: true });
  });

  beforeEach(() => {
    Object.assign(falso.modo, { caido: false, fallos503: 0, retardoMs: 0, cortes: 0, cortesTrasProcesar: 0, rutasCaidas: [], tokenAlterado: false });
  });

  const userRef = (u) => portal.usuarios.buscar(ced(u)).userRef;

  /** Ingresa con contraseña, enrola, activa y deja al navegador en /verificar. */
  async function enrolarYActivar(nav, usuario) {
    await nav.get('/ingresar');
    const r = await nav.post('/ingresar', ingreso(usuario));
    assert.equal(r.url, '/enrolar');
    const id = [...falso.enrolamientos.values()].reverse().find((e) => e.userRef === userRef(usuario)).id;
    const act = await nav.post('/enrolar/activar', { codigo: falso.codigoDeEnrolamiento(id) });
    assert.equal(act.url, '/enrolar/codigos');
    const fin = await nav.post('/enrolar/confirmar', { guardados: 'si' });
    assert.equal(fin.url, '/verificar');
    avanzar();
    return id;
  }

  test('cabeceras de seguridad, CSP estricta y cookie de sesión', async () => {
    const nav = new Navegador(base);
    const r = await nav.get('/ingresar');
    assert.equal(r.status, 200);
    const csp = r.cabeceras.get('content-security-policy');
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'self'/);
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
    assert.equal(r.cabeceras.get('x-frame-options'), 'DENY');
    assert.equal(r.cabeceras.get('referrer-policy'), 'same-origin');
    const cookie = r.cabeceras.get('set-cookie');
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /Secure/);
    assert.match(cookie, /SameSite=Strict/);
    assert.doesNotMatch(r.html, /<script>|<style>|style="|onclick=/, 'nada inline en el HTML');
  });

  test('login con contraseña incorrecta: 401 y sin sesión', async () => {
    const nav = new Navegador(base);
    await nav.get('/ingresar');
    const r = await nav.post('/ingresar', ingreso('ana', 'mala'));
    assert.equal(r.status, 401);
    assert.match(r.html, /Cédula o contraseña incorrectas/);
    const p = await nav.get('/panel');
    assert.equal(p.url, '/ingresar');
  });

  test('cédula: formato validado en el servidor y el servicio solo recibe un seudónimo', async () => {
    const nav = new Navegador(base);
    await nav.get('/ingresar');
    for (const mala of ['12a45678', '1.2345.678', '12345', '1234567890', '012345678']) {
      const r = await nav.post('/ingresar', { nacionalidad: 'V', cedula: mala, contrasena: CLAVE });
      assert.equal(r.status, 400, mala);
      assert.match(r.html, /Cédula de identidad no válida/);
    }
    assert.equal((await nav.post('/ingresar', { nacionalidad: 'X', cedula: '10000001', contrasena: CLAVE })).status, 400);
    // Con prefijo en el propio campo y sin puntos también vale.
    const r = await nav.post('/ingresar', { nacionalidad: 'E', cedula: 'v-10000002', contrasena: CLAVE });
    assert.equal(r.url, '/enrolar');
    const ref = portal.usuarios.buscar('V10000002').userRef;
    assert.match(ref, /^ptd-[0-9a-f]{32}$/);
    const enrol = [...falso.enrolamientos.values()].reverse().find((e) => e.userRef === ref);
    assert.ok(enrol, 'el servicio recibió el seudónimo');
    assert.doesNotMatch(r.html.match(/#add=([^"]+)"/)[1], /10000002|10\.000\.002/, 'la cédula no viaja en el otpauth');
  });

  test('CSRF: formulario sin token u otro origen se rechaza con 403', async () => {
    const nav = new Navegador(base);
    await nav.get('/ingresar');
    const sin = await nav.pedir('/ingresar', { metodo: 'POST', campos: ingreso('ana') });
    assert.equal(sin.status, 403);
    const otro = await nav.post('/ingresar', ingreso('ana'), { cabeceras: { origin: 'https://atacante.example' } });
    assert.equal(otro.status, 403);
  });

  test('flujo completo: login → enrolamiento → códigos de recuperación → verificación → panel', async () => {
    const nav = new Navegador(base);
    await nav.get('/ingresar');
    const sidAnonimo = nav.cookies.get('ptd_sesion');
    const r = await nav.post('/ingresar', ingreso('ana'));
    assert.equal(r.url, '/enrolar');
    assert.notEqual(nav.cookies.get('ptd_sesion'), sidAnonimo, 'rota la sesión al validar la contraseña');
    assert.match(r.html, /<img class="qr" src="data:image\/svg\+xml;base64,/);
    assert.match(r.html, /href="https:\/\/localhost:8443\/app\/#add=otpauth%3A%2F%2Ftotp%2F/);
    assert.match(r.html, /Abrir en el Autenticador Soberano/);
    assert.match(r.html, /id="clave-manual">[A-Z2-7 ]{20,}</);

    // Código malo en la activación
    const malo = await nav.post('/enrolar/activar', { codigo: '000000' });
    assert.equal(malo.status, 401);
    assert.match(malo.html, /Código incorrecto/);

    const id = [...falso.enrolamientos.values()].reverse().find((e) => e.userRef === userRef('ana')).id;
    const act = await nav.post('/enrolar/activar', { codigo: falso.codigoDeEnrolamiento(id) });
    assert.equal(act.url, '/enrolar/codigos');
    const codigos = [...act.html.matchAll(/<li><code>([A-Z2-7]{4}-[A-Z2-7]{4})<\/code><\/li>/g)];
    assert.equal(codigos.length, 10);
    assert.deepEqual(portal.usuarios.buscar(ced('ana')).factor.enrollmentId, id);

    const otraVez = await nav.get('/enrolar/codigos');
    assert.doesNotMatch(otraVez.html, /<li><code>[A-Z2-7]{4}-/, 'los códigos se muestran una sola vez');

    await nav.post('/enrolar/confirmar', { guardados: 'si' });
    avanzar();
    const sidAntes = nav.cookies.get('ptd_sesion');
    const v = await nav.post('/verificar', { codigo: falso.codigoPara(userRef('ana')) });
    assert.equal(v.url, '/panel');
    assert.equal(v.status, 200);
    assert.match(v.html, /Hola, Ana Rivera Soto/);
    assert.match(v.html, /V-10\.000\.001/, 'el panel muestra la cédula formateada');
    assert.match(v.html, /Validada en el servicio/);
    assert.notEqual(nav.cookies.get('ptd_sesion'), sidAntes, 'rota la sesión tras el segundo factor');
    assert.match(v.html, /Lo que ocurre por dentro/);
    assert.match(v.html, /POST \/api\/v1\/verify/);
    assert.doesNotMatch(v.html, new RegExp(falso.clientSecret), 'el secreto nunca aparece en la traza');

    // Step-up: operación sensible exige un código nuevo.
    const t = await nav.get('/tramites/datos-bancarios');
    assert.match(t.html, /Confirme que es usted/);
    const sinCodigo = await nav.post('/tramites/datos-bancarios', { entidad: 'Banco Ejemplo Uno', cuenta: '01020304050607080900', codigo: '000000' });
    assert.equal(sinCodigo.status, 401);
    avanzar();
    const ok = await nav.post('/tramites/datos-bancarios', { entidad: 'Banco Ejemplo Uno', cuenta: '01020304050607080900', codigo: falso.codigoPara(userRef('ana')) });
    assert.match(ok.url, /^\/comprobantes\/PT-\d{4}-[0-9A-F]{6}$/);
    assert.match(ok.html, /Trámite completado/);
    assert.match(ok.html, /terminada en 0900/);

    // Cerrar sesión
    await nav.post('/salir', {});
    assert.equal((await nav.get('/panel')).url, '/ingresar');

    // Toda llamada que comprueba un código lleva la IP del ciudadano (socket), no la del portal ni la de X-Forwarded-For.
    const conCodigo = falso.registro.filter((x) => /\/(verify|activate|recovery|resync)$/.test(x.ruta));
    assert.ok(conCodigo.length >= 4);
    assert.ok(conCodigo.every((x) => x.clientIp === '127.0.0.1'), JSON.stringify(conCodigo.map((x) => x.clientIp)));
  });

  test('client_ip: X-Forwarded-For se ignora salvo configuración explícita (y entonces vale la última entrada)', async () => {
    const nav = new Navegador(base);
    await enrolarYActivar(nav, 'prueba.ip');
    const antes = falso.registro.length;
    await nav.post('/verificar', { codigo: '123456' }, { cabeceras: { 'x-forwarded-for': '203.0.113.99' } });
    const verify = falso.registro.slice(antes).find((x) => x.ruta === '/api/v1/verify');
    assert.equal(verify.clientIp, '127.0.0.1', 'sin PORTAL_CONFIAR_X_FORWARDED_FOR no se confía en la cabecera');

    const req = (xff, remoto = '::ffff:10.0.0.5') => ({ headers: xff == null ? {} : { 'x-forwarded-for': xff }, socket: { remoteAddress: remoto ?? undefined } });
    assert.equal(ipCiudadano(req('203.0.113.99')), '10.0.0.5');
    assert.equal(ipCiudadano(req('198.51.100.1, 203.0.113.99'), true), '203.0.113.99');
    assert.equal(ipCiudadano(req('203.0.113.99, basura'), true), '10.0.0.5', 'entrada inválida → socket');
    assert.equal(ipCiudadano(req(null, '2001:db8::9'), true), '2001:db8::9');
    assert.equal(ipCiudadano(req(null, null)), undefined);
  });

  test('configuración: TOTP_CLIENT_ID es obligatorio (sin valor por defecto)', () => {
    assert.throws(() => configuracion({}), /TOTP_CLIENT_ID/);
    assert.throws(() => configuracion({ TOTP_CLIENT_ID: '  ' }), /TOTP_CLIENT_ID/);
    assert.throws(() => configuracion({ TOTP_CLIENT_ID: 'app_COPIAR_DEL_CLIENT_ID_QUE_IMPRIME_NPM_RUN_SEED' }), /TOTP_CLIENT_ID/);
    const c = configuracion({ TOTP_CLIENT_ID: 'app_0123', TOTP_CLIENT_SECRET: 'x' });
    assert.equal(c.servicio.clientId, 'app_0123');
    assert.equal(c.servicio.audience, 'app_0123');
    assert.equal(c.confiarXForwardedFor, false);
    assert.equal(configuracion({ TOTP_CLIENT_ID: 'app_0123', PORTAL_CONFIAR_X_FORWARDED_FOR: '1' }).confiarXForwardedFor, true);
  });

  test('verificación con código incorrecto: 401 y nunca acceso', async () => {
    const nav = new Navegador(base);
    await enrolarYActivar(nav, 'prueba.malo');
    const r = await nav.post('/verificar', { codigo: '123456' });
    assert.equal(r.status, 401);
    assert.match(r.html, /Código incorrecto/);
    const formato = await nav.post('/verificar', { codigo: '12ab' });
    assert.equal(formato.status, 401);
    const p = await nav.get('/panel');
    assert.notEqual(p.url, '/panel');
  });

  test('bloqueo (429): cuenta atrás visible y el portal no vuelve a consultar al servicio', async () => {
    const nav = new Navegador(base);
    await enrolarYActivar(nav, 'prueba.bloqueo');
    let r;
    for (let i = 0; i < 5; i++) r = await nav.post('/verificar', { codigo: '999999' });
    assert.equal(r.status, 429);
    assert.match(r.html, /Demasiados intentos/);
    assert.match(r.html, /data-cuenta-atras="\d+"/);
    const antes = falso.registro.length;
    const otra = await nav.post('/verificar', { codigo: falso.codigoPara(userRef('prueba.bloqueo')) });
    assert.equal(otra.status, 429, 'incluso con el código correcto mientras dura el bloqueo');
    assert.equal(falso.registro.length, antes);
    assert.notEqual((await nav.get('/panel')).url, '/panel');
  });

  test('servicio caído (503): "no se puede verificar", reintento idempotente y NUNCA acceso', async () => {
    const nav = new Navegador(base);
    await enrolarYActivar(nav, 'prueba.caido');
    falso.modo.caido = true;
    const antes = falso.registro.length;
    const r = await nav.post('/verificar', { codigo: falso.codigoPara(userRef('prueba.caido')) });
    assert.equal(r.status, 503);
    assert.match(r.html, /No se puede verificar en este momento/);
    assert.match(r.html, /Intente más tarde/);
    const intentos = falso.registro.slice(antes).filter((x) => x.ruta === '/api/v1/verify');
    assert.equal(intentos.length, 2, 'un intento + un reintento');
    assert.equal(intentos[0].idempotencyKey, intentos[1].idempotencyKey);
    assert.notEqual((await nav.get('/panel')).url, '/panel');
  });

  test('servicio lento (tiempo agotado): sin acceso', async () => {
    const nav = new Navegador(base);
    await enrolarYActivar(nav, 'prueba.lento');
    falso.modo.retardoMs = 1500;
    const r = await nav.post('/verificar', { codigo: falso.codigoPara(userRef('prueba.lento')) });
    falso.modo.retardoMs = 0;
    assert.equal(r.status, 503);
    assert.notEqual((await nav.get('/panel')).url, '/panel');
  });

  test('token alterado por el camino: la verificación local lo rechaza y no hay acceso', async () => {
    const nav = new Navegador(base);
    await enrolarYActivar(nav, 'prueba.alterado');
    falso.modo.tokenAlterado = true;
    const r = await nav.post('/verificar', { codigo: falso.codigoPara(userRef('prueba.alterado')) });
    assert.equal(r.status, 401);
    assert.match(r.html, /Verificación no válida/);
    assert.notEqual((await nav.get('/panel')).url, '/panel');
  });

  test('tokens/validate caído tras verify correcto: acceso con verificación offline (JWKS en caché)', async () => {
    const nav = new Navegador(base);
    await enrolarYActivar(nav, 'prueba.offline');
    falso.modo.rutasCaidas = ['/api/v1/tokens/validate'];
    const r = await nav.post('/verificar', { codigo: falso.codigoPara(userRef('prueba.offline')) });
    assert.equal(r.url, '/panel');
    assert.match(r.html, /Validada sin red con JWKS en caché/);
  });

  test('código de recuperación: obliga a re-enrolar y no concede acceso directo', async () => {
    const nav = new Navegador(base);
    const id = await enrolarYActivar(nav, 'prueba.recupera');
    const [codigo] = [...falso.enrolamientos.get(id).codigos];
    await nav.get('/recuperar');
    const malo = await nav.post('/recuperar', { recuperacion: 'XXXX-YYYY' });
    assert.equal(malo.status, 401);
    const r = await nav.post('/recuperar', { recuperacion: codigo });
    assert.equal(r.url, '/enrolar');
    assert.match(r.html, /Vincule su autenticador/);
    assert.equal(portal.usuarios.buscar(ced('prueba.recupera')).factor, null);
    assert.notEqual((await nav.get('/panel')).url, '/panel');
  });

  test('centro de ayuda (/ayuda): preguntas frecuentes sobre TOTP, pérdida, cambio de teléfono, hora y desactivación', async () => {
    const nav = new Navegador(base);
    const r = await nav.get('/ayuda');
    assert.equal(r.status, 200);
    assert.match(r.html, /Centro de ayuda sobre el segundo factor/);
    assert.match(r.html, /Perdí mi teléfono/);
    assert.match(r.html, /Cambié de teléfono/);
    assert.match(r.html, /El código no funciona/);
    assert.match(r.html, /desactivar o renovar el segundo factor/i);
    assert.match(r.cabeceras.get('content-security-policy') ?? '', /default-src 'none'/);
  });
});

test('cédula: normalización, formato y seudónimo', () => {
  assert.equal(normalizarCedula('V', '12.345.678'), 'V12345678');
  assert.equal(normalizarCedula('V', '12345678'), 'V12345678');
  assert.equal(normalizarCedula('V', 'E-81.234.567'), 'E81234567');
  assert.equal(normalizarCedula('e', ' 123456 '), 'E123456');
  assert.equal(normalizarCedula('V', '123.456.789'), 'V123456789');
  for (const mala of ['', '12345', '1234567890', '12.34.5678', '0123456', 'V-12-345-678', 'J-12345678']) assert.equal(normalizarCedula('V', mala), null, mala);
  assert.equal(normalizarCedula('J', '12345678'), null);
  assert.equal(formatearCedula('V12345678'), 'V-12.345.678');
  assert.equal(formatearCedula('E123456'), 'E-123.456');
  const s = 'x'.repeat(32);
  assert.equal(seudonimo('V12345678', s), seudonimo('V12345678', s));
  assert.notEqual(seudonimo('V12345678', s), seudonimo('V12345678', 'y'.repeat(32)));
  assert.doesNotMatch(seudonimo('V12345678', s), /12345678/);
  assert.throws(() => seudonimo('V12345678', 'corto'));
  assert.ok(USUARIOS_DEMO.every((u) => normalizarCedula('V', u.cedula)));
});

test('parser .env propio', () => {
  const env = parsearEnv([
    '# comentario', 'A=1', 'export B = "con espacios # no comentario"', "C='literal $X'", 'D=valor # comentario', 'mal linea', 'E=',
  ].join('\n'));
  assert.deepEqual(env, { A: '1', B: 'con espacios # no comentario', C: 'literal $X', D: 'valor', E: '' });
});
