// Portal de Trámites + verificación humana (Reto 2): el portal hace de intermediario con el servicio Captcha
// y valida el token en el servidor antes de comprobar la contraseña.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { crearServicioFalso } from '../../sdk/testing/servicio-falso.js';
import { configuracion } from '../src/config.js';
import { crearPortal } from '../src/portal.js';
import { generarUsuarios, USUARIOS_DEMO } from '../src/usuarios.js';

const CLAVE = 'Tramites-Demo-2026';
const SECRETO = 'secreto-del-portal-de-prueba';

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

/** Servicio Captcha falso: un reto fijo, un token por verificación y validación de un solo uso. */
function captchaFalso() {
  const tokens = new Set();
  let n = 0;
  const srv = createServer(async (req, res) => {
    let cuerpo = '';
    for await (const t of req) cuerpo += t;
    const d = JSON.parse(cuerpo || '{}');
    const json = (s, o) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.url === '/api/captcha/challenge') return json(200, { challenge_id: 'reto-1', prefix: 'abc', difficulty: 1, min_solve_ms: 0 });
    if (req.url === '/api/captcha/verify') {
      if (d.challenge_id !== 'reto-1' || !d.nonce || d.hp) return json(400, { success: false });
      const t = `tok-${++n}`; tokens.add(t); return json(200, { success: true, token: t });
    }
    if (req.url === '/api/captcha/validate-token') {
      if (d.secret_key !== SECRETO || !tokens.delete(d.token)) return json(400, { valid: false });
      return json(200, { valid: true });
    }
    return json(404, {});
  });
  return {
    iniciar: () => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${srv.address().port}`))),
    detener: () => new Promise((r) => srv.close(r)),
  };
}

describe('Portal con verificación humana (Reto 2) antes del segundo factor', () => {
  const totp = crearServicioFalso({});
  const captcha = captchaFalso();
  let portal; let base; let dir;

  before(async () => {
    const urlTotp = await totp.iniciar();
    const urlCaptcha = await captcha.iniciar();
    dir = mkdtempSync(join(tmpdir(), 'portal-captcha-'));
    await generarUsuarios(join(dir, 'usuarios.json'), USUARIOS_DEMO);
    const config = configuracion({
      TOTP_BASE_URL: urlTotp, TOTP_CLIENT_ID: totp.clientId, TOTP_CLIENT_SECRET: totp.clientSecret, TOTP_TIMEOUT_MS: '500',
      PORTAL_USUARIOS: join(dir, 'usuarios.json'), PORTAL_TLS_CERT: join(dir, 'x.crt'), PORTAL_TLS_KEY: join(dir, 'x.key'),
      PORTAL_CAPTCHA_URL: urlCaptcha, PORTAL_CAPTCHA_SECRETO: SECRETO, PORTAL_CAPTCHA_TIMEOUT_MS: '500',
    });
    portal = await crearPortal({ config });
    base = await portal.iniciar(0, '127.0.0.1');
  });

  after(async () => {
    await portal.detener(); await totp.detener(); await captcha.detener();
    rmSync(dir, { recursive: true, force: true });
  });

  const ingreso = { nacionalidad: 'V', cedula: '10.000.001', contrasena: CLAVE };

  test('el formulario de ingreso carga la verificación humana desde el propio portal', async () => {
    const nav = new Navegador(base);
    const r = await nav.get('/ingresar');
    assert.match(r.html, /data-captcha/);
    assert.match(r.html, /<script src="\/publico\/captcha\.js" defer><\/script>/);
    const js = await fetch(`${base}/publico/captcha.js`);
    assert.equal(js.status, 200);
  });

  test('sin token de verificación humana no se comprueba la contraseña', async () => {
    const nav = new Navegador(base);
    await nav.get('/ingresar');
    const r = await nav.post('/ingresar', ingreso);
    assert.equal(r.status, 400);
    assert.match(r.html, /Verificación humana no superada/);
  });

  test('reto → verificación → token válido: pasa al segundo factor; el token no se reutiliza', async () => {
    const nav = new Navegador(base);
    await nav.get('/ingresar');
    const reto = JSON.parse((await nav.post('/captcha/reto', {})).html);
    assert.equal(reto.prefix, 'abc');
    const v = JSON.parse((await nav.post('/captcha/verificar', { challenge_id: reto.challenge_id, nonce: '7', hp: '' })).html);
    assert.match(v.token, /^tok-/);
    const r = await nav.post('/ingresar', { ...ingreso, captcha_token: v.token });
    assert.ok(['/enrolar', '/verificar'].includes(r.url), `redirige al segundo factor (${r.url})`);

    const otro = new Navegador(base);
    await otro.get('/ingresar');
    const repetido = await otro.post('/ingresar', { ...ingreso, captcha_token: v.token });
    assert.equal(repetido.status, 400, 'un token ya usado se rechaza');
  });

  test('el campo trampa (honeypot) relleno no obtiene token', async () => {
    const nav = new Navegador(base);
    await nav.get('/ingresar');
    const r = await nav.post('/captcha/verificar', { challenge_id: 'reto-1', nonce: '7', hp: 'soy-un-bot' });
    assert.equal(r.status, 400);
  });
});
