// Pruebas del SDK contra el servicio falso local (node:http). Sin dependencias.

import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { inspect } from 'node:util';
import {
  crearClienteTotp, verificarTokenLocal, crearCacheJwks, ErrorTotp, decodificarSinVerificar, claveDeOtpauth, esClientIpValida,
} from '../src/index.js';
import { crearServicioFalso } from '../testing/servicio-falso.js';

const ISS = 'https://totp.soberano.local';

/** Enrola y activa un usuario en el servicio falso; devuelve el enrollmentId. */
async function enrolarActivo(cliente, falso, userRef) {
  const e = await cliente.enrolar(userRef);
  await cliente.activar(e.enrollmentId, falso.codigoDeEnrolamiento(e.enrollmentId));
  // El código de activación ya quedó consumido (anti-replay): el siguiente verify usa el paso +1.
  return e.enrollmentId;
}

describe('SDK TOTP soberano', () => {
  const falso = crearServicioFalso();
  let baseUrl;
  /** @type {ReturnType<typeof crearClienteTotp>} */
  let cliente;
  const trazas = [];

  before(async () => {
    baseUrl = await falso.iniciar();
    cliente = crearClienteTotp({
      baseUrl, clientId: falso.clientId, clientSecret: falso.clientSecret, timeoutMs: 400, issuer: ISS, alTrazar: (t) => trazas.push(t),
    });
  });
  after(async () => { cliente.cerrar(); await falso.detener(); });
  beforeEach(() => {
    Object.assign(falso.modo, { caido: false, fallos503: 0, retardoMs: 0, retardosPendientes: null, cortes: 0, cortesTrasProcesar: 0 });
    falso.registro.length = 0;
    trazas.length = 0;
  });

  test('flujo completo: enrolar, activar, verificar y validar token', async () => {
    const e = await cliente.enrolar('ref-flujo', { etiquetaCuenta: 'Portal de prueba' });
    assert.match(e.enrollmentId, /^[0-9a-f-]{36}$/);
    assert.equal(e.estado, 'pendiente');
    assert.ok(e.otpauthUri.startsWith('otpauth://totp/'));
    assert.match(e.claveManual, /^[A-Z2-7]+$/);
    assert.ok(e.qrSvg.startsWith('<svg'));

    const a = await cliente.activar(e.enrollmentId, falso.codigoDeEnrolamiento(e.enrollmentId));
    assert.equal(a.estado, 'activo');
    assert.equal(a.codigosRecuperacion.length, 10);

    const v = await cliente.verificar('ref-flujo', falso.codigoPara('ref-flujo', 1));
    assert.equal(v.aprobado, true);
    assert.deepEqual(v.riesgo, { nivel: 'LOW' }, 'solo el nivel de riesgo');
    assert.equal(decodificarSinVerificar(v.token).claims.aud, falso.clientId);

    const local = await cliente.verificarTokenLocal(v.token);
    assert.equal(local.valido, true);
    assert.deepEqual(local.claims.amr, ['otp']);

    const remoto = await cliente.validarToken(v.token);
    assert.equal(remoto.valido, true);
    const segunda = await cliente.validarToken(v.token);
    assert.equal(segunda.valido, false, 'el jti es de un solo uso');
  });

  test('reintento idempotente ante 503: misma Idempotency-Key en ambos intentos', async () => {
    await enrolarActivo(cliente, falso, 'ref-503');
    falso.registro.length = 0;
    falso.modo.fallos503 = 1;
    const v = await cliente.verificar('ref-503', falso.codigoPara('ref-503', 1), { idempotencyKey: 'clave-fija-123' });
    assert.equal(v.aprobado, true);
    const intentos = falso.registro.filter((r) => r.ruta === '/api/v1/verify');
    assert.equal(intentos.length, 2);
    assert.deepEqual(intentos.map((r) => r.idempotencyKey), ['clave-fija-123', 'clave-fija-123']);
    assert.deepEqual(trazas.filter((t) => t.operacion === 'verificar').map((t) => t.status), [503, 200]);
  });

  test('reintento idempotente ante respuesta perdida: genera la clave y el servidor no procesa dos veces', async () => {
    await enrolarActivo(cliente, falso, 'ref-corte');
    falso.registro.length = 0;
    falso.modo.cortesTrasProcesar = 1; // el servidor acepta el código pero la respuesta no llega
    const v = await cliente.verificar('ref-corte', falso.codigoPara('ref-corte', 1));
    assert.equal(v.aprobado, true, 'sin idempotencia el reintento sería un replay y fallaría');
    const intentos = falso.registro.filter((r) => r.ruta === '/api/v1/verify');
    assert.equal(intentos.length, 2);
    assert.ok(intentos[0].idempotencyKey);
    assert.equal(intentos[0].idempotencyKey, intentos[1].idempotencyKey);
    assert.equal(intentos[1].repetida, true);
  });

  test('servicio caído (503 persistente): ErrorTotp tipado, nunca aprobado', async () => {
    falso.modo.caido = true;
    await assert.rejects(cliente.verificar('ref-x', '123456'), (e) => {
      assert.ok(e instanceof ErrorTotp);
      assert.equal(e.status, 503);
      assert.equal(e.codigo, 'SERVICE_UNAVAILABLE');
      assert.equal(e.reintentarEn, 5);
      assert.equal(e.servicioNoDisponible, true);
      return true;
    });
    assert.equal(falso.registro.length, 2, 'un intento + un reintento');
  });

  test('tiempo agotado: reintenta una vez y lanza TIEMPO_AGOTADO', async () => {
    falso.modo.retardoMs = 1500;
    const t0 = Date.now();
    await assert.rejects(cliente.verificar('ref-lento', '123456'), (e) => {
      assert.equal(e.codigo, 'TIEMPO_AGOTADO');
      assert.equal(e.status, null);
      assert.equal(e.servicioNoDisponible, true);
      return true;
    });
    const ms = Date.now() - t0;
    assert.ok(ms < 1400, `debe respetar el plazo por intento (tardó ${ms} ms)`);
    assert.equal(falso.registro.length, 2);
  });

  test('tiempo agotado solo en el primer intento: el reintento con la misma clave aprueba', async () => {
    await enrolarActivo(cliente, falso, 'ref-lento-1');
    falso.registro.length = 0;
    Object.assign(falso.modo, { retardoMs: 800, retardosPendientes: 1 });
    const v = await cliente.verificar('ref-lento-1', falso.codigoPara('ref-lento-1', 1));
    assert.equal(v.aprobado, true);
    const [a, b] = falso.registro;
    assert.equal(a.idempotencyKey, b.idempotencyKey);
  });

  test('error de red (conexión rechazada): ERROR_RED', async () => {
    const libre = await puertoLibre();
    const c = crearClienteTotp({ baseUrl: `http://127.0.0.1:${libre}`, clientId: 'a', clientSecret: 'b', timeoutMs: 300 });
    await assert.rejects(c.verificar('ref', '123456'), (e) => e instanceof ErrorTotp && e.codigo === 'ERROR_RED' && e.status === null);
    c.cerrar();
  });

  test('código incorrecto: 401 tipado y sin reintento', async () => {
    await enrolarActivo(cliente, falso, 'ref-malo');
    falso.registro.length = 0;
    await assert.rejects(cliente.verificar('ref-malo', '000000'), (e) => {
      assert.equal(e.status, 401);
      assert.equal(e.codigo, 'VERIFICATION_FAILED');
      assert.equal(e.rechazado, true);
      assert.equal(e.servicioNoDisponible, false);
      return true;
    });
    assert.equal(falso.registro.length, 1, '401 no se reintenta');
  });

  test('bloqueo tras intentos fallidos: 429 con reintentarEn', async () => {
    await enrolarActivo(cliente, falso, 'ref-bloqueo');
    for (let i = 0; i < 4; i++) await assert.rejects(cliente.verificar('ref-bloqueo', '000000'));
    await assert.rejects(cliente.verificar('ref-bloqueo', '000000'), (e) => {
      assert.equal(e.status, 429);
      assert.equal(e.bloqueado, true);
      assert.ok(e.reintentarEn > 0);
      return true;
    });
  });

  test('entrada inválida se rechaza sin llamar al servicio', async () => {
    await assert.rejects(cliente.verificar('ref', '12ab'), (e) => e.codigo === 'ENTRADA_INVALIDA');
    for (const ref of ['', 'lab\u0000x', 'a\u001b[31m', ' inicio', 'fin ', 'a\u202eb', 'a\u200bb', 'x'.repeat(129), 7]) {
      await assert.rejects(cliente.verificar(ref, '123456'), (e) => e.codigo === 'ENTRADA_INVALIDA', JSON.stringify(ref));
    }
    for (const ip of ['999.1.1.1', '01.2.3.4', 'fe80::1%eth0', '[::1]', '1.2.3.4:80', 'localhost', '', 5]) {
      await assert.rejects(cliente.verificar('ref', '123456', { clientIp: ip }), (e) => e.codigo === 'ENTRADA_INVALIDA', JSON.stringify(ip));
      await assert.rejects(cliente.recuperar('ref', 'AAAA-BBBB', { clientIp: ip }), (e) => e.codigo === 'ENTRADA_INVALIDA');
      await assert.rejects(cliente.activar('e1', '123456', { clientIp: ip }), (e) => e.codigo === 'ENTRADA_INVALIDA');
      await assert.rejects(cliente.resincronizar('e1', '123456', '654321', { clientIp: ip }), (e) => e.codigo === 'ENTRADA_INVALIDA');
    }
    assert.equal(falso.registro.length, 0);
  });

  test('clientIp viaja como client_ip en verificar, recuperar, activar y resincronizar', async () => {
    const e = await cliente.enrolar('ref-ip');
    await cliente.activar(e.enrollmentId, falso.codigoDeEnrolamiento(e.enrollmentId), { clientIp: '203.0.113.7' });
    await cliente.verificar('ref-ip', falso.codigoPara('ref-ip', 1), { clientIp: '2001:db8::5' });
    await cliente.resincronizar(e.enrollmentId, falso.codigoPara('ref-ip', 3), falso.codigoPara('ref-ip', 4), { clientIp: '::ffff:198.51.100.9' });
    await assert.rejects(cliente.recuperar('ref-ip', 'AAAA-BBBB', { clientIp: '198.51.100.10' }), (er) => er.status === 401);
    await cliente.verificar('ref-ip', falso.codigoPara('ref-ip', 5)).catch(() => {});
    const porRuta = falso.registro.filter((r) => r.metodo === 'POST').map((r) => [r.ruta.replace(/[0-9a-f-]{36}/, ':id'), r.clientIp]);
    assert.deepEqual(porRuta, [
      ['/api/v1/enrollments', null],
      ['/api/v1/enrollments/:id/activate', '203.0.113.7'],
      ['/api/v1/verify', '2001:db8::5'],
      ['/api/v1/enrollments/:id/resync', '198.51.100.9'],
      ['/api/v1/recovery', '198.51.100.10'],
      ['/api/v1/verify', null],
    ]);
  });

  test('esClientIpValida: IPv4/IPv6 estrictas', () => {
    for (const ip of ['1.2.3.4', '255.255.255.255', '::1', '2001:db8::1', '::ffff:1.2.3.4']) assert.equal(esClientIpValida(ip), true, ip);
    for (const ip of ['1.2.3', '256.1.1.1', '01.1.1.1', 'fe80::1%lo', ' ::1', 'g::1', null]) assert.equal(esClientIpValida(ip), false, String(ip));
  });

  test('credenciales de app incorrectas: 401 UNAUTHORIZED', async () => {
    const c = crearClienteTotp({ baseUrl, clientId: falso.clientId, clientSecret: 'otro', timeoutMs: 400 });
    await assert.rejects(c.enrolar('ref-y'), (e) => e.status === 401 && e.codigo === 'UNAUTHORIZED');
    c.cerrar();
  });

  test('falla cerrado: 200 sin verified === true no aprueba', async () => {
    const s = await servidorFijo(200, { verified: 'true', token: 'a.b.c' });
    const c = crearClienteTotp({ baseUrl: s.url, clientId: 'a', clientSecret: 'b', timeoutMs: 300 });
    await assert.rejects(c.verificar('ref', '123456'), (e) => e.codigo === 'RESPUESTA_INVALIDA');
    c.cerrar(); await s.cerrar();
  });

  test('falla cerrado: cuerpo no JSON en 200', async () => {
    const s = await servidorFijo(200, '<html>proxy</html>');
    const c = crearClienteTotp({ baseUrl: s.url, clientId: 'a', clientSecret: 'b', timeoutMs: 300 });
    await assert.rejects(c.verificar('ref', '123456'), (e) => e.codigo === 'RESPUESTA_INVALIDA' && e.servicioNoDisponible);
    c.cerrar(); await s.cerrar();
  });

  test('429 genérico del detector (contracts/mocks/verify-anomaly-blocked.json): bloqueado con reintentarEn', async () => {
    const s = await servidorFijo(429, { error: 'TOO_MANY_REQUESTS', message: 'Demasiados intentos. Intente más tarde.', retry_after_seconds: 300 });
    const c = crearClienteTotp({ baseUrl: s.url, clientId: 'a', clientSecret: 'b', timeoutMs: 300 });
    await assert.rejects(c.verificar('ref', '123456'), (e) => e.codigo === 'TOO_MANY_REQUESTS' && e.reintentarEn === 300 && e.bloqueado);
    c.cerrar(); await s.cerrar();
  });

  test('formato heredado (errorCode / retryAfterSeconds) se sigue entendiendo', async () => {
    const s = await servidorFijo(429, { errorCode: 'TOO_MANY_REQUESTS', message: 'Bloqueado', retryAfterSeconds: 30 });
    const c = crearClienteTotp({ baseUrl: s.url, clientId: 'a', clientSecret: 'b', timeoutMs: 300 });
    await assert.rejects(c.verificar('ref', '123456'), (e) => e.codigo === 'TOO_MANY_REQUESTS' && e.reintentarEn === 30);
    c.cerrar(); await s.cerrar();
  });

  test('nunca expone el secreto ni el código en trazas, errores o inspección', async () => {
    falso.modo.caido = true;
    let error;
    try { await cliente.verificar('ref-secreto', '987654'); } catch (e) { error = e; }
    const textos = [inspect(cliente), JSON.stringify(cliente), JSON.stringify(error), String(error), JSON.stringify(trazas)].join('\n');
    assert.ok(!textos.includes(falso.clientSecret));
    assert.ok(!textos.includes('987654'));
  });

  test('configuración: HTTP sin TLS fuera de localhost se rechaza', () => {
    assert.throws(() => crearClienteTotp({ baseUrl: 'http://servicio.ejemplo', clientId: 'a', clientSecret: 'b' }), (e) => e.codigo === 'CONFIGURACION');
    assert.throws(() => crearClienteTotp({ baseUrl: 'https://x', clientId: 'a' }), (e) => e.codigo === 'CONFIGURACION');
  });

  test('resincronizar, recuperar y revocar', async () => {
    const id = await enrolarActivo(cliente, falso, 'ref-ops');
    const r = await cliente.resincronizar(id, falso.codigoPara('ref-ops', 2), falso.codigoPara('ref-ops', 3));
    assert.equal(r.resincronizado, true);
    assert.equal(r.derivaPasos, 3);

    const id2 = await enrolarActivo(cliente, falso, 'ref-rec');
    const e = falso.enrolamientos.get(id2);
    const [codigo] = [...e.codigos];
    const rec = await cliente.recuperar('ref-rec', codigo);
    assert.deepEqual(rec, { recuperado: true, debeReenrolar: true, codigosRestantes: 9 });

    const rev = await cliente.revocar(id);
    assert.equal(rev.estado, 'revocado');
  });

  test('dispositivos (issue #47): enrolar con dispositivo, consultar y desvincular', async () => {
    const e = await cliente.enrolar('ref-disp', { dispositivo: { nombre: 'Teléfono de trabajo', plataforma: 'android' } });
    assert.match(e.dispositivoId, /^dev_[A-Za-z0-9_-]{22}$/);
    assert.deepEqual(e.aprovisionamiento, { otpauthUri: e.otpauthUri, expiraEn: e.expiraEn, dispositivoId: e.dispositivoId, huellaCaSha256: null });
    const enviado = falso.enrolamientos.get(e.enrollmentId).dispositivo;
    assert.deepEqual([enviado.nombre, enviado.plataforma], ['Teléfono de trabajo', 'android'], 'el SDK envía device { name, platform }');

    await cliente.activar(e.enrollmentId, falso.codigoDeEnrolamiento(e.enrollmentId));
    assert.equal((await cliente.verificar('ref-disp', falso.codigoPara('ref-disp', 1))).aprobado, true);
    const d = await cliente.dispositivo(e.enrollmentId);
    assert.equal(d.dispositivoId, e.dispositivoId);
    assert.equal(d.nombre, 'Teléfono de trabajo');
    assert.equal(d.plataforma, 'android');
    assert.equal(d.estadoEnrolamiento, 'activo');
    assert.ok(d.ultimoUso);
    assert.equal(d.desvinculadoEn, null);

    const x = await cliente.desvincularDispositivo(e.enrollmentId);
    assert.equal(x.estado, 'revocado');
    assert.equal(x.dispositivoId, e.dispositivoId);
    assert.ok(x.desvinculadoEn);
    await assert.rejects(cliente.verificar('ref-disp', falso.codigoPara('ref-disp', 2)), (err) => err instanceof ErrorTotp && err.status === 401);

    // Sin dispositivo, la respuesta no cambia; entradas inválidas se rechazan sin llamar al servicio.
    const sin = await cliente.enrolar('ref-sin-disp');
    assert.equal(sin.dispositivoId, undefined);
    await assert.rejects(cliente.dispositivo(sin.enrollmentId), (err) => err.status === 404);
    for (const dispositivo of [{ nombre: '' }, { nombre: 'x'.repeat(65) }, { nombre: 'ok', plataforma: 'ios' }, null]) {
      await assert.rejects(cliente.enrolar('ref-x', { dispositivo }), (err) => err instanceof ErrorTotp && err.status === null);
    }
  });

  test('claveDeOtpauth extrae la clave Base32', () => {
    assert.equal(claveDeOtpauth('otpauth://totp/X:y?secret=jbswy3dpehpk3pxp&issuer=X'), 'JBSWY3DPEHPK3PXP');
    assert.equal(claveDeOtpauth('https://no'), null);
  });
});

describe('verificación local (offline) con JWKS', () => {
  const falso = crearServicioFalso();
  let baseUrl;

  before(async () => { baseUrl = await falso.iniciar(); });
  after(() => falso.detener());

  test('valida offline con la JWKS en caché cuando el servicio cae', async () => {
    const cliente = crearClienteTotp({ baseUrl, clientId: falso.clientId, clientSecret: falso.clientSecret, issuer: ISS, timeoutMs: 300 });
    const { token } = falso.firmarToken();
    assert.equal((await cliente.verificarTokenLocal(token)).valido, true); // descarga y cachea la JWKS
    falso.modo.caido = true;
    falso.registro.length = 0;
    const r = await cliente.verificarTokenLocal(token);
    assert.equal(r.valido, true, 'se valida sin red');
    assert.equal(falso.registro.length, 0, 'no hace falta llamar al servicio');
    falso.modo.caido = false;
    cliente.cerrar();
  });

  test('TTL vencido + servicio caído: usa la copia vencida (sigue validando)', async () => {
    let ahora = 1_000_000;
    let caido = false;
    const jwks = falso.jwks();
    const cache = crearCacheJwks({ obtener: async () => { if (caido) throw new Error('caído'); return jwks; }, reloj: () => ahora });
    const { token } = falso.firmarToken();
    assert.equal((await verificarTokenLocal(token, { jwks: cache, issuer: ISS, audience: falso.clientId })).valido, true);
    caido = true;
    ahora += 11 * 60 * 1000;
    assert.equal((await verificarTokenLocal(token, { jwks: cache, issuer: ISS, audience: falso.clientId })).valido, true);
  });

  test('kid desconocido provoca refresco de la JWKS (rotación de claves)', async () => {
    let descargas = 0;
    let ahora = 5_000_000;
    const cache = crearCacheJwks({ obtener: async () => { descargas++; return falso.jwks(); }, reloj: () => ahora });
    const t1 = falso.firmarToken().token;
    assert.equal((await verificarTokenLocal(t1, { jwks: cache, issuer: ISS, audience: falso.clientId })).valido, true);
    assert.equal(descargas, 1);
    falso.rotarClave();
    ahora += 31 * 1000;
    const t2 = falso.firmarToken().token;
    assert.equal((await verificarTokenLocal(t2, { jwks: cache, issuer: ISS, audience: falso.clientId })).valido, true);
    assert.equal(descargas, 2, 'refrescó al ver el kid nuevo');
    // Un kid inventado no provoca otra descarga inmediata (freno anti-avalancha).
    const raro = t2.replace(/^[^.]+/, Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid: 'inventado' })).toString('base64url'));
    assert.equal((await verificarTokenLocal(raro, { jwks: cache, issuer: ISS, audience: falso.clientId })).motivo, 'kid');
    assert.equal(descargas, 2);
  });

  test('token alterado se rechaza (claims, firma, alg none, aud, iss, exp, amr)', async () => {
    const jwks = falso.jwks();
    const o = { jwks, issuer: ISS, audience: falso.clientId };
    const { token } = falso.firmarToken();
    const [h, p, f] = token.split('.');
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());

    const pAlterado = Buffer.from(JSON.stringify({ ...claims, sub: 'otro-usuario' })).toString('base64url');
    assert.equal((await verificarTokenLocal(`${h}.${pAlterado}.${f}`, o)).motivo, 'firma');

    const fAlterada = (f[0] === 'A' ? 'B' : 'A') + f.slice(1);
    assert.equal((await verificarTokenLocal(`${h}.${p}.${fAlterada}`, o)).valido, false);

    const hNone = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    assert.equal((await verificarTokenLocal(`${hNone}.${p}.`, o)).valido, false);
    const hHs = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: jwks.keys[0].kid })).toString('base64url');
    assert.equal((await verificarTokenLocal(`${hHs}.${p}.${f}`, o)).motivo, 'alg');

    assert.equal((await verificarTokenLocal(token, { ...o, audience: 'otra-app' })).motivo, 'aud');
    assert.equal((await verificarTokenLocal(token, { ...o, issuer: 'https://falso' })).motivo, 'iss');
    assert.equal((await verificarTokenLocal(token, { ...o, ahora: Date.now() + 10 * 60 * 1000 })).motivo, 'exp');
    assert.equal((await verificarTokenLocal(falso.firmarToken({ amr: ['pwd'] }).token, o)).motivo, 'amr');
    assert.equal((await verificarTokenLocal('basura', o)).motivo, 'formato');
    assert.equal((await verificarTokenLocal(token, { ...o, jwks: { keys: [] } })).motivo, 'kid');
    assert.equal((await verificarTokenLocal(token, o)).valido, true, 'el original sigue siendo válido');
  });

  test('nunca lanza: configuración ausente o jwks que explota', async () => {
    const { token } = falso.firmarToken();
    assert.equal((await verificarTokenLocal(token, /** @type {any} */ ({}))).valido, false);
    const r = await verificarTokenLocal(token, { jwks: { obtenerClave: async () => { throw new Error('x'); } }, issuer: ISS, audience: falso.clientId });
    assert.equal(r.valido, false);
  });
});

// ---------- utilidades de prueba ----------

function puertoLibre() {
  return new Promise((r) => {
    const s = http.createServer();
    s.listen(0, '127.0.0.1', () => { const { port } = /** @type {any} */ (s.address()); s.close(() => r(port)); });
  });
}

async function servidorFijo(status, cuerpo) {
  const s = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(typeof cuerpo === 'string' ? cuerpo : JSON.stringify(cuerpo));
    });
  });
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const { port } = /** @type {any} */ (s.address());
  return { url: `http://127.0.0.1:${port}`, cerrar: () => new Promise((r) => { s.closeAllConnections(); s.close(r); }) };
}
