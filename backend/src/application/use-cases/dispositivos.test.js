// Pruebas de la vinculación y revocación de dispositivos (issue #47, M8) sobre SQLite en memoria.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { abrirBaseDatos } from '../../infrastructure/persistence/db.js';
import { crearRepositorios } from '../../infrastructure/persistence/repositorios.js';
import { crearVault } from '../../core/vault/vault.js';
import { generateTotp } from '../../core/totp/totp.js';
import { base32Decode } from '../../core/totp/base32.js';
import { hashSecreto } from '../../security/index.js';
import { crearBitacora, crearMetricas } from '../../audit/index.js';
import { crearFirmas } from '../../infrastructure/config/firmas.js';
import { crearCasosDeUso } from './index.js';
import { sanearNombreDispositivo, PATRON_ID_DISPOSITIVO, dispositivoPublico } from './dispositivos.js';

const NEUTRA = { riskScore: 5, level: 'bajo', action: 'permitir', reasons: ['ok'], inferenceMs: 0.1 };
const PERIODO = 30_000;
const HUELLA = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0').toUpperCase()).join(':');

function montar(configExtra = {}) {
  const db = abrirBaseDatos(':memory:');
  const repos = crearRepositorios(db);
  const vault = crearVault({ llaves: { v1: randomBytes(32) }, versionActiva: 'v1' });
  const estado = { t: Date.parse('2026-11-26T12:00:05.000Z') };
  const reloj = () => estado.t;
  const firmas = crearFirmas({ repos, vault });
  firmas.recargar();
  const bitacora = crearBitacora({
    ultimo: () => repos.auditLog.ultimo(), insertar: (f) => repos.auditLog.insertar(f).id, ahora: () => new Date(estado.t).toISOString(),
  });
  const politica = { algoritmo: 'SHA256', digitos: 6, periodo: 30, ventana: 1, max_intentos: 5, modo_heuristica: 'bloqueo' };
  const app = repos.apps.crear({ nombre: 'Portal', client_id: 'portal', secret_hash: hashSecreto('s1'), ...politica });
  const otra = repos.apps.crear({ nombre: 'Otra', client_id: 'otra', secret_hash: hashSecreto('s2'), ...politica });
  const config = {
    userRefPepper: 'pepper', ipPepperSemilla: 'semilla-ip', emisorTotp: 'SoberanoTOTP', emisorJwt: 'https://totp.soberano.local',
    ttlJwtSegundos: 300, minutosPendiente: 10, ...configExtra,
  };
  const casos = crearCasosDeUso({
    repos, vault, firmas, detector: { evaluar: () => NEUTRA }, bitacora, metricas: crearMetricas({ ahora: reloj }), config, reloj, db,
  });
  return { db, repos, casos, estado, app, otra, ctx: { app, ip: '10.0.0.7' }, ctxOtra: { app: otra, ip: '10.0.0.8' }, avanzar(ms) { estado.t += ms; } };
}

const semillaDeUri = (uri) => base32Decode(new URL(uri).searchParams.get('secret'));
const codigo = (semilla, t) => generateTotp(semilla, t, { algoritmo: 'SHA256', digitos: 6, periodo: 30 });
const eventos = (m, accion) => m.db.prepare('SELECT * FROM audit_log WHERE accion = ?').all(accion);

async function enrolarConDispositivo(m, device = { name: 'Teléfono de trabajo', platform: 'android' }, userRef = 'ciudadano-1') {
  const r = await m.casos.enrolar({ user_ref: userRef, device }, m.ctx);
  assert.equal(r.status, 201, JSON.stringify(r.cuerpo));
  return r;
}

describe('saneado del nombre visible', () => {
  test('quita controles e invisibles, colapsa espacios y recorta a 64', () => {
    assert.equal(sanearNombreDispositivo('  Mi\u0000 teléfono\u200B  \u00A0 nuevo\t'), 'Mi teléfono nuevo');
    assert.equal(sanearNombreDispositivo('Cafe\u0301'), 'Café'); // NFC
    assert.equal(sanearNombreDispositivo('\u202Egnp.exe'), 'gnp.exe'); // sin override bidi
    assert.equal([...sanearNombreDispositivo('ñ'.repeat(80))].length, 64);
    assert.equal(sanearNombreDispositivo('\u200B\u2060 \u3164'), null);
    assert.equal(sanearNombreDispositivo(42), null);
  });
});

describe('enrolar con dispositivo', () => {
  test('sin device la respuesta no cambia (compatibilidad)', async () => {
    const m = montar();
    const r = await m.casos.enrolar({ user_ref: 'sin-disp' }, m.ctx);
    assert.equal(r.status, 201);
    assert.equal(r.cuerpo.device_id, undefined);
    assert.equal(r.cuerpo.provisioning, undefined);
    assert.equal(m.db.prepare('SELECT COUNT(*) AS n FROM dispositivos').get().n, 0);
  });

  test('con device devuelve device_id y provisioning; guarda seudónimo, nombre saneado y plataforma', async () => {
    const m = montar();
    const r = await enrolarConDispositivo(m, { name: '  Teléfono\u200B  de   trabajo ', platform: 'android' });
    const c = r.cuerpo;
    assert.match(c.device_id, PATRON_ID_DISPOSITIVO);
    assert.deepEqual(Object.keys(c.provisioning).sort(), ['device_id', 'expires_at', 'otpauth_uri']);
    assert.equal(c.provisioning.otpauth_uri, c.otpauth_uri);
    assert.equal(c.provisioning.expires_at, c.expires_at);
    assert.equal(c.provisioning.device_id, c.device_id);
    assert.equal(r.cabeceras['Cache-Control'], 'no-store');
    const fila = m.repos.dispositivos.buscarPorEnrolamiento(c.enrollment_id);
    assert.deepEqual(
      { ...fila },
      { id: c.device_id, enrollment_id: c.enrollment_id, nombre: 'Teléfono de trabajo', plataforma: 'android', created_at: '2026-11-26T12:00:05.000Z', ultimo_uso: null, desvinculado_en: null },
    );
    const [ev] = eventos(m, 'enrolamiento.creado');
    assert.equal(JSON.parse(ev.detalle).device_id, c.device_id);
    assert.ok(!ev.detalle.includes('Teléfono'), 'el nombre visible no va a la bitácora');
  });

  test('plataforma por defecto "otro"; dos dispositivos nunca comparten id', async () => {
    const m = montar();
    const a = await enrolarConDispositivo(m, { name: 'PWA casa' }, 'u-a');
    const b = await enrolarConDispositivo(m, { name: 'PWA casa' }, 'u-b');
    assert.equal(m.repos.dispositivos.buscarPorEnrolamiento(a.cuerpo.enrollment_id).plataforma, 'otro');
    assert.notEqual(a.cuerpo.device_id, b.cuerpo.device_id);
  });

  test('con TLS_CA_PUBLIC_PATH añade ca_fingerprint_sha256; una huella mal formada se ignora', async () => {
    const m = montar({ caHuellaSha256: HUELLA });
    const r = await enrolarConDispositivo(m);
    assert.equal(r.cuerpo.provisioning.ca_fingerprint_sha256, HUELLA);
    const m2 = montar({ caHuellaSha256: 'no-es-huella' });
    const r2 = await enrolarConDispositivo(m2);
    assert.equal(r2.cuerpo.provisioning.ca_fingerprint_sha256, undefined);
  });

  test('device inválido → 400 y no crea nada', async () => {
    const m = montar();
    for (const device of [
      { name: '' }, { name: '\u200B\u200C' }, { name: 'x'.repeat(65) }, { name: 'ok', platform: 'ios' },
      { name: 'ok', imei: '356938035643809' }, { platform: 'android' }, 'telefono', null,
    ]) {
      const r = await m.casos.enrolar({ user_ref: 'u', device }, m.ctx);
      assert.equal(r.status, 400, JSON.stringify(device));
    }
    assert.equal(m.db.prepare('SELECT COUNT(*) AS n FROM enrollments').get().n, 0);
  });
});

describe('uso, consulta y desvinculación', () => {
  async function activo(m) {
    const r = await enrolarConDispositivo(m);
    const semilla = semillaDeUri(r.cuerpo.otpauth_uri);
    const id = r.cuerpo.enrollment_id;
    const act = await m.casos.activar({ id, cuerpo: { code: codigo(semilla, m.estado.t) } }, m.ctx);
    assert.equal(act.status, 200);
    return { id, semilla, deviceId: r.cuerpo.device_id };
  }

  test('activar y verificar actualizan last_used_at; un código incorrecto no', async () => {
    const m = montar();
    const { id, semilla } = await activo(m);
    let d = await m.casos.dispositivo({ id }, m.ctx);
    assert.equal(d.cuerpo.last_used_at, '2026-11-26T12:00:05.000Z');
    m.avanzar(5 * PERIODO);
    const v = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    assert.equal(v.status, 200);
    d = await m.casos.dispositivo({ id }, m.ctx);
    assert.equal(d.cuerpo.last_used_at, '2026-11-26T12:02:35.000Z');
    m.avanzar(PERIODO);
    const mal = await m.casos.verificar({ user_ref: 'ciudadano-1', code: '000000' === codigo(semilla, m.estado.t) ? '111111' : '000000' }, m.ctx);
    assert.equal(mal.status, 401);
    d = await m.casos.dispositivo({ id }, m.ctx);
    assert.equal(d.cuerpo.last_used_at, '2026-11-26T12:02:35.000Z');
  });

  test('GET device: esquema cerrado; 404 si es de otra app o no tiene dispositivo; 400 si no es UUID', async () => {
    const m = montar();
    const { id, deviceId } = await activo(m);
    const d = await m.casos.dispositivo({ id: id.toUpperCase() }, m.ctx);
    assert.equal(d.status, 200);
    assert.deepEqual(Object.keys(d.cuerpo).sort(), ['created_at', 'device_id', 'enrollment_estado', 'enrollment_id', 'last_used_at', 'name', 'platform', 'unlinked_at']);
    assert.equal(d.cuerpo.device_id, deviceId);
    assert.equal(d.cuerpo.enrollment_estado, 'activo');
    assert.equal(d.cuerpo.unlinked_at, null);
    assert.equal((await m.casos.dispositivo({ id }, m.ctxOtra)).status, 404);
    const sin = await m.casos.enrolar({ user_ref: 'sin' }, m.ctx);
    assert.equal((await m.casos.dispositivo({ id: sin.cuerpo.enrollment_id }, m.ctx)).status, 404);
    assert.equal((await m.casos.dispositivo({ id: 'no-uuid' }, m.ctx)).status, 400);
  });

  test('DELETE device revoca el enrolamiento; verify falla igual que con código incorrecto; idempotente', async () => {
    const m = montar();
    const { id, semilla, deviceId } = await activo(m);
    m.avanzar(2 * PERIODO);
    assert.equal((await m.casos.desvincularDispositivo({ id }, m.ctxOtra)).status, 404, 'otra app no puede');
    const r = await m.casos.desvincularDispositivo({ id }, m.ctx);
    assert.equal(r.status, 200);
    assert.deepEqual(r.cuerpo, { enrollment_id: id, device_id: deviceId, estado: 'revocado', revoked_at: '2026-11-26T12:01:05.000Z', unlinked_at: '2026-11-26T12:01:05.000Z' });
    assert.equal(m.repos.enrollments.buscarPorId(id).estado, 'revocado');

    const tras = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    const incorrecto = await m.casos.verificar({ user_ref: 'otro-usuario', code: '123456' }, m.ctx);
    assert.equal(tras.status, 401);
    assert.deepEqual(tras.cuerpo, incorrecto.cuerpo);

    m.avanzar(PERIODO);
    const otra = await m.casos.desvincularDispositivo({ id }, m.ctx);
    assert.deepEqual(otra.cuerpo, r.cuerpo, 'repetir conserva las fechas originales');
    assert.equal(eventos(m, 'dispositivo.desvinculado').length, 1);
    const revocados = eventos(m, 'enrolamiento.revocado');
    assert.equal(revocados.length, 1);
    assert.equal(JSON.parse(revocados[0].detalle).motivo, 'dispositivo_desvinculado');
    const d = await m.casos.dispositivo({ id }, m.ctx);
    assert.equal(d.cuerpo.enrollment_estado, 'revocado');
    assert.equal(d.cuerpo.unlinked_at, '2026-11-26T12:01:05.000Z');
  });

  test('revocar por otra vía marca unlinked_at con la fecha de revocación', async () => {
    const m = montar();
    const { id } = await activo(m);
    m.avanzar(PERIODO);
    await m.casos.revocar({ id }, m.ctx);
    const d = await m.casos.dispositivo({ id }, m.ctx);
    assert.equal(d.cuerpo.unlinked_at, m.repos.enrollments.buscarPorId(id).revoked_at);
    assert.equal(dispositivoPublico(null), null);
  });

  test('la consola lista el dispositivo y su último uso, y la revocación lo refleja', async () => {
    const m = montar();
    const { id, deviceId } = await activo(m);
    const admin = { id: 'a1', usuario: 'root', rol: 'Administrador' };
    const l = await m.casos.adminListarEnrolamientos({}, { admin });
    assert.equal(l.status, 200);
    const e = l.cuerpo.enrollments.find((x) => x.id === id);
    assert.equal(e.device.device_id, deviceId);
    assert.equal(e.device.name, 'Teléfono de trabajo');
    assert.equal(e.device.platform, 'android');
    assert.equal(e.last_used_at, e.device.last_used_at);
    const rv = await m.casos.adminRevocarEnrolamiento({ id }, { admin });
    assert.equal(rv.status, 200);
    assert.equal(rv.cuerpo.enrollment.device.unlinked_at, rv.cuerpo.enrollment.revoked_at);
    const sin = await m.casos.enrolar({ user_ref: 'sin' }, m.ctx);
    const l2 = await m.casos.adminListarEnrolamientos({}, { admin });
    assert.equal(l2.cuerpo.enrollments.find((x) => x.id === sin.cuerpo.enrollment_id).device, null);
  });

  test('la tabla no admite plataformas ni ids fuera del contrato (CHECK en la migración)', () => {
    const m = montar();
    m.db.prepare("INSERT INTO apps (id, nombre, client_id, secret_hash) VALUES ('x','x','x','x')").run();
    m.db.prepare(`INSERT INTO enrollments (id, app_id, user_ref_hash, algoritmo, digitos, seed_ct, seed_nonce, seed_auth_tag)
      VALUES ('e1','x','h','SHA256',6,'a','b','c')`).run();
    assert.throws(() => m.repos.dispositivos.crear({ id: 'dev_AAAAAAAAAAAAAAAAAAAAAA', enrollment_id: 'e1', nombre: 'x', plataforma: 'ios', created_at: 'now' }));
    assert.throws(() => m.repos.dispositivos.crear({ id: 'imei-356938035643809', enrollment_id: 'e1', nombre: 'x', plataforma: 'otro', created_at: 'now' }));
  });
});
