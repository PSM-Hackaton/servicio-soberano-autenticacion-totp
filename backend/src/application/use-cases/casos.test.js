// Pruebas de punta a punta de los casos de uso sobre SQLite en memoria, con reloj controlable,
// bóveda con llave aleatoria, par de firma generado y detector falso configurable.

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
import { crearCasosDeUso, puede } from './index.js';
import { crearFirmas } from '../../infrastructure/config/firmas.js';
import { entrenarDetectorPorDefecto } from '../../heuristics/index.js';
import { hashPepper, pepperDiario } from '../../core/vault/vault.js';

const NEUTRA = { riskScore: 5, level: 'bajo', action: 'permitir', reasons: ['Comportamiento dentro del patrón habitual'], inferenceMs: 0.4 };
const PERIODO = 30_000;

function montar({ config: configExtra = {}, detectorReal = null } = {}) {
  const db = abrirBaseDatos(':memory:');
  const repos = crearRepositorios(db);
  const vault = crearVault({ llaves: { v1: randomBytes(32) }, versionActiva: 'v1' });
  const estado = { t: Date.parse('2026-11-26T12:00:05.000Z') };
  const reloj = () => estado.t;
  const firmas = crearFirmas({ repos, vault });
  firmas.recargar();
  const detector = detectorReal ?? {
    respuesta: NEUTRA,
    llamadas: 0,
    evaluar() { this.llamadas++; return this.respuesta; },
  };
  const bitacora = crearBitacora({
    ultimo: () => repos.auditLog.ultimo(),
    insertar: (f) => repos.auditLog.insertar(f).id,
    ahora: () => new Date(estado.t).toISOString(),
  });
  const metricas = crearMetricas({ ahora: reloj });
  const politica = { algoritmo: 'SHA256', digitos: 6, periodo: 30, ventana: 1, max_intentos: 5, modo_heuristica: 'bloqueo' };
  const app = repos.apps.crear({ nombre: 'Portal de Trámites', client_id: 'portal', secret_hash: hashSecreto('secreto-portal'), ...politica });
  const otra = repos.apps.crear({ nombre: 'Reto 1', client_id: 'reto1', secret_hash: hashSecreto('secreto-reto1'), ...politica });
  const config = {
    userRefPepper: 'pepper-usuarios', ipPepperSemilla: 'semilla-ip', emisorTotp: 'SoberanoTOTP',
    emisorJwt: 'https://totp.soberano.local', ttlJwtSegundos: 300, minutosPendiente: 10, ...configExtra,
  };
  const casos = crearCasosDeUso({ repos, vault, firmas, detector, bitacora, metricas, config, reloj, db });
  return {
    db, repos, casos, detector, estado, app, otra, firmas, vault, metricas, bitacora, config,
    /** Reconstruye los casos de uso sobre la misma base (simula un reinicio del proceso). */
    reiniciar() {
      this.casos = crearCasosDeUso({ repos, vault, firmas, detector, bitacora, metricas: crearMetricas({ ahora: reloj }), config, reloj, db });
      return this.casos;
    },
    ctx: { app, ip: '10.0.0.7' },
    ctxOtra: { app: otra, ip: '10.0.0.8' },
    avanzar(ms) { estado.t += ms; },
  };
}

/** Semilla en claro a partir del URI otpauth (lo que haría la app autenticadora). */
function semillaDeUri(uri) {
  return base32Decode(new URL(uri).searchParams.get('secret'));
}

function codigo(semilla, t, pasos = 0) {
  return generateTotp(semilla, t + pasos * PERIODO, { algoritmo: 'SHA256', digitos: 6, periodo: 30 });
}

async function enrolarYActivar(m, userRef = 'ciudadano-1', ctx = m.ctx) {
  const enrol = await m.casos.enrolar({ user_ref: userRef, account_label: 'demo' }, ctx);
  assert.equal(enrol.status, 201);
  const semilla = semillaDeUri(enrol.cuerpo.otpauth_uri);
  const act = await m.casos.activar({ id: enrol.cuerpo.enrollment_id, cuerpo: { code: codigo(semilla, m.estado.t) } }, ctx);
  assert.equal(act.status, 200, JSON.stringify(act.cuerpo));
  m.avanzar(PERIODO); // el paso de la activación ya está consumido
  return { id: enrol.cuerpo.enrollment_id, semilla, recovery: act.cuerpo.recovery_codes, enrol, act };
}

const filaEnrol = (m, id) => m.repos.enrollments.buscarPorId(id);
const contarIntentos = (m, resultado) => m.db.prepare('SELECT COUNT(*) AS n FROM attempts WHERE resultado = ?').get(resultado).n;

describe('flujo integrador', () => {
  test('enrolar → activar → verificar → validarToken', async () => {
    const m = montar();
    const enrol = await m.casos.enrolar({ user_ref: 'ciudadano-1' }, m.ctx);
    assert.equal(enrol.status, 201);
    const c = enrol.cuerpo;
    assert.deepEqual(Object.keys(c).sort(), ['algoritmo', 'digitos', 'enrollment_id', 'estado', 'expires_at', 'otpauth_uri', 'periodo', 'qr_svg']);
    assert.equal(c.estado, 'pendiente');
    assert.match(c.otpauth_uri, /^otpauth:\/\/totp\/SoberanoTOTP:ciudadano-1\?secret=[A-Z2-7]+/);
    assert.match(c.qr_svg, /^<svg/);
    assert.equal(c.expires_at, new Date(m.estado.t + 10 * 60_000).toISOString());
    // Nunca se guarda user_ref en claro.
    const fila = filaEnrol(m, c.enrollment_id);
    assert.notEqual(fila.user_ref_hash, 'ciudadano-1');
    assert.match(fila.user_ref_hash, /^[0-9a-f]{64}$/);

    const semilla = semillaDeUri(c.otpauth_uri);
    const act = await m.casos.activar({ id: c.enrollment_id, cuerpo: { code: codigo(semilla, m.estado.t) } }, m.ctx);
    assert.equal(act.status, 200);
    assert.equal(act.cuerpo.estado, 'activo');
    assert.equal(act.cuerpo.recovery_codes.length, 10);
    assert.equal(m.repos.recoveryCodes.listarNoUsados(c.enrollment_id).length, 10);

    m.avanzar(PERIODO);
    const ver = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    assert.equal(ver.status, 200, JSON.stringify(ver.cuerpo));
    assert.equal(ver.cuerpo.verified, true);
    assert.equal(ver.cuerpo.drift_steps, 0);
    // Solo el nivel de riesgo: nunca puntuación, razones, acción ni umbrales del detector.
    assert.deepEqual(ver.cuerpo.risk, { level: 'LOW' });
    assert.equal(ver.cuerpo.kid, m.firmas.activa().kid);

    const val = await m.casos.validarToken({ token: ver.cuerpo.token }, m.ctx);
    assert.equal(val.status, 200);
    assert.equal(val.cuerpo.valid, true);
    assert.equal(val.cuerpo.jti, ver.cuerpo.jti);
    assert.equal(val.cuerpo.aud, 'portal');
    assert.equal(val.cuerpo.sub, fila.user_ref_hash);
    assert.deepEqual(val.cuerpo.amr, ['otp']);

    const jwks = await m.casos.jwks();
    assert.equal(jwks.cuerpo.keys.length, 1);
    assert.equal(jwks.cuerpo.keys[0].kid, ver.cuerpo.kid);
  });

  test('activar falla con código incorrecto, enrolamiento caducado o de otra app', async () => {
    const m = montar();
    const e = await m.casos.enrolar({ user_ref: 'ciudadano-1' }, m.ctx);
    const semilla = semillaDeUri(e.cuerpo.otpauth_uri);
    const id = e.cuerpo.enrollment_id;
    assert.equal((await m.casos.activar({ id, cuerpo: { code: '000000' } }, m.ctx)).status, 401);
    assert.equal((await m.casos.activar({ id, cuerpo: { code: codigo(semilla, m.estado.t) } }, m.ctxOtra)).status, 401);
    assert.equal((await m.casos.activar({ id, cuerpo: { code: '12', extra: 1 } }, m.ctx)).status, 400);
    m.avanzar(11 * 60_000);
    assert.equal((await m.casos.activar({ id, cuerpo: { code: codigo(semilla, m.estado.t) } }, m.ctx)).status, 401);
  });

  test('activar un segundo enrolamiento revoca el anterior', async () => {
    const m = montar();
    const primero = await enrolarYActivar(m);
    const segundo = await enrolarYActivar(m);
    assert.equal(filaEnrol(m, primero.id).estado, 'revocado');
    assert.equal(filaEnrol(m, segundo.id).estado, 'activo');
  });

  test('entrada inválida → 400 genérico (esquema cerrado)', async () => {
    const m = montar();
    for (const cuerpo of [{}, { user_ref: '' }, { user_ref: 'ciudadano', extra: true }, { user_ref: 'ciudadano', digits: 7 }]) {
      const r = await m.casos.enrolar(cuerpo, m.ctx);
      assert.equal(r.status, 400);
      assert.equal(r.cuerpo.error, 'INVALID_REQUEST');
    }
    // SHA1 solo si la app lo permite.
    assert.equal((await m.casos.enrolar({ user_ref: 'ciudadano', algorithm: 'SHA1' }, m.ctx)).status, 400);
    assert.equal((await m.casos.verificar({ user_ref: 'ciudadano', code: 'abc' }, m.ctx)).status, 400);
  });
});

describe('verificación', () => {
  test('replay del mismo código: respuesta idéntica a código incorrecto, registrado internamente', async () => {
    const m = montar();
    const { id, semilla } = await enrolarYActivar(m);
    const code = codigo(semilla, m.estado.t);
    assert.equal((await m.casos.verificar({ user_ref: 'ciudadano-1', code }, m.ctx)).status, 200);
    const replay = await m.casos.verificar({ user_ref: 'ciudadano-1', code }, m.ctx);
    const incorrecto = await m.casos.verificar({ user_ref: 'ciudadano-1', code: code === '000000' ? '111111' : '000000' }, m.ctx);
    // Sin oráculo: mismo status, mismo cuerpo y mismas cabeceras que un código incorrecto.
    assert.deepEqual(replay, incorrecto);
    assert.equal(replay.status, 401);
    assert.deepEqual(replay.cuerpo, { error: 'VERIFICATION_FAILED', message: 'No se pudo completar la verificación.' });
    assert.equal(replay.cabeceras['Retry-After'], undefined);
    // Internamente sí se distingue: attempts, bitácora y métricas.
    assert.equal(contarIntentos(m, 'replay'), 1);
    assert.equal(contarIntentos(m, 'invalid_code'), 1);
    const audit = m.db.prepare("SELECT * FROM audit_log WHERE accion = 'verificacion.replay'").all();
    assert.equal(audit.length, 1);
    assert.equal(audit[0].objetivo, id);
    assert.equal(m.metricas.instantanea().resultadosVerificacion.replay, 1);
    // Y cuenta para el bloqueo progresivo como cualquier fallo.
    assert.equal(filaEnrol(m, id).failed_attempts, 2);
  });

  test('replays repetidos activan el bloqueo progresivo (429 genérico)', async () => {
    const m = montar();
    m.repos.apps.actualizarPolitica(m.app.id, { max_intentos: 3 });
    const ctx = { ...m.ctx, app: m.repos.apps.buscarPorId(m.app.id) };
    const { semilla } = await enrolarYActivar(m, 'ciudadano-1', ctx);
    const code = codigo(semilla, m.estado.t);
    assert.equal((await m.casos.verificar({ user_ref: 'ciudadano-1', code }, ctx)).status, 200);
    for (let i = 0; i < 3; i++) {
      const r = await m.casos.verificar({ user_ref: 'ciudadano-1', code }, ctx);
      assert.equal(r.cuerpo.error, 'VERIFICATION_FAILED');
    }
    const r = await m.casos.verificar({ user_ref: 'ciudadano-1', code }, ctx);
    assert.equal(r.status, 429);
    assert.equal(r.cuerpo.error, 'TOO_MANY_REQUESTS');
    assert.equal(r.cuerpo.retry_after_seconds, 30);
    assert.equal(r.cabeceras['Retry-After'], '30');
    assert.equal(contarIntentos(m, 'replay'), 3);
    assert.ok(m.db.prepare("SELECT 1 FROM audit_log WHERE accion = 'enrolamiento.bloqueado'").get());
  });

  test('token validado dos veces: la segunda es inválida', async () => {
    const m = montar();
    const { semilla } = await enrolarYActivar(m);
    const ver = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    assert.equal((await m.casos.validarToken({ token: ver.cuerpo.token }, m.ctx)).cuerpo.valid, true);
    const segunda = await m.casos.validarToken({ token: ver.cuerpo.token }, m.ctx);
    assert.deepEqual(segunda.cuerpo, { valid: false, reason: 'jti_consumido' });
    const consulta = await m.casos.validarToken({ token: ver.cuerpo.token, consume_jti: false }, m.ctx);
    assert.deepEqual(consulta.cuerpo, { valid: false, reason: 'jti_consumido' });
  });

  test('consultar sin consumir no gasta el jti', async () => {
    const m = montar();
    const { semilla } = await enrolarYActivar(m);
    const ver = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    assert.equal((await m.casos.validarToken({ token: ver.cuerpo.token, consume_jti: false }, m.ctx)).cuerpo.valid, true);
    assert.equal((await m.casos.validarToken({ token: ver.cuerpo.token }, m.ctx)).cuerpo.valid, true);
  });

  test('token de otra app (aud distinta) es inválido y no consume el jti', async () => {
    const m = montar();
    const { semilla } = await enrolarYActivar(m);
    const ver = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    const ajena = await m.casos.validarToken({ token: ver.cuerpo.token }, m.ctxOtra);
    assert.deepEqual(ajena.cuerpo, { valid: false, reason: 'aud' });
    assert.equal((await m.casos.validarToken({ token: ver.cuerpo.token }, m.ctx)).cuerpo.valid, true);
    assert.equal((await m.casos.validarToken({ token: 'a.b.c' }, m.ctx)).cuerpo.valid, false);
  });

  test('5 fallos → 429 con bloqueo, que se libera al avanzar el reloj', async () => {
    const m = montar();
    const { id, semilla } = await enrolarYActivar(m);
    for (let i = 0; i < 5; i++) {
      const r = await m.casos.verificar({ user_ref: 'ciudadano-1', code: '000000' }, m.ctx);
      assert.equal(r.status, 401);
    }
    assert.ok(filaEnrol(m, id).locked_until);
    const bloqueado = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    assert.equal(bloqueado.status, 429);
    assert.equal(bloqueado.cuerpo.retry_after_seconds, 30);
    assert.equal(bloqueado.cabeceras['Retry-After'], '30');
    m.avanzar(31_000);
    const libre = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    assert.equal(libre.status, 200);
    assert.equal(filaEnrol(m, id).failed_attempts, 0);
  });

  test('usuario inexistente responde igual que código incorrecto (también al bloquear)', async () => {
    const m = montar();
    await enrolarYActivar(m);
    for (let i = 0; i < 6; i++) {
      const real = await m.casos.verificar({ user_ref: 'ciudadano-1', code: '000000' }, m.ctx);
      const fantasma = await m.casos.verificar({ user_ref: 'nadie-existe', code: '000000' }, m.ctx);
      assert.deepEqual(fantasma, real);
    }
    const real = await m.casos.verificar({ user_ref: 'ciudadano-1', code: '000000' }, m.ctx);
    assert.equal(real.status, 429);
  });

  test('detector en bloqueo → anomaly_blocked (429) y sin evaluar el código', async () => {
    const m = montar();
    const { semilla } = await enrolarYActivar(m);
    m.detector.respuesta = {
      riskScore: 91.5, level: 'alto', action: 'bloqueo_temporal', inferenceMs: 2.3,
      reasons: ['Ráfaga de 14 intentos fallidos sobre la misma cuenta en 15 minutos'],
    };
    const r = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    // Hacia fuera: 429 genérico, sin puntuación, razones, acción ni umbrales.
    assert.equal(r.status, 429);
    assert.deepEqual(r.cuerpo, { error: 'TOO_MANY_REQUESTS', message: 'Demasiados intentos. Intente más tarde.', retry_after_seconds: 300 });
    assert.deepEqual(r.cabeceras, { 'Retry-After': '300' });
    assert.doesNotMatch(JSON.stringify(r), /91|Ráfaga|risk|reason|umbral/i);
    // El detalle queda solo en attempts y en la bitácora.
    assert.equal(contarIntentos(m, 'anomaly_blocked'), 1);
    const fila = m.db.prepare("SELECT * FROM attempts WHERE resultado = 'anomaly_blocked'").get();
    assert.equal(fila.risk_score, 91.5);
    assert.deepEqual(JSON.parse(fila.reasons_json), ['Ráfaga de 14 intentos fallidos sobre la misma cuenta en 15 minutos']);
    assert.match(fila.ip_hash, /^[0-9a-f]{64}$/);
    assert.notEqual(fila.ip_hash, '10.0.0.7');
    const audit = JSON.parse(m.db.prepare("SELECT detalle FROM audit_log WHERE accion = 'verificacion.anomalia_bloqueada'").get().detalle);
    assert.equal(audit.risk_score, 91.5);
    assert.equal(audit.reasons.length, 1);

    // En modo monitorización la app deja pasar el intento.
    m.repos.apps.actualizarPolitica(m.app.id, { modo_heuristica: 'monitorizacion' });
    m.detector.respuesta = { ...m.detector.respuesta, action: 'alerta' };
    const ctx = { ...m.ctx, app: m.repos.apps.buscarPorId(m.app.id) };
    const pasa = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, ctx);
    assert.equal(pasa.status, 200);
    assert.deepEqual(pasa.cuerpo.risk, { level: 'CRITICAL' });
  });

  test('HEURISTICS_MODE=monitorizacion prevalece sobre la app en modo bloqueo: alerta y audita, no bloquea', async () => {
    const m = montar({ config: { modoHeuristica: 'monitorizacion' } });
    const { semilla } = await enrolarYActivar(m);
    assert.equal(m.app.modo_heuristica, 'bloqueo');
    m.repos.apps.actualizarPolitica(m.app.id, { umbral_riesgo_bloqueo: 50 });
    const ctx = { ...m.ctx, app: m.repos.apps.buscarPorId(m.app.id) };
    m.detector.respuesta = {
      riskScore: 95, level: 'alto', action: 'bloqueo_temporal', inferenceMs: 1.1, reasons: ['Ráfaga de intentos'],
    };
    const r = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, ctx);
    assert.equal(r.status, 200, JSON.stringify(r.cuerpo));
    assert.deepEqual(r.cuerpo.risk, { level: 'CRITICAL' });
    assert.equal(contarIntentos(m, 'anomaly_blocked'), 0);
    const alerta = m.db.prepare("SELECT * FROM audit_log WHERE accion = 'verificacion.alerta'").get();
    assert.ok(alerta, 'la alerta queda auditada');
    assert.equal(JSON.parse(alerta.detalle).risk_score, 95);

    // Sin el modo global, la misma app y la misma evaluación sí bloquean.
    const b = montar();
    const e = await enrolarYActivar(b);
    b.detector.respuesta = m.detector.respuesta;
    const bloqueado = await b.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(e.semilla, b.estado.t) }, b.ctx);
    assert.equal(bloqueado.status, 429);
  });

  test('resincronización tras deriva de 6 pasos', async () => {
    const m = montar();
    const { id, semilla } = await enrolarYActivar(m);
    // El reloj del dispositivo va 6 pasos adelantado: fuera de la ventana ±1.
    assert.equal((await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t, 6) }, m.ctx)).status, 401);
    const r = await m.casos.resincronizar({
      id, cuerpo: { code_1: codigo(semilla, m.estado.t, 5), code_2: codigo(semilla, m.estado.t, 6) },
    }, m.ctx);
    assert.equal(r.status, 200, JSON.stringify(r.cuerpo));
    assert.deepEqual(r.cuerpo, { resynced: true, drift_steps: 6 });
    assert.equal(filaEnrol(m, id).drift_steps, 6);
    m.avanzar(PERIODO);
    const ver = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t, 6) }, m.ctx);
    assert.equal(ver.status, 200);
    assert.equal(ver.cuerpo.drift_steps, 6);
    // Otra app no puede resincronizar ese enrolamiento.
    const ajena = await m.casos.resincronizar({ id, cuerpo: { code_1: '111111', code_2: '222222' } }, m.ctxOtra);
    assert.equal(ajena.status, 401);
  });

  test('idempotency-key devuelve la misma respuesta sin reevaluar', async () => {
    const m = montar();
    const { semilla } = await enrolarYActivar(m);
    const cuerpo = { user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) };
    const ctx = { ...m.ctx, idempotencyKey: 'clave-123' };
    const a = await m.casos.verificar(cuerpo, ctx);
    const llamadas = m.detector.llamadas;
    const intentos = m.db.prepare('SELECT COUNT(*) AS n FROM attempts').get().n;
    const b = await m.casos.verificar(cuerpo, ctx);
    assert.equal(a.status, 200);
    assert.deepEqual(b, a);
    assert.equal(m.detector.llamadas, llamadas);
    assert.equal(m.db.prepare('SELECT COUNT(*) AS n FROM attempts').get().n, intentos);
    // Misma clave con otro cuerpo → 400; tras 5 minutos la clave caduca.
    assert.equal((await m.casos.verificar({ ...cuerpo, code: '000000' }, ctx)).status, 400);
    m.avanzar(5 * 60_000 + 1);
    assert.equal((await m.casos.verificar(cuerpo, ctx)).status, 401); // ahora es replay real
  });
});

describe('recuperación y revocación', () => {
  test('código de recuperación válido una vez y revocación resultante', async () => {
    const m = montar();
    const { id, recovery } = await enrolarYActivar(m);
    const r = await m.casos.recuperar({ user_ref: 'ciudadano-1', recovery_code: recovery[0].toLowerCase().replace('-', ' ') }, m.ctx);
    assert.equal(r.status, 200, JSON.stringify(r.cuerpo));
    assert.deepEqual(r.cuerpo, { recovered: true, must_reenroll: true, remaining_codes: 9 });
    assert.equal(filaEnrol(m, id).estado, 'revocado');
    // El mismo código (u otro) ya no sirve: el enrolamiento está revocado.
    assert.equal((await m.casos.recuperar({ user_ref: 'ciudadano-1', recovery_code: recovery[0] }, m.ctx)).status, 401);
    assert.equal((await m.casos.recuperar({ user_ref: 'ciudadano-1', recovery_code: recovery[1] }, m.ctx)).status, 401);
  });

  test('recuperación con código falso cuenta como fallo', async () => {
    const m = montar();
    const { id } = await enrolarYActivar(m);
    const r = await m.casos.recuperar({ user_ref: 'ciudadano-1', recovery_code: 'AAAA-AAAA' }, m.ctx);
    assert.equal(r.status, 401);
    assert.equal(filaEnrol(m, id).failed_attempts, 1);
    assert.equal(filaEnrol(m, id).estado, 'activo');
  });

  test('revocar enrolamiento de otra app → 404; propio → 200', async () => {
    const m = montar();
    const { id } = await enrolarYActivar(m);
    const ajena = await m.casos.revocar({ id }, m.ctxOtra);
    assert.equal(ajena.status, 404);
    assert.equal(filaEnrol(m, id).estado, 'activo');
    assert.equal((await m.casos.revocar({ id: '00000000-0000-4000-8000-000000000000' }, m.ctx)).status, 404);
    assert.equal((await m.casos.revocar({ id: 'no-es-uuid' }, m.ctx)).status, 400);
    const propia = await m.casos.revocar({ id }, m.ctx);
    assert.equal(propia.status, 200);
    assert.equal(propia.cuerpo.estado, 'revocado');
    assert.equal(propia.cuerpo.enrollment_id, id);
    assert.equal((await m.casos.revocar({ id }, m.ctx)).cuerpo.revoked_at, propia.cuerpo.revoked_at);
  });
});

describe('administración', () => {
  async function crearAdmin(m, rol = 'Administrador') {
    const { id, semilla } = await enrolarYActivar(m, `admin-${rol}`);
    m.repos.admins.crear({ usuario: `ana-${rol}`, password_hash: hashSecreto('clave-larga-segura'), rol, totp_enrollment_id: id });
    return { usuario: `ana-${rol}`, semilla };
  }

  test('autenticarApp', async () => {
    const m = montar();
    assert.equal((await m.casos.autenticarApp('portal', 'secreto-portal')).id, m.app.id);
    assert.equal(await m.casos.autenticarApp('portal', 'otro'), null);
    assert.equal(await m.casos.autenticarApp('no-existe', 'secreto-portal'), null);
    m.repos.apps.actualizarPolitica(m.app.id, { estado: 'suspendido' });
    assert.equal(await m.casos.autenticarApp('portal', 'secreto-portal'), null);
  });

  test('adminLogin correcto e incorrecto', async () => {
    const m = montar();
    const { usuario, semilla } = await crearAdmin(m);
    const code = codigo(semilla, m.estado.t);
    const ok = await m.casos.adminLogin({ usuario, password: 'clave-larga-segura', totp_code: code }, { ip: '10.1.1.1' });
    assert.equal(ok.status, 200);
    assert.equal(ok.cuerpo.rol, 'Administrador');
    assert.equal(ok.cuerpo.usuario, usuario);
    assert.match(ok.cuerpo.csrf_token, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(ok.admin.csrf_token, ok.cuerpo.csrf_token);

    const generico = { status: 401, error: 'UNAUTHORIZED' };
    const casos = [
      { usuario, password: 'clave-larga-segura', totp_code: code }, // replay del TOTP
      { usuario, password: 'incorrecta', totp_code: codigo(semilla, m.estado.t, 1) },
      { usuario: 'desconocido', password: 'clave-larga-segura', totp_code: code },
      { usuario, password: 'clave-larga-segura' }, // sin TOTP
    ];
    for (const entrada of casos) {
      const r = await m.casos.adminLogin(entrada, {});
      assert.equal(r.status, generico.status);
      assert.equal(r.cuerpo.error, generico.error);
      assert.equal(r.admin, undefined);
    }
    assert.equal((await m.casos.adminLogin({ usuario, password: 'x', extra: 1 }, {})).status, 400);
    // Un único nombre de campo: el alias `codigo` ya no existe.
    const alias = await m.casos.adminLogin({ usuario, password: 'clave-larga-segura', codigo: codigo(semilla, m.estado.t, 1) }, {});
    assert.equal(alias.status, 400);
  });

  test('puede() por rol y RBAC en los casos de uso', async () => {
    assert.equal(puede('Administrador', 'llaves.rotar'), true);
    assert.equal(puede('Operador', 'llaves.rotar'), false);
    assert.equal(puede('Operador', 'apps.escribir'), true);
    assert.equal(puede('Operador', 'auditoria.leer'), false);
    assert.equal(puede('Auditor', 'auditoria.verificar'), true);
    assert.equal(puede('Auditor', 'apps.leer'), false);
    assert.equal(puede('Auditor', 'metricas.leer'), true);
    assert.equal(puede('Auditor', 'anomalias.leer'), true);
    assert.equal(puede('Intruso', 'metricas.leer'), false);

    const m = montar();
    const auditor = { admin: { id: 'a', usuario: 'aud', rol: 'Auditor' } };
    const operador = { admin: { id: 'o', usuario: 'ope', rol: 'Operador' } };
    assert.equal((await m.casos.adminRotarLlaves({}, operador)).status, 403);
    assert.equal((await m.casos.adminListarApps({}, auditor)).status, 403);
    assert.equal((await m.casos.adminListarApps({}, {})).status, 401);
    const apps = await m.casos.adminListarApps({}, operador);
    assert.equal(apps.status, 200);
    assert.equal(apps.cuerpo.apps.length, 2);
    assert.ok(apps.cuerpo.apps.every((a) => !('secret_hash' in a)));
    assert.equal((await m.casos.adminMetricas({}, auditor)).status, 200);
  });

  test('registrar y actualizar app', async () => {
    const m = montar();
    const ctx = { admin: { id: 'o', usuario: 'ope', rol: 'Operador' } };
    const alta = await m.casos.adminActualizarApp({ nombre: 'Nueva app', digitos: 8 }, ctx);
    assert.equal(alta.status, 201);
    assert.ok(alta.cuerpo.client_secret);
    assert.equal((await m.casos.autenticarApp(alta.cuerpo.client_id, alta.cuerpo.client_secret)).digitos, 8);
    const cambio = await m.casos.adminActualizarApp({ id: alta.cuerpo.app.id, ventana: 2 }, ctx);
    assert.equal(cambio.status, 200);
    assert.equal(cambio.cuerpo.app.ventana, 2);
    assert.equal((await m.casos.adminActualizarApp({ id: alta.cuerpo.app.id, algoritmo: 'SHA1' }, ctx)).status, 400);
    assert.equal((await m.casos.adminActualizarApp({ id: 'no-existe', ventana: 2 }, ctx)).status, 404);
  });

  test('rotación de llaves: el token firmado antes sigue validando', async () => {
    const m = montar();
    const { semilla } = await enrolarYActivar(m);
    const antes = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    const kidAnterior = antes.cuerpo.kid;

    const rot = await m.casos.adminRotarLlaves({}, { admin: { id: 'x', usuario: 'root', rol: 'Administrador' } });
    assert.equal(rot.status, 200);
    assert.equal(rot.cuerpo.previous_kid, kidAnterior);
    assert.notEqual(rot.cuerpo.new_kid, kidAnterior);
    assert.equal(m.repos.signingKeys.buscarPorKid(kidAnterior).estado, 'solo_verificacion');
    assert.equal((await m.casos.jwks()).cuerpo.keys.length, 2);

    assert.equal((await m.casos.validarToken({ token: antes.cuerpo.token }, m.ctx)).cuerpo.valid, true);
    m.avanzar(PERIODO);
    const despues = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    assert.equal(despues.cuerpo.kid, rot.cuerpo.new_kid);
    assert.equal((await m.casos.validarToken({ token: despues.cuerpo.token }, m.ctx)).cuerpo.valid, true);
  });

  test('bitácora íntegra tras el flujo, sin secretos, y anomalías/enrolamientos visibles', async () => {
    const m = montar();
    const { semilla, recovery } = await enrolarYActivar(m);
    await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    m.detector.respuesta = { riskScore: 88, level: 'alto', action: 'bloqueo_temporal', inferenceMs: 1, reasons: ['Prueba'] };
    await m.casos.verificar({ user_ref: 'ciudadano-1', code: '000000' }, m.ctx);
    m.detector.respuesta = NEUTRA;
    await m.casos.recuperar({ user_ref: 'ciudadano-1', recovery_code: recovery[3] }, m.ctx);

    const auditor = { admin: { id: 'a', usuario: 'aud', rol: 'Auditor' } };
    const cadena = await m.casos.adminVerificarCadena({}, auditor);
    assert.equal(cadena.status, 200);
    assert.equal(cadena.cuerpo.intact, true);
    assert.ok(cadena.cuerpo.checked_records >= 5);
    assert.equal(cadena.cuerpo.broken_at_id, null);
    assert.match(cadena.cuerpo.last_hash, /^[0-9a-f]{64}$/);

    const aud = await m.casos.adminAuditoria({ limite: '100' }, auditor);
    assert.equal(aud.status, 200);
    const texto = JSON.stringify(aud.cuerpo.eventos);
    assert.ok(!texto.includes('ciudadano-1'));
    assert.ok(!texto.includes(recovery[0]));
    assert.ok(!texto.includes('10.0.0.7'));
    assert.ok(!texto.includes('eyJ')); // ningún JWT
    assert.ok(aud.cuerpo.eventos.some((e) => e.accion === 'verificacion.anomalia_bloqueada'));
    // `detalle` se entrega como objeto, no como texto JSON.
    const bloqueo = aud.cuerpo.eventos.find((e) => e.accion === 'verificacion.anomalia_bloqueada');
    assert.equal(typeof bloqueo.detalle, 'object');
    assert.equal(bloqueo.detalle.risk_score, 88);
    assert.deepEqual(bloqueo.detalle.reasons, ['Prueba']);
    assert.ok(aud.cuerpo.eventos.every((e) => e.detalle === null || typeof e.detalle === 'object'));

    const anom = await m.casos.adminAnomalias({}, auditor);
    assert.equal(anom.status, 200);
    assert.equal(anom.cuerpo.alerts.length, 1);
    assert.equal(anom.cuerpo.alerts[0].action, 'BLOCK');
    assert.equal(anom.cuerpo.summary.blockedAnomalyCount, 1);

    const enr = await m.casos.adminListarEnrolamientos({ estado: 'revocado' }, { admin: { id: 'o', usuario: 'o', rol: 'Operador' } });
    assert.equal(enr.status, 200);
    assert.equal(enr.cuerpo.enrollments.length, 1);
    assert.ok(!('seed_ct' in enr.cuerpo.enrollments[0]));

    // Alterar una fila rompe la cadena.
    m.db.prepare("UPDATE audit_log SET detalle = '{}' WHERE id = 2").run();
    const rota = await m.casos.adminVerificarCadena({}, auditor);
    assert.equal(rota.cuerpo.intact, false);
    assert.equal(rota.cuerpo.broken_at_id, 2);
  });
});

describe('deriva acotada en verify', () => {
  test('códigos T+1, T+2, T+3 seguidos: solo se acepta T+1', async () => {
    const m = montar();
    const { id, semilla } = await enrolarYActivar(m);
    const r1 = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t, 1) }, m.ctx);
    assert.equal(r1.status, 200);
    assert.equal(r1.cuerpo.drift_steps, 1);
    for (const pasos of [2, 3]) {
      const r = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t, pasos) }, m.ctx);
      assert.equal(r.status, 401, `T+${pasos} debe rechazarse`);
      assert.equal(r.cuerpo.error, 'VERIFICATION_FAILED');
    }
    assert.equal(filaEnrol(m, id).drift_steps, 1);
    assert.equal(contarIntentos(m, 'invalid_code'), 2, 'fuera del tope cuenta como código inválido, no como replay');
  });

  test('ráfaga T+1…T+12 en el mismo segundo: una sola aceptación y la deriva no se arrastra', async () => {
    const m = montar();
    m.repos.apps.actualizarPolitica(m.app.id, { max_intentos: 15 });
    const ctx = { ...m.ctx, app: m.repos.apps.buscarPorId(m.app.id) };
    const { id, semilla } = await enrolarYActivar(m, 'ciudadano-1', ctx);
    const estados = [];
    for (let k = 1; k <= 12; k++) {
      estados.push((await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t, k) }, ctx)).status);
    }
    assert.deepEqual(estados, [200, ...Array(11).fill(401)]);
    assert.equal(filaEnrol(m, id).drift_steps, 1);
  });

  test('cota de aceptaciones: como mucho 2·ventana+1 en un periodo y una por periodo sostenido', async () => {
    const m = montar();
    m.repos.apps.actualizarPolitica(m.app.id, { max_intentos: 15 });
    const ctx = { ...m.ctx, app: m.repos.apps.buscarPorId(m.app.id) };
    const { id, semilla } = await enrolarYActivar(m, 'ciudadano-1', ctx);
    m.avanzar(PERIODO); // que el paso T-1 no sea el ya consumido por la activación
    // En un mismo periodo, en orden creciente, solo pueden entrar T-1, T y T+1 (ventana = 1).
    const enPeriodo = [];
    for (const k of [-3, -2, -1, 0, 1, 2, 3]) {
      const r = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t, k) }, ctx);
      if (r.status === 200) enPeriodo.push(k);
    }
    assert.deepEqual(enPeriodo, [-1, 0, 1]);
    // Sostenido: en N periodos, a lo sumo N aceptaciones más la holgura fija de la ventana, y |deriva| <= ventana.
    let aceptadas = 0;
    const periodos = 6;
    for (let p = 0; p < periodos; p++) {
      m.avanzar(PERIODO);
      for (const k of [-2, -1, 0, 1, 2, 3]) {
        const r = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t, k) }, ctx);
        if (r.status === 200) aceptadas++;
        assert.ok(Math.abs(filaEnrol(m, id).drift_steps) <= 1);
      }
    }
    assert.ok(aceptadas <= periodos + 2, `aceptadas ${aceptadas}`);
    assert.ok(filaEnrol(m, id).last_step <= Math.floor(m.estado.t / PERIODO) + 1, 'last_step nunca supera T + ventana');
  });

  test('solo resync fija derivas mayores (hasta ±10); verify respeta ese tope y no lo reduce por un código tardío', async () => {
    const m = montar();
    const { id, semilla } = await enrolarYActivar(m);
    const r = await m.casos.resincronizar({ id, cuerpo: { code_1: codigo(semilla, m.estado.t, 3), code_2: codigo(semilla, m.estado.t, 4) } }, m.ctx);
    assert.deepEqual(r.cuerpo, { resynced: true, drift_steps: 4 });
    // Más allá de ±10, ni resync.
    const fuera = await m.casos.resincronizar({ id, cuerpo: { code_1: codigo(semilla, m.estado.t, 11), code_2: codigo(semilla, m.estado.t, 12) } }, m.ctx);
    assert.equal(fuera.status, 401);
    m.avanzar(2 * PERIODO); // que T+3 ya no sea un paso consumido por la resincronización
    // T+5 queda fuera del tope (|5| > max(|4|, 1)).
    assert.equal((await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t, 5) }, m.ctx)).status, 401);
    // Un código tecleado tarde (deriva 3) se acepta pero no reduce la deriva guardada…
    const tarde = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t, 3) }, m.ctx);
    assert.equal(tarde.status, 200);
    assert.equal(filaEnrol(m, id).drift_steps, 4);
    // …así que el siguiente código del mismo dispositivo (deriva 4) sigue entrando.
    m.avanzar(PERIODO);
    assert.equal((await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t, 4) }, m.ctx)).status, 200);
  });
});

describe('origen del usuario final (client_ip)', () => {
  const origen = (m, appId, ip) => hashPepper(`${appId}:${ip}`, pepperDiario(m.config.ipPepperSemilla, new Date(m.estado.t)));

  test('ip_hash = HMAC(app_id:client_ip) con pepper diario; sin client_ip se usa la IP TCP', async () => {
    const m = montar();
    await m.casos.verificar({ user_ref: 'nadie', code: '000000', client_ip: '203.0.113.9' }, m.ctx);
    await m.casos.verificar({ user_ref: 'nadie', code: '000000' }, m.ctx);
    await m.casos.verificar({ user_ref: 'nadie', code: '000000', client_ip: '203.0.113.9' }, m.ctxOtra);
    await m.casos.recuperar({ user_ref: 'nadie', recovery_code: 'AAAA-AAAA', client_ip: '::FFFF:203.0.113.9' }, m.ctx);
    const filas = m.db.prepare('SELECT app_id, ip_hash FROM attempts ORDER BY id').all();
    assert.equal(filas[0].ip_hash, origen(m, m.app.id, '203.0.113.9'));
    assert.equal(filas[1].ip_hash, origen(m, m.app.id, '10.0.0.7'), 'sin client_ip: IP TCP de la app');
    assert.equal(filas[2].ip_hash, origen(m, m.otra.id, '203.0.113.9'));
    assert.notEqual(filas[0].ip_hash, filas[2].ip_hash, 'la misma IP en otra app es otro origen');
    assert.equal(filas[3].ip_hash, filas[0].ip_hash, 'IPv4 mapeada en IPv6 = misma identidad');
    assert.ok(filas.every((f) => !JSON.stringify(f).includes('203.0.113')));
  });

  test('client_ip inválida → 400 en verify, recovery, activate y resync', async () => {
    const m = montar();
    const { id, semilla } = await enrolarYActivar(m);
    const malas = ['999.1.1.1', '01.2.3.4', '1.2.3', '1.2.3.4:80', 'fe80::1%eth0', '[::1]', ' 1.2.3.4', 'localhost', '', 7, null];
    for (const ip of malas) {
      const ver = await m.casos.verificar({ user_ref: 'ciudadano-1', code: codigo(semilla, m.estado.t), client_ip: ip }, m.ctx);
      assert.equal(ver.status, 400, `verify ${JSON.stringify(ip)}`);
      const rec = await m.casos.recuperar({ user_ref: 'ciudadano-1', recovery_code: 'AAAA-AAAA', client_ip: ip }, m.ctx);
      assert.equal(rec.status, 400, `recovery ${JSON.stringify(ip)}`);
      const res = await m.casos.resincronizar({ id, cuerpo: { code_1: '111111', code_2: '222222', client_ip: ip } }, m.ctx);
      assert.equal(res.status, 400, `resync ${JSON.stringify(ip)}`);
    }
    const e = await m.casos.enrolar({ user_ref: 'ciudadano-2' }, m.ctx);
    const s2 = semillaDeUri(e.cuerpo.otpauth_uri);
    const mala = await m.casos.activar({ id: e.cuerpo.enrollment_id, cuerpo: { code: codigo(s2, m.estado.t), client_ip: '300.0.0.1' } }, m.ctx);
    assert.equal(mala.status, 400);
    const buena = await m.casos.activar({ id: e.cuerpo.enrollment_id, cuerpo: { code: codigo(s2, m.estado.t), client_ip: '2001:db8::7' } }, m.ctx);
    assert.equal(buena.status, 200);
    assert.equal(m.db.prepare('SELECT COUNT(*) AS n FROM attempts').get().n, 0, 'una entrada inválida no deja intentos');
  });

  test('detector real: muchos ciudadanos detrás del mismo portal no bloquean a un legítimo; un atacante con un solo client_ip sí queda bloqueado', async () => {
    const detectorReal = entrenarDetectorPorDefecto(42);
    const m = montar({ detectorReal });
    const legitimo = await enrolarYActivar(m, 'ciudadano-legitimo');
    // 20 ciudadanos distintos (mismo TCP 10.0.0.7 del portal, distinto client_ip) fallan 2 veces cada uno.
    for (let i = 0; i < 20; i++) {
      for (let k = 0; k < 2; k++) {
        const r = await m.casos.verificar({ user_ref: `ciudadano-${i}`, code: '000000', client_ip: `203.0.113.${10 + i}` }, m.ctx);
        assert.equal(r.status, 401);
      }
      m.avanzar(1000);
    }
    const ok = await m.casos.verificar({ user_ref: 'ciudadano-legitimo', code: codigo(legitimo.semilla, m.estado.t), client_ip: '198.51.100.5' }, m.ctx);
    assert.equal(ok.status, 200, JSON.stringify(ok.cuerpo));
    assert.equal(contarIntentos(m, 'anomaly_blocked'), 0);

    // Un atacante con un único client_ip recorre 20 cuentas: el detector bloquea ESE origen.
    const respuestas = [];
    for (let i = 0; i < 20; i++) {
      for (let k = 0; k < 2; k++) {
        respuestas.push(await m.casos.verificar({ user_ref: `victima-${i}`, code: '000000', client_ip: '192.0.2.66' }, m.ctx));
      }
    }
    assert.ok(contarIntentos(m, 'anomaly_blocked') > 0, 'el detector bloquea al atacante');
    assert.ok(respuestas.some((r) => r.status === 429 && r.cuerpo.error === 'TOO_MANY_REQUESTS'));
    // Y el ciudadano legítimo (otro client_ip, mismo portal) sigue entrando.
    m.avanzar(PERIODO);
    const otraVez = await m.casos.verificar({ user_ref: 'ciudadano-legitimo', code: codigo(legitimo.semilla, m.estado.t), client_ip: '198.51.100.5' }, m.ctx);
    assert.equal(otraVez.status, 200, JSON.stringify(otraVez.cuerpo));
  });
});

describe('bloqueo persistente de usuarios sin enrolamiento', () => {
  test('el bloqueo se calcula desde attempts y sobrevive a un reinicio, idéntico al de una cuenta real', async () => {
    const m = montar();
    await enrolarYActivar(m);
    for (let i = 0; i < 5; i++) {
      const real = await m.casos.verificar({ user_ref: 'ciudadano-1', code: '000000' }, m.ctx);
      const fantasma = await m.casos.verificar({ user_ref: 'nadie-existe', code: '000000' }, m.ctx);
      assert.deepEqual(fantasma, real);
    }
    m.avanzar(4000);
    m.reiniciar(); // nuevo proceso: nada en memoria
    const real = await m.casos.verificar({ user_ref: 'ciudadano-1', code: '000000' }, m.ctx);
    const fantasma = await m.casos.verificar({ user_ref: 'nadie-existe', code: '000000' }, m.ctx);
    assert.equal(fantasma.status, 429);
    assert.deepEqual(fantasma, real);
    assert.equal(fantasma.cuerpo.retry_after_seconds, 26);
    // Al vencer, el siguiente fallo vuelve a bloquear (6.º fallo) igual que en la cuenta real.
    m.avanzar(27_000);
    const r6 = await m.casos.verificar({ user_ref: 'ciudadano-1', code: '000000' }, m.ctx);
    const f6 = await m.casos.verificar({ user_ref: 'nadie-existe', code: '000000' }, m.ctx);
    assert.deepEqual(f6, r6);
    m.reiniciar();
    assert.deepEqual(await m.casos.verificar({ user_ref: 'nadie-existe', code: '000000' }, m.ctx),
      await m.casos.verificar({ user_ref: 'ciudadano-1', code: '000000' }, m.ctx));
  });

  test('verify y recovery comparten el contador, por app; fuera de la ventana configurada se olvida', async () => {
    const m = montar({ config: { ventanaInexistentesMin: 10 } });
    for (let i = 0; i < 3; i++) await m.casos.verificar({ user_ref: 'nadie', code: '000000' }, m.ctx);
    for (let i = 0; i < 2; i++) await m.casos.recuperar({ user_ref: 'nadie', recovery_code: 'AAAA-AAAA' }, m.ctx);
    assert.equal((await m.casos.verificar({ user_ref: 'nadie', code: '000000' }, m.ctx)).status, 429);
    assert.equal((await m.casos.recuperar({ user_ref: 'nadie', recovery_code: 'AAAA-AAAA' }, m.ctx)).status, 429);
    // Otra app con el mismo user_ref no hereda el bloqueo.
    assert.equal((await m.casos.verificar({ user_ref: 'nadie', code: '000000' }, m.ctxOtra)).status, 401);
    m.avanzar(11 * 60_000);
    assert.equal((await m.casos.verificar({ user_ref: 'nadie', code: '000000' }, m.ctx)).status, 401);
  });
});

describe('validación estricta de user_ref', () => {
  test('rechaza NUL, controles C0/C1, bidi, invisibles, espacios en extremos y más de 128 caracteres', async () => {
    const m = montar();
    const malos = [
      '', 'lab\u0000x', 'a\u001b[31m', 'x\u007fy', 'x\u0085y', 'x\u009by', ' inicio', 'fin ', '\t', 'x\ny', 'a‮b', 'a⁦b',
      'a​b', 'a‍b', '﻿a', 'a⁠b', 'a b', 'a b', 'aㅤb', 'aᅟb', 'ab', 'x'.repeat(129),
    ];
    for (const user_ref of malos) {
      for (const [nombre, llamada] of [
        ['enrolar', () => m.casos.enrolar({ user_ref }, m.ctx)],
        ['verificar', () => m.casos.verificar({ user_ref, code: '123456' }, m.ctx)],
        ['recuperar', () => m.casos.recuperar({ user_ref, recovery_code: 'AAAA-AAAA' }, m.ctx)],
      ]) {
        const r = await llamada();
        assert.equal(r.status, 400, `${nombre} ${JSON.stringify(user_ref)}`);
        assert.equal(r.cuerpo.error, 'INVALID_REQUEST');
      }
    }
    assert.equal(m.db.prepare('SELECT COUNT(*) AS n FROM attempts').get().n, 0);
  });

  test('acepta 1 a 128 imprimibles, con espacios interiores, acentos y símbolos', async () => {
    const m = montar();
    for (const user_ref of ['a', 'x'.repeat(128), 'ciudadano 12', 'ñandú-Ü', 'rut:12.345.678-9', 'usuario@dominio.cl', '用户', 'áb']) {
      assert.equal((await m.casos.enrolar({ user_ref }, m.ctx)).status, 201, JSON.stringify(user_ref));
    }
  });
});
