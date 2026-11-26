// Pruebas de los casos de uso de gestión desde la consola: inventario de llaves, ciclo de vida de
// enrolamientos, secreto de apps y administradores. SQLite en memoria, reloj controlable.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { abrirBaseDatos } from '../../infrastructure/persistence/db.js';
import { crearRepositorios } from '../../infrastructure/persistence/repositorios.js';
import { crearVault } from '../../core/vault/vault.js';
import { generateTotp } from '../../core/totp/totp.js';
import { base32Decode } from '../../core/totp/base32.js';
import { hashSecreto } from '../../security/index.js';
import { crearBitacora, crearMetricas, verificarCadena } from '../../audit/index.js';
import { crearCasosDeUso, puede } from './index.js';
import { crearFirmas } from '../../infrastructure/config/firmas.js';

const NEUTRA = { riskScore: 5, level: 'bajo', action: 'permitir', reasons: ['Comportamiento habitual'], inferenceMs: 0.4 };
const PERIODO = 30_000;
const ADMIN = { admin: { id: 'adm-1', usuario: 'jefa', rol: 'Administrador' } };
const OPERADOR = { admin: { id: 'ope-1', usuario: 'ope', rol: 'Operador' } };
const AUDITOR = { admin: { id: 'aud-1', usuario: 'aud', rol: 'Auditor' } };

function montar() {
  const db = abrirBaseDatos(':memory:');
  const repos = crearRepositorios(db);
  const vault = crearVault({ llaves: { v1: randomBytes(32) }, versionActiva: 'v1' });
  const estado = { t: Date.parse('2026-11-26T12:00:05.000Z') };
  const reloj = () => estado.t;
  const firmas = crearFirmas({ repos, vault });
  firmas.recargar();
  const detector = { evaluar: () => NEUTRA };
  const bitacora = crearBitacora({
    ultimo: () => repos.auditLog.ultimo(),
    insertar: (f) => repos.auditLog.insertar(f).id,
    ahora: () => new Date(estado.t).toISOString(),
  });
  const politica = { algoritmo: 'SHA256', digitos: 6, periodo: 30, ventana: 1, max_intentos: 5, modo_heuristica: 'bloqueo' };
  const app = repos.apps.crear({ nombre: 'Portal de Trámites', client_id: 'portal', secret_hash: hashSecreto('secreto-portal'), ...politica });
  const config = {
    userRefPepper: 'pepper-usuarios', ipPepperSemilla: 'semilla-ip', emisorTotp: 'SoberanoTOTP',
    emisorJwt: 'https://totp.soberano.local', ttlJwtSegundos: 300, minutosPendiente: 10,
  };
  const casos = crearCasosDeUso({ repos, vault, firmas, detector, bitacora, metricas: crearMetricas({ ahora: reloj }), config, reloj, db });
  return { db, repos, casos, estado, app, firmas, ctx: { app, ip: '10.0.0.7' }, avanzar(ms) { estado.t += ms; } };
}

const semillaDeUri = (uri) => base32Decode(new URL(uri).searchParams.get('secret'));
const codigo = (semilla, t, pasos = 0) => generateTotp(semilla, t + pasos * PERIODO, { algoritmo: 'SHA256', digitos: 6, periodo: 30 });
const acciones = (m) => m.db.prepare('SELECT accion FROM audit_log ORDER BY id').all().map((f) => f.accion);

describe('GET /admin/api/keys (adminListarLlaves)', () => {
  test('inventario sin material privado; RBAC llaves.leer para los tres roles', async () => {
    const m = montar();
    const kidInicial = m.firmas.kidActivo;
    await m.casos.adminRotarLlaves({}, ADMIN);
    const r = await m.casos.adminListarLlaves({}, AUDITOR);
    assert.equal(r.status, 200);
    assert.deepEqual(Object.keys(r.cuerpo).sort(), ['active_kid', 'keys']);
    assert.equal(r.cuerpo.active_kid, m.firmas.kidActivo);
    assert.notEqual(r.cuerpo.active_kid, kidInicial);
    assert.equal(r.cuerpo.keys.length, 2);
    for (const k of r.cuerpo.keys) {
      assert.deepEqual(Object.keys(k).sort(), ['alg', 'created_at', 'crv', 'estado', 'kid', 'rotated_at']);
      assert.equal(k.alg, 'EdDSA');
      assert.equal(k.crv, 'Ed25519');
    }
    const previa = r.cuerpo.keys.find((k) => k.kid === kidInicial);
    assert.equal(previa.estado, 'solo_verificacion');
    assert.ok(previa.rotated_at);
    assert.equal(r.cuerpo.keys.find((k) => k.kid === r.cuerpo.active_kid).rotated_at, null);
    assert.doesNotMatch(JSON.stringify(r.cuerpo), /private|PRIVATE|key_version|"x"/);

    for (const rol of ['Administrador', 'Operador', 'Auditor']) assert.equal(puede(rol, 'llaves.leer'), true, rol);
    assert.equal((await m.casos.adminListarLlaves({}, OPERADOR)).status, 200);
    assert.equal((await m.casos.adminListarLlaves({}, {})).status, 401);
    assert.equal((await m.casos.adminListarLlaves({}, { admin: { id: 'x', usuario: 'x', rol: 'Intruso' } })).status, 403);
    assert.equal((await m.casos.adminListarLlaves({ extra: '1' }, ADMIN)).status, 400, 'consulta cerrada');
  });
});

/** Enrola y activa un usuario en la app de prueba; devuelve el id y la semilla. */
async function enrolarActivo(m, userRef, ctx = m.ctx) {
  const e = await m.casos.enrolar({ user_ref: userRef }, ctx);
  assert.equal(e.status, 201);
  const semilla = semillaDeUri(e.cuerpo.otpauth_uri);
  const a = await m.casos.activar({ id: e.cuerpo.enrollment_id, cuerpo: { code: codigo(semilla, m.estado.t) } }, ctx);
  assert.equal(a.status, 200);
  return { id: e.cuerpo.enrollment_id, semilla };
}

describe('ciclo de vida de enrolamientos desde la consola', () => {
  test('activo → suspendido → activo → revocado (final); verify de un suspendido = código incorrecto', async () => {
    const m = montar();
    const { id, semilla } = await enrolarActivo(m, 'ciudadana-1');

    m.avanzar(PERIODO);
    const s = await m.casos.adminSuspenderEnrolamiento({ id, cuerpo: {} }, OPERADOR);
    assert.equal(s.status, 200);
    assert.equal(s.cuerpo.enrollment.estado, 'suspendido');
    assert.doesNotMatch(JSON.stringify(s.cuerpo), /seed_/);

    // Suspendido: un código correcto responde exactamente igual que uno incorrecto.
    const conSuspendido = await m.casos.verificar({ user_ref: 'ciudadana-1', code: codigo(semilla, m.estado.t) }, m.ctx);
    const incorrecto = await m.casos.verificar({ user_ref: 'ciudadana-1', code: '000000' }, m.ctx);
    assert.equal(conSuspendido.status, 401);
    assert.deepEqual(conSuspendido.cuerpo, incorrecto.cuerpo);
    assert.deepEqual(conSuspendido.cuerpo, { error: 'VERIFICATION_FAILED', message: 'No se pudo completar la verificación.' });

    assert.equal((await m.casos.adminSuspenderEnrolamiento({ id, cuerpo: {} }, ADMIN)).status, 409, 'ya suspendido');
    const r = await m.casos.adminReactivarEnrolamiento({ id, cuerpo: {} }, ADMIN);
    assert.equal(r.status, 200);
    assert.equal(r.cuerpo.enrollment.estado, 'activo');
    assert.equal((await m.casos.adminReactivarEnrolamiento({ id, cuerpo: {} }, ADMIN)).status, 409, 'ya activo');

    m.avanzar(PERIODO);
    assert.equal((await m.casos.verificar({ user_ref: 'ciudadana-1', code: codigo(semilla, m.estado.t) }, m.ctx)).status, 200);

    const v = await m.casos.adminRevocarEnrolamiento({ id, cuerpo: {} }, OPERADOR);
    assert.equal(v.status, 200);
    assert.equal(v.cuerpo.enrollment.estado, 'revocado');
    assert.ok(v.cuerpo.enrollment.revoked_at);
    for (const f of ['adminRevocarEnrolamiento', 'adminSuspenderEnrolamiento', 'adminReactivarEnrolamiento']) {
      assert.equal((await m.casos[f]({ id, cuerpo: {} }, ADMIN)).status, 409, `${f} sobre revocado`);
    }
    const eventos = acciones(m);
    for (const a of ['enrolamiento.suspendido', 'enrolamiento.reactivado', 'enrolamiento.revocado']) assert.ok(eventos.includes(a), a);
    assert.equal(verificarCadena(m.db.prepare('SELECT * FROM audit_log ORDER BY id').all()).intact, true);
  });

  test('suspendido → revocado; pendiente no admite transiciones; 404 genérico; RBAC y cuerpo cerrado', async () => {
    const m = montar();
    const { id } = await enrolarActivo(m, 'ciudadano-2');
    assert.equal((await m.casos.adminSuspenderEnrolamiento({ id }, ADMIN)).status, 200);
    assert.equal((await m.casos.adminRevocarEnrolamiento({ id }, ADMIN)).status, 200);

    const pend = await m.casos.enrolar({ user_ref: 'ciudadano-3' }, m.ctx);
    for (const f of ['adminRevocarEnrolamiento', 'adminSuspenderEnrolamiento', 'adminReactivarEnrolamiento']) {
      assert.equal((await m.casos[f]({ id: pend.cuerpo.enrollment_id }, ADMIN)).status, 409, f);
    }
    const inexistente = await m.casos.adminRevocarEnrolamiento({ id: '00000000-0000-4000-8000-000000000000' }, ADMIN);
    assert.equal(inexistente.status, 404);
    assert.deepEqual(inexistente.cuerpo, { error: 'NOT_FOUND', message: 'Recurso no encontrado.' });
    assert.equal((await m.casos.adminRevocarEnrolamiento({ id: 'no-es-uuid' }, ADMIN)).status, 404);
    assert.equal((await m.casos.adminSuspenderEnrolamiento({ id: pend.cuerpo.enrollment_id, cuerpo: { motivo: 'x' } }, ADMIN)).status, 400);
    assert.equal((await m.casos.adminSuspenderEnrolamiento({ id }, AUDITOR)).status, 403);
    assert.equal((await m.casos.adminSuspenderEnrolamiento({ id }, {})).status, 401);
    for (const rol of ['Administrador', 'Operador']) assert.equal(puede(rol, 'enrolamientos.gestionar'), true);
    assert.equal(puede('Auditor', 'enrolamientos.gestionar'), false);
  });

  test('reactivar no deja dos activos del mismo usuario; el factor de un administrador no se gestiona por aquí', async () => {
    const m = montar();
    const viejo = await enrolarActivo(m, 'ciudadana-4');
    assert.equal((await m.casos.adminSuspenderEnrolamiento({ id: viejo.id }, ADMIN)).status, 200);
    m.avanzar(PERIODO);
    await enrolarActivo(m, 'ciudadana-4');
    const r = await m.casos.adminReactivarEnrolamiento({ id: viejo.id }, ADMIN);
    assert.equal(r.status, 409);
    assert.equal(r.cuerpo.error, 'CONFLICT');

    m.avanzar(PERIODO);
    const delAdmin = await enrolarActivo(m, 'admin:jefa');
    m.repos.admins.crear({ usuario: 'jefa', password_hash: hashSecreto('x'), rol: 'Administrador', totp_enrollment_id: delAdmin.id });
    assert.equal((await m.casos.adminRevocarEnrolamiento({ id: delAdmin.id }, OPERADOR)).status, 409);
    assert.equal(m.repos.enrollments.buscarPorId(delAdmin.id).estado, 'activo');
  });
});

