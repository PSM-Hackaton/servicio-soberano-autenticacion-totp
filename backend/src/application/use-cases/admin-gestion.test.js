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
import { derivarUserRefDesdeCedula } from '../../../../sdk/src/index.js';

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

describe('administradores de la consola (GET/POST /admin/api/admins, /disable)', () => {
  test('alta con contraseña aleatoria y TOTP activo; se entrega una vez; el primer login usa el paso siguiente', async () => {
    const m = montar();
    const r = await m.casos.adminCrearAdministrador({ usuario: 'operadora.1', rol: 'Operador' }, ADMIN);
    assert.equal(r.status, 201);
    assert.equal(r.cabeceras['Cache-Control'], 'no-store');
    assert.deepEqual(Object.keys(r.cuerpo).sort(), ['admin', 'otpauth_uri', 'password', 'qr_svg']);
    assert.match(r.cuerpo.password, /^[A-Za-z0-9_-]{24}$/);
    assert.match(r.cuerpo.otpauth_uri, /^otpauth:\/\/totp\//);
    assert.match(r.cuerpo.qr_svg, /^<svg[\s\S]*<\/svg>\s*$/);
    assert.deepEqual(r.cuerpo.admin, {
      id: r.cuerpo.admin.id, usuario: 'operadora.1', rol: 'Operador', activo: true, created_at: r.cuerpo.admin.created_at, totp_estado: 'activo',
    });
    const consola = m.repos.apps.listar().find((a) => a.nombre === 'Consola Administrativa');
    assert.ok(consola, 'crea la app interna si no existía');

    const semilla = semillaDeUri(r.cuerpo.otpauth_uri);
    const mismoPaso = await m.casos.adminLogin({ usuario: 'operadora.1', password: r.cuerpo.password, totp_code: codigo(semilla, m.estado.t) });
    assert.equal(mismoPaso.status, 401, 'el código del paso de alta ya se consumió');
    m.avanzar(PERIODO);
    const login = await m.casos.adminLogin({ usuario: 'operadora.1', password: r.cuerpo.password, totp_code: codigo(semilla, m.estado.t) });
    assert.equal(login.status, 200);
    assert.equal(login.cuerpo.rol, 'Operador');

    const lista = await m.casos.adminListarAdministradores({}, ADMIN);
    assert.equal(lista.status, 200);
    assert.deepEqual(lista.cuerpo.admins.map((a) => a.usuario), ['operadora.1']);
    assert.doesNotMatch(JSON.stringify(lista.cuerpo), /password|scrypt|hash/);
    const auditoria = JSON.stringify(m.db.prepare('SELECT * FROM audit_log').all());
    assert.ok(acciones(m).includes('admin.creado'));
    assert.doesNotMatch(auditoria, new RegExp(r.cuerpo.password));
    assert.doesNotMatch(auditoria, /secret=/);

    assert.equal((await m.casos.adminCrearAdministrador({ usuario: 'operadora.1', rol: 'Auditor' }, ADMIN)).status, 409);
    // Una segunda cuenta reutiliza la misma app interna.
    assert.equal((await m.casos.adminCrearAdministrador({ usuario: 'auditor', rol: 'Auditor' }, ADMIN)).status, 201);
    assert.equal(m.repos.apps.listar().filter((a) => a.nombre === 'Consola Administrativa').length, 1);
  });

  test('validación cerrada y RBAC: solo Administrador', async () => {
    const m = montar();
    for (const cuerpo of [{ usuario: 'ab', rol: 'Operador' }, { usuario: 'Mayus', rol: 'Operador' }, { usuario: 'con espacio', rol: 'Operador' },
      { usuario: 'valido', rol: 'Root' }, { usuario: 'valido' }, { usuario: 'valido', rol: 'Operador', password: 'x' }]) {
      assert.equal((await m.casos.adminCrearAdministrador(cuerpo, ADMIN)).status, 400, JSON.stringify(cuerpo));
    }
    assert.equal((await m.casos.adminCrearAdministrador({ usuario: 'valido', rol: 'Operador' }, OPERADOR)).status, 403);
    assert.equal((await m.casos.adminListarAdministradores({}, OPERADOR)).status, 403);
    assert.equal((await m.casos.adminListarAdministradores({}, AUDITOR)).status, 403);
    assert.equal((await m.casos.adminListarAdministradores({ x: '1' }, ADMIN)).status, 400);
    assert.equal((await m.casos.adminDeshabilitarAdministrador({ id: 'x' }, OPERADOR)).status, 403);
    for (const rol of ['Operador', 'Auditor']) {
      assert.equal(puede(rol, 'admins.leer'), false);
      assert.equal(puede(rol, 'admins.escribir'), false);
    }
  });

  test('deshabilitar: no a uno mismo ni al último Administrador activo; la cuenta deshabilitada no entra', async () => {
    const m = montar();
    const jefa = await m.casos.adminCrearAdministrador({ usuario: 'jefa', rol: 'Administrador' }, ADMIN);
    const ope = await m.casos.adminCrearAdministrador({ usuario: 'ope', rol: 'Operador' }, ADMIN);
    const ctxJefa = { admin: { id: jefa.cuerpo.admin.id, usuario: 'jefa', rol: 'Administrador' } };

    const propia = await m.casos.adminDeshabilitarAdministrador({ id: jefa.cuerpo.admin.id }, ctxJefa);
    assert.equal(propia.status, 409);
    const ultima = await m.casos.adminDeshabilitarAdministrador({ id: jefa.cuerpo.admin.id }, ADMIN);
    assert.equal(ultima.status, 409, 'jefa es la única Administradora activa');
    assert.match(ultima.cuerpo.message, /último Administrador/);

    const d = await m.casos.adminDeshabilitarAdministrador({ id: ope.cuerpo.admin.id, cuerpo: {} }, ctxJefa);
    assert.equal(d.status, 200);
    assert.equal(d.cuerpo.admin.activo, false);
    assert.equal((await m.casos.adminDeshabilitarAdministrador({ id: ope.cuerpo.admin.id }, ctxJefa)).status, 409, 'ya deshabilitada');
    m.avanzar(PERIODO);
    const login = await m.casos.adminLogin({ usuario: 'ope', password: ope.cuerpo.password, totp_code: codigo(semillaDeUri(ope.cuerpo.otpauth_uri), m.estado.t) });
    assert.equal(login.status, 401);

    // Con dos Administradores activos sí se puede deshabilitar a uno.
    const otra = await m.casos.adminCrearAdministrador({ usuario: 'subjefa', rol: 'Administrador' }, ctxJefa);
    assert.equal((await m.casos.adminDeshabilitarAdministrador({ id: otra.cuerpo.admin.id }, ctxJefa)).status, 200);
    assert.equal((await m.casos.adminDeshabilitarAdministrador({ id: '00000000-0000-4000-8000-000000000000' }, ctxJefa)).status, 404);
    assert.equal((await m.casos.adminDeshabilitarAdministrador({ id: jefa.cuerpo.admin.id, cuerpo: { x: 1 } }, ADMIN)).status, 400);
    assert.ok(acciones(m).includes('admin.deshabilitado'));
    assert.equal(verificarCadena(m.db.prepare('SELECT * FROM audit_log ORDER BY id').all()).intact, true);
  });
});

describe('POST /admin/api/apps/:id/secret (adminRegenerarSecretoApp)', () => {
  test('el secreto anterior deja de valer; solo Administrador; 404; una sola vez y sin hash', async () => {
    const m = montar();
    assert.ok(await m.casos.autenticarApp('portal', 'secreto-portal'));
    const r = await m.casos.adminRegenerarSecretoApp({ id: m.app.id, cuerpo: {} }, ADMIN);
    assert.equal(r.status, 200);
    assert.equal(r.cabeceras['Cache-Control'], 'no-store');
    assert.equal(r.cuerpo.client_id, 'portal');
    assert.match(r.cuerpo.client_secret, /^[\x21-\x7e]{32,}$/);
    assert.doesNotMatch(JSON.stringify(r.cuerpo.app), /secret_hash|scrypt/);
    assert.equal(await m.casos.autenticarApp('portal', 'secreto-portal'), null, 'el anterior ya no autentica');
    assert.ok(await m.casos.autenticarApp('portal', r.cuerpo.client_secret));
    assert.ok(acciones(m).includes('app.secreto_regenerado'));
    assert.doesNotMatch(JSON.stringify(m.db.prepare('SELECT detalle FROM audit_log').all()), new RegExp(r.cuerpo.client_secret));

    assert.equal((await m.casos.adminRegenerarSecretoApp({ id: m.app.id }, OPERADOR)).status, 403);
    assert.equal((await m.casos.adminRegenerarSecretoApp({ id: 'no-existe' }, ADMIN)).status, 404);
    assert.equal((await m.casos.adminRegenerarSecretoApp({ id: m.app.id, cuerpo: { x: 1 } }, ADMIN)).status, 400);
    assert.equal(puede('Administrador', 'apps.secreto'), true);
    assert.equal(puede('Operador', 'apps.secreto'), false);
  });
});

describe('búsqueda por cédula y por user_ref (GET /admin/api/enrollments)', () => {
  /** Registra una app con derivación HMAC (secreto generado por el servicio) y enrola a dos ciudadanos. */
  async function montarConCedula() {
    const m = montar();
    const alta = await m.casos.adminActualizarApp({ nombre: 'Portal ciudadano', user_ref_desde_cedula: 'hmac', cedula_prefijo: 'ciud_' }, ADMIN);
    assert.equal(alta.status, 201);
    assert.match(alta.cuerpo.cedula_secreto, /^[A-Za-z0-9_-]{43}$/);
    const app = m.repos.apps.buscarPorId(alta.cuerpo.app.id);
    const ctx = { app, ip: '10.0.0.8' };
    // La app integradora deriva el user_ref con el SDK, igual que lo hará el servicio.
    const ref = derivarUserRefDesdeCedula('V-12.345.678', alta.cuerpo.cedula_secreto, 'ciud_');
    const e = await enrolarActivo(m, ref, ctx);
    m.avanzar(PERIODO);
    await enrolarActivo(m, derivarUserRefDesdeCedula('E-80.000.003', alta.cuerpo.cedula_secreto, 'ciud_'), ctx);
    return { m, app, alta, ref, enrolId: e.id };
  }

  test('la app declara hmac: el secreto se guarda cifrado, nunca sale en listados y la búsqueda encuentra el factor', async () => {
    const { m, app, alta, ref, enrolId } = await montarConCedula();
    assert.equal(alta.cuerpo.app.user_ref_desde_cedula, 'hmac');
    assert.equal(alta.cuerpo.app.cedula_prefijo, 'ciud_');
    const crudo = m.db.prepare('SELECT * FROM apps WHERE id = ?').get(app.id);
    assert.ok(crudo.cedula_secreto_ct && crudo.cedula_key_version === 'v1');
    assert.notEqual(crudo.cedula_secreto_ct, alta.cuerpo.cedula_secreto);
    const listado = await m.casos.adminListarApps({}, ADMIN);
    assert.doesNotMatch(JSON.stringify(listado.cuerpo), /cedula_secreto|cedula_key_version|secret_hash/);

    for (const forma of ['V-12.345.678', 'v12345678', 'V 12345678']) {
      const r = await m.casos.adminListarEnrolamientos({ app_id: app.id, cedula: forma }, OPERADOR);
      assert.equal(r.status, 200, forma);
      assert.deepEqual(r.cuerpo.enrollments.map((x) => x.id), [enrolId], forma);
      assert.doesNotMatch(JSON.stringify(r.cuerpo), /seed_/);
    }
    const porRef = await m.casos.adminListarEnrolamientos({ app_id: app.id, user_ref: ref }, ADMIN);
    assert.deepEqual(porRef.cuerpo.enrollments.map((x) => x.id), [enrolId]);
    const otra = await m.casos.adminListarEnrolamientos({ app_id: app.id, cedula: 'V-11.111.111' }, ADMIN);
    assert.deepEqual(otra.cuerpo.enrollments, []);
    const soloRevocados = await m.casos.adminListarEnrolamientos({ app_id: app.id, cedula: 'V12345678', estado: 'revocado' }, ADMIN);
    assert.deepEqual(soloRevocados.cuerpo.enrollments, []);

    // Auditoría de cada búsqueda, sin la cédula ni el user_ref en claro.
    const busquedas = m.db.prepare("SELECT detalle FROM audit_log WHERE accion = 'enrolamientos.busqueda'").all().map((f) => JSON.parse(f.detalle));
    assert.equal(busquedas.length, 6);
    assert.equal(busquedas[0].criterio, 'cedula');
    assert.match(busquedas[0].cedula_hmac, /^[0-9a-f]{64}$/);
    assert.equal(busquedas[0].cedula_hmac, busquedas[1].cedula_hmac, 'misma cédula, mismo HMAC');
    assert.equal(busquedas[3].criterio, 'user_ref');
    const todo = JSON.stringify(m.db.prepare('SELECT * FROM audit_log').all());
    assert.doesNotMatch(todo, /12345678|12\.345\.678|80000003|11111111/);
    assert.doesNotMatch(todo, new RegExp(ref));
    assert.doesNotMatch(todo, new RegExp(alta.cuerpo.cedula_secreto));
    assert.equal(verificarCadena(m.db.prepare('SELECT * FROM audit_log ORDER BY id').all()).intact, true);
  });

  test('errores: cédula inválida, sin app_id, criterios juntos, app inexistente, app sin derivación, RBAC', async () => {
    const { m, app, ref } = await montarConCedula();
    const q = (consulta, ctx = ADMIN) => m.casos.adminListarEnrolamientos(consulta, ctx);
    assert.equal((await q({ app_id: app.id, cedula: 'J-12345678' })).status, 400);
    assert.equal((await q({ app_id: app.id, cedula: 'V-012345678' })).status, 400);
    assert.equal((await q({ cedula: 'V12345678' })).status, 400, 'app_id obligatorio');
    assert.equal((await q({ user_ref: ref })).status, 400, 'app_id obligatorio');
    assert.equal((await q({ app_id: app.id, cedula: 'V12345678', user_ref: ref })).status, 400);
    assert.equal((await q({ app_id: 'no-existe', cedula: 'V12345678' })).status, 404);
    const sin = await q({ app_id: m.app.id, cedula: 'V12345678' });
    assert.equal(sin.status, 409);
    assert.equal(sin.cuerpo.error, 'CONFLICT');
    assert.equal((await q({ app_id: m.app.id, user_ref: 'ciudadana-x' })).status, 200, 'user_ref exacto vale para cualquier app');
    assert.equal((await q({ app_id: app.id, cedula: 'V12345678' }, AUDITOR)).status, 403);
  });

  test('configuración por actualización: aportar secreto, conservarlo al cambiar el prefijo y desactivar', async () => {
    const m = montar();
    const secreto = randomBytes(32).toString('base64url');
    const r = await m.casos.adminActualizarApp({ id: m.app.id, user_ref_desde_cedula: 'hmac', cedula_secreto: secreto }, ADMIN);
    assert.equal(r.status, 200);
    assert.equal(r.cuerpo.cedula_secreto, undefined, 'un secreto aportado no se devuelve');
    await enrolarActivo(m, derivarUserRefDesdeCedula('V-9.876.543', secreto, ''));
    assert.equal((await m.casos.adminListarEnrolamientos({ app_id: m.app.id, cedula: 'V9876543' }, ADMIN)).cuerpo.enrollments.length, 1);

    const pref = await m.casos.adminActualizarApp({ id: m.app.id, cedula_prefijo: 'nuevo_' }, ADMIN);
    assert.equal(pref.cuerpo.app.cedula_prefijo, 'nuevo_');
    assert.equal(pref.cuerpo.cedula_secreto, undefined, 'se conserva el secreto');
    assert.equal((await m.casos.adminListarEnrolamientos({ app_id: m.app.id, cedula: 'V9876543' }, ADMIN)).cuerpo.enrollments.length, 0);

    const off = await m.casos.adminActualizarApp({ id: m.app.id, user_ref_desde_cedula: 'ninguno' }, ADMIN);
    assert.equal(off.cuerpo.app.user_ref_desde_cedula, 'ninguno');
    assert.equal(m.db.prepare('SELECT cedula_secreto_ct AS c FROM apps WHERE id = ?').get(m.app.id).c, null, 'secreto borrado');
    assert.equal((await m.casos.adminListarEnrolamientos({ app_id: m.app.id, cedula: 'V9876543' }, ADMIN)).status, 409);

    assert.equal((await m.casos.adminActualizarApp({ id: m.app.id, cedula_prefijo: 'x_' }, ADMIN)).status, 400, 'prefijo sin hmac');
    assert.equal((await m.casos.adminActualizarApp({ nombre: 'Otra', cedula_secreto: secreto }, ADMIN)).status, 400, 'secreto sin hmac');
    assert.equal((await m.casos.adminActualizarApp({ id: m.app.id, user_ref_desde_cedula: 'hmac', cedula_secreto: 'corto' }, ADMIN)).status, 400);
    assert.equal((await m.casos.adminActualizarApp({ id: m.app.id, user_ref_desde_cedula: 'hmac', cedula_prefijo: 'con espacio' }, ADMIN)).status, 400);
    assert.doesNotMatch(JSON.stringify(m.db.prepare('SELECT detalle FROM audit_log').all()), new RegExp(secreto));
  });
});

