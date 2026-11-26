import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { abrirBaseDatos } from './db.js';
import { crearRepositorios } from './repositorios.js';

const TABLAS = ['apps', 'enrollments', 'recovery_codes', 'attempts', 'consumed_jti', 'signing_keys', 'admins', 'audit_log'];

function entorno() {
  const db = abrirBaseDatos(':memory:');
  return { db, repos: crearRepositorios(db) };
}

/** @param {ReturnType<typeof crearRepositorios>} repos */
function crearAppYEnrolamiento(repos) {
  const app = repos.apps.crear({ nombre: 'Portal de Trámites', client_id: 'portal', secret_hash: 'scrypt$x' });
  const enrol = repos.enrollments.crearPendiente({
    app_id: app.id, user_ref_hash: 'a'.repeat(64), algoritmo: 'SHA256', digitos: 6, periodo: 30,
    seed_ct: randomBytes(32), seed_nonce: randomBytes(12), seed_auth_tag: randomBytes(16),
    pending_expires_at: new Date(Date.now() + 600_000).toISOString(),
  });
  return { app, enrol };
}

test('migraciones idempotentes: abrir dos veces el mismo archivo no reaplica nada', () => {
  const carpeta = mkdtempSync(join(tmpdir(), 'totp-db-'));
  try {
    const ruta = join(carpeta, 'prueba.sqlite');
    const db1 = abrirBaseDatos(ruta);
    assert.equal(db1.prepare('PRAGMA journal_mode').get().journal_mode, 'wal');
    crearRepositorios(db1).apps.crear({ nombre: 'A', client_id: 'a', secret_hash: 'h' });
    db1.close();

    const db2 = abrirBaseDatos(ruta);
    const migraciones = db2.prepare('SELECT version FROM schema_migrations').all().map((f) => f.version);
    assert.deepEqual(migraciones, ['001_esquema.sql', '002_cedula_apps.sql', '003_dispositivos.sql']);
    const tablas = db2.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((f) => f.name);
    for (const t of TABLAS) assert.ok(tablas.includes(t), `falta la tabla ${t}`);
    assert.equal(crearRepositorios(db2).apps.listar().length, 1, 'los datos sobreviven a la reapertura');
    assert.equal(db2.prepare('PRAGMA busy_timeout').get().timeout, 5000);
    db2.close();
  } finally {
    rmSync(carpeta, { recursive: true, force: true });
  }
});

test('crea app y enrolamiento con valores por defecto del esquema y semilla como Buffer', () => {
  const { repos } = entorno();
  const { app, enrol } = crearAppYEnrolamiento(repos);
  assert.equal(app.algoritmo, 'SHA256');
  assert.equal(app.ventana, 1);
  assert.equal(app.permitir_sha1, false);
  assert.deepEqual(repos.apps.buscarPorClientId('portal'), app);

  assert.equal(enrol.estado, 'pendiente');
  assert.equal(enrol.last_step, -1);
  assert.ok(Buffer.isBuffer(enrol.seed_ct) && enrol.seed_ct.length === 32);
  assert.equal(repos.enrollments.buscarActivoPorUsuario(app.id, 'a'.repeat(64)), null);

  assert.equal(repos.enrollments.activar(enrol.id), true);
  assert.equal(repos.enrollments.activar(enrol.id), false, 'no se activa dos veces');
  assert.equal(repos.enrollments.buscarActivoPorUsuario(app.id, 'a'.repeat(64)).id, enrol.id);

  assert.equal(repos.apps.actualizarPolitica(app.id, { ventana: 2, permitir_sha1: true }), true);
  const actualizada = repos.apps.buscarPorId(app.id);
  assert.equal(actualizada.ventana, 2);
  assert.equal(actualizada.permitir_sha1, true);
});

test('anti replay: el mismo paso o uno anterior no se acepta dos veces', () => {
  const { repos } = entorno();
  const { enrol } = crearAppYEnrolamiento(repos);
  repos.enrollments.activar(enrol.id);
  repos.enrollments.registrarFallo(enrol.id, null);

  assert.equal(repos.enrollments.registrarPasoAceptado(enrol.id, 1000, 1), true);
  assert.equal(repos.enrollments.registrarPasoAceptado(enrol.id, 1000, 1), false, 'mismo paso');
  assert.equal(repos.enrollments.registrarPasoAceptado(enrol.id, 999, 0), false, 'paso anterior');
  assert.equal(repos.enrollments.registrarPasoAceptado(enrol.id, 1001, 0), true, 'paso siguiente');

  const fila = repos.enrollments.buscarPorId(enrol.id);
  assert.equal(fila.last_step, 1001);
  assert.equal(fila.failed_attempts, 0, 'un acierto reinicia los fallos');
});

test('registrarFallo acumula y un null no levanta un bloqueo vigente', () => {
  const { repos } = entorno();
  const { enrol } = crearAppYEnrolamiento(repos);
  const hasta = new Date(Date.now() + 60_000).toISOString();
  assert.equal(repos.enrollments.registrarFallo(enrol.id, null), 1);
  assert.equal(repos.enrollments.registrarFallo(enrol.id, hasta), 2);
  assert.equal(repos.enrollments.registrarFallo(enrol.id, null), 3);
  assert.equal(repos.enrollments.buscarPorId(enrol.id).locked_until, hasta);
});

test('consumed_jti: un jti solo se consume una vez', () => {
  const { repos } = entorno();
  const jti = '0b6f2c1e-7a4d-4c3b-9f1e-2d5a8b7c6e01';
  const expira = new Date(Date.now() + 300_000).toISOString();
  assert.equal(repos.consumedJti.consumir(jti, expira), true);
  assert.equal(repos.consumedJti.consumir(jti, expira), false);
  assert.equal(repos.consumedJti.purgarCaducados(new Date(Date.now() + 600_000).toISOString()), 1);
});

test('código de recuperación: el segundo uso falla', () => {
  const { repos } = entorno();
  const { enrol } = crearAppYEnrolamiento(repos);
  const ids = repos.recoveryCodes.insertarLote(enrol.id, Array.from({ length: 10 }, (_, i) => `hash-${i}`));
  assert.equal(ids.length, 10);
  assert.equal(repos.recoveryCodes.marcarUsado(ids[0]), true);
  assert.equal(repos.recoveryCodes.marcarUsado(ids[0]), false);
  assert.equal(repos.recoveryCodes.listarNoUsados(enrol.id).length, 9);
});

test('transacción: un error deshace todo lo escrito dentro', () => {
  const { repos } = entorno();
  assert.throws(() => repos.transaccion(() => {
    repos.apps.crear({ nombre: 'Temporal', client_id: 'temporal', secret_hash: 'h' });
    throw new Error('fallo simulado');
  }), /fallo simulado/);
  assert.equal(repos.apps.buscarPorClientId('temporal'), null);

  // Anidada: el fallo interno solo deshace su SAVEPOINT.
  repos.transaccion(() => {
    repos.apps.crear({ nombre: 'Externa', client_id: 'externa', secret_hash: 'h' });
    assert.throws(() => repos.transaccion(() => {
      repos.apps.crear({ nombre: 'Interna', client_id: 'interna', secret_hash: 'h' });
      throw new Error('interno');
    }));
  });
  assert.ok(repos.apps.buscarPorClientId('externa'));
  assert.equal(repos.apps.buscarPorClientId('interna'), null);
});

test('foreign keys activas: no hay enrolamiento sin app y el borrado es en cascada', () => {
  const { db, repos } = entorno();
  assert.equal(db.prepare('PRAGMA foreign_keys').get().foreign_keys, 1);
  assert.throws(() => repos.enrollments.crearPendiente({
    app_id: 'no-existe', user_ref_hash: 'b'.repeat(64), algoritmo: 'SHA256', digitos: 6,
    seed_ct: randomBytes(32), seed_nonce: randomBytes(12), seed_auth_tag: randomBytes(16),
  }), /FOREIGN KEY/);

  const { app, enrol } = crearAppYEnrolamiento(repos);
  db.prepare('DELETE FROM apps WHERE id = ?').run(app.id);
  assert.equal(repos.enrollments.buscarPorId(enrol.id), null);
});

test('attempts: conteo de fallos por usuario e IP y purga por antigüedad', () => {
  const { repos } = entorno();
  const hace40Dias = new Date(Date.now() - 40 * 86_400_000).toISOString();
  repos.attempts.registrar({ ip_hash: 'ip1', user_ref_hash: 'u1', resultado: 'invalid_code', reasons_json: ['ráfaga'] });
  repos.attempts.registrar({ ip_hash: 'ip1', user_ref_hash: 'u1', resultado: 'ok' });
  repos.attempts.registrar({ ip_hash: 'ip1', user_ref_hash: 'u2', resultado: 'replay' });
  repos.attempts.registrar({ ip_hash: 'ip1', user_ref_hash: 'u1', resultado: 'invalid_code', ts: hace40Dias });

  const desde = new Date(Date.now() - 3_600_000).toISOString();
  assert.equal(repos.attempts.contarFallosRecientes({ userRefHash: 'u1', desde }), 1);
  assert.equal(repos.attempts.contarFallosRecientes({ ipHash: 'ip1', desde }), 2);
  assert.deepEqual(repos.attempts.ultimosPorIp('ip1', 10).at(-1).reasons_json, null);
  assert.equal(repos.attempts.purgarAntiguos(30), 1);
  assert.equal(repos.attempts.ultimosPorIp('ip1').length, 3);
});

test('signing_keys, admins y audit_log', () => {
  const { repos } = entorno();
  const clave = repos.signingKeys.guardar({
    kid: 'k1', public_jwk: { kty: 'OKP', crv: 'Ed25519', x: 'abc' },
    private_ct: randomBytes(48), private_nonce: randomBytes(12), private_auth_tag: randomBytes(16), estado: 'activa',
  });
  assert.equal(clave.public_jwk.crv, 'Ed25519');
  assert.ok(Buffer.isBuffer(clave.private_ct));
  assert.equal(repos.signingKeys.activa().kid, 'k1');
  assert.equal(repos.signingKeys.cambiarEstado('k1', 'solo_verificacion'), true);
  assert.equal(repos.signingKeys.activa(), null);
  assert.equal(repos.signingKeys.listarVerificables().length, 1);

  const admin = repos.admins.crear({ usuario: 'root', password_hash: 'scrypt$y', rol: 'Administrador' });
  assert.equal(admin.activo, true);
  assert.equal(repos.admins.buscarPorUsuario('root').id, admin.id);

  const e1 = repos.auditLog.insertar({ actor: 'root', accion: 'login', prev_hash: '0'.repeat(64), hash: '1'.repeat(64) });
  const e2 = repos.auditLog.insertar({ actor: 'root', accion: 'rotar', detalle: { kid: 'k1' }, prev_hash: e1.hash, hash: '2'.repeat(64) });
  assert.equal(repos.auditLog.ultimo().id, e2.id);
  assert.equal(e2.detalle, '{"kid":"k1"}');
  assert.deepEqual(repos.auditLog.listar(e1.id, 10).map((e) => e.id), [e2.id]);
  assert.deepEqual([...repos.auditLog.recorrerTodo()].map((e) => e.accion), ['login', 'rotar']);
});
