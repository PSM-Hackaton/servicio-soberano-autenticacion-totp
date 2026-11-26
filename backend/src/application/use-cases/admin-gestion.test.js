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

