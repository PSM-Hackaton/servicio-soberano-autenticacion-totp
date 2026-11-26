import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ROLES,
  getPermissions,
  parsePrometheusMetrics,
  verifyLocalAuditLinks,
  createAdminClient,
} from './admin-api.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MOCKS_DIR = join(__dirname, '..', 'contracts', 'mocks');

/** fetch simulado que lee directamente contracts/mocks/ del disco */
async function fsMockFetch(url) {
  const filename = String(url).split('/').pop();
  const content = await readFile(join(MOCKS_DIR, filename), 'utf8');
  return {
    ok: true,
    status: 200,
    json: async () => JSON.parse(content),
    text: async () => content,
  };
}

test('RBAC: Administrador, Operador y Auditor cumplen principio de mínimo privilegio', () => {
  assert.equal(getPermissions(ROLES.ADMINISTRADOR).rotateKeys, true);
  assert.equal(getPermissions(ROLES.ADMINISTRADOR).manageApps, true);

  assert.equal(getPermissions(ROLES.OPERADOR).revokeEnrollment, true);
  assert.equal(getPermissions(ROLES.OPERADOR).rotateKeys, false);
  assert.equal(getPermissions(ROLES.OPERADOR).manageApps, false);

  assert.equal(getPermissions(ROLES.AUDITOR).revokeEnrollment, false);
  assert.equal(getPermissions(ROLES.AUDITOR).rotateKeys, false);
  assert.equal(getPermissions(ROLES.AUDITOR).verifyAudit, true);
});

test('Parser de métricas Prometheus interpreta contracts/mocks/metrics.txt', async () => {
  const raw = await readFile(join(MOCKS_DIR, 'metrics.txt'), 'utf8');
  const parsed = parsePrometheusMetrics(raw);
  assert.equal(parsed.gauges.totp_availability_percent, 100);
  assert.equal(parsed.verifications.ok, 129);
  assert.equal(parsed.verifications.replay, 4);
  assert.equal(parsed.latency['/api/v1/verify'].p95, 11.8);
});

test('Cliente Admin en modo mock: login RBAC, rotación de llaves, revocación y detección de tamper en audit_log', async () => {
  const client = createAdminClient({ mode: 'mock', fetchImpl: fsMockFetch });
  const sess = await client.login({ usuario: 'admin_seguridad', password: 'secret', totp_code: '123456' });
  assert.equal(sess.rol, ROLES.ADMINISTRADOR);

  const beforeChain = await client.verifyAuditChain();
  assert.equal(beforeChain.intact, true);

  const rot = await client.rotateKeys();
  assert.ok(rot.new_kid && rot.previous_kid);

  const jwks = await client.getJwks();
  assert.equal(jwks.keys.length, 2);

  client.simulateMockAuditTamper();
  const brokenChain = await client.verifyAuditChain();
  assert.equal(brokenChain.intact, false);
  assert.equal(brokenChain.broken_at_id, 2);

  // Verificación directa de utilidad pura
  assert.equal(verifyLocalAuditLinks([]).intact, true);
});
