import test from 'node:test';
import assert from 'node:assert/strict';
import { runAttackAndChaosSuite } from './run-all.js';

test('Attack Lab & Caos: los 7 escenarios pasan con 0 accesos indebidos concedidos', async () => {
  const report = await runAttackAndChaosSuite({ writeReports: false });
  assert.equal(report.total_escenarios, 7);
  assert.equal(report.exitosos, 7, JSON.stringify(report.escenarios, null, 2));
  assert.equal(report.accesos_indebidos_concedidos, 0);
});
