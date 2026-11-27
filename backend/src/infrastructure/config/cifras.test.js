import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const RAIZ = new URL('../../../../', import.meta.url);

test('docs/evidencias/cifras.json mantiene coherencia interna y con la documentación', () => {
  const cifras = JSON.parse(readFileSync(new URL('docs/evidencias/cifras.json', RAIZ), 'utf8'));
  const sumaSuites = Object.values(cifras.pruebas.suites).reduce((acc, n) => acc + n, 0);

  assert.equal(cifras.dependenciasNpm, 0);
  assert.equal(cifras.pruebas.fallos, 0);
  assert.equal(cifras.pruebas.total, sumaSuites, 'total debe coincidir con la suma de las 5 suites');
  assert.equal(
    cifras.openapi.rutasTotal,
    cifras.openapi.integracionV1 + cifras.openapi.sistema + cifras.openapi.consola,
    'rutasTotal debe coincidir con el desglose OpenAPI',
  );
  assert.equal(cifras.attackLab.hallazgos, 0);
  assert.equal(cifras.dast.hallazgos, 0);

  const totalTxt = String(cifras.pruebas.total);
  for (const rel of [
    'README.md',
    'docs/cumplimiento/matriz-cumplimiento.html',
    'docs/presentacion/presentacion.html',
    'docs/presentacion/guion-demo.html',
    'docs/entrega/lista-entrega.md',
  ]) {
    const contenido = readFileSync(new URL(rel, RAIZ), 'utf8');
    assert.ok(contenido.includes(totalTxt), `${rel} debe reflejar el total vigente (${totalTxt})`);
  }
});
