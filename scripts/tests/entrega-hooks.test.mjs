// Pruebas del gancho commit-msg (scripts/hooks/revisar.mjs mensaje): commits detallados, con cuerpo de al
// menos 2 líneas descriptivas. Herramienta interna (no se publica).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REVISAR = join(dirname(fileURLToPath(import.meta.url)), '..', 'hooks', 'revisar.mjs');

function revisar(texto) {
  const dir = mkdtempSync(join(tmpdir(), 'commit-msg-'));
  try {
    const archivo = join(dir, 'COMMIT_EDITMSG');
    writeFileSync(archivo, texto);
    const r = spawnSync(process.execPath, [REVISAR, 'mensaje', archivo], { encoding: 'utf8' });
    return { codigo: r.status, salida: r.stdout + r.stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const TITULO = 'feat(backend): añadir ventana de deriva configurable (#12)';

test('acepta un mensaje con cuerpo de 2 o más líneas descriptivas', () => {
  const r = revisar(`${TITULO}\n\nAñade TOTP_DRIFT_MAX a la configuración y la aplica en verificarCodigo.\n`
    + 'Pruebas: npm test en backend, 50 de 50 correctas.\nCloses #12\n');
  assert.equal(r.codigo, 0, r.salida);
});

test('rechaza un mensaje sin cuerpo', () => {
  const r = revisar(`${TITULO}\n`);
  assert.equal(r.codigo, 1);
  assert.match(r.salida, /el cuerpo tiene 0 línea\(s\) descriptiva\(s\); se exigen al menos 2/);
});

test('rechaza un cuerpo de una sola línea descriptiva', () => {
  const r = revisar(`${TITULO}\n\nAñade TOTP_DRIFT_MAX a la configuración del backend.\n`);
  assert.equal(r.codigo, 1);
  assert.match(r.salida, /el cuerpo tiene 1 línea/);
});

test('las referencias sueltas, comentarios y líneas cortas no cuentan como descripción', () => {
  const r = revisar(`${TITULO}\n\nCloses #12\nRefs #3, #4\n- ok\nvarios\n# comentario de git que no cuenta para nada\n`);
  assert.equal(r.codigo, 1);
  assert.match(r.salida, /el cuerpo tiene 0 línea/);
});

test('fixup! y squash! quedan exentos; las menciones a herramientas se siguen rechazando', () => {
  assert.equal(revisar('fixup! feat(backend): añadir ventana de deriva\n').codigo, 0);
  const r = revisar(`${TITULO}\n\nAñade TOTP_DRIFT_MAX a la configuración y la aplica.\nPruebas del backend en verde, 50 de 50.\n`
    + `${['Co', 'Authored', 'By'].join('-')}: Alguien <alguien@example.com>\n`);
  assert.equal(r.codigo, 1);
});
