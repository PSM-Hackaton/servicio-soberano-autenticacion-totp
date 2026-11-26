// Pruebas de scripts/mr-gitlab.sh y de los controles de entrada de scripts/etapa-gitlab.sh (herramientas
// internas del modelo del GitLab del evento; no se publican). Ninguna prueba llama a la red.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPTS = join(dirname(fileURLToPath(import.meta.url)), '..');
const TOKEN_FALSO = 'glpat-token-de-prueba-que-no-debe-salir';

function sh(script, args, env = {}) {
  const r = spawnSync('sh', [join(SCRIPTS, script), ...args], {
    encoding: 'utf8', env: { ...process.env, GITLAB_TOKEN: '', ...env }, timeout: 20000,
  });
  if (r.error) throw r.error;
  return { codigo: r.status, salida: r.stdout + r.stderr };
}

test('mr-gitlab.sh sin --ejecutar solo muestra la petición, con remove_source_branch=false', () => {
  const r = sh('mr-gitlab.sh', ['--origen', 'diego', '--titulo', 'Etapa 3 · Núcleo criptográfico', '--issue', '3'],
    { GITLAB_TOKEN: TOKEN_FALSO });
  assert.equal(r.codigo, 0, r.salida);
  assert.match(r.salida, /NO se envía/);
  assert.match(r.salida, /\/api\/v4\/projects\/1409\/merge_requests/);
  assert.match(r.salida, /source_branch=diego/);
  assert.match(r.salida, /target_branch=desarrollo/);
  assert.match(r.salida, /remove_source_branch=false/);
  assert.match(r.salida, /squash=false/);
  assert.match(r.salida, /reviewer_ids\[\]=1016/);
  assert.match(r.salida, /Closes #3/);
  assert.match(r.salida, /PRIVATE-TOKEN: \$GITLAB_TOKEN/);
  assert.doesNotMatch(r.salida, new RegExp(TOKEN_FALSO));
});

test('mr-gitlab.sh: revisor por rama, destino y proyecto configurables', () => {
  const r = sh('mr-gitlab.sh', ['--origen', 'laya', '--titulo', 'Etapa 2', '--proyecto', '1407', '--destino', 'pruebas']);
  assert.equal(r.codigo, 0, r.salida);
  assert.match(r.salida, /projects\/1407\//);
  assert.match(r.salida, /target_branch=pruebas/);
  assert.match(r.salida, /reviewer_ids\[\]=1013/);
});

test('mr-gitlab.sh rechaza datos inválidos y --ejecutar sin token en el entorno', () => {
  assert.notEqual(sh('mr-gitlab.sh', ['--titulo', 'x']).codigo, 0);
  assert.notEqual(sh('mr-gitlab.sh', ['--origen', 'diego']).codigo, 0);
  assert.notEqual(sh('mr-gitlab.sh', ['--origen', 'desarrollo', '--titulo', 'x']).codigo, 0);
  assert.notEqual(sh('mr-gitlab.sh', ['--origen', 'diego', '--titulo', 'x', '--proyecto', 'abc']).codigo, 0);
  const herramienta = sh('mr-gitlab.sh', ['--origen', 'diego', '--titulo', 'Hecho con Copilot']);
  assert.notEqual(herramienta.codigo, 0);
  assert.match(herramienta.salida, /texto no permitido/);
  const sinToken = sh('mr-gitlab.sh', ['--origen', 'diego', '--titulo', 'x', '--ejecutar']);
  assert.notEqual(sinToken.codigo, 0);
  assert.match(sinToken.salida, /GITLAB_TOKEN/);
});

test('etapa-gitlab.sh exige --clon y --etapa y no acepta el propio repositorio como clon', () => {
  assert.notEqual(sh('etapa-gitlab.sh', ['--etapa', '3']).codigo, 0);
  assert.notEqual(sh('etapa-gitlab.sh', ['--clon', SCRIPTS]).codigo, 0);
  const propio = sh('etapa-gitlab.sh', ['--clon', join(SCRIPTS, '..'), '--etapa', '3']);
  assert.notEqual(propio.codigo, 0);
  assert.match(propio.salida, /no el repositorio de trabajo/);
});

test('gitlab-evento.txt: identidades GitLab por rama personal, sin secretos', () => {
  const texto = readFileSync(join(SCRIPTS, 'gitlab-evento.txt'), 'utf8');
  assert.match(texto, /^identidad\s+diego\s+Diego Landaeta <diego\.landaeta\.g@gmail\.com>$/m);
  assert.match(texto, /^identidad\s+laya\s+Juan Laya <1016-juanluislaya@users\.noreply\.gitlab\.nube\.gob\.ve>$/m);
  assert.match(texto, /^destino\s+desarrollo$/m);
  assert.doesNotMatch(texto, /glpat-|ghp_/);
});

test('etapas-entrega.txt: cada etapa con cuerpo detallado (2+ líneas) e issue de GitLab', () => {
  const etapas = readFileSync(join(SCRIPTS, 'etapas-entrega.txt'), 'utf8').split(/^etapa\s+/m).slice(1);
  assert.ok(etapas.length >= 10);
  etapas.forEach((bloque, i) => {
    const id = bloque.split('\n')[0].trim();
    assert.ok((bloque.match(/^cuerpo\s+\S/gm) || []).length >= 2, `etapa ${id}: cuerpo`);
    assert.match(bloque, new RegExp(`^issue\\s+${i + 1}$`, 'm'), `etapa ${id}: issue`);
  });
});

test('el reparto en etapas rechaza una etapa sin cuerpo detallado', () => {
  const dir = mkdtempSync(join(tmpdir(), 'etapas-'));
  try {
    mkdirSync(join(dir, 'copia'));
    writeFileSync(join(dir, 'copia', 'a.txt'), 'a\n');
    writeFileSync(join(dir, 'excl.txt'), '');
    const etapas = (cuerpo) => `etapa uno\nmensaje Primera etapa\nautor Diego Landaeta <d@example.com>\nrama diego\n${cuerpo}ruta /a.txt\n`;
    const correr = (texto) => {
      writeFileSync(join(dir, 'etapas.txt'), texto);
      return spawnSync(process.execPath, [join(SCRIPTS, 'entrega-herramientas.mjs'), 'etapas', join(dir, 'copia'),
        join(dir, 'etapas.txt'), join(dir, 'excl.txt'), join(dir, 'plan')], { encoding: 'utf8' });
    };
    const sin = correr(etapas('cuerpo Solo una línea del cuerpo del mensaje\n'));
    assert.equal(sin.status, 1);
    assert.match(sin.stdout, /el cuerpo del mensaje tiene 1 línea/);
    const con = correr(etapas('cuerpo Incluye a.txt con el contenido base.\ncuerpo Cubre el requisito de prueba.\nissue 7\n'));
    assert.equal(con.status, 0, con.stdout);
    assert.equal(readFileSync(join(dir, 'plan', 'etapa-1.mensaje'), 'utf8'),
      'Primera etapa\n\nIncluye a.txt con el contenido base.\nCubre el requisito de prueba.\n');
    assert.equal(readFileSync(join(dir, 'plan', 'etapa-1.issue'), 'utf8'), '7\n');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
