// Pruebas de las reglas de identidad y de texto de scripts/entrega-comun.sh (herramienta interna, no se
// publica: este archivo está en scripts/exclusiones-entrega.txt). Ejecutar: node --test 'scripts/tests/*.test.mjs'
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const COMUN = join(dirname(fileURLToPath(import.meta.url)), '..', 'entrega-comun.sh');

/** Ejecuta la función $funcion de entrega-comun.sh con los argumentos dados; devuelve el código de salida. */
function llamar(funcion, ...args) {
  const r = spawnSync('sh', ['-c', `. "$0"; ${funcion} "$@"`, COMUN, ...args], { encoding: 'utf8' });
  if (r.error) throw r.error;
  return r.status;
}
const identidad = (nombre, correo) => llamar('entrega_identidad_valida', nombre, correo) === 0;
const texto = (t) => llamar('entrega_texto_valido', t) === 0;

test('acepta las identidades noreply personales del GitLab del evento', () => {
  for (const [nombre, correo] of [
    ['Juan Laya', '1016-juanluislaya@users.noreply.gitlab.nube.gob.ve'],
    ['Enggel Rodriguez', '1017-metagamingprohd@users.noreply.gitlab.nube.gob.ve'],
    ['Javier Rodriguez', '1015-jarmolina2015@users.noreply.gitlab.nube.gob.ve'],
    ['Giovani Marcano', '1014-gregoriogonzales2011@users.noreply.gitlab.nube.gob.ve'],
  ]) assert.equal(identidad(nombre, correo), true, `${nombre} <${correo}>`);
});

test('acepta correos normales y el noreply personal de GitHub', () => {
  assert.equal(identidad('Diego Landaeta', 'diego.landaeta.g@gmail.com'), true);
  assert.equal(identidad('Juan Laya', '12345678+lya0509@users.noreply.github.com'), true);
});

test('sigue rechazando noreply de servicios y cuentas automáticas', () => {
  assert.equal(identidad('Asistente', 'noreply@example.com'), false);
  assert.equal(identidad('Servicio', 'no-reply@example.com'), false);
  assert.equal(identidad('Juan Laya', 'juanluislaya@users.noreply.gitlab.nube.gob.ve'), false, 'sin id numérico no es personal');
  assert.equal(identidad('github-actions[bot]', '41898282+github-actions[bot]@users.noreply.github.com'), false);
  assert.equal(identidad('', 'diego.landaeta.g@gmail.com'), false);
  assert.equal(identidad('Diego Landaeta', ''), false);
});

test('sigue bloqueando menciones a herramientas, también dentro de un noreply personal', () => {
  for (const nombre of ['Claude', 'ChatGPT', 'Gemini', 'Copilot', 'OpenAI', 'Anthropic']) {
    assert.equal(identidad(nombre, 'diego.landaeta.g@gmail.com'), false, nombre);
  }
  assert.equal(identidad('Diego Landaeta', '1016-claude@users.noreply.gitlab.nube.gob.ve'), false);
  assert.equal(identidad('Diego Landaeta', '1016-copilot@users.noreply.github.com'), false);
});

test('mensajes de commit: coautorías y noreply ajenos se rechazan; el noreply personal no', () => {
  assert.equal(texto('Núcleo criptográfico propio, con pruebas'), true);
  assert.equal(texto('Etapa 2 de Juan Laya <1016-juanluislaya@users.noreply.gitlab.nube.gob.ve>'), true);
  assert.equal(texto('Arreglo\n\nCo-Authored-By: Alguien <alguien@example.com>'), false);
  assert.equal(texto('Arreglo\n\nRevisado por <noreply@example.com>'), false);
  assert.equal(texto('Generado con una herramienta: claude'), false);
});

test('entrega_historial_valido revisa autor, quien confirma y mensaje de cada commit', () => {
  const dir = mkdtempSync(join(tmpdir(), 'historial-'));
  try {
    const git = (env, ...a) => {
      const r = spawnSync('git', ['-C', dir, '-c', 'commit.gpgsign=false', ...a], { encoding: 'utf8', env: { ...process.env, ...env } });
      assert.equal(r.status, 0, r.stderr);
    };
    const juan = { GIT_AUTHOR_NAME: 'Juan Laya', GIT_AUTHOR_EMAIL: '1016-juanluislaya@users.noreply.gitlab.nube.gob.ve',
      GIT_COMMITTER_NAME: 'Juan Laya', GIT_COMMITTER_EMAIL: '1016-juanluislaya@users.noreply.gitlab.nube.gob.ve' };
    git({}, 'init', '--quiet', '-b', 'laya');
    git(juan, 'commit', '--quiet', '--allow-empty', '-m', 'Arquitectura y contratos');
    assert.equal(llamar('entrega_historial_valido', dir, 'laya'), 0);
    git({ ...juan, GIT_COMMITTER_EMAIL: 'noreply@example.com' }, 'commit', '--quiet', '--allow-empty', '-m', 'Otro');
    assert.equal(llamar('entrega_historial_valido', dir, 'laya'), 1);
    assert.equal(llamar('entrega_historial_valido', dir, '-1', 'laya~1'), 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('mensaje de etapa detallado: título, cuerpo, pruebas ejecutadas y Closes #n', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mensaje-'));
  try {
    const registro = join(dir, 'pruebas.log');
    writeFileSync(registro, '  OK     backend                50 pruebas, 50 correctas, 0 fallidas\n'
      + '  OK     sdk                    28 pruebas, 28 correctas, 0 fallidas\n  FALLA  otra cosa\n');
    const mensaje = join(dir, 'etapa-3.mensaje');
    writeFileSync(mensaje, 'Núcleo criptográfico propio\n\nIncluye backend/src/core/.\nCubre el núcleo criptográfico.\n');
    const r = spawnSync('sh', ['-c', '. "$0"; entrega_mensaje_etapa "$1" "en verde: $(entrega_resumen_pruebas "$2")" 3',
      COMUN, mensaje, registro], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, 'Núcleo criptográfico propio\n\nIncluye backend/src/core/.\nCubre el núcleo criptográfico.\n'
      + 'Pruebas ejecutadas: en verde: backend: 50 pruebas, 50 correctas, 0 fallidas; sdk: 28 pruebas, 28 correctas, 0 fallidas.\n'
      + '\nCloses #3\n');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
