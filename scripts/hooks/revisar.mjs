// Lógica de los ganchos de git del equipo (pre-commit, commit-msg y pre-push). Solo módulos nativos de Node.js 22.
// Las reglas (cadenas prohibidas, rutas /home/, secretos, nombres sensibles, tamaño) NO se repiten aquí: se
// importan de scripts/entrega-herramientas.mjs, las mismas que verifican la copia de la entrega para GitLab.
//
// Subcomandos (los llama cada gancho; el directorio actual es la raíz del repositorio que se confirma):
//   confirmacion          revisa el contenido preparado para el commit (índice), no la copia de trabajo
//   mensaje <archivo>     revisa el mensaje del commit
//   envio <remoto>        revisa autores y mensajes de los commits nuevos y ejecuta scripts/verificar-todo.js
//
// Las listas de exclusiones y permitidos se leen de la carpeta scripts/ de este mismo repositorio de trabajo,
// también cuando los ganchos se instalan en otro repositorio (p. ej. la copia de la entrega).

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  revisarArchivo, PALABRAS_HERRAMIENTAS, cargarExclusiones, excluido, cargarPermitidos,
} from '../entrega-herramientas.mjs';

const DIR_SCRIPTS = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const VARIABLE_EMERGENCIA = 'SALTAR_VERIFICACION';
const CERO = /^0+$/;

const rojo = (t) => (process.stderr.isTTY ? `\x1b[31m${t}\x1b[0m` : t);
const error = (t) => console.error(rojo(`  ERROR  ${t}`));
const aviso = (t) => console.error(`  AVISO  ${t}`);

function git(args, { buffer = false, entrada } = {}) {
  const r = spawnSync('git', args, {
    encoding: buffer ? 'buffer' : 'utf8', maxBuffer: 256 * 1024 * 1024, input: entrada,
  });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${String(r.stderr).trim()}`);
  return r.stdout;
}

// ------------------------------------------------------------------ pre-commit

const TITULOS = {
  marcas: 'menciona herramientas de generación de contenido o líneas de coautoría',
  rutas: 'contiene rutas locales /home/',
  secretos: 'contiene un secreto (token o llave privada)',
  nombres: 'es un archivo sensible por nombre (.env real, llave, certificado, base de datos, node_modules)',
  tamano: 'supera 5 MB',
};

function confirmacion() {
  const exclusiones = join(DIR_SCRIPTS, 'exclusiones-entrega.txt');
  const permitidosArch = join(DIR_SCRIPTS, 'permitidos-entrega.txt');
  const reglas = existsSync(exclusiones) ? cargarExclusiones(exclusiones) : [];
  const permitidos = cargarPermitidos(existsSync(permitidosArch) ? permitidosArch : null);

  const rutas = git(['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z']).split('\0').filter(Boolean);
  const fallos = [];
  for (const ruta of rutas) {
    const buf = git(['cat-file', 'blob', `:${ruta}`], { buffer: true });
    // Material interno (scripts/exclusiones-entrega.txt) nunca llega a GitLab: puede nombrar herramientas y
    // rutas porque son justo lo que buscan los verificadores. Los .gitignore se ajustan solos en la entrega.
    // Archivos sensibles, secretos y tamaño se bloquean siempre.
    const interno = excluido(ruta, reglas) || /(^|\/)\.gitignore$/.test(ruta);
    for (const [cat, texto] of revisarArchivo(ruta, buf).hallazgos) {
      if ((cat === 'marcas' || cat === 'rutas') && interno) continue;
      if (permitidos[cat]?.has(ruta)) continue;
      fallos.push([cat, texto]);
    }
  }
  if (!fallos.length) return 0;
  console.error(`\npre-commit: el commit no se creó. ${fallos.length} problema(s) en lo preparado (git add):`);
  for (const [cat, texto] of fallos) error(`${texto} → ${TITULOS[cat]}`);
  console.error(`
  Corríjalo y vuelva a preparar el archivo; para sacarlo del commit: git restore --staged <archivo>.
  Los .env, llaves, certificados y bases de datos se generan en cada instalación: nunca se versionan.
  Si un hallazgo es legítimo, anótelo en scripts/permitidos-entrega.txt (y avíselo en el Merge Request).\n`);
  return 1;
}

// ------------------------------------------------------------------ commit-msg

// Primeras palabras típicas de mensajes en inglés (también los generados por git: Merge, Revert).
const VERBOS_INGLES = new Set(('add adds added fix fixes fixed update updates updated remove removes removed delete '
  + 'deleted refactor refactored implement implemented create created change changed improve improved bump merge '
  + 'merged revert reverted initial wip move moved rename renamed clean cleanup upgrade use make allow support '
  + 'enable disable handle replace replaced'
).split(' '));
const PALABRAS_INGLES = new Set('the and with for to of from into when this that on by is are was it'.split(' '));
const PALABRAS_CASTELLANO = new Set(('de la el los las del con para por en y o que se al un una sin según '
  + 'desde hasta como más').split(' '));
const RE_TIPO = /^([a-z]+)(\([^)]*\))?!?:\s+/;

const MINIMO_LINEAS_CUERPO = 2;
const RE_SOLO_REFERENCIA = /^(?:[-*]\s*)?(?:(?:closes|close|closed|fixes|fix|fixed|resolves|resolve|resolved|refs|ref|cierra|relacionado con)\s*:?\s*)?(?:[\w./-]*#\d+[\s,]*)+$/i;

/** Línea del cuerpo que describe algo: al menos 3 palabras y 15 caracteres, y no solo una referencia a un issue. */
function esLineaDescriptiva(linea) {
  const t = linea.trim();
  if (!t || RE_SOLO_REFERENCIA.test(t)) return false;
  return [...t].length >= 15 && (t.match(/[\p{L}\p{N}]+/gu) || []).length >= 3;
}

function limpiarMensaje(texto) {
  const lineas = [];
  for (const l of texto.split(/\r?\n/)) {
    if (/^# -+ >8 -+$/.test(l)) break; // git commit -v: lo que sigue es el diff
    if (l.startsWith('#')) continue;
    lineas.push(l.replace(/\s+$/, ''));
  }
  while (lineas.length && !lineas[0]) lineas.shift();
  while (lineas.length && !lineas[lineas.length - 1]) lineas.pop();
  return lineas;
}

function mensaje(archivo) {
  const lineas = limpiarMensaje(readFileSync(archivo, 'utf8'));
  if (!lineas.length) return 0; // git aborta por sí mismo los mensajes vacíos
  const asunto = lineas[0];
  const fallos = [];
  const avisos = [];

  lineas.forEach((l, i) => {
    const m = PALABRAS_HERRAMIENTAS.exec(l);
    if (m) fallos.push(`línea ${i + 1}: «${m[0]}». No se admiten líneas de coautoría ni menciones a herramientas de generación; el autor es quien hace el commit.`);
  });

  if (/^(fixup|squash|amend)! /.test(asunto)) return informarMensaje(fallos, avisos);

  const largo = [...asunto].length;
  if (largo < 10) fallos.push(`el título tiene ${largo} caracteres: describa qué cambia (mínimo 10).`);
  if (largo > 100) fallos.push(`el título tiene ${largo} caracteres (máximo 100); el detalle va en el cuerpo, tras una línea en blanco.`);
  else if (largo > 72) avisos.push(`el título tiene ${largo} caracteres; se recomiendan 72 como máximo.`);
  if (lineas.length > 1 && lineas[1]) avisos.push('deje una línea en blanco entre el título y el cuerpo.');

  // Commits detallados: cuerpo con al menos 2 líneas descriptivas (qué incluye, qué requisito cubre, qué
  // pruebas se ejecutaron). No cuentan las referencias sueltas («Closes #3», «Refs #3») ni las líneas cortas.
  const descriptivas = lineas.slice(1).filter(esLineaDescriptiva);
  if (descriptivas.length < MINIMO_LINEAS_CUERPO) {
    fallos.push(`el cuerpo tiene ${descriptivas.length} línea(s) descriptiva(s); se exigen al menos ${MINIMO_LINEAS_CUERPO}: `
      + 'tras una línea en blanco, explique qué módulos o archivos cambian, qué requisito o issue cubre y qué pruebas se ejecutaron y con qué resultado.');
  }

  const tipo = RE_TIPO.exec(asunto);
  const descripcion = tipo ? asunto.slice(tipo[0].length) : asunto;
  const palabras = descripcion.toLowerCase().match(/[a-záéíóúüñ]+/g) || [];
  const resto = [asunto, ...lineas.slice(1)].join(' ').toLowerCase().match(/[a-záéíóúüñ]+/g) || [];
  const ingles = resto.filter((p) => PALABRAS_INGLES.has(p)).length;
  const castellano = resto.filter((p) => PALABRAS_CASTELLANO.has(p)).length;
  if (palabras[0] && VERBOS_INGLES.has(palabras[0])) {
    fallos.push(`el mensaje empieza en inglés («${palabras[0]}»). Escríbalo en castellano, en infinitivo: «añadir», «corregir», «actualizar», «integrar la rama…», «revertir…».`);
  } else if (ingles >= 2 && castellano === 0) {
    fallos.push('el mensaje parece escrito en inglés. Escríbalo en castellano.');
  }

  if (!tipo) avisos.push('formato recomendado «tipo(ámbito): descripción» (feat, fix, docs, test, refactor, ci, chore).');
  if (!/#\d+/.test(lineas.join('\n'))) avisos.push('no referencia ningún issue: añada «(#N)» al título o «Refs #N» en el cuerpo.');
  return informarMensaje(fallos, avisos);
}

function informarMensaje(fallos, avisos) {
  if (fallos.length) console.error('\ncommit-msg: el commit no se creó. El mensaje no cumple las reglas del equipo:');
  else if (avisos.length) console.error('\ncommit-msg: mensaje aceptado, con recomendaciones:');
  for (const f of fallos) error(f);
  for (const a of avisos) aviso(a);
  if (fallos.length) console.error('\n  Ejemplo:\n    feat(backend): añadir ventana de deriva configurable (#12)\n\n    Añade TOTP_DRIFT_MAX a la configuración y la aplica en verificarCodigo (backend/src/core/totp).\n    Cubre el requisito de tolerancia de reloj del reto; pruebas: npm test en backend, 50/50 correctas.\n    Closes #12\n  (el mensaje escrito sigue en .git/COMMIT_EDITMSG)\n');
  else if (avisos.length) console.error('');
  return fallos.length ? 1 : 0;
}

// ------------------------------------------------------------------ pre-push

function envio(remoto) {
  const entrada = readFileSync(0, 'utf8');
  const fallos = [];
  let commits = 0;
  for (const linea of entrada.split('\n').filter(Boolean)) {
    const [, local, , remotoSha] = linea.split(' ');
    if (CERO.test(local)) continue; // borrado de una rama remota
    const rango = CERO.test(remotoSha) ? [local, '--not', `--remotes=${remoto}`] : [`${remotoSha}..${local}`];
    let salida;
    try {
      salida = git(['log', '--format=%h%x1f%an <%ae>%x1f%cn <%ce>%x1f%B%x1e', ...rango]);
    } catch {
      // El commit remoto no está en local (falta git fetch): se revisa solo el último commit.
      salida = git(['log', '-1', '--format=%h%x1f%an <%ae>%x1f%cn <%ce>%x1f%B%x1e', local]);
    }
    for (const registro of salida.split('\x1e').map((r) => r.trim()).filter(Boolean)) {
      commits += 1;
      const [h, autor, confirma, cuerpo = ''] = registro.split('\x1f');
      for (const [que, texto] of [['autor', autor], ['quien confirma', confirma], ['mensaje', cuerpo]]) {
        const m = PALABRAS_HERRAMIENTAS.exec(texto);
        if (m) fallos.push(`${h}: ${que} con «${m[0]}»`);
      }
      if (/\[bot\]/i.test(autor)) fallos.push(`${h}: autor automático (${autor}); la autoría debe ser de una persona del equipo`);
    }
  }
  if (fallos.length) {
    console.error(`\npre-push: no se subió nada. ${fallos.length} problema(s) en los commits nuevos:`);
    for (const f of fallos) error(f);
    console.error(`
  Reescriba esos commits antes de subirlos (git commit --amend o git rebase -i sobre su rama de trabajo,
  nunca sobre avance ni terminado) y quite las líneas de coautoría o menciones.\n`);
    return 1;
  }

  if (process.env[VARIABLE_EMERGENCIA] === '1') {
    console.error(`\npre-push: ${VARIABLE_EMERGENCIA}=1 → se omite node scripts/verificar-todo.js (${commits} commit(s) revisados).`);
    console.error('  Solo para emergencias. Anótelo en el Merge Request y ejecute la verificación en cuanto sea posible.\n');
    return 0;
  }
  if (!existsSync('scripts/verificar-todo.js')) {
    error('no existe scripts/verificar-todo.js en este repositorio; no se puede verificar antes de subir.');
    return 1;
  }
  // verificar-todo.js regenera docs/sbom/ (fecha y commit). Lo que no estaba modificado antes se restaura después.
  // (Se verifica la copia de trabajo: confirme o aparte los cambios sin commit antes de subir.)
  const sucios = () => git(['status', '--porcelain', '-z', '--', 'docs/sbom']).split('\0').filter(Boolean).map((l) => l.slice(3));
  const antes = new Set(sucios());
  console.error(`\npre-push: ${commits} commit(s) revisados; ejecutando node scripts/verificar-todo.js antes de subir…`);
  const r = spawnSync(process.execPath, ['scripts/verificar-todo.js'], { stdio: ['ignore', 'inherit', 'inherit'] });
  const restaurar = sucios().filter((ruta) => !antes.has(ruta));
  if (restaurar.length) git(['checkout', '--', ...restaurar]);
  if (r.status === 0) return 0;
  console.error(`
pre-push: no se subió nada porque la verificación falló. Corrija y vuelva a subir.
  Solo en una emergencia acordada con Diego o Juan: ${VARIABLE_EMERGENCIA}=1 git push …  (y anótelo en el Merge Request).\n`);
  return 1;
}

// ------------------------------------------------------------------ principal

const [cmd, arg] = process.argv.slice(2);
const comandos = { confirmacion: () => confirmacion(), mensaje: () => mensaje(arg), envio: () => envio(arg || 'origin') };
if (!comandos[cmd] || (cmd === 'mensaje' && !arg)) {
  console.error('Uso: node scripts/hooks/revisar.mjs confirmacion | mensaje <archivo> | envio <remoto>');
  process.exitCode = 2;
} else {
  try {
    process.exitCode = comandos[cmd]();
  } catch (e) {
    error(e.message);
    process.exitCode = 1;
  }
}
