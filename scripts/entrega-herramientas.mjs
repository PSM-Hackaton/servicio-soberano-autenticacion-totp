// Herramientas de apoyo de scripts/preparar-entrega.sh. Solo módulos nativos de Node.js 22.
// No modifica el repositorio: trabaja siempre sobre la copia exportada que recibe como argumento.
//
// Subcomandos:
//   excluir   <copia> <exclusiones.txt>                 borra lo excluido e imprime la lista de rutas borradas
//   ajustar   <copia> <lista-excluidos.txt>             revisa enlaces y menciones; corrige README.md y ARCHITECTURE.md
//   verificar <copia> [permitidos.txt] [--sin-readme]   verificaciones de limpieza; código 1 si alguna falla
//                                                       (--sin-readme: etapa intermedia, aún sin README.md)
//   env       <archivo .env generado>                   comprueba el .env creado por generar-env.js
//   etapas    <copia> <etapas.txt> <exclusiones.txt> <dir-plan> [--autor-laya "Nombre <correo>"]
//                                                       reparte la copia limpia en etapas (subida progresiva)
//   copiar    <origen> <lista> <destino>                copia los archivos de la lista con sus permisos

import {
  readFileSync, writeFileSync, readdirSync, statSync, lstatSync, rmSync, rmdirSync, existsSync,
  mkdirSync, copyFileSync, chmodSync,
} from 'node:fs';
import { join, relative, dirname, resolve, sep, basename } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const LIMITE_TAMANO = 5 * 1024 * 1024; // 5 MB

// ------------------------------------------------------------------ utilidades

/** Lista recursiva de archivos (rutas relativas con '/'), sin entrar en .git. */
function listarArchivos(raiz) {
  const salida = [];
  const recorrer = (dir) => {
    for (const nombre of readdirSync(dir)) {
      if (dir === raiz && nombre === '.git') continue;
      const ruta = join(dir, nombre);
      const st = lstatSync(ruta);
      if (st.isDirectory()) recorrer(ruta);
      else salida.push(relative(raiz, ruta).split(sep).join('/'));
    }
  };
  recorrer(raiz);
  return salida.sort();
}

/** Borra directorios vacíos de abajo hacia arriba (nunca la raíz). */
function podarVacios(raiz) {
  const podar = (dir) => {
    for (const nombre of readdirSync(dir)) {
      const ruta = join(dir, nombre);
      if (lstatSync(ruta).isDirectory() && !(dir === raiz && nombre === '.git')) podar(ruta);
    }
    if (dir !== raiz && readdirSync(dir).length === 0) rmdirSync(dir);
  };
  podar(raiz);
}

export function esBinario(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i += 1) if (buf[i] === 0) return true;
  return false;
}

export function leerLista(archivo) {
  return readFileSync(archivo, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
}

// ------------------------------------------------------------------ patrones tipo .gitignore

/**
 * Convierte un patrón de exclusión en expresión regular sobre rutas de archivo relativas.
 * - Sin '/' interna: coincide con el nombre en cualquier nivel (p. ej. "*.db", ".env").
 * - Con '/': anclado a la raíz de la copia (p. ej. "attack-lab/resultados/*").
 * - Terminado en '/': carpeta (coincide con todo lo que contiene).
 * - '*' no cruza '/', '**' sí, '?' es un carácter.
 */
function patronARegex(patron) {
  let p = patron;
  const soloCarpeta = p.endsWith('/');
  if (soloCarpeta) p = p.slice(0, -1);
  const anclado = p.includes('/');
  if (p.startsWith('/')) p = p.slice(1);
  let re = '';
  for (let i = 0; i < p.length; i += 1) {
    const c = p[i];
    if (c === '*' && p[i + 1] === '*') {
      if (p[i + 2] === '/') { re += '(?:.*/)?'; i += 2; } else { re += '.*'; i += 1; }
    } else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  const prefijo = anclado ? '^' : '^(?:.*/)?';
  const sufijo = soloCarpeta ? '/.*$' : '(?:/.*)?$';
  return new RegExp(prefijo + re + sufijo);
}

export function cargarExclusiones(archivo) {
  return leerLista(archivo).map((linea) => {
    const negado = linea.startsWith('!');
    const patron = negado ? linea.slice(1) : linea;
    return { linea, negado, re: patronARegex(patron) };
  });
}

/** La última regla que coincide decide (como en .gitignore, pero evaluada archivo por archivo). */
export function excluido(ruta, reglas) {
  let resultado = false;
  for (const r of reglas) if (r.re.test(ruta)) resultado = !r.negado;
  return resultado;
}

// ------------------------------------------------------------------ excluir

function cmdExcluir(copia, archivoExclusiones) {
  const reglas = cargarExclusiones(archivoExclusiones);
  const borrados = [];
  for (const ruta of listarArchivos(copia)) {
    if (excluido(ruta, reglas)) {
      rmSync(join(copia, ruta), { force: true });
      borrados.push(ruta);
    }
  }
  podarVacios(copia);
  process.stdout.write(borrados.map((r) => `${r}\n`).join(''));
  return 0;
}

// ------------------------------------------------------------------ ajustar (enlaces y menciones)

export const PALABRAS_HERRAMIENTAS = /claude|anthropic|gemini|chatgpt|openai|copilot|co-authored-by/i;

const RE_ENLACE_MD = /\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g;
const RE_ENLACE_HTML = /\b(?:href|src)\s*=\s*["']([^"']+)["']/gi;

function esEnlaceExterno(destino) {
  return /^(?:[a-z][a-z0-9+.-]*:|\/\/|#|\/|\$\{|\{\{)/i.test(destino);
}

function resolverDestino(copia, archivo, destino) {
  let d = destino.split('#')[0].split('?')[0];
  if (!d) return null;
  try { d = decodeURIComponent(d); } catch { /* se usa tal cual */ }
  const absoluto = resolve(copia, dirname(archivo), d);
  return { absoluto, relativo: relative(copia, absoluto).split(sep).join('/') };
}

/** Quita de README/ARCHITECTURE los enlaces y menciones en código a archivos excluidos. */
function corregirDocumento(texto, excluidos) {
  let t = texto;
  for (const ruta of excluidos) {
    const e = ruta.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const enlace = `\\[[^\\]]*\\]\\(\\s*(?:\\./)?${e}(?:#[^)]*)?\\s*\\)`;
    // "A · [X](x)" o "[X](x) · B": se quita el enlace junto con su separador.
    t = t.replace(new RegExp(`\\s*[·|,]\\s*${enlace}`, 'g'), '');
    t = t.replace(new RegExp(`${enlace}\\s*[·,]\\s*`, 'g'), '');
    // Enlace aislado: se deja solo el texto, sin enlace.
    t = t.replace(new RegExp(enlace, 'g'), (m) => m.replace(/^\[([^\]]*)\].*$/s, '$1').replace(/`/g, ''));
    // Menciones en listas: "`X`, " o ", `X`".
    const nombre = `\`(?:\\./)?${e}\``;
    t = t.replace(new RegExp(`${nombre}\\s*,\\s*`, 'g'), '');
    t = t.replace(new RegExp(`\\s*,\\s*${nombre}`, 'g'), '');
  }
  return t;
}

function cmdAjustar(copia, archivoExcluidos) {
  const excluidos = existsSync(archivoExcluidos) ? leerLista(archivoExcluidos) : [];
  const nombresExcluidos = [...new Set(excluidos.map((r) => basename(r)).filter((n) => n !== '.gitkeep'))];
  const archivos = listarArchivos(copia);
  let avisos = 0;
  const aviso = (msg) => { avisos += 1; console.log(`  AVISO  ${msg}`); };

  // 1) README.md y ARCHITECTURE.md de la raíz: se corrigen en la copia.
  for (const doc of ['README.md', 'ARCHITECTURE.md']) {
    const ruta = join(copia, doc);
    if (!existsSync(ruta)) continue;
    const antes = readFileSync(ruta, 'utf8');
    const despues = corregirDocumento(antes, excluidos);
    if (despues !== antes) {
      writeFileSync(ruta, despues);
      const a = antes.split('\n'); const d = despues.split('\n');
      const cambiadas = a.map((l, i) => (l !== d[i] ? i + 1 : 0)).filter(Boolean);
      console.log(`  CORREGIDO  ${doc} (líneas ${cambiadas.join(', ')}): se quitaron enlaces/menciones a material excluido`);
    }
  }

  // 2) .gitignore: se quitan las entradas que nombran carpetas de herramientas locales (ya no existen en la copia).
  for (const archivo of archivos.filter((a) => basename(a) === '.gitignore')) {
    const ruta = join(copia, archivo);
    const lineas = readFileSync(ruta, 'utf8').split('\n');
    const quitar = new Set();
    lineas.forEach((l, i) => {
      if (!l.startsWith('#') && PALABRAS_HERRAMIENTAS.test(l)) {
        quitar.add(i);
        // Comentario de cabecera que queda huérfano.
        const sigVacio = i + 1 >= lineas.length || lineas[i + 1].trim() === '';
        if (i > 0 && lineas[i - 1].startsWith('#') && sigVacio) quitar.add(i - 1);
        if (i > 1 && quitar.has(i - 1) && lineas[i - 2].trim() === '' && sigVacio) quitar.add(i - 2);
      }
    });
    if (quitar.size) {
      let nuevo = lineas.filter((_, i) => !quitar.has(i)).join('\n');
      if (!nuevo.endsWith('\n')) nuevo += '\n';
      writeFileSync(ruta, nuevo.replace(/\n{3,}$/, '\n'));
      console.log(`  CORREGIDO  ${archivo} (líneas ${[...quitar].map((i) => i + 1).sort((x, y) => x - y).join(', ')}): entrada de carpeta local de herramientas`);
    }
  }

  // 3) Revisión de enlaces relativos y menciones en *.md y *.html de la copia (ya corregida).
  for (const archivo of archivos.filter((a) => /\.(md|html?)$/i.test(a))) {
    const ruta = join(copia, archivo);
    if (!existsSync(ruta)) continue;
    const lineas = readFileSync(ruta, 'utf8').split('\n');
    const esHtml = /\.html?$/i.test(archivo);
    lineas.forEach((linea, i) => {
      const destinos = [];
      if (!esHtml) for (const m of linea.matchAll(RE_ENLACE_MD)) destinos.push(m[2]);
      for (const m of linea.matchAll(RE_ENLACE_HTML)) destinos.push(m[1]);
      for (const destino of destinos) {
        if (esEnlaceExterno(destino)) continue;
        const r = resolverDestino(copia, archivo, destino);
        if (!r) continue;
        if (r.relativo.startsWith('..')) { aviso(`${archivo}:${i + 1}: enlace fuera del proyecto → ${destino}`); continue; }
        if (existsSync(r.absoluto)) continue;
        if (excluidos.includes(r.relativo)) aviso(`${archivo}:${i + 1}: enlace a material excluido → ${destino}`);
        else aviso(`${archivo}:${i + 1}: enlace roto (ya lo estaba en el repositorio) → ${destino}`);
      }
      for (const nombre of nombresExcluidos) {
        if (linea.includes(nombre)) aviso(`${archivo}:${i + 1}: menciona el archivo excluido ${nombre}`);
      }
    });
  }
  console.log(avisos ? `  ${avisos} aviso(s) de enlaces/menciones (no bloquean la entrega; revíselos).` : '  Sin enlaces rotos ni menciones a material excluido.');
  return 0;
}

// ------------------------------------------------------------------ verificar

const RE_RUTAS_LOCALES = /\/home\//;
const PATRONES_SECRETOS = [
  ['token de GitHub', /\bgh[pousr]_[A-Za-z0-9]{30,}/],
  ['token de GitHub (fine-grained)', /\bgithub_pat_[A-Za-z0-9_]{20,}/],
  ['token de GitLab', /\bglpat-[A-Za-z0-9_-]{20,}/],
  ['token de GitLab (otros)', /\bgl(?:dt|rt|cbt|ptt|ft|imt|agent|oas|soat)-[A-Za-z0-9_-]{20,}/],
  ['llave de acceso AWS', /\bAKIA[0-9A-Z]{16}\b/],
  ['token de Slack', /\bxox[baprs]-[A-Za-z0-9-]{10,}/],
];
// Bloque PEM completo con cuerpo base64 real; no coincide con textos de prueba como '-----BEGIN PRIVATE KEY-----...'
// ni con código que genera las llaves en tiempo de ejecución.
const RE_PEM_PRIVADA = /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----\r?\n(?:[A-Za-z-]+: [^\n]*\r?\n|\r?\n)*(?:[A-Za-z0-9+/=]{40,}\r?\n)+[A-Za-z0-9+/=]*\r?\n?-----END \1-----/;
const NOMBRES_SENSIBLES = [
  /(^|\/)\.env$/, /(^|\/)[^/]*\.env$/, /(^|\/)\.env\.(?!example$)[^/]+$/,
  /\.(?:pem|key|crt|p12|pfx|jks|keystore|db|db-shm|db-wal|sqlite|sqlite3)$/i,
  /(^|\/)id_(?:rsa|ecdsa|ed25519|dsa)(?:\.pub)?$/, /(^|\/)node_modules\//,
];

const SECCIONES_README = [
  ['1', 'Nombre del proyecto'],
  ['2', 'Participantes'],
  ['3', 'Descripción del proyecto'],
  ['4', 'Alcance'],
  ['5', 'Requerimientos del sistema'],
  ['6', 'Instalación y despliegue'],
];

const sinAcentos = (s) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();

export function cargarPermitidos(archivo) {
  const permitidos = { marcas: new Set(), rutas: new Set(), secretos: new Set() };
  if (!archivo) return permitidos;
  for (const linea of leerLista(archivo)) {
    const [cat, ...resto] = linea.split(/\s+/);
    const ruta = resto.join(' ');
    if (!permitidos[cat] || !ruta) throw new Error(`Línea no válida en ${archivo}: "${linea}" (formato: marcas|rutas|secretos <ruta>)`);
    permitidos[cat].add(ruta);
  }
  return permitidos;
}

/** Texto de un PDF con pdftotext si está instalado; null si no se puede extraer. */
function textoPdf(ruta) {
  const r = spawnSync('pdftotext', ['-q', ruta, '-'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return r.status === 0 ? r.stdout : null;
}

function recortar(s) {
  const t = s.trim();
  return t.length > 140 ? `${t.slice(0, 137)}...` : t;
}

/**
 * Revisa un archivo (ruta relativa y contenido) con las reglas de la entrega. Lo usan cmdVerificar y los
 * ganchos de git (scripts/hooks/revisar.mjs, sobre el contenido preparado para el commit).
 * Devuelve { hallazgos: [[categoría, texto], ...], pdfSinTexto } con categorías
 * marcas | rutas | secretos | nombres | tamano. Con rutaEnDisco se extrae además el texto de los PDF.
 */
export function revisarArchivo(archivo, buf, { rutaEnDisco = null } = {}) {
  const hallazgos = [];
  let pdfSinTexto = false;
  if (buf.length > LIMITE_TAMANO) hallazgos.push(['tamano', `${archivo}: ${(buf.length / 1048576).toFixed(1)} MB`]);
  if (NOMBRES_SENSIBLES.some((re) => re.test(archivo))) hallazgos.push(['nombres', archivo]);

  const binario = esBinario(buf) || /\.pdf$/i.test(archivo);
  const fuentes = [];
  if (!binario) fuentes.push(['', buf.toString('utf8')]);
  else {
    fuentes.push([' (bytes)', buf.toString('latin1')]);
    if (/\.pdf$/i.test(archivo)) {
      const t = rutaEnDisco ? textoPdf(rutaEnDisco) : null;
      if (t === null) pdfSinTexto = true; else fuentes.push([' (texto del PDF)', t]);
    }
  }
  for (const [origen, contenido] of fuentes) {
    const enBytes = binario && !origen.includes('texto');
    contenido.split('\n').forEach((linea, i) => {
      const pos = enBytes ? '' : `:${i + 1}`;
      const m = PALABRAS_HERRAMIENTAS.exec(linea);
      if (m) hallazgos.push(['marcas', `${archivo}${pos}${origen}: «${m[0]}» en ${recortar(enBytes ? m[0] : linea)}`]);
      if (RE_RUTAS_LOCALES.test(linea)) hallazgos.push(['rutas', `${archivo}${pos}${origen}: ${recortar(enBytes ? '/home/…' : linea)}`]);
      for (const [nombre, re] of PATRONES_SECRETOS) {
        const s = re.exec(linea);
        if (s) hallazgos.push(['secretos', `${archivo}${pos}${origen}: ${nombre} (${s[0].slice(0, 8)}…)`]);
      }
    });
    const pem = RE_PEM_PRIVADA.exec(contenido);
    if (pem) {
      const linea = contenido.slice(0, pem.index).split('\n').length;
      hallazgos.push(['secretos', `${archivo}:${linea}${origen}: bloque PEM de llave privada (${pem[1]})`]);
    }
  }
  return { hallazgos, pdfSinTexto };
}

function cmdVerificar(copia, archivoPermitidos, { sinReadme = false } = {}) {
  const permitidos = cargarPermitidos(archivoPermitidos);
  const archivos = listarArchivos(copia);
  const hallazgos = { marcas: [], rutas: [], secretos: [], nombres: [], tamano: [], readme: [] };
  const permitidosUsados = [];
  let pdfSinTexto = 0;

  const anotar = (cat, archivo, texto) => {
    if (permitidos[cat]?.has(archivo)) permitidosUsados.push(`[${cat}] ${texto}`);
    else hallazgos[cat].push(texto);
  };

  for (const archivo of archivos) {
    const ruta = join(copia, archivo);
    const r = revisarArchivo(archivo, readFileSync(ruta), { rutaEnDisco: ruta });
    if (r.pdfSinTexto) pdfSinTexto += 1;
    for (const [cat, texto] of r.hallazgos) anotar(cat, archivo, texto);
  }

  // README.md: seis apartados obligatorios, en orden, como títulos de nivel 2.
  // Con --sin-readme (etapas intermedias de la subida progresiva) el README aún no se ha incorporado.
  const readme = join(copia, 'README.md');
  if (sinReadme) { /* se comprueba en la etapa que lo incorpora y en la copia completa */ }
  else if (!existsSync(readme)) hallazgos.readme.push('No existe README.md en la raíz.');
  else {
    const titulos = readFileSync(readme, 'utf8').split('\n')
      .map((l, i) => ({ l, i: i + 1 }))
      .filter(({ l }) => /^##\s+/.test(l) && !/^###/.test(l))
      .map(({ l, i }) => ({ t: sinAcentos(l.replace(/^##\s+/, '').trim()), i }));
    let ultimo = 0;
    for (const [n, nombre] of SECCIONES_README) {
      const objetivo = sinAcentos(nombre);
      const h = titulos.find(({ t }) => t.replace(/^\d+[.)]?\s*/, '').startsWith(objetivo));
      if (!h) { hallazgos.readme.push(`Falta el apartado ${n}. ${nombre} (título "## ${n}. ${nombre}")`); continue; }
      if (!new RegExp(`^${n}[.)]?\\s`).test(h.t)) hallazgos.readme.push(`README.md:${h.i}: el apartado "${nombre}" no lleva el número ${n}`);
      if (h.i < ultimo) hallazgos.readme.push(`README.md:${h.i}: "${nombre}" está fuera del orden del instructivo`);
      ultimo = Math.max(ultimo, h.i);
    }
  }

  const informe = [
    ['marcas', 'Menciones a herramientas externas de generación o coautoría'],
    ['rutas', 'Rutas locales /home/'],
    ['secretos', 'Secretos (tokens, llaves privadas PEM)'],
    ['nombres', 'Archivos sensibles por nombre (.env, llaves, bases, node_modules)'],
    ['tamano', 'Archivos de más de 5 MB'],
    ['readme', 'README.md con los 6 apartados del instructivo, en orden'],
  ].filter(([cat]) => !(sinReadme && cat === 'readme'));
  let fallos = 0;
  for (const [cat, titulo] of informe) {
    const lista = hallazgos[cat];
    if (!lista.length) { console.log(`  OK     ${titulo}`); continue; }
    fallos += 1;
    console.log(`  FALLA  ${titulo}: ${lista.length} hallazgo(s)`);
    for (const h of lista.slice(0, 40)) console.log(`           - ${h}`);
    if (lista.length > 40) console.log(`           … y ${lista.length - 40} más`);
  }
  if (permitidosUsados.length) {
    console.log(`  NOTA   ${permitidosUsados.length} hallazgo(s) aceptados por la lista de permitidos:`);
    for (const p of permitidosUsados) console.log(`           - ${p}`);
  }
  if (pdfSinTexto) console.log(`  NOTA   ${pdfSinTexto} PDF sin texto extraíble (pdftotext no disponible): solo se revisaron sus bytes; revíselos a mano.`);
  console.log(`  Archivos revisados: ${archivos.length}`);
  return fallos ? 1 : 0;
}

// ------------------------------------------------------------------ env

function cmdEnv(archivo) {
  if (!existsSync(archivo)) { console.log(`  FALLA  no se creó ${archivo}`); return 1; }
  const texto = readFileSync(archivo, 'utf8');
  const modo = statSync(archivo).mode & 0o777;
  const problemas = [];
  // Solo cuentan las asignaciones; los comentarios de la plantilla mencionan CHANGE_ME a propósito.
  if (/^\s*[A-Za-z_][A-Za-z0-9_]*=.*CHANGE_ME/m.test(texto)) problemas.push('quedan valores CHANGE_ME');
  if (modo !== 0o600) problemas.push(`permisos ${modo.toString(8)} (se esperaba 600)`);
  if (!/^MASTER_KEY_[A-Z0-9]+_HEX=[0-9a-f]{64}$/m.test(texto)) problemas.push('no hay llave maestra de 256 bits');
  if (problemas.length) { console.log(`  FALLA  .env generado: ${problemas.join('; ')}`); return 1; }
  const variables = texto.split('\n').filter((l) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(l)).length;
  console.log(`  OK     .env generado (${variables} variables, sin CHANGE_ME, permisos 600)`);
  return 0;
}

// ------------------------------------------------------------------ etapas (subida progresiva)

const RE_IDENTIDAD = /^(\S(?:.*\S)?)\s*<([^<>\s@]+@[^<>\s@]+\.[^<>\s@]+)>$/;
const RAMAS_TRABAJO = new Set(['diego', 'laya']);
const MARCADOR_LAYA = 'AUTOR_LAYA';

/**
 * Lee scripts/etapas-entrega.txt. Formato: líneas "clave valor"; cada "etapa <id>" abre una etapa nueva.
 * Claves: etapa, mensaje, autor, rama, ruta (repetible; admite "!patrón").
 */
function leerEtapas(archivo) {
  const etapas = [];
  const errores = [];
  readFileSync(archivo, 'utf8').split(/\r?\n/).forEach((original, i) => {
    const linea = original.trim();
    if (!linea || linea.startsWith('#')) return;
    const m = /^(\S+)\s+(.+)$/.exec(linea);
    if (!m) { errores.push(`${basename(archivo)}:${i + 1}: línea sin valor: "${linea}"`); return; }
    const [, clave, valor] = m;
    if (clave === 'etapa') { etapas.push({ id: valor, linea: i + 1, rutas: [] }); return; }
    const actual = etapas.at(-1);
    if (!actual) { errores.push(`${basename(archivo)}:${i + 1}: "${clave}" antes de la primera "etapa"`); return; }
    if (clave === 'ruta') actual.rutas.push(valor);
    else if (['mensaje', 'autor', 'rama'].includes(clave)) {
      if (actual[clave] !== undefined) errores.push(`${basename(archivo)}:${i + 1}: "${clave}" repetido en la etapa ${actual.id}`);
      actual[clave] = valor;
    } else errores.push(`${basename(archivo)}:${i + 1}: clave desconocida "${clave}"`);
  });
  return { etapas, errores };
}

/**
 * Asigna cada archivo de la copia limpia a la PRIMERA etapa cuyas rutas lo incluyan (dentro de una etapa,
 * la última regla que coincide decide, como en las exclusiones). Escribe en <dirPlan>:
 *   plan.tsv        n, id, rama, nombre, correo, nº de archivos, mensaje (separados por tabulador)
 *   etapa-N.lista   archivos que incorpora la etapa N (uno por línea)
 * Falla si un archivo queda sin etapa, si una etapa queda vacía, si una regla no coincide con nada,
 * si falta un dato o si se incluye algo que las exclusiones prohíben.
 */
function cmdEtapas(copia, archivoEtapas, archivoExclusiones, dirPlan, opciones) {
  const { etapas, errores } = leerEtapas(archivoEtapas);
  const archivos = listarArchivos(copia);
  const exclusiones = cargarExclusiones(archivoExclusiones);
  const ids = new Set();
  let autorLaya = null;
  if (opciones.autorLaya !== undefined) {
    if (!RE_IDENTIDAD.test(opciones.autorLaya)) errores.push(`--autor-laya no tiene el formato "Nombre Apellido <correo@dominio>": "${opciones.autorLaya}"`);
    else autorLaya = opciones.autorLaya;
  }
  if (!etapas.length) errores.push(`${basename(archivoEtapas)} no define ninguna etapa`);

  for (const e of etapas) {
    const donde = `etapa ${e.id} (línea ${e.linea})`;
    if (ids.has(e.id)) errores.push(`${donde}: identificador repetido`);
    ids.add(e.id);
    for (const clave of ['mensaje', 'autor', 'rama']) if (!e[clave]) errores.push(`${donde}: falta "${clave}"`);
    if (e.rama && !RAMAS_TRABAJO.has(e.rama)) errores.push(`${donde}: rama "${e.rama}" no es una rama de trabajo (${[...RAMAS_TRABAJO].join(', ')})`);
    if (e.autor === MARCADOR_LAYA) {
      if (!autorLaya && opciones.autorLaya === undefined) errores.push(`${donde}: el autor es ${MARCADOR_LAYA}; indíquelo con --autor-laya "Nombre Apellido <correo>"`);
      e.autor = autorLaya ?? e.autor;
    }
    const id = RE_IDENTIDAD.exec(e.autor ?? '');
    if (e.autor && e.autor !== MARCADOR_LAYA && !id) errores.push(`${donde}: autor sin formato "Nombre <correo>": "${e.autor}"`);
    if (id) { e.nombre = id[1]; e.correo = id[2]; }
    if (!e.rutas.length) errores.push(`${donde}: no tiene rutas`);
    e.reglas = e.rutas.map((linea) => {
      const negado = linea.startsWith('!');
      return { linea, negado, re: patronARegex(negado ? linea.slice(1) : linea) };
    });
    for (const r of e.reglas) {
      if (!archivos.some((a) => r.re.test(a))) errores.push(`${donde}: la ruta "${r.linea}" no coincide con ningún archivo de la copia limpia`);
    }
    e.archivos = [];
  }

  const sinEtapa = [];
  for (const archivo of archivos) {
    if (excluido(archivo, exclusiones)) errores.push(`${archivo}: está en la copia pero las exclusiones lo prohíben`);
    const etapa = etapas.find((e) => excluido(archivo, e.reglas));
    if (etapa) etapa.archivos.push(archivo); else sinEtapa.push(archivo);
  }
  if (sinEtapa.length) errores.push(`${sinEtapa.length} archivo(s) de la copia limpia sin etapa:\n${sinEtapa.map((a) => `      - ${a}`).join('\n')}`);
  for (const e of etapas) if (e.reglas.length && !e.archivos.length) errores.push(`etapa ${e.id}: no incorpora ningún archivo (todo lo toman etapas anteriores)`);

  if (errores.length) {
    for (const e of errores) console.log(`  ERROR  ${e}`);
    return 1;
  }

  const limpiar = (s) => s.replace(/[\t\r\n]+/g, ' ');
  const tsv = etapas.map((e, i) => [i + 1, e.id, e.rama, e.nombre, e.correo, e.archivos.length, e.mensaje].map((c) => limpiar(String(c))).join('\t'));
  mkdirSync(dirPlan, { recursive: true });
  writeFileSync(join(dirPlan, 'plan.tsv'), `${tsv.join('\n')}\n`);
  etapas.forEach((e, i) => writeFileSync(join(dirPlan, `etapa-${i + 1}.lista`), `${e.archivos.join('\n')}\n`));

  const ancho = Math.max(...etapas.map((e) => e.id.length));
  etapas.forEach((e, i) => {
    console.log(`  ${String(i + 1).padStart(2)}. ${e.id.padEnd(ancho)}  ${e.rama.padEnd(5)}  ${String(e.archivos.length).padStart(4)} arch.  ${e.nombre} <${e.correo}>`);
    console.log(`      ${e.mensaje}`);
  });
  console.log(`  Total: ${archivos.length} archivos en ${etapas.length} etapas; ninguno sin etapa, ninguno excluido.`);
  return 0;
}

/** Copia los archivos de <lista> (rutas relativas, una por línea) de <origen> a <destino>, con sus permisos. */
function cmdCopiar(origen, lista, destino) {
  const rutas = readFileSync(lista, 'utf8').split('\n').filter(Boolean);
  for (const ruta of rutas) {
    const desde = join(origen, ruta);
    const hacia = join(destino, ruta);
    if (!existsSync(desde)) { console.error(`No existe ${desde}`); return 1; }
    mkdirSync(dirname(hacia), { recursive: true });
    copyFileSync(desde, hacia);
    chmodSync(hacia, statSync(desde).mode & 0o777);
  }
  return 0;
}

// ------------------------------------------------------------------ principal

// Solo se ejecuta como programa; al importarlo (ganchos de git) solo aporta las reglas exportadas.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  principal();
}

function principal() {
  const [cmd, ...resto] = process.argv.slice(2);
  const banderas = new Set(resto.filter((a) => a === '--sin-readme'));
  const args = resto.filter((a) => !banderas.has(a));
  /** Extrae "--opcion valor" de args (para valores que pueden contener espacios). */
  function opcionConValor(nombre) {
    const i = args.indexOf(nombre);
    if (i === -1) return undefined;
    const valor = args[i + 1] ?? '';
    args.splice(i, 2);
    return valor;
  }
  const autorLaya = opcionConValor('--autor-laya');
  const comandos = {
    excluir: () => cmdExcluir(resolve(args[0]), resolve(args[1])),
    ajustar: () => cmdAjustar(resolve(args[0]), resolve(args[1])),
    verificar: () => cmdVerificar(resolve(args[0]), args[1] ? resolve(args[1]) : null, { sinReadme: banderas.has('--sin-readme') }),
    env: () => cmdEnv(resolve(args[0])),
    etapas: () => cmdEtapas(resolve(args[0]), resolve(args[1]), resolve(args[2]), resolve(args[3]), { autorLaya }),
    copiar: () => cmdCopiar(resolve(args[0]), resolve(args[1]), resolve(args[2])),
  };
  // Argumentos obligatorios de cada subcomando (sin ellos resolve() recibiría undefined y lanzaría TypeError).
  const usos = {
    excluir: ['<copia>', '<exclusiones.txt>'],
    ajustar: ['<copia>', '<lista-excluidos.txt>'],
    verificar: ['<copia>'],
    env: ['<archivo .env>'],
    etapas: ['<copia>', '<etapas.txt>', '<exclusiones.txt>', '<dir-plan>'],
    copiar: ['<origen>', '<lista>', '<destino>'],
  };
  if (!comandos[cmd] || args.length < usos[cmd].length || args.slice(0, usos[cmd].length).some((a) => !a)) {
    if (comandos[cmd]) {
      console.error(`Uso: node entrega-herramientas.mjs ${cmd} ${usos[cmd].join(' ')}${cmd === 'etapas' ? ' [--autor-laya "Nombre <correo>"]' : ''}`);
    } else {
      console.error('Uso: node entrega-herramientas.mjs excluir|ajustar|verificar|env|etapas|copiar <copia> [...]');
    }
    process.exitCode = 2;
  } else {
    process.exitCode = comandos[cmd]();
  }
}
