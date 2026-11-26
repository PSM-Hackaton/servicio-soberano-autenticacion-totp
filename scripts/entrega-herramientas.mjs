// Herramientas de apoyo de scripts/preparar-entrega.sh. Solo módulos nativos de Node.js 22.
// No modifica el repositorio: trabaja siempre sobre la copia exportada que recibe como argumento.
//
// Subcomandos:
//   excluir   <copia> <exclusiones.txt>                 borra lo excluido e imprime la lista de rutas borradas
//   ajustar   <copia> <lista-excluidos.txt>             revisa enlaces y menciones; corrige README.md y ARCHITECTURE.md
//   verificar <copia> [permitidos.txt]                  verificaciones de limpieza; código 1 si alguna falla
//   env       <archivo .env generado>                   comprueba el .env creado por generar-env.js

import { readFileSync, writeFileSync, readdirSync, statSync, lstatSync, rmSync, rmdirSync, existsSync } from 'node:fs';
import { join, relative, dirname, resolve, sep, basename } from 'node:path';
import { spawnSync } from 'node:child_process';

const LIMITE_TAMANO = 5 * 1024 * 1024; // 5 MB

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

function esBinario(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i += 1) if (buf[i] === 0) return true;
  return false;
}

function leerLista(archivo) {
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

function cargarExclusiones(archivo) {
  return leerLista(archivo).map((linea) => {
    const negado = linea.startsWith('!');
    const patron = negado ? linea.slice(1) : linea;
    return { linea, negado, re: patronARegex(patron) };
  });
}

/** La última regla que coincide decide (como en .gitignore, pero evaluada archivo por archivo). */
function excluido(ruta, reglas) {
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

const PALABRAS_HERRAMIENTAS = /claude|anthropic|gemini|chatgpt|openai|copilot|co-authored-by/i;

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

function cargarPermitidos(archivo) {
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

function cmdVerificar(copia, archivoPermitidos) {
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
    const st = statSync(ruta);
    if (st.size > LIMITE_TAMANO) hallazgos.tamano.push(`${archivo}: ${(st.size / 1048576).toFixed(1)} MB`);
    if (NOMBRES_SENSIBLES.some((re) => re.test(archivo))) hallazgos.nombres.push(archivo);

    const buf = readFileSync(ruta);
    const binario = esBinario(buf) || /\.pdf$/i.test(archivo);
    const fuentes = [];
    if (!binario) fuentes.push(['', buf.toString('utf8')]);
    else {
      fuentes.push([' (bytes)', buf.toString('latin1')]);
      if (/\.pdf$/i.test(archivo)) {
        const t = textoPdf(ruta);
        if (t === null) pdfSinTexto += 1; else fuentes.push([' (texto del PDF)', t]);
      }
    }
    for (const [origen, contenido] of fuentes) {
      const lineas = contenido.split('\n');
      lineas.forEach((linea, i) => {
        const pos = binario && !origen.includes('texto') ? '' : `:${i + 1}`;
        const m = PALABRAS_HERRAMIENTAS.exec(linea);
        if (m) anotar('marcas', archivo, `${archivo}${pos}${origen}: «${m[0]}» en ${recortar(binario && !origen.includes('texto') ? m[0] : linea)}`);
        if (RE_RUTAS_LOCALES.test(linea)) anotar('rutas', archivo, `${archivo}${pos}${origen}: ${recortar(binario && !origen.includes('texto') ? '/home/…' : linea)}`);
        for (const [nombre, re] of PATRONES_SECRETOS) {
          const s = re.exec(linea);
          if (s) anotar('secretos', archivo, `${archivo}${pos}${origen}: ${nombre} (${s[0].slice(0, 8)}…)`);
        }
      });
      const pem = RE_PEM_PRIVADA.exec(contenido);
      if (pem) {
        const linea = contenido.slice(0, pem.index).split('\n').length;
        anotar('secretos', archivo, `${archivo}:${linea}${origen}: bloque PEM de llave privada (${pem[1]})`);
      }
    }
  }

  // README.md: seis apartados obligatorios, en orden, como títulos de nivel 2.
  const readme = join(copia, 'README.md');
  if (!existsSync(readme)) hallazgos.readme.push('No existe README.md en la raíz.');
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
  ];
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

// ------------------------------------------------------------------ principal

const [cmd, ...args] = process.argv.slice(2);
const comandos = {
  excluir: () => cmdExcluir(resolve(args[0]), resolve(args[1])),
  ajustar: () => cmdAjustar(resolve(args[0]), resolve(args[1])),
  verificar: () => cmdVerificar(resolve(args[0]), args[1] ? resolve(args[1]) : null),
  env: () => cmdEnv(resolve(args[0])),
};
if (!comandos[cmd] || !args[0]) {
  console.error('Uso: node entrega-herramientas.mjs excluir|ajustar|verificar|env <copia> [...]');
  process.exitCode = 2;
} else {
  process.exitCode = comandos[cmd]();
}
