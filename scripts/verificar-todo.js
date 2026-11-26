#!/usr/bin/env node
// Verificación integral de Integración Continua (0 dependencias npm, Node.js 22.5+).
// Issue #31 (D5): ejecuta todas las suites, valida contracts/openapi.yaml (claves duplicadas
// y resolución de $ref), verifica SBOM con 0 dependencias externas y escanea secretos/rutas locales.
//
// Uso:
//   node scripts/verificar-todo.js
//   node scripts/verificar-todo.js --cobertura [--guardar-cobertura docs/evidencias/cobertura-2026-11-26.txt]

import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const RAIZ = resolve(__dirname, '..');

/**
 * Validador YAML estricto propio para OpenAPI:
 * - Detecta claves duplicadas dentro del mismo mapeo por indentación.
 * - Comprueba que todas las referencias internas `$ref: '#/...'` existen en el documento.
 * @param {string} textoYaml
 */
export function validarOpenApiEstricto(textoYaml) {
  const lineas = textoYaml.split(/\r?\n/);
  /** @type {Array<{ indent: number, path: string, keys: Set<string> }>} */
  const pila = [{ indent: -1, path: '', keys: new Set() }];
  /** @type {Set<string>} */
  const rutasDefinidas = new Set();
  /** @type {Array<{ linea: number, ref: string }>} */
  const refs = [];
  /** @type {string[]} */
  const errores = [];

  let enBloqueTexto = false;
  let indentBloque = -1;

  for (let i = 0; i < lineas.length; i++) {
    const numLinea = i + 1;
    const raw = lineas[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const indent = raw.match(/^ */)?.[0].length ?? 0;

    if (enBloqueTexto) {
      if (indent > indentBloque) continue;
      enBloqueTexto = false;
    }

    // Elementos de lista `- ...`: reinician submapa al nivel del contenido del elemento
    const esLista = /^-\s+/.test(trimmed);
    const contenido = esLista ? trimmed.replace(/^-\s+/, '') : trimmed;

    // Extraer $ref en línea (inline o en línea propia)
    const refMatch = contenido.match(/\$ref\s*:\s*['"]?(#\/[^'"}\s,]+)['"]?/);
    if (refMatch) {
      refs.push({ linea: numLinea, ref: refMatch[1] });
    }

    // Si es una línea de clave YAML (key: ...), registrar en el mapeo actual
    const keyMatch = contenido.match(/^(['"]?)([^'":{}[\]#][^:{}[\]#]*?)\1\s*:(.*)$/);
    if (!keyMatch) continue;

    const clave = keyMatch[2].trim();
    const resto = keyMatch[3].trim();
    const indentEfectivo = esLista ? indent + 2 : indent;

    if (esLista) {
      while (pila.length > 1 && pila[pila.length - 1].indent >= indent) pila.pop();
      pila.push({ indent: indentEfectivo, path: `${pila[pila.length - 1].path}[]`, keys: new Set() });
    } else {
      while (pila.length > 1 && pila[pila.length - 1].indent >= indentEfectivo) pila.pop();
      if (pila[pila.length - 1].indent < indentEfectivo) {
        const padre = pila[pila.length - 1];
        if (!padre._ultimoHijo) {
          pila.push({ indent: indentEfectivo, path: padre.path, keys: new Set() });
        } else {
          pila.push({ indent: indentEfectivo, path: padre._ultimoHijo, keys: new Set() });
        }
      }
    }

    const actual = pila[pila.length - 1];
    if (actual.keys.has(clave)) {
      errores.push(`Línea ${numLinea}: clave YAML duplicada '${clave}' en '${actual.path || '/'}'`);
    } else {
      actual.keys.add(clave);
    }

    const rutaCompleta = actual.path ? `${actual.path}/${clave.replace(/~/g, '~0').replace(/\//g, '~1')}` : `#/${clave.replace(/~/g, '~0').replace(/\//g, '~1')}`;
    actual._ultimoHijo = rutaCompleta;
    rutasDefinidas.add(rutaCompleta);

    if (resto === '|' || resto === '>' || resto === '|-' || resto === '>-') {
      enBloqueTexto = true;
      indentBloque = indent;
    }
  }

  for (const { linea, ref } of refs) {
    if (!rutasDefinidas.has(ref)) {
      errores.push(`Línea ${linea}: $ref rota '${ref}' (no definida en el documento)`);
    }
  }

  return { ok: errores.length === 0, errores, totalRefs: refs.length };
}

/**
 * Escanea archivos rastreados del repositorio en busca de secretos, rutas locales o rastros prohibidos.
 */
function auditarHigieneRepo() {
  const errores = [];
  const resGit = spawnSync('git', ['ls-files'], { cwd: RAIZ, encoding: 'utf8' });
  const archivos = resGit.status === 0
    ? resGit.stdout.split(/\r?\n/).filter(Boolean)
    : [];

  const excluiblesRutas = new Set([
    'scripts/verificar-todo.js',
    'scripts/preparar-entrega.sh',
    'scripts/entrega-herramientas.mjs',
    'scripts/exclusiones-entrega.txt',
    'scripts/README-entrega.md',
    'attack-lab/lib/servicio.js',
    'attack-lab/tests/utilidades.test.js',
    'AGENTS.md',
    'TASKS.md',
    'ANALISIS_FASE0.md',
  ]);

  // Una línea de coautoría de commit no tiene sentido dentro de un archivo del proyecto. El patrón se arma por
  // partes para que este mismo archivo no la contenga.
  const RE_LINEA_COAUTORIA = new RegExp(`^\\s*${'Co-'}${'Authored-By'}:`, 'im');

  for (const rel of archivos) {
    if (/(^|\/)\.env$|\.(pem|key|crt|db|db-wal|db-shm)$/.test(rel)) {
      errores.push(`Archivo sensible rastreado en Git: ${rel}`);
      continue;
    }
    const abs = join(RAIZ, rel);
    if (!existsSync(abs) || statSync(abs).isDirectory()) continue;
    if (/\.(pdf|png|jpg|jpeg|webp|ico|woff2?)$/i.test(rel)) continue;

    const contenido = readFileSync(abs, 'utf8');
    if (!excluiblesRutas.has(rel) && /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(contenido) && !rel.endsWith('.test.js')) {
      errores.push(`Posible clave privada PEM en ${rel}`);
    }
    if (!excluiblesRutas.has(rel) && /\/home\/[a-z0-9_.-]+\//i.test(contenido)) {
      errores.push(`Ruta local de usuario detectada en ${rel}`);
    }
    if (!excluiblesRutas.has(rel) && RE_LINEA_COAUTORIA.test(contenido)) {
      errores.push(`Línea de coautoría dentro de un archivo: ${rel}`);
    }
  }
  return errores;
}

function ejecutarPaso(titulo, cmd, args, { cwd = RAIZ, capturar = false } = {}) {
  console.log(`\n▶ ${titulo}`);
  const r = spawnSync(cmd, args, {
    cwd,
    encoding: 'utf8',
    stdio: capturar ? 'pipe' : 'inherit',
  });
  if (capturar) {
    if (r.stdout) process.stdout.write(r.stdout);
    if (r.stderr) process.stderr.write(r.stderr);
  }
  return r;
}

function main() {
  const args = process.argv.slice(2);
  const conCobertura = args.includes('--cobertura');
  const idxGuardar = args.indexOf('--guardar-cobertura');
  const rutaCobertura = idxGuardar !== -1 ? args[idxGuardar + 1] : null;

  const fallos = [];
  const salidasCobertura = [];

  // 1. Validar contracts/openapi.yaml (claves duplicadas y $ref)
  console.log('=== 1. Validación estricta de contracts/openapi.yaml ===');
  const openapiPath = join(RAIZ, 'contracts', 'openapi.yaml');
  const validacionApi = validarOpenApiEstricto(readFileSync(openapiPath, 'utf8'));
  if (validacionApi.ok) {
    console.log(`OK: contracts/openapi.yaml sin claves duplicadas (${validacionApi.totalRefs} referencias $ref resueltas).`);
  } else {
    for (const e of validacionApi.errores) console.error(`ERROR OpenAPI: ${e}`);
    fallos.push('contracts/openapi.yaml');
  }

  // 2. Suites de pruebas (con cobertura opcional)
  console.log('\n=== 2. Ejecución de todas las suites de pruebas ===');
  const flagCov = conCobertura ? ['--experimental-test-coverage'] : [];
  const suites = [
    { nombre: 'Backend', cwd: join(RAIZ, 'backend'), args: ['--test', ...flagCov, 'src/**/*.test.js'] },
    { nombre: 'App Autenticadora PWA', cwd: RAIZ, args: ['--test', ...flagCov, 'authenticator-app/tests/*.test.mjs'] },
    { nombre: 'SDK', cwd: RAIZ, args: ['--test', ...flagCov, 'sdk/tests/*.test.js'] },
    { nombre: 'Portal de Trámites Demo', cwd: RAIZ, args: ['--test', ...flagCov, 'demo-portal-tramites/tests/*.test.js'] },
    { nombre: 'Attack Lab y DAST', cwd: join(RAIZ, 'attack-lab'), args: ['--test', ...flagCov, 'tests/*.test.js'] },
  ];

  for (const s of suites) {
    const r = ejecutarPaso(`Pruebas: ${s.nombre}`, process.execPath, s.args, { cwd: s.cwd, capturar: conCobertura });
    if (r.status !== 0) fallos.push(`Pruebas ${s.nombre}`);
    if (conCobertura) {
      const lineasResumen = (r.stdout || '').split(/\r?\n/).filter((l) => /all files|tests |pass |fail |start of coverage|end of coverage|file\s+\|/i.test(l) || /^\s*[ℹ#].*\|/.test(l));
      salidasCobertura.push(`## ${s.nombre}\n${lineasResumen.join('\n')}\n`);
    }
  }

  if (conCobertura && rutaCobertura) {
    const cabecera = [
      `# Evidencia de Cobertura de Pruebas (node --test --experimental-test-coverage)`,
      `Fecha UTC: ${new Date().toISOString()}`,
      `Runtime: Node.js ${process.version} (${process.platform})`,
      '',
    ].join('\n');
    writeFileSync(resolve(RAIZ, rutaCobertura), `${cabecera}${salidasCobertura.join('\n')}`, 'utf8');
    console.log(`\nCobertura guardada en ${rutaCobertura}`);
  }

  // 3. SBOM CycloneDX y 0 dependencias npm externas
  console.log('\n=== 3. Verificación SBOM y cero dependencias npm ===');
  const sbomRes = ejecutarPaso('Regenerar SBOM CycloneDX 1.5', process.execPath, ['docs/sbom/generar-sbom.js']);
  if (sbomRes.status !== 0) fallos.push('SBOM');
  const sbomJson = JSON.parse(readFileSync(join(RAIZ, 'docs', 'sbom', 'sbom.cdx.json'), 'utf8'));
  const props = sbomJson?.metadata?.component?.properties || [];
  const depsProp = props.find((p) => /third_party|npm_deps|dependencias/i.test(p.name));
  if (depsProp && depsProp.value !== '0') {
    console.error(`ERROR SBOM: dependencias externas detectadas (${depsProp.name}=${depsProp.value})`);
    fallos.push('Dependencias externas en SBOM');
  }

  // Verificar directamente todos los package.json
  for (const relPkg of ['backend/package.json', 'sdk/package.json', 'demo-portal-tramites/package.json', 'attack-lab/package.json']) {
    const pkg = JSON.parse(readFileSync(join(RAIZ, relPkg), 'utf8'));
    const total = Object.keys(pkg.dependencies || {}).length + Object.keys(pkg.devDependencies || {}).length;
    if (total !== 0) {
      console.error(`ERROR: ${relPkg} declara ${total} dependencia(s) npm externas.`);
      fallos.push(relPkg);
    }
  }

  // 4. Auditoría de secretos, rutas locales y coautorías
  console.log('\n=== 4. Auditoría de secretos, rutas locales e higiene ===');
  const erroresHigiene = auditarHigieneRepo();
  if (erroresHigiene.length === 0) {
    console.log('OK: 0 archivos sensibles, 0 rutas locales filtradas, 0 líneas de coautoría.');
  } else {
    for (const e of erroresHigiene) console.error(`ERROR Higiene: ${e}`);
    fallos.push('Higiene del repositorio');
  }

  console.log('\n=== RESUMEN FINAL ===');
  if (fallos.length === 0) {
    console.log('TODO VERDE: OpenAPI estricto, 5 suites de pruebas, SBOM (0 deps) e higiene OK.');
  } else {
    console.error(`FALLOS (${fallos.length}): ${fallos.join(', ')}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
