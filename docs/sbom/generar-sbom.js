#!/usr/bin/env node
// Generador del inventario de software (SBOM) en formato CycloneDX 1.5 (JSON).
// Sin dependencias: solo módulos nativos de Node.js.
//
// Qué hace:
//   1. Recorre todos los package.json del repositorio y comprueba que no declaran dependencias
//      (dependencies, devDependencies, peerDependencies, optionalDependencies, bundleDependencies).
//   2. Escanea todo el código JavaScript (.js, .mjs, .cjs) y lista los módulos nativos de Node.js
//      que se importan (`import … from 'node:…'`, `import('node:…')`, `require('node:…')`), y
//      cualquier importación de un paquete externo (debería no haber ninguna).
//   3. Describe cada componente propio (carpeta de primer nivel con código) con su versión y un
//      hash SHA-256 de sus archivos, y escribe además la lista de hashes por archivo.
//   4. Escribe docs/sbom/sbom.cdx.json, docs/sbom/hashes-sha256.txt y docs/sbom/README.md.
// Todas las rutas que imprime o escribe son relativas a la raíz del repositorio.
//
// Uso (desde cualquier carpeta):  node docs/sbom/generar-sbom.js [--comprobar]
//   --comprobar  termina con código 1 si encuentra dependencias declaradas o importaciones externas.
// Solo se consideran los archivos versionados o versionables (git ls-files, respetando .gitignore):
// nunca .env, certificados, bases de datos ni resultados locales.

import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const SALIDA = dirname(fileURLToPath(import.meta.url));
const RAIZ = join(SALIDA, '..', '..');
const COMPROBAR = process.argv.includes('--comprobar');

const NOMBRE_PROYECTO = 'servicio-soberano-autenticacion-totp';
const LICENCIA = 'AGPL-3.0-or-later';
const REPOSITORIO = 'https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp';
const CAMPOS_DEPENDENCIAS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'bundleDependencies', 'bundledDependencies'];

/** Componentes propios: carpeta → descripción (las que existan en el repositorio). */
const COMPONENTES = {
  backend: 'API HTTPS, motor TOTP, bóveda AES-256-GCM, JWT EdDSA, seguridad, detector local y auditoría',
  'authenticator-app': 'App autenticadora PWA (HTML/CSS/JS propios, sin conexión, PIN)',
  'admin-console': 'Consola administrativa (HTML/CSS/JS propios, RBAC, auditoría)',
  sdk: 'SDK para sistemas integradores (cliente API v1 y validación local del JWT)',
  'demo-portal-tramites': 'Portal de Trámites de demostración que integra el segundo factor con el SDK',
  'attack-lab': 'Laboratorio de ataques simulados y pruebas de caos',
  contracts: 'Contratos: OpenAPI 3.1, esquema SQL y respuestas de ejemplo',
  deploy: 'Unidad systemd y guía de despliegue institucional',
};

// ---------------------------------------------------------------------------------------------
// Utilidades

const sha256 = (datos) => createHash('sha256').update(datos).digest('hex');
const aPosix = (ruta) => ruta.split(sep).join('/');

/** Archivos del repositorio (rutas relativas POSIX), respetando .gitignore. */
function archivosDelRepositorio() {
  try {
    const salida = execFileSync('git', ['ls-files', '-co', '--exclude-standard', '-z'], { cwd: RAIZ, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return salida.split('\0').filter(Boolean).filter((r) => existsSync(join(RAIZ, r)) && statSync(join(RAIZ, r)).isFile()).sort();
  } catch {
    // Sin git: recorrido manual excluyendo lo que nunca se versiona.
    const EXCLUIR = new Set(['.git', 'node_modules', 'certs', 'data', 'resultados', 'dist', 'build', 'coverage']);
    const lista = [];
    const recorrer = (carpeta) => {
      for (const e of readdirSync(carpeta, { withFileTypes: true })) {
        if (EXCLUIR.has(e.name)) continue;
        const ruta = join(carpeta, e.name);
        if (e.isDirectory()) recorrer(ruta);
        else if (e.isFile() && !/(^|\.)env$/.test(e.name) && !/\.(key|crt|pem|db|db-wal|db-shm|log)$/.test(e.name)) lista.push(aPosix(relative(RAIZ, ruta)));
      }
    };
    recorrer(RAIZ);
    return lista.sort();
  }
}

function commitActual() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: RAIZ, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return null;
  }
}

/** Busca las importaciones de un archivo JavaScript. */
function importaciones(texto) {
  const sinComentarios = texto.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/.*$/gm, '$1');
  const encontradas = new Set();
  const patrones = [
    /\bimport\s+[^'";]*?\bfrom\s*['"]([^'"]+)['"]/g, // import x from '…' (también multilínea)
    /\bexport\s+[^'";]*?\bfrom\s*['"]([^'"]+)['"]/g, // export … from '…'
    /\bimport\s*['"]([^'"]+)['"]/g, // import '…'
    /\bimport\(\s*['"]([^'"]+)['"]\s*\)/g, // import('…')
    /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g, // require('…')
  ];
  for (const p of patrones) for (const m of sinComentarios.matchAll(p)) encontradas.add(m[1]);
  return [...encontradas];
}

const esRelativa = (e) => e.startsWith('.') || e.startsWith('/');

// ---------------------------------------------------------------------------------------------
// 1. Recorrido del repositorio

const archivos = archivosDelRepositorio();
const commit = commitActual();
const problemas = [];

// package.json y dependencias declaradas
const paquetes = archivos.filter((r) => r === 'package.json' || r.endsWith('/package.json')).map((ruta) => {
  const pj = JSON.parse(readFileSync(join(RAIZ, ruta), 'utf8'));
  const declaradas = {};
  for (const campo of CAMPOS_DEPENDENCIAS) {
    const v = pj[campo];
    const n = Array.isArray(v) ? v.length : v && typeof v === 'object' ? Object.keys(v).length : 0;
    if (n > 0) {
      declaradas[campo] = v;
      problemas.push(`${ruta}: declara ${n} en ${campo}`);
    }
  }
  return { ruta, carpeta: dirname(ruta) === '.' ? '' : aPosix(dirname(ruta)), nombre: pj.name, version: pj.version, licencia: pj.license ?? null, motor: pj.engines?.node ?? null, declaradas };
});

// Importaciones en el código
const ARCHIVOS_JS = archivos.filter((r) => /\.(m?js|cjs)$/.test(r));
/** @type {Map<string, Set<string>>} módulo nativo → archivos */
const nativos = new Map();
/** @type {Map<string, Set<string>>} paquete externo → archivos */
const externas = new Map();
for (const ruta of ARCHIVOS_JS) {
  for (const espec of importaciones(readFileSync(join(RAIZ, ruta), 'utf8'))) {
    if (esRelativa(espec)) continue;
    // Todo lo que no es relativo ni node:… es un paquete externo (no debería haber ninguno).
    const destino = espec.startsWith('node:') ? nativos : externas;
    if (!destino.has(espec)) destino.set(espec, new Set());
    destino.get(espec).add(ruta);
  }
}
for (const [paquete, rutas] of externas) problemas.push(`importación externa "${paquete}" en ${[...rutas].join(', ')}`);

// Recursos externos en los frontends (CDN, fuentes web): solo se informa.
const recursosExternos = [];
for (const ruta of archivos.filter((r) => /^(authenticator-app|admin-console|demo-portal-tramites\/publico)\/.*\.(html|css)$/.test(r))) {
  const texto = readFileSync(join(RAIZ, ruta), 'utf8');
  for (const m of texto.matchAll(/\b(?:src|href)\s*=\s*["'](https?:\/\/[^"']+)["']|url\(\s*["']?(https?:\/\/[^"')]+)/g)) {
    recursosExternos.push(`${ruta}: ${m[1] ?? m[2]}`);
  }
}

// ---------------------------------------------------------------------------------------------
// 2. Componentes propios con hash

const versionDe = (carpeta) => paquetes.find((p) => p.carpeta === carpeta)?.version ?? null;
const versionRaiz = versionDe('backend') ?? '0.0.0';
const lineasHash = [];

const componentes = Object.entries(COMPONENTES).filter(([carpeta]) => existsSync(join(RAIZ, carpeta))).map(([carpeta, descripcion]) => {
  const propios = archivos.filter((r) => r.startsWith(`${carpeta}/`));
  const resumen = createHash('sha256');
  let bytes = 0;
  for (const r of propios) {
    const contenido = readFileSync(join(RAIZ, r));
    const h = sha256(contenido);
    bytes += contenido.length;
    lineasHash.push(`${h}  ${r}`);
    resumen.update(`${h}  ${r}\n`);
  }
  const paquete = paquetes.find((p) => p.carpeta === carpeta);
  const version = paquete?.version ?? (commit ? `0.0.0+git.${commit.slice(0, 12)}` : '0.0.0');
  const nativosUsados = [...nativos].filter(([, rutas]) => [...rutas].some((r) => r.startsWith(`${carpeta}/`))).map(([m]) => m).sort();
  return {
    carpeta, descripcion, version, paquete, archivos: propios.length, bytes, hash: resumen.digest('hex'), nativosUsados,
  };
});

// ---------------------------------------------------------------------------------------------
// 3. Documento CycloneDX 1.5

const refRaiz = `${NOMBRE_PROYECTO}@${versionRaiz}`;
const refNode = `runtime:nodejs@${process.versions.node}`;
const refOpenssl = 'herramienta:openssl';
const refNativo = (m) => `nodejs-builtin:${m}`;
const refPropio = (c) => `propio:${c.carpeta}@${c.version}`;

const propiedad = (name, value) => ({ name, value: String(value) });

const bom = {
  $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    lifecycles: [{ phase: 'build' }],
    tools: {
      components: [{ type: 'application', name: 'generar-sbom.js', version: '1.0.0', description: 'Generador propio sin dependencias (docs/sbom/generar-sbom.js)' }],
    },
    authors: [{ name: 'Equipo PSM-Hackaton' }],
    component: {
      type: 'application',
      'bom-ref': refRaiz,
      name: NOMBRE_PROYECTO,
      version: versionRaiz,
      description: 'Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP)',
      licenses: [{ license: { id: LICENCIA } }],
      externalReferences: [{ type: 'vcs', url: REPOSITORIO }],
      ...(commit ? { properties: [propiedad('git:commit', commit)] } : {}),
    },
    properties: [
      propiedad('sbom:dependencias-npm-declaradas', paquetes.reduce((n, p) => n + Object.values(p.declaradas).reduce((a, v) => a + (Array.isArray(v) ? v.length : Object.keys(v).length), 0), 0)),
      propiedad('sbom:importaciones-externas', externas.size),
      propiedad('sbom:package-json-revisados', paquetes.length),
      propiedad('sbom:archivos-js-escaneados', ARCHIVOS_JS.length),
      propiedad('sbom:node-usado-al-generar', process.version),
    ],
  },
  components: [
    {
      type: 'platform',
      'bom-ref': refNode,
      name: 'Node.js',
      version: process.versions.node,
      description: 'Entorno de ejecución. Versión mínima exigida por engines: >=22.5 (node:sqlite). Incluye OpenSSL y SQLite embebidos.',
      licenses: [{ license: { id: 'MIT' } }],
      externalReferences: [{ type: 'website', url: 'https://nodejs.org/' }],
      properties: [
        propiedad('engines.node (backend)', paquetes.find((p) => p.carpeta === 'backend')?.motor ?? '>=22.5'),
        propiedad('openssl embebido', process.versions.openssl ?? 'desconocido'),
        ...(process.versions.sqlite ? [propiedad('sqlite embebido', process.versions.sqlite)] : []),
      ],
    },
    {
      type: 'application',
      'bom-ref': refOpenssl,
      name: 'openssl (herramienta del sistema)',
      description: 'Solo para generar certificados de desarrollo (backend/scripts/certificados.js, npm run certs). No se usa en ejecución.',
      scope: 'excluded',
      licenses: [{ license: { id: 'Apache-2.0' } }],
    },
    ...[...nativos.keys()].sort().map((m) => ({
      type: 'library',
      'bom-ref': refNativo(m),
      group: 'nodejs',
      name: m,
      version: process.versions.node,
      description: 'Módulo nativo de Node.js (incluido en el entorno de ejecución, no se descarga)',
      scope: [...nativos.get(m)].every((r) => /(\.test\.m?js$|\/tests?\/|\/testing\/)/.test(r)) ? 'optional' : 'required',
      properties: [propiedad('usado-en-archivos', nativos.get(m).size)],
    })),
    ...componentes.map((c) => ({
      type: c.carpeta === 'contracts' || c.carpeta === 'deploy' ? 'data' : 'application',
      'bom-ref': refPropio(c),
      name: c.paquete?.nombre ?? c.carpeta,
      version: c.version,
      description: c.descripcion,
      licenses: [{ license: { id: LICENCIA } }],
      hashes: [{ alg: 'SHA-256', content: c.hash }],
      properties: [
        propiedad('carpeta', `${c.carpeta}/`),
        propiedad('archivos', c.archivos),
        propiedad('bytes', c.bytes),
        propiedad('hash', 'SHA-256 de la lista "<sha256>  <ruta>\\n" de sus archivos en orden (ver hashes-sha256.txt)'),
        ...(c.paquete ? [propiedad('package.json', c.paquete.ruta), propiedad('package.json license', c.paquete.licencia ?? '(no declarada)')] : [propiedad('package.json', '(no tiene; versión derivada del commit)')]),
      ],
    })),
  ],
  dependencies: [
    { ref: refRaiz, dependsOn: [refNode, ...componentes.map(refPropio)] },
    ...componentes.map((c) => ({ ref: refPropio(c), dependsOn: [...(c.nativosUsados.length ? [refNode] : []), ...c.nativosUsados.map(refNativo), ...(c.carpeta === 'backend' ? [refOpenssl] : [])] })),
    ...[...nativos.keys()].sort().map((m) => ({ ref: refNativo(m), dependsOn: [refNode] })),
    { ref: refNode, dependsOn: [] },
    { ref: refOpenssl, dependsOn: [] },
  ],
};

// ---------------------------------------------------------------------------------------------
// 4. Escritura

mkdirSync(SALIDA, { recursive: true });
writeFileSync(join(SALIDA, 'sbom.cdx.json'), `${JSON.stringify(bom, null, 2)}\n`);
writeFileSync(join(SALIDA, 'hashes-sha256.txt'), `${lineasHash.join('\n')}\n`);

const fila = (...celdas) => `| ${celdas.join(' | ')} |`;
const totalDeclaradas = bom.metadata.properties[0].value;
const md = [
  '# Inventario de software (SBOM)',
  '',
  `Generado por \`node docs/sbom/generar-sbom.js\` el ${bom.metadata.timestamp} con Node.js ${process.version}${commit ? ` sobre la copia de trabajo del commit \`${commit.slice(0, 12)}\`` : ''}.`,
  'No edite estos archivos a mano: vuelva a ejecutar el script tras cualquier cambio.',
  '',
  '| Archivo | Contenido |',
  '| --- | --- |',
  '| [`sbom.cdx.json`](sbom.cdx.json) | SBOM en formato CycloneDX 1.5 (JSON): metadatos, componentes y grafo de dependencias. |',
  '| [`hashes-sha256.txt`](hashes-sha256.txt) | SHA-256 de cada archivo de los componentes propios. Comprobación: `sha256sum -c docs/sbom/hashes-sha256.txt` desde la raíz. |',
  '',
  '## Resultado',
  '',
  `- **Dependencias npm declaradas: ${totalDeclaradas}** en ${paquetes.length} archivos \`package.json\` (campos ${CAMPOS_DEPENDENCIAS.map((c) => `\`${c}\``).join(', ')}).`,
  `- **Importaciones de paquetes externos: ${externas.size}** en ${ARCHIVOS_JS.length} archivos JavaScript escaneados.`,
  `- **Módulos nativos de Node.js usados: ${nativos.size}.** Vienen con el entorno de ejecución; no se descarga nada de Internet.`,
  `- **Recursos externos en los frontends (CDN, fuentes, scripts remotos): ${recursosExternos.length}.**`,
  '- No hay `package-lock.json` porque no hay nada que instalar: `npm install` no es necesario.',
  ...(problemas.length ? ['', '**Problemas detectados:**', '', ...problemas.map((p) => `- ${p}`)] : []),
  ...(recursosExternos.length ? ['', '**Recursos externos encontrados:**', '', ...recursosExternos.map((p) => `- ${p}`)] : []),
  '',
  '## package.json revisados',
  '',
  fila('Archivo', 'Nombre', 'Versión', 'Node (engines)', 'Licencia declarada', 'Dependencias'),
  fila('---', '---', '---', '---', '---', '---'),
  ...paquetes.map((p) => fila(`\`${p.ruta}\``, `\`${p.nombre}\``, p.version ?? '—', p.motor ?? '—', p.licencia ?? '—', Object.keys(p.declaradas).length ? 'SÍ' : '0')),
  '',
  '## Componentes propios',
  '',
  fila('Componente', 'Versión', 'Archivos', 'SHA-256 (resumen)', 'Módulos nativos'),
  fila('---', '---', '---:', '---', '---'),
  ...componentes.map((c) => fila(`\`${c.carpeta}/\``, c.version, c.archivos, `\`${c.hash.slice(0, 16)}…\``, c.nativosUsados.map((m) => `\`${m}\``).join(', ') || (archivos.some((r) => r.startsWith(`${c.carpeta}/`) && /\.m?js$/.test(r)) ? '— (código de navegador)' : '— (sin JavaScript)'))),
  '',
  'El hash de cada componente es el SHA-256 de su lista `"<sha256>  <ruta>\\n"` (la de `hashes-sha256.txt`) en orden alfabético.',
  '',
  '## Módulos nativos de Node.js',
  '',
  fila('Módulo', 'Archivos que lo importan', 'Uso'),
  fila('---', '---:', '---'),
  ...[...nativos.keys()].sort().map((m) => fila(`\`${m}\``, nativos.get(m).size, bom.components.find((c) => c['bom-ref'] === refNativo(m)).scope === 'optional' ? 'solo pruebas' : 'ejecución')),
  '',
  '## Entorno',
  '',
  `- Node.js ${process.versions.node} (mínimo \`>=22.5\` por \`node:sqlite\`), con OpenSSL ${process.versions.openssl}${process.versions.sqlite ? ` y SQLite ${process.versions.sqlite}` : ''} embebidos.`,
  '- `openssl` del sistema: solo para `npm run certs` (certificados de desarrollo).',
  '- Navegador moderno para la app autenticadora y la consola (Web Crypto, Service Worker).',
  '',
].join('\n');
writeFileSync(join(SALIDA, 'README.md'), md);

console.log(`SBOM CycloneDX 1.5 escrito en ${aPosix(relative(RAIZ, join(SALIDA, 'sbom.cdx.json')))}`);
console.log(`  package.json revisados:          ${paquetes.length}`);
console.log(`  dependencias npm declaradas:     ${totalDeclaradas}`);
console.log(`  archivos JavaScript escaneados:  ${ARCHIVOS_JS.length}`);
console.log(`  importaciones externas:          ${externas.size}`);
console.log(`  módulos nativos de Node.js:      ${nativos.size} (${[...nativos.keys()].sort().join(', ')})`);
console.log(`  componentes propios:             ${componentes.length}`);
console.log(`  recursos externos en frontends:  ${recursosExternos.length}`);
if (problemas.length) {
  console.log('Problemas:');
  for (const p of problemas) console.log(`  - ${p}`);
  if (COMPROBAR) process.exit(1);
}
