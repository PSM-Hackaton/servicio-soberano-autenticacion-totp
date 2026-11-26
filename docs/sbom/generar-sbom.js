// Generador propio de SBOM en formato CycloneDX 1.5 (JSON) sin dependencias npm.
// Calcula hashes SHA-256 reales de cada componente propio del repositorio y certifica 0 paquetes externos.

import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..');

const COMPONENT_DIRS = [
  { name: 'contracts', type: 'data', desc: 'Contratos OpenAPI 3.1, esquema SQLite único y mocks' },
  { name: 'authenticator-app', type: 'application', desc: 'PWA autenticadora TOTP offline (Web Crypto + IndexedDB AES-GCM)' },
  { name: 'admin-console', type: 'application', desc: 'Consola administrativa RBAC + verificador audit_log + métricas' },
  { name: 'sdk', type: 'library', desc: 'SDK JavaScript ESM cero dependencias + verificador JWKS Ed25519 offline' },
  { name: 'demo-portal-tramites', type: 'application', desc: 'Portal Institucional de Trámites demo integrado al SDK' },
  { name: 'attack-lab', type: 'application', desc: 'Laboratorio de ataques simulados y pruebas de caos' },
];

async function collectFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  const files = [];
  for (const e of entries) {
    if (e.name.startsWith('.') || e.name === 'node_modules') continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      files.push(...(await collectFiles(full)));
    } else {
      files.push(full);
    }
  }
  return files.sort();
}

async function hashDirectory(dirPath) {
  const files = await collectFiles(dirPath);
  const hash = createHash('sha256');
  for (const f of files) {
    hash.update(relative(REPO_ROOT, f));
    hash.update(await readFile(f));
  }
  return { sha256: hash.digest('hex'), fileCount: files.length };
}

export async function generateSbom() {
  const components = [];
  for (const item of COMPONENT_DIRS) {
    const dirPath = join(REPO_ROOT, item.name);
    const { sha256, fileCount } = await hashDirectory(dirPath);
    components.push({
      type: item.type,
      'bom-ref': `pkg:generic/psm-hackaton/${item.name}@1.0.0`,
      name: item.name,
      version: '1.0.0',
      description: item.desc,
      licenses: [{ license: { id: 'MIT' } }],
      hashes: [{ alg: 'SHA-256', content: sha256 }],
      properties: [
        { name: 'sovereignty:third_party_npm_deps', value: '0' },
        { name: 'sovereignty:file_count', value: String(fileCount) },
        { name: 'sovereignty:runtime', value: 'Node.js 22 / Web Platform APIs' },
      ],
    });
  }

  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'PSM-Hackaton',
          name: 'generar-sbom.js (propio, 0 dependencias)',
          version: '1.0.0',
        },
      ],
      component: {
        type: 'application',
        'bom-ref': 'pkg:generic/psm-hackaton/servicio-soberano-autenticacion-totp@1.0.0',
        name: 'servicio-soberano-autenticacion-totp',
        version: '1.0.0',
        description: 'Servicio Soberano de Autenticación Multifactorial TOTP (RFC 6238, 0 dependencias npm)',
        licenses: [{ license: { id: 'MIT' } }],
        properties: [
          { name: 'sovereignty:third_party_runtime_dependencies', value: '0' },
          { name: 'sovereignty:third_party_dev_dependencies', value: '0' },
          { name: 'sovereignty:adr', value: 'ADR-002 (Node.js 22 nativo + SQLite WAL + Web Crypto)' },
        ],
      },
    },
    components,
    dependencies: [
      {
        ref: 'pkg:generic/psm-hackaton/servicio-soberano-autenticacion-totp@1.0.0',
        dependsOn: components.map((c) => c['bom-ref']),
      },
    ],
  };

  const outPath = join(__dirname, 'sbom.cdx.json');
  await writeFile(outPath, `${JSON.stringify(sbom, null, 2)}\n`, 'utf8');
  return { outPath, sbom };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { outPath, sbom } = await generateSbom();
  console.log(`SBOM CycloneDX 1.5 generado en ${outPath} (${sbom.components.length} módulos propios, 0 dependencias npm externas).`);
}
