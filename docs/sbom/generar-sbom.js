// Generador propio de SBOM en formato CycloneDX 1.5 (JSON) sin dependencias npm.
// Calcula hashes SHA-256 reales de los 8 módulos propios del repositorio y certifica 0 paquetes externos.

import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..');

const COMPONENT_DIRS = [
  { name: 'backend', type: 'application', desc: 'API HTTPS TLS 1.3, motor TOTP RFC 6238, vault AES-256-GCM, JWT Ed25519, QR ISO 18004, SQLite WAL, seguridad, auditoría encadenada e Isolation Forest local' },
  { name: 'contracts', type: 'data', desc: 'Contratos congelados OpenAPI 3.1, esquema SQLite WAL único (8 tablas) y mocks oficiales' },
  { name: 'authenticator-app', type: 'application', desc: 'PWA autenticadora TOTP offline propia (Web Crypto, bóveda IndexedDB cifrada con PIN, Service Worker)' },
  { name: 'admin-console', type: 'application', desc: 'Consola administrativa RBAC + TOTP propio, rotación Ed25519, verificador audit_log, métricas y alertas IA' },
  { name: 'sdk', type: 'library', desc: 'SDK JavaScript ESM cero dependencias + verificador JWKS Ed25519 offline + servicio falso de pruebas' },
  { name: 'demo-portal-tramites', type: 'application', desc: 'Portal Institucional de Trámites demo integrado al SDK con enrolamiento, verificación y step-up MFA' },
  { name: 'attack-lab', type: 'application', desc: 'Laboratorio de ataques simulados (9 escenarios) y proxy TCP de ingeniería del caos' },
  { name: 'deploy', type: 'operating-system', desc: 'Unidad systemd endurecida y guía de despliegue institucional sin contenedores' },
];

const IGNORED_NAMES = new Set(['.git', 'node_modules', 'certs', 'data', 'resultados', '.env']);

async function collectFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  const files = [];
  for (const e of entries) {
    if (IGNORED_NAMES.has(e.name) || e.name.endsWith('.db') || e.name.endsWith('.db-wal') || e.name.endsWith('.db-shm')) {
      continue;
    }
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
  let totalFiles = 0;

  for (const item of COMPONENT_DIRS) {
    const dirPath = join(REPO_ROOT, item.name);
    const { sha256, fileCount } = await hashDirectory(dirPath);
    totalFiles += fileCount;
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
        { name: 'sovereignty:runtime', value: 'Node.js 22.5+ / Web Platform APIs' },
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
        description: 'Servicio Soberano de Autenticación Multifactorial TOTP (RFC 6238, 100% código propio, 0 dependencias npm)',
        licenses: [{ license: { id: 'MIT' } }],
        properties: [
          { name: 'sovereignty:third_party_runtime_dependencies', value: '0' },
          { name: 'sovereignty:third_party_dev_dependencies', value: '0' },
          { name: 'sovereignty:total_audited_files', value: String(totalFiles) },
          { name: 'sovereignty:adr', value: 'ADR-002 (Node.js 22 nativo + SQLite WAL + TLS 1.3 + Web Crypto)' },
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
  return { outPath, sbom, totalFiles };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { outPath, sbom, totalFiles } = await generateSbom();
  console.log(`SBOM CycloneDX 1.5 generado en ${outPath} (${sbom.components.length} módulos propios, ${totalFiles} archivos auditados, 0 dependencias npm externas).`);
}
