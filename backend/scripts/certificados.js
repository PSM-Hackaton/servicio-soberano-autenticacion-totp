// Genera una CA local y un certificado de servidor para localhost / 127.0.0.1 / ::1 con el
// openssl del sistema, en backend/certs/ (ignorado por git). No sobrescribe sin --forzar.
// Uso: node scripts/certificados.js [--forzar] [--dias 825]

import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const CARPETA = resolve(fileURLToPath(new URL('../', import.meta.url)), 'certs');
const argv = process.argv.slice(2);
const forzar = argv.includes('--forzar');
const iDias = argv.indexOf('--dias');
const dias = String(iDias >= 0 ? Number(argv[iDias + 1]) || 825 : 825);

const archivo = (n) => join(CARPETA, n);
const openssl = (...args) => execFileSync('openssl', args, { stdio: ['ignore', 'ignore', 'pipe'] });

try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  console.error('No se encontró openssl en el sistema.');
  process.exit(1);
}

mkdirSync(CARPETA, { recursive: true, mode: 0o700 });
if (existsSync(archivo('localhost.crt')) && !forzar) {
  console.log(`Ya existen certificados en ${CARPETA}. Use --forzar para regenerarlos.`);
  process.exit(0);
}

// 1. CA local (P-256), solo para firmar el certificado del servidor.
openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', archivo('ca.key'));
openssl('req', '-x509', '-new', '-key', archivo('ca.key'), '-sha256', '-days', dias,
  '-subj', '/O=Servicio Soberano TOTP/CN=CA local Servicio Soberano TOTP',
  '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
  '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
  '-out', archivo('ca.crt'));

// 2. Certificado del servidor con SAN para localhost y loopback.
openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', archivo('localhost.key'));
openssl('req', '-new', '-key', archivo('localhost.key'), '-subj', '/O=Servicio Soberano TOTP/CN=localhost', '-out', archivo('localhost.csr'));
const extensiones = archivo('localhost.ext');
writeFileSync(extensiones, [
  'basicConstraints=critical,CA:FALSE',
  'keyUsage=critical,digitalSignature',
  'extendedKeyUsage=serverAuth',
  'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1',
  '',
].join('\n'));
openssl('x509', '-req', '-in', archivo('localhost.csr'), '-CA', archivo('ca.crt'), '-CAkey', archivo('ca.key'),
  '-CAcreateserial', '-days', dias, '-sha256', '-extfile', extensiones, '-out', archivo('localhost.crt'));
rmSync(archivo('localhost.csr'), { force: true });
rmSync(extensiones, { force: true });
rmSync(archivo('ca.srl'), { force: true });

for (const n of ['ca.key', 'localhost.key']) chmodSync(archivo(n), 0o600);

console.log(`Certificados creados en ${CARPETA}:`);
console.log('  ca.crt         CA local (impórtela en el navegador o use curl --cacert certs/ca.crt)');
console.log('  localhost.crt  certificado del servidor (localhost, 127.0.0.1, ::1)');
console.log('  localhost.key  llave privada del servidor (permisos 600)');
