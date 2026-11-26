// Genera una CA local y un certificado de servidor con el openssl del sistema. Por defecto, en
// backend/certs/ (ignorado por git) y para localhost / 127.0.0.1 / ::1. No sobrescribe sin --forzar.
//
// Uso: node scripts/certificados.js [--forzar] [--dias 825] [--carpeta <dir>] [--nombre localhost]
//                                   [--san DNS:totp.local,IP:192.168.1.50,...] [--solo-servidor]
//   --carpeta        carpeta de salida (por defecto backend/certs/)
//   --nombre         nombre base de los archivos del servidor (<nombre>.crt y <nombre>.key)
//   --san            nombres e IP adicionales para el certificado del servidor (se suman a
//                    localhost, 127.0.0.1 y ::1); formato DNS:nombre o IP:dirección, separados por comas
//   --solo-servidor  reutiliza la CA existente (ca.crt + ca.key) y solo emite de nuevo el certificado
//                    del servidor: los equipos que ya confían en la CA no tienen que volver a instalarla
//   --forzar         regenera aunque ya existan (con --solo-servidor, solo el del servidor)

import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const argv = process.argv.slice(2);
const valor = (nombre) => {
  const i = argv.indexOf(nombre);
  return i >= 0 ? argv[i + 1] : undefined;
};
const CARPETA = resolve(valor('--carpeta') ?? resolve(fileURLToPath(new URL('../', import.meta.url)), 'certs'));
const forzar = argv.includes('--forzar');
const soloServidor = argv.includes('--solo-servidor');
const dias = String(Number(valor('--dias')) || 825);
const nombre = valor('--nombre') ?? 'localhost';
if (!/^[A-Za-z0-9._-]{1,64}$/.test(nombre)) {
  console.error(`Nombre de archivo no válido: ${nombre}`);
  process.exit(1);
}

// SAN: siempre localhost y loopback; luego los adicionales, validados y sin duplicados.
const san = ['DNS:localhost', 'IP:127.0.0.1', 'IP:::1'];
for (const entrada of (valor('--san') ?? '').split(',').map((s) => s.trim()).filter(Boolean)) {
  const m = /^(DNS|IP):(.+)$/.exec(entrada);
  const ok = m && (m[1] === 'DNS' ? /^[A-Za-z0-9*]([A-Za-z0-9.-]{0,252})$/.test(m[2]) : /^[0-9A-Fa-f:.]{2,45}$/.test(m[2]));
  if (!ok) {
    console.error(`Entrada --san no válida: "${entrada}" (use DNS:nombre o IP:dirección)`);
    process.exit(1);
  }
  if (!san.includes(entrada)) san.push(entrada);
}
const cn = san.find((s, i) => i >= 3 && s.startsWith('DNS:'))?.slice(4) ?? 'localhost';

const archivo = (n) => join(CARPETA, n);
const openssl = (...args) => execFileSync('openssl', args, { stdio: ['ignore', 'ignore', 'pipe'] });

try {
  execFileSync('openssl', ['version'], { stdio: 'ignore' });
} catch {
  console.error('No se encontró openssl en el sistema.');
  process.exit(1);
}

mkdirSync(CARPETA, { recursive: true, mode: 0o700 });
if (existsSync(archivo(`${nombre}.crt`)) && !forzar) {
  console.log(`Ya existen certificados en ${CARPETA}. Use --forzar para regenerarlos.`);
  process.exit(0);
}

// 1. CA local (P-256), solo para firmar el certificado del servidor.
if (soloServidor && existsSync(archivo('ca.crt')) && existsSync(archivo('ca.key'))) {
  console.log(`Se reutiliza la CA existente (${archivo('ca.crt')}).`);
} else {
  openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', archivo('ca.key'));
  chmodSync(archivo('ca.key'), 0o600);
  openssl('req', '-x509', '-new', '-key', archivo('ca.key'), '-sha256', '-days', dias,
    '-subj', '/O=Servicio Soberano TOTP/CN=CA local Servicio Soberano TOTP',
    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    '-out', archivo('ca.crt'));
}

// 2. Certificado del servidor con los SAN pedidos.
openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', archivo(`${nombre}.key`));
chmodSync(archivo(`${nombre}.key`), 0o600);
openssl('req', '-new', '-key', archivo(`${nombre}.key`), '-subj', `/O=Servicio Soberano TOTP/CN=${cn}`, '-out', archivo(`${nombre}.csr`));
const extensiones = archivo(`${nombre}.ext`);
writeFileSync(extensiones, [
  'basicConstraints=critical,CA:FALSE',
  'keyUsage=critical,digitalSignature',
  'extendedKeyUsage=serverAuth',
  `subjectAltName=${san.join(',')}`,
  '',
].join('\n'));
openssl('x509', '-req', '-in', archivo(`${nombre}.csr`), '-CA', archivo('ca.crt'), '-CAkey', archivo('ca.key'),
  '-CAcreateserial', '-days', dias, '-sha256', '-extfile', extensiones, '-out', archivo(`${nombre}.crt`));
rmSync(archivo(`${nombre}.csr`), { force: true });
rmSync(extensiones, { force: true });
rmSync(archivo('ca.srl'), { force: true });

console.log(`Certificados creados en ${CARPETA}:`);
console.log(`  ca.crt          CA local (impórtela en el navegador o use curl --cacert ${archivo('ca.crt')})`);
console.log(`  ${`${nombre}.crt`.padEnd(15)} certificado del servidor (${san.join(', ')})`);
console.log(`  ${`${nombre}.key`.padEnd(15)} llave privada del servidor (permisos 600)`);
