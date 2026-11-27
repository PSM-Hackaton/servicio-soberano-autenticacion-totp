#!/usr/bin/env node
// Instala en vendor/ los SDK del Servicio de Verificación Humana (Reto 2) a partir de los paquetes .tgz que
// entrega su consola («Descargar SDK»). Son paquetes del propio equipo: no se usa el registro npm.
//   node scripts/instalar-sdk-captcha.js <pow-captcha-client-x.y.z.tgz> <pow-captcha-server-x.y.z.tgz>
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const RAIZ = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const destinos = { '@pow-captcha/client': 'pow-captcha-client', '@pow-captcha/server': 'pow-captcha-server' };
const paquetes = process.argv.slice(2);
if (paquetes.length !== 2) {
  console.error('Uso: node scripts/instalar-sdk-captcha.js <cliente.tgz> <servidor.tgz>');
  process.exit(2);
}
const registro = [];
for (const tgz of paquetes) {
  const sha256 = createHash('sha256').update(readFileSync(tgz)).digest('hex');
  const temporal = join(RAIZ, 'vendor', '.instalando');
  rmSync(temporal, { recursive: true, force: true });
  mkdirSync(temporal, { recursive: true });
  execFileSync('tar', ['-xzf', tgz, '-C', temporal, '--strip-components=1', '--no-same-owner']);
  const pkg = JSON.parse(readFileSync(join(temporal, 'package.json'), 'utf8'));
  const carpeta = destinos[pkg.name];
  if (!carpeta) throw new Error(`Paquete no esperado: ${pkg.name}`);
  if (Object.keys(pkg.dependencies ?? {}).length) throw new Error(`${pkg.name} declara dependencias: no se instala`);
  const destino = join(RAIZ, 'vendor', carpeta);
  rmSync(destino, { recursive: true, force: true });
  execFileSync('mv', [temporal, destino]);
  registro.push({ nombre: pkg.name, version: pkg.version, archivo: basename(tgz), sha256 });
  console.log(`OK ${pkg.name}@${pkg.version} → vendor/${carpeta} (sha256 ${sha256.slice(0, 16)}…)`);
}
writeFileSync(join(RAIZ, 'vendor', 'sdk-captcha.json'), `${JSON.stringify({ origen: 'Consola del Servicio de Verificación Humana (Reto 2) · Grupo 4 · Sede Chuao', paquetes: registro }, null, 2)}\n`);
