#!/usr/bin/env node
// Carga datos de demostración a través de la API real del servicio (solo para entornos locales de demo):
//  - enrola y activa ciudadanos ficticios (SHA-256 y SHA-512, 6 y 8 dígitos),
//  - genera tráfico legítimo, códigos incorrectos y un código reutilizado,
//  - simula un ataque de fuerza bruta distribuida y uno de "spraying" desde direcciones de loopback
//    distintas (127.x.y.z) para que el detector de anomalías genere alertas,
//  - escribe una página HTML local con enlaces para cargar las cuentas en la app autenticadora
//    (salvo con --sin-pagina: entonces solo imprime el resumen y no deja semillas en disco).
//
// Uso: node scripts/datos-demo.js --url http://localhost:8443 --client-id app_... --client-secret ...
//      [--ciudadanos 12] [--salida data/demo-cuentas.html] [--app-url http://localhost:8443/app/]
//      [--ca ruta/ca.crt] [--sin-pagina]
//   --ca          verifica el certificado del servicio con esta CA (sin ella no se verifica: solo demo local)
//   --sin-pagina  no escribe la página de cuentas (recomendado en un despliegue como servicio)

import http from 'node:http';
import https from 'node:https';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateTotp } from '../src/core/totp/totp.js';
import { base32Decode } from '../src/core/totp/base32.js';

const RAIZ = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function argumentos(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const siguiente = argv[i + 1];
    a[argv[i].slice(2)] = siguiente === undefined || siguiente.startsWith('--') ? true : siguiente;
  }
  return a;
}

const args = argumentos(process.argv.slice(2));
const BASE = new URL(args.url ?? 'http://localhost:8443');
if (!['localhost', '127.0.0.1', '::1'].includes(BASE.hostname)) {
  console.error('Este script solo se ejecuta contra un servicio local de demostración.');
  process.exit(1);
}
if (!args['client-id'] || !args['client-secret']) {
  console.error('Faltan --client-id y --client-secret (los imprime `npm run seed`).');
  process.exit(1);
}
const TOTAL = Math.min(Number(args.ciudadanos ?? 12), 50);
const SALIDA = resolve(RAIZ, args.salida ?? 'data/demo-cuentas.html');
const APP_URL = args['app-url'] ?? `${BASE.origin}/app/`;
const SIN_PAGINA = args['sin-pagina'] === true;
const CA = typeof args.ca === 'string' ? readFileSync(resolve(args.ca)) : undefined;
const espera = (ms) => new Promise((r) => setTimeout(r, ms));

/** Llamada a la API v1 con las credenciales de la app; `origen` fija la IP local de salida. */
function api(ruta, cuerpo, origen) {
  const modulo = BASE.protocol === 'https:' ? https : http;
  const datos = JSON.stringify(cuerpo);
  return new Promise((ok) => {
    const req = modulo.request({
      hostname: BASE.hostname === 'localhost' ? '127.0.0.1' : BASE.hostname,
      port: BASE.port, path: ruta, method: 'POST', localAddress: origen,
      ...(CA ? { ca: CA } : { rejectUnauthorized: false }),
      headers: {
        'content-type': 'application/json', 'content-length': Buffer.byteLength(datos),
        'x-client-id': args['client-id'], 'x-client-secret': args['client-secret'],
      },
    }, (res) => {
      let t = '';
      res.on('data', (c) => { t += c; });
      res.on('end', () => { let j = {}; try { j = JSON.parse(t); } catch { /* sin cuerpo */ } ok({ status: res.statusCode, cuerpo: j }); });
    });
    req.on('error', () => ok({ status: 0, cuerpo: {} }));
    req.end(datos);
  });
}

const codigo = (c, desfasePasos = 0) => generateTotp(c.semilla, Date.now() + desfasePasos * c.periodo * 1000, c);
const incorrecto = (c) => String((Number(codigo(c)) + 1) % 10 ** c.digitos).padStart(c.digitos, '0');

const NOMBRES = ['ana.rivera', 'bruno.mendez', 'carla.ortiz', 'daniel.paez', 'elena.suarez', 'felix.rojas',
  'gabriela.leon', 'hector.mora', 'irene.vargas', 'jorge.salas', 'karina.diaz', 'luis.parra'];

console.log(`Cargando datos de demostración en ${BASE.origin} …`);
const cuentas = [];
for (let i = 0; i < TOTAL; i++) {
  const ref = `demo-${NOMBRES[i % NOMBRES.length]}${i >= NOMBRES.length ? `-${i}` : ''}`;
  const enr = await api('/api/v1/enrollments', { user_ref: ref });
  if (enr.status !== 201) { console.error(`  enrolar ${ref}: HTTP ${enr.status}`); continue; }
  const uri = new URL(enr.cuerpo.otpauth_uri);
  const p = uri.searchParams;
  const c = {
    ref, uri: enr.cuerpo.otpauth_uri, semilla: base32Decode(p.get('secret')),
    algoritmo: p.get('algorithm'), digitos: Number(p.get('digits')), periodo: Number(p.get('period')),
  };
  const act = await api(`/api/v1/enrollments/${enr.cuerpo.enrollment_id}/activate`, { code: codigo(c) });
  if (act.status === 200) cuentas.push(c);
  console.log(`  ${ref.padEnd(26)} enrolado y ${act.status === 200 ? 'activado' : `sin activar (HTTP ${act.status})`}`);
}

// Esperar al siguiente paso para no repetir el código usado al activar.
await espera(30_000 - (Date.now() % 30_000) + 1200);

let ok = 0; let fallidos = 0; let reutilizados = 0;
for (const [i, c] of cuentas.entries()) {
  const origen = `127.10.${Math.floor(i / 200)}.${(i % 200) + 1}`;
  if (i % 4 === 1) { await api('/api/v1/verify', { user_ref: c.ref, code: incorrecto(c) }, origen); fallidos++; }
  const v = await api('/api/v1/verify', { user_ref: c.ref, code: codigo(c) }, origen);
  if (v.status === 200) {
    ok++;
    await api('/api/v1/tokens/validate', { token: v.cuerpo.token }, origen);
    if (i % 5 === 0) { await api('/api/v1/verify', { user_ref: c.ref, code: codigo(c) }, origen); reutilizados++; }
  }
}
console.log(`  tráfico legítimo: ${ok} accesos correctos, ${fallidos} códigos incorrectos, ${reutilizados} códigos reutilizados`);

// Ataque distribuido contra una cuenta y "spraying" contra muchas, cada uno desde su bloque de direcciones.
const victima = cuentas.at(-1);
if (victima) {
  for (let n = 0; n < 12; n++) await api('/api/v1/verify', { user_ref: victima.ref, code: String(100000 + n * 7919).slice(0, victima.digitos) }, `127.20.0.${n + 1}`);
  console.log(`  ataque distribuido: 12 intentos desde 12 direcciones contra ${victima.ref}`);
}
for (let n = 0; n < 15; n++) await api('/api/v1/verify', { user_ref: `objetivo-${n}`, code: '000000' }, '127.30.0.9');
console.log('  spraying: 15 cuentas probadas desde una sola dirección');

for (const c of cuentas) c.semilla.fill(0);
if (SIN_PAGINA) {
  console.log(`\nListo: ${cuentas.length} ciudadanos de demostración activos. No se escribió ninguna página con semillas (--sin-pagina).`);
  process.exit(0);
}

// Página local para cargar las cuentas en la app autenticadora.
const esc = (t) => String(t).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
const filas = cuentas.map((c) => `<tr><td>${esc(c.ref)}</td><td>${esc(c.algoritmo)} · ${c.digitos} dígitos</td>
<td><a href="${esc(`${APP_URL}#add=${encodeURIComponent(c.uri)}`)}">Agregar a la app</a></td></tr>`).join('\n');
mkdirSync(dirname(SALIDA), { recursive: true });
writeFileSync(SALIDA, `<!doctype html><html lang="es"><meta charset="utf-8"><title>Cuentas de demostración</title>
<style>body{font:16px system-ui;margin:2rem;color:#1b1f24}table{border-collapse:collapse}td,th{border:1px solid #ccd;padding:.5rem .8rem;text-align:left}</style>
<h1>Cuentas de demostración</h1><p>Datos ficticios para la demo local. Cada enlace abre la app autenticadora y carga la cuenta.
No publique este archivo: contiene semillas.</p>
<table><tr><th>Ciudadano (user_ref)</th><th>Política</th><th></th></tr>${filas}</table></html>\n`, { mode: 0o600 });
console.log(`\nListo. Abra ${SALIDA} en el navegador para cargar las cuentas en la app.`);
