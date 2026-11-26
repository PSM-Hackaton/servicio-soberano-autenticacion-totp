#!/usr/bin/env node
// Herramientas auxiliares del instalador y de operar.sh (solo módulos nativos de Node.js 22).
//
//   node herramientas.mjs esperar-salud <url> <ca.crt> [segundos]   espera HTTP 200 de <url> (TLS verificado con la CA)
//   node herramientas.mjs esperar-http  <url> <ca.crt> [segundos]   espera cualquier respuesta HTTP < 500
//   node herramientas.mjs instantanea   <base.db> <copia.db>         copia consistente en caliente (VACUUM INTO)
//   node herramientas.mjs comprobar     <base.db>                    integrity_check y recuento de tablas principales
//   node herramientas.mjs cifrar        <entrada> <salida> <archivo-clave>
//   node herramientas.mjs descifrar     <entrada> <salida> <archivo-clave>
//   node herramientas.mjs aleatorio     <bytes> [hex|base64url]      valor aleatorio del CSPRNG
//
// Formato de los respaldos cifrados (AES-256-GCM, autenticado):
//   "STOTPR01" (8 bytes) | sal (16) | IV (12) | texto cifrado | etiqueta GCM (16)
// La llave se deriva de la frase del <archivo-clave> con scrypt (N=2^15, r=8, p=1) y la sal del
// archivo. La cabecera, la sal y el IV van como datos asociados: cualquier alteración se detecta.

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { existsSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';

const MAGIA = Buffer.from('STOTPR01', 'ascii');
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function fallar(mensaje, codigo = 1) {
  process.stderr.write(`${mensaje}\n`);
  process.exit(codigo);
}

function llaveDesde(archivoClave, sal) {
  const frase = readFileSync(archivoClave, 'utf8').trim();
  if (frase.length < 32) fallar(`La frase de ${archivoClave} es demasiado corta (mínimo 32 caracteres).`);
  return scryptSync(frase, sal, 32, SCRYPT);
}

/** Escribe con permisos 0600 en un temporal y renombra (nunca queda un archivo a medias). */
function escribirSeguro(ruta, datos) {
  const tmp = `${ruta}.tmp-${process.pid}`;
  writeFileSync(tmp, datos, { mode: 0o600, flag: 'wx' });
  renameSync(tmp, ruta);
}

function cifrar(entrada, salida, archivoClave) {
  const sal = randomBytes(16);
  const iv = randomBytes(12);
  const llave = llaveDesde(archivoClave, sal);
  const c = createCipheriv('aes-256-gcm', llave, iv);
  c.setAAD(Buffer.concat([MAGIA, sal, iv]));
  const cifrado = Buffer.concat([c.update(readFileSync(entrada)), c.final()]);
  escribirSeguro(salida, Buffer.concat([MAGIA, sal, iv, cifrado, c.getAuthTag()]));
  llave.fill(0);
}

function descifrar(entrada, salida, archivoClave) {
  const t = readFileSync(entrada);
  if (t.length < 8 + 16 + 12 + 16 || !t.subarray(0, 8).equals(MAGIA)) fallar(`${entrada} no es un respaldo del Servicio Soberano TOTP.`);
  const sal = t.subarray(8, 24);
  const iv = t.subarray(24, 36);
  const etiqueta = t.subarray(t.length - 16);
  const llave = llaveDesde(archivoClave, sal);
  const d = createDecipheriv('aes-256-gcm', llave, iv);
  d.setAAD(Buffer.concat([MAGIA, sal, iv]));
  d.setAuthTag(etiqueta);
  let plano;
  try {
    plano = Buffer.concat([d.update(t.subarray(36, t.length - 16)), d.final()]);
  } catch {
    fallar('No se pudo descifrar: frase incorrecta o archivo alterado (la etiqueta GCM no coincide).');
  } finally {
    llave.fill(0);
  }
  escribirSeguro(salida, plano);
}

async function abrirSqlite(ruta, opciones = {}) {
  process.removeAllListeners('warning'); // el aviso experimental de node:sqlite no aporta aquí
  const { DatabaseSync } = await import('node:sqlite');
  return new DatabaseSync(ruta, opciones);
}

async function instantanea(origen, destino) {
  if (!existsSync(origen)) fallar(`No existe la base de datos ${origen}.`);
  if (existsSync(destino)) rmSync(destino);
  const db = await abrirSqlite(origen);
  try {
    db.exec(`VACUUM INTO '${destino.replaceAll("'", "''")}'`);
  } finally {
    db.close();
  }
}

async function comprobar(ruta) {
  if (!existsSync(ruta)) fallar(`No existe la base de datos ${ruta}.`);
  const db = await abrirSqlite(ruta, { readOnly: true });
  try {
    const integridad = db.prepare('PRAGMA integrity_check').get();
    const valor = Object.values(integridad ?? {})[0];
    if (valor !== 'ok') fallar(`integrity_check: ${valor}`);
    const tablas = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((f) => f.name));
    const partes = ['integridad ok'];
    for (const t of ['apps', 'enrollments', 'admins', 'audit_log', 'signing_keys']) {
      if (tablas.has(t)) partes.push(`${t}=${db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n}`);
    }
    console.log(partes.join(' · '));
  } finally {
    db.close();
  }
}

function pedir(url, ca) {
  return new Promise((ok) => {
    const req = https.get(url, { ca, timeout: 3000 }, (res) => {
      res.resume();
      res.on('end', () => ok(res.statusCode ?? 0));
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => ok(0));
  });
}

async function esperar(url, archivoCa, segundos, acepta) {
  const ca = readFileSync(archivoCa);
  const limite = Date.now() + Number(segundos || 30) * 1000;
  let ultimo = 0;
  while (Date.now() < limite) {
    ultimo = await pedir(url, ca);
    if (acepta(ultimo)) {
      console.log(`${url} → HTTP ${ultimo}`);
      return;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  fallar(`${url} no respondió a tiempo (último estado: ${ultimo || 'sin conexión'}).`, 2);
}

const [orden, ...args] = process.argv.slice(2);
const requerir = (n) => {
  if (args.length < n) fallar(`Faltan argumentos para "${orden}". Vea la cabecera de herramientas.mjs.`);
};
switch (orden) {
  case 'esperar-salud': requerir(2); await esperar(args[0], args[1], args[2], (s) => s === 200); break;
  case 'esperar-http': requerir(2); await esperar(args[0], args[1], args[2], (s) => s > 0 && s < 500); break;
  case 'instantanea': requerir(2); await instantanea(args[0], args[1]); break;
  case 'comprobar': requerir(1); await comprobar(args[0]); break;
  case 'cifrar': requerir(3); cifrar(args[0], args[1], args[2]); break;
  case 'descifrar': requerir(3); descifrar(args[0], args[1], args[2]); break;
  case 'aleatorio': {
    requerir(1);
    const n = Number(args[0]);
    if (!Number.isInteger(n) || n < 16 || n > 128) fallar('Número de bytes fuera de rango (16 a 128).');
    console.log(randomBytes(n).toString(args[1] === 'base64url' ? 'base64url' : 'hex'));
    break;
  }
  default: fallar('Uso: node herramientas.mjs <esperar-salud|esperar-http|instantanea|comprobar|cifrar|descifrar|aleatorio> …');
}
