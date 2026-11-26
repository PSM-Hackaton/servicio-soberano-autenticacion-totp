// Medición por partes: coste aislado (microsegundos por operación, un solo hilo) de cada pieza que
// interviene en una verificación, para localizar el cuello de botella con evidencia.
// Usa los módulos reales del backend. La base es un archivo temporal en la carpeta indicada.
// Uso: node partes.js <carpeta-temporal>

import { randomBytes } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = fileURLToPath(new URL('../../../backend/src/', import.meta.url));
const m = (r) => import(resolve(SRC, r));
const { generateTotp, verifyTotpWithDrift } = await m('core/totp/totp.js');
const { crearVault, generateSeed, hashPepper } = await m('core/vault/vault.js');
const { generarParFirma, signMfaJwt, verifyMfaJwt } = await m('core/tokens/tokens.js');
const { hashSecretoAsync, verificarSecretoAsync } = await m('security/secretos.js');
const { abrirBaseDatos } = await m('infrastructure/persistence/db.js');
const { crearRepositorios } = await m('infrastructure/persistence/repositorios.js');
const { crearBitacora } = await m('audit/index.js');
const { entrenarDetectorPorDefecto } = await m('heuristics/index.js');

const carpeta = resolve(process.argv[2] ?? '.', 'partes');
rmSync(carpeta, { recursive: true, force: true });
mkdirSync(carpeta, { recursive: true });

/** Ejecuta fn n veces (tras calentar) y devuelve µs por operación. */
async function medir(nombre, n, fn) {
  for (let i = 0; i < Math.min(200, n); i++) await fn(i);
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < n; i++) await fn(i);
  const us = Number(process.hrtime.bigint() - t0) / 1e3 / n;
  return { nombre, n, usPorOp: Math.round(us * 10) / 10, opsPorSegundo: Math.round(1e6 / us) };
}

const res = [];
const semilla = generateSeed('SHA256');
const pol = { algoritmo: 'SHA256', digitos: 6, periodo: 30 };
const ahora = Date.now();
const codigo = generateTotp(semilla, ahora, pol);
res.push(await medir('TOTP: verificar código (ventana ±1, 3 HMAC-SHA256)', 50_000,
  () => verifyTotpWithDrift(semilla, codigo, ahora, { ...pol, ventana: 1, driftSteps: 0, lastStep: -1 })));

const vault = crearVault({ llaves: { v1: randomBytes(32) }, versionActiva: 'v1' });
const cifrado = vault.encryptSeed(semilla, 'id-1');
res.push(await medir('AES-256-GCM: descifrar semilla', 50_000, () => vault.decryptSeed(cifrado, 'id-1')));
res.push(await medir('HMAC-SHA256: anonimizar user_ref', 50_000, (i) => hashPepper(`ciudadano-${i}`, 'p'.repeat(43))));

const par = generarParFirma();
const jwt = () => signMfaJwt({ privateKey: par.privateKey, kid: par.kid, issuer: 'i', audience: 'a', subject: 's', ahora: Date.now() });
res.push(await medir('Ed25519: firmar JWT', 20_000, jwt));
const tok = jwt();
res.push(await medir('Ed25519: verificar JWT', 20_000,
  () => verifyMfaJwt(tok, { buscarClave: () => par.publicJwk, issuer: 'i', audience: 'a' })));

const detector = entrenarDetectorPorDefecto(42, { modo: 'bloqueo' });
const hist = Array.from({ length: 100 }, (_, i) => ({ user_ref_hash: `u${i % 7}`, ip_hash: 'ip', resultado: i % 9 ? 'ok' : 'invalid_code', ts: new Date(ahora - i * 60_000).toISOString() }));
res.push(await medir('Detector local: evaluar intento (100 eventos de historial)', 5_000,
  () => detector.evaluar({ user_ref_hash: 'u1', ip_hash: 'ip', ts: ahora }, hist, ahora)));

const hs = await hashSecretoAsync('secreto-de-prueba');
res.push(await medir('scrypt N=16384: verificar client_secret o código (1 hilo)', 40, () => verificarSecretoAsync('secreto-de-prueba', hs)));

// SQLite: inserción de un intento + un evento de bitácora, como en cada verificación.
for (const modo of ['FULL', 'NORMAL']) {
  const ruta = resolve(carpeta, `p-${modo}.db`);
  const db = abrirBaseDatos(ruta);
  db.exec(`PRAGMA synchronous = ${modo};`);
  const repos = crearRepositorios(db);
  const bitacora = crearBitacora({ ultimo: () => repos.auditLog.ultimo(), insertar: (f) => repos.auditLog.insertar(f).id });
  res.push(await medir(`SQLite ${modo}: transacción con 1 intento (attempts)`, 3_000, (i) => repos.transaccion(() => repos.attempts.registrar({
    app_id: null, user_ref_hash: `u${i % 500}`, ip_hash: `ip${i % 300}`, resultado: 'ok', risk_score: 3, reasons_json: ['ok'], inference_ms: 0.1, ts: new Date().toISOString(),
  }))));
  res.push(await medir(`SQLite ${modo}: evento de bitácora encadenada`, 3_000, (i) => bitacora.registrar({ actor: 'app:x', accion: 'verificacion.exitosa', objetivo: `e${i}`, detalle: { jti: `j${i}` } })));
  res.push(await medir(`SQLite ${modo}: historial del detector (2 consultas de 50 filas)`, 3_000, (i) => {
    repos.attempts.ultimosPorIp(`ip${i % 300}`, 50);
    db.prepare('SELECT * FROM attempts WHERE user_ref_hash = ? ORDER BY ts DESC, id DESC LIMIT 50').all(`u${i % 500}`);
  }));
  db.close();
}

for (const r of res) console.log(`${r.nombre.padEnd(70)} ${String(r.usPorOp).padStart(9)} µs  ${String(r.opsPorSegundo).padStart(8)} op/s`);
writeFileSync(resolve(carpeta, '..', 'partes.json'), JSON.stringify(res, null, 2));
rmSync(carpeta, { recursive: true, force: true });
