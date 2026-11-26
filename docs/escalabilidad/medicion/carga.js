// Generador de carga propio (node:https con keep-alive, concurrencia en lazo cerrado) contra banco.js.
// Usuarios legítimos distintos: los enrola y activa por la API pública y calcula sus códigos con
// backend/src/core/totp/totp.js usando el mismo reloj acelerado que el banco.
// Uso: node carga.js <carpeta> [--usuarios 1000] [--duracion 8] [--concurrencias 1,10,50,100]
// Escribe <carpeta>/resultados.json y muestra un resumen.

import { Agent, request } from 'node:https';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as esperar } from 'node:timers/promises';

const BACKEND = fileURLToPath(new URL('../../../backend/', import.meta.url));
const { generateTotp, pasoDeTiempo } = await import(resolve(BACKEND, 'src/core/totp/totp.js'));
const { base32Decode } = await import(resolve(BACKEND, 'src/core/totp/base32.js'));

// ------------------------------------------------------------------ argumentos
const carpeta = process.argv[2];
const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i > 0 ? process.argv[i + 1] : d; };
const N_USUARIOS = Number(arg('usuarios', 1000));
const DURACION_S = Number(arg('duracion', 8));
const CONCURRENCIAS = arg('concurrencias', '1,10,50,100').split(',').map(Number);
const FASES = new Set(arg('fases', 'jwks,verify,validate').split(','));
const banco = JSON.parse(readFileSync(resolve(carpeta, 'banco.json'), 'utf8'));
const CA = readFileSync(resolve(BACKEND, 'certs/ca.crt'));
const reloj = () => banco.T0 + (Date.now() - banco.T0) * banco.K;
const CRED = { 'x-client-id': banco.client_id, 'x-client-secret': banco.client_secret };

// ------------------------------------------------------------------ HTTP
function peticion(agente, metodo, ruta, cuerpo, cabeceras = {}) {
  const datos = cuerpo === undefined ? null : Buffer.from(JSON.stringify(cuerpo));
  return new Promise((ok, mal) => {
    const t0 = process.hrtime.bigint();
    const req = request({
      host: 'localhost', port: banco.puerto, method: metodo, path: ruta, agent: agente,
      headers: { ...cabeceras, ...(datos ? { 'content-type': 'application/json', 'content-length': datos.length } : {}) },
    }, (res) => {
      const trozos = [];
      res.on('data', (t) => trozos.push(t));
      res.on('end', () => {
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        let json = null;
        try { json = JSON.parse(Buffer.concat(trozos).toString('utf8')); } catch { /* no JSON */ }
        ok({ status: res.statusCode, json, ms });
      });
    });
    req.on('error', mal);
    if (datos) req.write(datos);
    req.end();
  });
}
const nuevoAgente = (c) => new Agent({ keepAlive: true, maxSockets: c, ca: CA });

// ------------------------------------------------------------------ proceso y base
function muestraProceso() {
  const stat = readFileSync(`/proc/${banco.pid}/stat`, 'utf8');
  const campos = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
  const ticks = Number(campos[11]) + Number(campos[12]); // utime + stime
  const status = readFileSync(`/proc/${banco.pid}/status`, 'utf8');
  const kb = (c) => Number(new RegExp(`${c}:\\s+(\\d+)`).exec(status)?.[1] ?? 0);
  return { cpuS: ticks / 100, rssMB: kb('VmRSS') / 1024, hwmMB: kb('VmHWM') / 1024, hilos: kb('Threads') };
}
function infoBase() {
  const db = new DatabaseSync(banco.db, { readOnly: true });
  try {
    const n = (t) => db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n;
    const pag = db.prepare('PRAGMA page_count').get().page_count;
    const tam = db.prepare('PRAGMA page_size').get().page_size;
    const libres = db.prepare('PRAGMA freelist_count').get().freelist_count;
    let porTabla = null;
    try {
      porTabla = Object.fromEntries(db.prepare('SELECT name, SUM(pgsize) AS b FROM dbstat GROUP BY name').all().map((f) => [f.name, f.b]));
    } catch { /* dbstat no disponible */ }
    const tamArchivo = (s) => { try { return statSync(banco.db + s).size; } catch { return 0; } };
    return {
      bytesLogicos: (pag - libres) * tam, archivoDb: tamArchivo(''), archivoWal: tamArchivo('-wal'),
      filas: Object.fromEntries(['enrollments', 'recovery_codes', 'attempts', 'audit_log', 'consumed_jti'].map((t) => [t, n(t)])),
      porTabla,
    };
  } finally { db.close(); }
}

// ------------------------------------------------------------------ estadística
function resumen(latencias, segundos, estados, cpu0, cpu1) {
  const s = Float64Array.from(latencias).sort();
  const p = (q) => (s.length ? s[Math.min(s.length - 1, Math.ceil(q * s.length) - 1)] : null);
  const r2 = (x) => (x == null ? null : Math.round(x * 100) / 100);
  return {
    peticiones: s.length, segundos: r2(segundos), rps: Math.round(s.length / segundos),
    p50: r2(p(0.5)), p95: r2(p(0.95)), p99: r2(p(0.99)), max: r2(s[s.length - 1]), estados,
    cpuNucleos: r2((cpu1.cpuS - cpu0.cpuS) / segundos), rssMB: Math.round(cpu1.rssMB), picoRssMB: Math.round(cpu1.hwmMB),
  };
}

/** Lazo cerrado: `c` trabajadores repiten `una()` hasta `fin()`; devuelve el resumen. */
async function lazo(c, una, fin) {
  const latencias = [];
  const estados = {};
  const cpu0 = muestraProceso();
  const t0 = performance.now();
  await Promise.all(Array.from({ length: c }, async () => {
    while (!fin(performance.now() - t0)) {
      const r = await una();
      if (r === null) { await esperar(1); continue; }
      latencias.push(r.ms);
      estados[r.status] = (estados[r.status] ?? 0) + 1;
    }
  }));
  const seg = (performance.now() - t0) / 1000;
  return resumen(latencias, seg, estados, cpu0, muestraProceso());
}

// ------------------------------------------------------------------ usuarios
const usuarios = [];
let cursor = 0;
const clientIp = (i) => `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;

async function enrolarUno(agente, i) {
  const user_ref = `ciudadano-${i}`;
  const e = await peticion(agente, 'POST', '/api/v1/enrollments', { user_ref }, CRED);
  if (e.status !== 201) throw new Error(`Enrolar ${e.status}`);
  const uri = new URL(e.json.otpauth_uri);
  const semilla = base32Decode(uri.searchParams.get('secret'));
  const politica = { algoritmo: e.json.algoritmo, digitos: e.json.digitos, periodo: e.json.periodo };
  const ahora = reloj();
  const a = await peticion(agente, 'POST', `/api/v1/enrollments/${e.json.enrollment_id}/activate`,
    { code: generateTotp(semilla, ahora, politica), client_ip: clientIp(i) }, CRED);
  if (a.status !== 200) throw new Error(`Activar ${a.status}`);
  usuarios.push({ user_ref, semilla, politica, ip: clientIp(i), ultimoPaso: pasoDeTiempo(ahora, politica.periodo), ocupado: false });
  return { enrolarMs: e.ms, activarMs: a.ms };
}

/** Siguiente usuario con un paso TOTP nuevo disponible (respeta el anti replay). */
function tomarUsuario() {
  for (let k = 0; k < usuarios.length; k++) {
    const u = usuarios[cursor++ % usuarios.length];
    if (!u.ocupado && pasoDeTiempo(reloj(), u.politica.periodo) > u.ultimoPaso) { u.ocupado = true; return u; }
  }
  return null;
}

async function verificarUno(agente, tokens) {
  const u = tomarUsuario();
  if (!u) return null;
  const ahora = reloj();
  const r = await peticion(agente, 'POST', '/api/v1/verify',
    { user_ref: u.user_ref, code: generateTotp(u.semilla, ahora, u.politica), client_ip: u.ip }, CRED);
  u.ultimoPaso = pasoDeTiempo(ahora, u.politica.periodo);
  u.ocupado = false;
  if (tokens && r.status === 200) tokens.push(r.json.token);
  return r;
}

// ------------------------------------------------------------------ fases
const resultados = { inicio: new Date().toISOString(), banco: { K: banco.K, heuristicas: banco.heuristicas, sincrono: banco.sincrono }, N_USUARIOS, DURACION_S };
resultados.baseInicial = infoBase();
resultados.procesoInicial = muestraProceso();

// 1. Enrolamiento + activación (incluye 10 hashes scrypt de códigos de recuperación por usuario).
{
  const agente = nuevoAgente(16);
  const lat = { enrolar: [], activar: [] };
  const cpu0 = muestraProceso();
  const t0 = performance.now();
  let i = 0;
  await Promise.all(Array.from({ length: 16 }, async () => {
    while (i < N_USUARIOS) {
      const r = await enrolarUno(agente, i++);
      lat.enrolar.push(r.enrolarMs);
      lat.activar.push(r.activarMs);
    }
  }));
  const seg = (performance.now() - t0) / 1000;
  const cpu1 = muestraProceso();
  resultados.enrolamiento = {
    concurrencia: 16,
    usuariosPorSegundo: Math.round((N_USUARIOS / seg) * 10) / 10,
    enrolar: resumen(lat.enrolar, seg, {}, cpu0, cpu1),
    activar: resumen(lat.activar, seg, {}, cpu0, cpu1),
  };
  agente.destroy();
  resultados.baseTrasEnrolar = infoBase();
  console.log(`Enrolados ${N_USUARIOS} usuarios en ${seg.toFixed(1)} s`);
}

const fin = (ms) => ms >= DURACION_S * 1000;
resultados.jwks = {};
resultados.verify = {};
resultados.validate = {};

for (const c of CONCURRENCIAS) {
  const agente = nuevoAgente(c);
  // calentamiento breve (no se registra)
  await lazo(c, () => peticion(agente, 'GET', '/.well-known/jwks.json'), (ms) => ms > 500);
  if (FASES.has('jwks')) {
    resultados.jwks[c] = await lazo(c, () => peticion(agente, 'GET', '/.well-known/jwks.json'), fin);
    console.log(`jwks c=${c}`, resultados.jwks[c].rps, 'rps p99', resultados.jwks[c].p99);
  }
  if (FASES.has('verify')) {
    resultados.verify[c] = await lazo(c, () => verificarUno(agente, null), fin);
    console.log(`verify c=${c}`, resultados.verify[c].rps, 'rps p99', resultados.verify[c].p99, resultados.verify[c].estados);
  }
  if (!FASES.has('validate')) { agente.destroy(); continue; }

  // validate: se obtienen tokens reales (verify sin medir) y se validan consumiendo el jti.
  const tokens = [];
  const objetivo = c === 1 ? 1500 : 6000;
  await lazo(50, () => verificarUno(agente, tokens), () => tokens.length >= objetivo);
  let k = 0;
  resultados.validate[c] = await lazo(c, () => {
    if (k >= tokens.length) return Promise.resolve(null);
    return peticion(agente, 'POST', '/api/v1/tokens/validate', { token: tokens[k++] }, CRED);
  }, () => k >= tokens.length);
  console.log(`validate c=${c}`, resultados.validate[c].rps, 'rps p99', resultados.validate[c].p99, resultados.validate[c].estados);
  agente.destroy();
}

resultados.baseFinal = infoBase();
resultados.procesoFinal = muestraProceso();
resultados.fin = new Date().toISOString();
writeFileSync(resolve(carpeta, 'resultados.json'), JSON.stringify(resultados, null, 2));
console.log('Resultados en', resolve(carpeta, 'resultados.json'));
