#!/usr/bin/env node
// Escenario: reinicio/caída del backend. Mata el proceso del servicio y lo relanza con el comando
// indicado, midiendo cuánto tarda /health/ready en volver a 200. Antes de matarlo bloquea una cuenta
// de prueba y comprueba después que el bloqueo SIGUE vigente (los bloqueos se guardan en la base de
// datos, un reinicio no los borra).
//
// Uso:
//   node attack-lab/caos/reinicio.js --comando "node src/main.js" --cwd backend [--pid 12345]
//        [--senal SIGKILL] [--ruta-salud /health/ready] [--max-espera 60] [--detener-al-final]
// Si el servicio ya está en marcha hay que indicar su --pid (o el del grupo que lo lanzó). Si no lo
// está, se arranca primero (midiendo el arranque en frío) y luego se mata y relanza.
// El backend relanzado queda en marcha (desacoplado) salvo --detener-al-final; su salida va a
// attack-lab/resultados/backend-reinicio.log.

import { spawn } from 'node:child_process';
import { mkdirSync, openSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { crearUsuarioPrueba, esPrincipal, exigirCredenciales, principal, sondearSalud } from '../lib/escenario.js';
import { codigoError, etiquetaEstado } from '../lib/http.js';
import { codigoIncorrecto } from '../lib/totp.js';
import { dormir, redondear } from '../lib/metricas.js';
import { RAIZ_LAB, RAIZ_REPO, opcionNumero } from '../lib/config.js';
import { verificar } from '../lib/servicio.js';

export const id = 'reinicio';
export const nombre = 'Caída y reinicio del backend';
export const demuestra = 'Tras matar el proceso, el servicio vuelve a estar listo en segundos y los bloqueos por cuenta sobreviven al reinicio.';

/** Espera hasta que la ruta de salud responda 200 (o se agote el tiempo). Devuelve ms o null. */
async function esperarListo(cliente, ruta, maxMs) {
  const t0 = performance.now();
  while (performance.now() - t0 < maxMs) {
    const r = await sondearSalud(cliente, ruta, 1000);
    if (r.status === 200) return performance.now() - t0;
    await dormir(100);
  }
  return null;
}

/** Espera hasta que el servicio deje de responder. Devuelve ms o null. */
async function esperarCaido(cliente, maxMs) {
  const t0 = performance.now();
  while (performance.now() - t0 < maxMs) {
    const r = await sondearSalud(cliente, '/health', 500);
    if (r.status === 0) return performance.now() - t0;
    await dormir(50);
  }
  return null;
}

function matar(pid, senal) {
  // Primero el grupo (npm → node), luego el proceso.
  try { process.kill(-pid, senal); return true; } catch { /* no es líder de grupo */ }
  try { process.kill(pid, senal); return true; } catch { return false; }
}

function lanzar(comando, cwd) {
  const dirLog = join(RAIZ_LAB, 'resultados');
  mkdirSync(dirLog, { recursive: true });
  const log = openSync(join(dirLog, 'backend-reinicio.log'), 'a');
  const hijo = spawn(comando, { cwd, shell: true, detached: true, stdio: ['ignore', log, log] });
  hijo.unref();
  return hijo;
}

export async function ejecutar(ctx, res) {
  const { cliente, config } = ctx;
  const comando = config.opciones.comando ?? config.opciones['comando-arranque'];
  if (!comando || comando === true) {
    res.verificar('Comando de arranque', '--comando "<orden>"', 'no indicado', null);
    res.nota('Escenario omitido: pasa --comando "node src/main.js" --cwd backend (y --pid si ya está en marcha).');
    return;
  }
  const cwd = resolve(RAIZ_REPO, String(config.opciones.cwd ?? 'backend'));
  const senal = String(config.opciones.senal ?? 'SIGKILL');
  const rutaSalud = String(config.opciones['ruta-salud'] ?? '/health/ready');
  const maxMs = opcionNumero(config, 'max-espera', 60) * 1000;
  let pid = Number(config.opciones.pid ?? config.opciones['pid-backend']) || null;

  // 0. Si no está en marcha, arranque en frío.
  const inicial = await sondearSalud(cliente);
  if (inicial.status === 0) {
    const hijo = lanzar(String(comando), cwd);
    const ms = await esperarListo(cliente, rutaSalud, maxMs);
    res.verificar('Arranque en frío', `${rutaSalud} 200`, ms === null ? 'no arrancó' : `${redondear(ms / 1000, 2)} s`, ms !== null);
    if (ms === null) return;
    pid = hijo.pid ?? null;
  } else if (!pid) {
    throw new Error('El servicio ya está en marcha: indica su PID con --pid para poder matarlo y relanzarlo.');
  }

  // 1. Bloquear una cuenta antes de la caída (si hay credenciales).
  let bloqueada = null;
  const op = await ctx.opOrigen(ctx.ip(51));
  if (config.apps.length) {
    exigirCredenciales(ctx);
    bloqueada = await crearUsuarioPrueba(ctx);
    let r;
    for (let i = 0; i <= config.maxIntentos; i++) r = await verificar(cliente, bloqueada.userRef, codigoIncorrecto(bloqueada.datos), op);
    res.verificar('Cuenta bloqueada antes de la caída', '429', `${etiquetaEstado(r)} ${codigoError(r) ?? ''}`.trim(), r.status === 429);
  }

  // 2. Matar.
  const ok = matar(/** @type {number} */ (pid), /** @type {NodeJS.Signals} */ (senal));
  res.verificar(`Matar el backend (PID ${pid}, ${senal})`, 'proceso terminado', ok ? 'señal enviada' : 'no se pudo enviar', ok);
  if (!ok) return;
  const msCaida = await esperarCaido(cliente, 10000);
  res.metrica('tiempo hasta dejar de responder', msCaida === null ? 'seguía respondiendo' : `${Math.round(msCaida)} ms`);
  if (msCaida === null) {
    res.verificar('El servicio cae', 'deja de responder', 'sigue respondiendo (¿PID correcto?)', false);
    return;
  }

  // 3. Relanzar y medir.
  const t0 = performance.now();
  const hijo = lanzar(String(comando), cwd);
  const msListo = await esperarListo(cliente, rutaSalud, maxMs);
  const msSalud = msListo === null ? null : performance.now() - t0;
  res.verificar(`Tiempo hasta ${rutaSalud} 200 tras relanzar`, '< 30 s', msSalud === null ? `no volvió en ${maxMs / 1000} s` : `${redondear(msSalud / 1000, 2)} s`,
    msSalud !== null && msSalud < 30000);
  res.metrica('PID del backend relanzado', hijo.pid ?? '—');
  res.metrica('comando', `${comando} (cwd ${cwd})`);

  // 4. El bloqueo sobrevive al reinicio.
  if (bloqueada && msSalud !== null) {
    const r = await verificar(cliente, bloqueada.userRef, codigoIncorrecto(bloqueada.datos), op);
    res.verificar('Bloqueo vigente tras el reinicio', '429 (persistido en BD)', `${etiquetaEstado(r)} ${codigoError(r) ?? ''}`.trim(), r.status === 429);
    if (r.status !== 429) res.hallazgo('El bloqueo progresivo de una cuenta se pierde al reiniciar el backend.');
  }

  if (config.opciones['detener-al-final'] && hijo.pid) {
    matar(hijo.pid, 'SIGTERM');
    res.nota('Backend relanzado detenido al final (--detener-al-final).');
  } else {
    res.nota(`El backend relanzado sigue en marcha (PID ${hijo.pid}); salida en attack-lab/resultados/backend-reinicio.log.`);
  }
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
