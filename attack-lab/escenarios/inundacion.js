#!/usr/bin/env node
// Escenario: inundación controlada (mini DoS de laboratorio). Un origen lanza una ráfaga concurrente
// de verificaciones mientras otro origen (el "ciudadano") sondea /health.
// Esperado: el limitador por (app, origen) —y, si se adelanta, el detector— responde 429 al atacante,
// no aparecen 5xx, y /health sigue respondiendo durante y después de la ráfaga. El límite global por
// IP TCP es alto a propósito (anti-DDoS: un portal concentra a todos sus ciudadanos en una IP).
// Opciones: --peticiones N (400), --concurrencia N (50).

import { randomInt } from 'node:crypto';
import { esPrincipal, exigirCredenciales, nuevoUserRef, principal, sondearSalud } from '../lib/escenario.js';
import { codigoError, etiquetaEstado } from '../lib/http.js';
import { cronometro, distribucionEstados, dormir, enParalelo, redondear, resumenLatencias, tasa } from '../lib/metricas.js';
import { opcionNumero } from '../lib/config.js';
import { verificar } from '../lib/servicio.js';

export const id = 'inundacion';
export const nombre = 'Inundación concurrente';
export const demuestra = 'Una ráfaga concurrente recibe 429 (limitador por origen y detector de anomalías) sin errores internos, y /health sigue respondiendo para los demás.';

export async function ejecutar(ctx, res) {
  exigirCredenciales(ctx);
  const { cliente, config } = ctx;
  const total = opcionNumero(config, 'peticiones', 400);
  const concurrencia = opcionNumero(config, 'concurrencia', 50);
  const op = await ctx.opOrigen(ctx.ip(200));
  if (!op.origen) res.nota('Sin orígenes simulados: atacante y sondeo de salud comparten IP, así que /health también puede recibir 429.');

  // Sondeo de salud en paralelo cada 100 ms desde el origen "legítimo" (antes, durante y 1 s después).
  const sondeos = [];
  let activo = true;
  const sondeador = (async () => {
    while (activo) {
      sondeos.push(await sondearSalud(cliente, '/health', 2000));
      await dormir(100);
    }
  })();

  const reloj = cronometro();
  const respuestas = await enParalelo(total, concurrencia, () =>
    verificar(cliente, nuevoUserRef('inundacion'), String(randomInt(1e6)).padStart(6, '0'), { ...op, timeoutMs: 10000 }));
  const duracion = reloj.s();
  await dormir(1000);
  activo = false;
  await sondeador;
  const despues = await sondearSalud(cliente);

  const d = distribucionEstados(respuestas);
  const n429 = d['429'] ?? 0;
  const n5xx = respuestas.filter((r) => r.status >= 500).length;
  const sinRespuesta = respuestas.filter((r) => r.status === 0).length;
  const saludOk = sondeos.filter((r) => r.status === 200).length;

  /** @type {Record<string, number>} */
  const codigos = {};
  for (const r of respuestas) { const k = codigoError(r) ?? etiquetaEstado(r); codigos[k] = (codigos[k] ?? 0) + 1; }
  res.verificar('La ráfaga es frenada (limitador o detector)', '≥ 1 respuesta 429', `${n429} × 429`, n429 > 0);
  res.verificar('Errores internos (5xx)', '0', n5xx, n5xx === 0);
  res.verificar('Peticiones sin respuesta (caídas/timeouts)', '0', sinRespuesta, sinRespuesta === 0);
  res.verificar('Disponibilidad de /health durante la ráfaga', '≥ 95 %', `${tasa(saludOk, sondeos.length)} % (${saludOk}/${sondeos.length})`,
    sondeos.length === 0 || tasa(saludOk, sondeos.length) >= 95);
  res.verificar('/health tras la ráfaga', '200', etiquetaEstado(despues), despues.status === 200);

  res.metrica('peticiones / concurrencia', `${total} / ${concurrencia}`);
  res.metrica('duración de la ráfaga', `${redondear(duracion, 2)} s`);
  res.metrica('rendimiento', `${redondear(total / duracion, 0)} pet/s`);
  res.metrica('estados', d);
  res.metrica('tasa de 429', `${tasa(n429, total)} %`);
  res.metrica('códigos de error', codigos);
  res.metrica('latencia (todas)', resumenLatencias(respuestas.map((r) => r.ms)));
  res.metrica('latencia de /health durante la ráfaga', resumenLatencias(sondeos.map((r) => r.ms)));
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
