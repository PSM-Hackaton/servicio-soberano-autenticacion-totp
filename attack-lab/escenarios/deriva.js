#!/usr/bin/env node
// Escenario: arrastre de deriva. Antes, cada código aceptado en T+1 movía el centro de la ventana un
// paso, así que una ráfaga T+1, T+2, … T+12 se aceptaba entera en un segundo (12 códigos futuros
// válidos de una vez). Ahora verify acota la deriva resultante a max(|deriva guardada|, ventana):
// solo T+1 entra. Solo la resincronización (dos códigos consecutivos) puede fijar derivas mayores
// (hasta ±10) y verify respeta después ese tope.

import { crearUsuarioPrueba, esPrincipal, exigirCredenciales, principal } from '../lib/escenario.js';
import { codigoError, etiquetaEstado } from '../lib/http.js';
import { codigoEnPaso, codigoIncorrecto, pasoActual } from '../lib/totp.js';
import { distribucionEstados, dormir } from '../lib/metricas.js';
import { firmaRespuesta, verificar } from '../lib/servicio.js';

export const id = 'deriva';
export const nombre = 'Deriva acotada (ráfaga T+1…T+12)';
export const demuestra = 'Códigos futuros enviados en ráfaga no arrastran la deriva: de T+1…T+12 solo entra T+1; solo resync fija derivas mayores y verify respeta ese tope.';

/** Espera, si hace falta, a que queden al menos `margenMs` del periodo actual (la ráfaga no cruza de paso). */
async function inicioDePeriodo(datos, margenMs = 8000) {
  const ms = datos.periodo * 1000;
  const restante = ms - (Date.now() % ms);
  if (restante < margenMs) await dormir(restante + 100);
}

export async function ejecutar(ctx, res) {
  exigirCredenciales(ctx);
  const { cliente } = ctx;

  // 1. Ráfaga T+1 … T+12 contra un usuario recién activado.
  const a = await crearUsuarioPrueba(ctx);
  await inicioDePeriodo(a.datos);
  const t = pasoActual(a.datos);
  const rafaga = [];
  for (let k = 1; k <= 12; k++) rafaga.push({ k, r: await verificar(cliente, a.userRef, codigoEnPaso(a.datos, t + k)) });
  const mismoPaso = pasoActual(a.datos) === t;
  const aceptados = rafaga.filter((x) => x.r.status === 200).map((x) => `T+${x.k}`);
  res.metrica('ráfaga T+1…T+12', rafaga.map((x) => `T+${x.k}:${etiquetaEstado(x.r)}`).join(' '));
  res.verificar('Ráfaga T+1…T+12 en el mismo periodo', 'solo T+1 aceptado', aceptados.length ? aceptados.join(', ') : 'ninguno',
    mismoPaso && aceptados.length === 1 && aceptados[0] === 'T+1');
  if (aceptados.length > 1) res.hallazgo(`Arrastre de deriva: se aceptaron ${aceptados.length} códigos futuros en una ráfaga (${aceptados.join(', ')}).`);
  res.verificar('Deriva devuelta tras T+1', 'drift_steps = 1', rafaga[0].r.cuerpo?.drift_steps ?? '—', rafaga[0].r.cuerpo?.drift_steps === 1);
  const rechazos = rafaga.slice(1).map((x) => x.r);
  res.verificar('Rechazos de la ráfaga', '401 VERIFICATION_FAILED o 429 (bloqueo progresivo), nunca 200 ni 5xx',
    JSON.stringify(distribucionEstados(rechazos)),
    rechazos.every((r) => (r.status === 401 && codigoError(r) === 'VERIFICATION_FAILED') || (r.status === 429 && codigoError(r) === 'TOO_MANY_REQUESTS')));

  // 2. Resync fija una deriva mayor (hasta ±10) y verify la respeta como tope. Otro usuario final
  //    (client_ip propio): los fallos de la ráfaga anterior no deben contaminar su origen.
  const IP_B = '198.51.100.40';
  const b = await crearUsuarioPrueba(ctx);
  await inicioDePeriodo(b.datos);
  const tb = pasoActual(b.datos);
  const rs = await cliente.post(`/api/v1/enrollments/${encodeURIComponent(b.enrollmentId)}/resync`, {
    code_1: codigoEnPaso(b.datos, tb + 8), code_2: codigoEnPaso(b.datos, tb + 9), client_ip: IP_B,
  });
  res.verificar('Resincronización con T+8, T+9', '200 drift_steps = 9', `${etiquetaEstado(rs)} drift_steps = ${rs.cuerpo?.drift_steps ?? '—'}`,
    rs.status === 200 && rs.cuerpo?.drift_steps === 9);
  const fueraTope = await verificar(cliente, b.userRef, codigoEnPaso(b.datos, tb + 10), { clientIp: IP_B });
  const incorrecto = await verificar(cliente, b.userRef, codigoIncorrecto(b.datos, { margen: 12 }), { clientIp: IP_B });
  res.verificar('Tras resync, T+10 supera el tope (|10| > 9)', '401, idéntico a un código incorrecto',
    `${etiquetaEstado(fueraTope)} ${codigoError(fueraTope) ?? ''}`.trim(),
    fueraTope.status === 401 && firmaRespuesta(fueraTope) === firmaRespuesta(incorrecto));
  const fuera = await cliente.post(`/api/v1/enrollments/${encodeURIComponent(b.enrollmentId)}/resync`, {
    code_1: codigoEnPaso(b.datos, tb + 11), code_2: codigoEnPaso(b.datos, tb + 12), client_ip: IP_B,
  });
  res.verificar('Resync más allá de ±10 pasos', 'rechazado (401)', etiquetaEstado(fuera), fuera.status === 401);
  if (!mismoPaso) res.nota('La ráfaga cruzó un cambio de paso TOTP; repita el escenario.');
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
