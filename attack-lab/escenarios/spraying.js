#!/usr/bin/env node
// Escenario: password/code spraying. UN origen prueba pocos códigos contra MUCHAS cuentas (por debajo
// del umbral de bloqueo por cuenta). Mezcla cuentas reales e inexistentes para comprobar además que
// el servicio no permite enumerar usuarios (mismas respuestas para ambas).
//
// Esperado: ninguna cuenta comprometida, respuestas indistinguibles, y el detector local de anomalías
// bloquea el origen (se ve en /metrics como resultado anomaly_blocked). Hacia fuera, el bloqueo es
// un 429 TOO_MANY_REQUESTS genérico: sin puntuación, razones ni umbrales que guíen al atacante.

import { crearUsuarioPrueba, esPrincipal, exigirCredenciales, nuevoUserRef, principal } from '../lib/escenario.js';
import { codigoError, etiquetaEstado } from '../lib/http.js';
import { codigoIncorrecto, codigoNuevo } from '../lib/totp.js';
import { distribucionEstados, resumenLatencias, redondear } from '../lib/metricas.js';
import { opcionNumero } from '../lib/config.js';
import { deltaMetrica, leerMetricas, verificar, verificarUsuario } from '../lib/servicio.js';

export const id = 'spraying';
export const nombre = 'Spraying: un origen contra muchas cuentas';
export const demuestra = 'Pocos intentos por cuenta no comprometen ninguna; no hay enumeración de usuarios y el detector bloquea el origen con un 429 genérico que no revela su puntuación ni sus razones.';

export async function ejecutar(ctx, res) {
  exigirCredenciales(ctx);
  const { cliente, config } = ctx;
  const nReales = opcionNumero(config, 'cuentas-reales', 6);
  const nFalsas = opcionNumero(config, 'cuentas-falsas', 14);
  const porCuenta = opcionNumero(config, 'intentos-por-cuenta', 2);
  const op = await ctx.opOrigen(ctx.ip(77)); // el origen atacante (distinto del de preparación)

  const reales = [];
  for (let i = 0; i < nReales; i++) reales.push(await crearUsuarioPrueba(ctx));
  const objetivos = [
    ...reales.map((u) => ({ userRef: u.userRef, datos: u.datos, real: true })),
    ...Array.from({ length: nFalsas }, () => ({ userRef: nuevoUserRef('inexistente'), datos: null, real: false })),
  ].sort(() => Math.random() - 0.5);

  const metricasAntes = await leerMetricas(cliente);
  const porTipo = { real: [], falsa: [] };
  for (let ronda = 0; ronda < porCuenta; ronda++) {
    for (const o of objetivos) {
      const r = await verificar(cliente, o.userRef, codigoIncorrecto(o.datos ?? reales[0].datos), op);
      porTipo[o.real ? 'real' : 'falsa'].push(r);
    }
  }
  const todas = [...porTipo.real, ...porTipo.falsa];

  const aceptadas = todas.filter((r) => r.status === 200).length;
  res.verificar('Cuentas comprometidas', '0', aceptadas, aceptadas === 0);
  res.verificar('Errores internos (5xx)', '0', todas.filter((r) => r.status >= 500).length, todas.every((r) => r.status < 500));

  // Enumeración: mismas combinaciones (estado, error, mensaje) para cuentas reales e inexistentes.
  const firma = (r) => `${r.status}|${codigoError(r)}|${r.cuerpo?.message ?? ''}`;
  const fReales = new Set(porTipo.real.map(firma));
  const fFalsas = new Set(porTipo.falsa.map(firma));
  const iguales = fReales.size === fFalsas.size && [...fReales].every((f) => fFalsas.has(f));
  res.verificar('Sin enumeración de usuarios', 'misma respuesta para cuentas reales e inexistentes',
    iguales ? `idénticas (${[...fReales].map((f) => f.split('|').slice(0, 2).join(' ')).join(', ')})` : `distintas: reales ${[...fReales].join(';')} / inexistentes ${[...fFalsas].join(';')}`,
    iguales);
  if (!iguales) res.hallazgo('Las respuestas a cuentas reales e inexistentes difieren: permite enumerar usuarios.');
  const lr = resumenLatencias(porTipo.real.map((r) => r.ms));
  const lf = resumenLatencias(porTipo.falsa.map((r) => r.ms));
  res.metrica('latencia p50 cuentas reales / inexistentes', `${lr.p50} ms / ${lf.p50} ms`);
  const diferencia = lr.p50 !== null && lf.p50 !== null ? Math.abs(lr.p50 - lf.p50) : 0;
  res.verificar('Sin enumeración por tiempo de respuesta', 'diferencia p50 < 15 ms', `${redondear(diferencia)} ms`, diferencia < 15);

  // Detector: verificación LEGÍTIMA de una cuenta real desde el mismo origen atacante.
  const testigo = reales[0];
  const c = await codigoNuevo(testigo, { ventana: config.ventana });
  const legit = await verificarUsuario(cliente, testigo, c.codigo, op);
  const metricasDespues = await leerMetricas(cliente);
  const anomalias = deltaMetrica(metricasAntes, metricasDespues, 'totp_verifications_total', 'anomaly');
  const limitados = todas.filter((r) => r.status === 429);
  res.metrica('verificación legítima posterior desde el origen atacante', `${legit.status} ${codigoError(legit) ?? ''}`.trim());
  res.metrica('429 durante el spraying (bloqueo del detector)', limitados.length);
  res.metrica('Δ bloqueos del detector (métrica anomaly_blocked)', anomalias ?? '—');
  const detectado = (anomalias ?? 0) > 0;
  res.verificar('Detector local de anomalías bloquea el origen', 'Δ anomaly_blocked > 0 (en /metrics, solo loopback)',
    anomalias === null ? 'métricas no disponibles' : `${anomalias} bloqueos del detector`, detectado);
  if (!detectado) res.hallazgo(`Tras ${todas.length} fallos desde una sola IP contra ${objetivos.length} cuentas, el detector no bloqueó el origen.`);
  res.verificar('El titular tampoco entra desde el origen bloqueado', '429', etiquetaEstado(legit), legit.status === 429);

  // Sin detalles del detector hacia fuera: el 429 es el genérico del contrato.
  const bloqueos = [...limitados, ...(legit.status === 429 ? [legit] : [])];
  const genericos = bloqueos.every((r) => {
    const claves = Object.keys(r.cuerpo ?? {}).sort().join(',');
    return codigoError(r) === 'TOO_MANY_REQUESTS' && claves === 'error,message,retry_after_seconds' && r.cabeceras['retry-after'] === String(r.cuerpo.retry_after_seconds);
  });
  const filtra = bloqueos.some((r) => /risk|reason|score|umbral|anomal|riesgo|detector/i.test(r.texto));
  res.verificar('El 429 del detector no expone riesgo, razones ni umbrales', '{ error: TOO_MANY_REQUESTS, message, retry_after_seconds } + Retry-After',
    bloqueos.length ? (genericos && !filtra ? `genérico (${JSON.stringify(bloqueos[0].cuerpo)})` : `con detalles: ${bloqueos.find((r) => !genericos || filtra)?.texto.slice(0, 160)}`) : 'sin 429',
    bloqueos.length > 0 && genericos && !filtra);
  if (filtra) res.hallazgo('La respuesta del bloqueo adaptativo expone detalles del detector.');
  res.metrica('estados', distribucionEstados(todas));
  res.metrica('latencia', resumenLatencias(todas.map((r) => r.ms)));
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
