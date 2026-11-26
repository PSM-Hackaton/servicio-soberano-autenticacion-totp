#!/usr/bin/env node
// Escenario: password/code spraying. UN origen prueba pocos códigos contra MUCHAS cuentas (por debajo
// del umbral de bloqueo por cuenta). Mezcla cuentas reales e inexistentes para comprobar además que
// el servicio no permite enumerar usuarios (mismas respuestas para ambas).
//
// Esperado: ninguna cuenta comprometida, respuestas indistinguibles, y el detector local de anomalías
// eleva el riesgo del origen (se ve en la evaluación `risk` de una verificación posterior desde la
// misma IP, en /metrics o, en apps con modo "bloqueo", con 429 ANOMALY_BLOCKED).

import { crearUsuarioPrueba, esPrincipal, exigirCredenciales, nuevoUserRef, principal } from '../lib/escenario.js';
import { codigoError } from '../lib/http.js';
import { codigoIncorrecto, codigoNuevo } from '../lib/totp.js';
import { distribucionEstados, resumenLatencias, redondear } from '../lib/metricas.js';
import { opcionNumero } from '../lib/config.js';
import { deltaMetrica, leerMetricas, verificar, verificarUsuario } from '../lib/servicio.js';

export const id = 'spraying';
export const nombre = 'Spraying: un origen contra muchas cuentas';
export const demuestra = 'Pocos intentos por cuenta no comprometen ninguna; no hay enumeración de usuarios y el detector eleva el riesgo del origen.';

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
  const metricasDespues = await leerMetricas(cliente);
  const anomalias = todas.filter((r) => codigoError(r) === 'ANOMALY_BLOCKED').length;
  const limitados = todas.filter((r) => r.status === 429).length;
  const testigo = reales[0];
  const c = await codigoNuevo(testigo, { ventana: config.ventana });
  const legit = await verificarUsuario(cliente, testigo, c.codigo, op);
  const riesgo = legit.cuerpo?.risk ?? legit.cuerpo?.riskAssessment ?? null;
  const nivel = riesgo?.level ?? (codigoError(legit) === 'ANOMALY_BLOCKED' ? 'BLOCK' : null);
  res.metrica('verificación legítima posterior desde el origen atacante', `${legit.status} ${codigoError(legit) ?? ''}`.trim());
  res.metrica('riesgo asignado al origen', riesgo ? `${riesgo.score ?? riesgo.riskScore} (${riesgo.level}) · ${(riesgo.reasons ?? []).join('; ')}` : '—');
  res.metrica('429 durante el spraying (limitador o detector)', limitados);
  res.metrica('Δ bloqueos del detector (métrica anomaly_blocked)', deltaMetrica(metricasAntes, metricasDespues, 'totp_verifications_total', 'anomaly') ?? '—');
  const detectado = anomalias > 0 || ['MEDIUM', 'HIGH', 'CRITICAL', 'BLOCK'].includes(String(nivel));
  res.verificar('Detector local de anomalías marca el origen', 'riesgo ≥ MEDIUM o ANOMALY_BLOCKED',
    anomalias > 0 ? `${anomalias} ANOMALY_BLOCKED` : `nivel ${nivel ?? 'desconocido'}`, detectado);
  if (!detectado) {
    res.hallazgo(`Tras ${todas.length} fallos desde una sola IP contra ${objetivos.length} cuentas, el detector asigna riesgo ${nivel ?? 'desconocido'} a una verificación desde ese mismo origen.`);
  }
  res.metrica('estados', distribucionEstados(todas));
  res.metrica('latencia', resumenLatencias(todas.map((r) => r.ms)));
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
