#!/usr/bin/env node
// Evaluación reproducible del detector local de anomalías sobre tráfico sintético.
// Uso: node src/heuristics/evaluar.js [--semilla 42] [--json]
// Entrena con tráfico normal, evalúa sobre tráfico mixto (normal + ataques) y sobre tráfico normal
// independiente, y muestra detección por tipo de ataque, falsos positivos y latencia de inferencia.

import { performance } from 'node:perf_hooks';
import { parseArgs } from 'node:util';
import { recorrerFlujo } from './caracteristicas.js';
import { entrenarDetectorPorDefecto } from './detector.js';
import { generarTraficoMixto, generarTraficoNormal, TIPOS_ATAQUE } from './generadorTrafico.js';

const { values } = parseArgs({
  options: { semilla: { type: 'string', default: '42' }, json: { type: 'boolean', default: false } },
});
const semilla = Number.isFinite(Number(values.semilla)) ? Number(values.semilla) : values.semilla;

const pct = (a, b) => (b === 0 ? 0 : (100 * a) / b);
const percentil = (v, p) => {
  const o = v.slice().sort((a, b) => a - b);
  return o.length ? o[Math.min(o.length - 1, Math.round(p * (o.length - 1)))] : 0;
};

/** Evalúa un flujo y devuelve las evaluaciones junto a su evento. */
function evaluarFlujo(detector, eventos) {
  const filas = [];
  recorrerFlujo(eventos, (evento, intento, historial, ahora) => {
    filas.push({ evento, ev: detector.evaluar(intento, historial, ahora) });
  });
  return filas;
}

const t0 = performance.now();
const detector = entrenarDetectorPorDefecto(semilla);
const msEntrenamiento = performance.now() - t0;

const mixto = evaluarFlujo(detector, generarTraficoMixto({ semilla: `${semilla}-mixto`, campanasPorTipo: 10 }));
const soloNormal = evaluarFlujo(detector, generarTraficoNormal({ semilla: `${semilla}-validacion` }));

const ataques = {};
for (const tipo of TIPOS_ATAQUE) {
  const filas = mixto.filter((f) => f.evento.etiqueta === tipo);
  const campanas = new Map();
  for (const f of filas) {
    const c = campanas.get(f.evento.campana) ?? { intentos: 0, primeraAlta: null };
    c.intentos++;
    if (f.ev.level === 'alto' && c.primeraAlta === null) c.primeraAlta = c.intentos;
    campanas.set(f.evento.campana, c);
  }
  const detectadas = [...campanas.values()].filter((c) => c.primeraAlta !== null);
  const altos = filas.filter((f) => f.ev.level === 'alto');
  ataques[tipo] = {
    intentos: filas.length,
    deteccionAltoPct: pct(altos.length, filas.length),
    deteccionMedioOAltoPct: pct(filas.filter((f) => f.ev.level !== 'bajo').length, filas.length),
    campanas: campanas.size,
    campanasDetectadasPct: pct(detectadas.length, campanas.size),
    intentosHastaBloqueoMediana: percentil(detectadas.map((c) => c.primeraAlta), 0.5),
    conAporteBosquePct: pct(altos.filter((f) => f.ev.reasons.some((r) => r.startsWith('Isolation Forest'))).length, altos.length),
  };
}

const falsosPositivos = (filas) => ({
  intentos: filas.length,
  medioOAltoPct: pct(filas.filter((f) => f.ev.level !== 'bajo').length, filas.length),
  altoPct: pct(filas.filter((f) => f.ev.level === 'alto').length, filas.length),
});

const latencias = [...mixto, ...soloNormal].map((f) => f.ev.inferenceMs);
const informe = {
  semilla,
  entrenamientoMs: Number(msEntrenamiento.toFixed(1)),
  arboles: detector.modelo.bosque.arboles.length,
  muestra: detector.modelo.bosque.muestra,
  calibracion: detector.modelo.calibracion,
  ataques,
  falsosPositivos: {
    normalEnTraficoMixto: falsosPositivos(mixto.filter((f) => f.evento.etiqueta === 'normal')),
    normalIndependiente: falsosPositivos(soloNormal),
  },
  latenciaMs: {
    evaluaciones: latencias.length,
    media: latencias.reduce((a, b) => a + b, 0) / latencias.length,
    p95: percentil(latencias, 0.95),
    max: Math.max(...latencias),
  },
};

if (values.json) {
  console.log(JSON.stringify(informe, null, 2));
} else {
  const f = (x, d = 1) => x.toFixed(d).padStart(6);
  console.log('Detector local de anomalías: Isolation Forest + reglas explicables (sin red, sin telemetría)');
  console.log(`Semilla ${semilla} · ${informe.arboles} árboles · ψ=${informe.muestra} · entrenamiento ${informe.entrenamientoMs} ms`);
  console.log(`Calibración: normal p50=${informe.calibracion.mediana.toFixed(3)} p99=${informe.calibracion.base.toFixed(3)}\n`);
  console.log('Tipo de ataque               intentos  alto %  medio+ %  campañas  detectadas %  hasta bloqueo  aporte bosque %');
  for (const [tipo, a] of Object.entries(ataques)) {
    console.log(`${tipo.padEnd(28)} ${String(a.intentos).padStart(8)} ${f(a.deteccionAltoPct)}  ${f(a.deteccionMedioOAltoPct)}    ${String(a.campanas).padStart(6)}        ${f(a.campanasDetectadasPct)}  ${String(a.intentosHastaBloqueoMediana).padStart(6)} (med.)  ${f(a.conAporteBosquePct)}`);
  }
  console.log('\nFalsos positivos sobre tráfico legítimo');
  for (const [nombre, fp] of Object.entries(informe.falsosPositivos)) {
    console.log(`  ${nombre.padEnd(24)} ${String(fp.intentos).padStart(6)} intentos · medio+ ${fp.medioOAltoPct.toFixed(2)} % · alto ${fp.altoPct.toFixed(2)} %`);
  }
  const l = informe.latenciaMs;
  console.log(`\nLatencia de inferencia (${l.evaluaciones} evaluaciones): media ${l.media.toFixed(3)} ms · p95 ${l.p95.toFixed(3)} ms · máx ${l.max.toFixed(3)} ms`);
}
