// Detector local de anomalías: combina el Isolation Forest (aprendizaje automático local, sin
// telemetría) con reglas explicables que aportan razones legibles en castellano.
// Todo se ejecuta en proceso: ninguna llamada de red, ningún dato sale del servidor.

import { performance } from 'node:perf_hooks';
import { extraerCaracteristicas, recorrerFlujo } from './caracteristicas.js';
import { entrenar, puntuar, serializar as serializarBosque, deserializar as deserializarBosque } from './isolationForest.js';
import { generarTraficoNormal } from './generadorTrafico.js';

/** @typedef {'bajo' | 'medio' | 'alto'} Nivel */
/** @typedef {'permitir' | 'espera_extra' | 'bloqueo_temporal' | 'alerta'} Accion */

/**
 * @typedef {object} Evaluacion
 * @property {number} riskScore Riesgo combinado en [0, 100].
 * @property {Nivel} level
 * @property {Accion} action
 * @property {string[]} reasons Razones legibles en castellano.
 * @property {number} inferenceMs Tiempo de extracción + inferencia en milisegundos.
 */

/**
 * Calibración del bosque frente al tráfico normal con el que se entrenó.
 * `base`: percentil 99 de las puntuaciones normales (por debajo, el bosque no aporta riesgo).
 * `techo`: puntuación a partir de la cual el bosque aporta su peso completo.
 * @typedef {{ base: number, techo: number, mediana: number }} Calibracion
 */

/**
 * Modelo completo del detector (lo que se persiste).
 * @typedef {{ tipo: 'detector-anomalias', version: 1, bosque: import('./isolationForest.js').ModeloIsolationForest, calibracion: Calibracion }} ModeloDetector
 */

/**
 * Reglas explicables. Cada regla de conteo tiene `umbral` (empieza a sumar riesgo) y `saturacion`
 * (riesgo máximo de la regla). La severidad va de 0.55 en el umbral a 1 en la saturación.
 */
export const REGLAS_POR_DEFECTO = Object.freeze({
  /** Fallos sobre la misma cuenta en 15 min (fuerza bruta, lenta o rápida). */
  fallosCuenta: { umbral: 5, saturacion: 15 },
  /** IP distintas sobre la misma cuenta en 15 min, con al menos `minFallos` fallos (distribuida). */
  ipsPorCuenta: { umbral: 4, saturacion: 12, minFallos: 2 },
  /** Cuentas distintas desde una IP en 15 min con mayoría de fallos (spraying; tolera NAT de oficina). */
  cuentasPorIp: { umbral: 6, saturacion: 20, minProporcionFallos: 0.5 },
  /** Fallos desde la misma IP en 15 min. */
  fallosIp: { umbral: 8, saturacion: 25 },
  /** Intervalo medio entre intentos de la IP por debajo de `maxSegundos`, con `minFallos` fallos. */
  ritmo: { maxSegundos: 5, minFallos: 3, severidad: 0.5 },
  /** Proporción de fallos de la IP muy alta con suficientes intentos. */
  proporcionFallos: { umbral: 0.9, minFallos: 5, severidad: 0.4 },
  /** Hora alejada del patrón de la cuenta (0.5 ≈ 6 h de diferencia). */
  horaInusual: { umbral: 0.5, severidad: 0.25 },
  /** Peso máximo del bosque: sin reglas activas no llega a bloqueo, solo a espera o alerta. */
  pesoBosque: 0.65,
});

/** Umbrales sobre riskScore: ≥ alerta → nivel medio, ≥ bloqueo → nivel alto. */
export const UMBRALES_POR_DEFECTO = Object.freeze({ alerta: 60, bloqueo: 75 });

const MODOS = new Set(['bloqueo', 'monitorizacion']);

const limitar = (x, min = 0, max = 1) => Math.min(max, Math.max(min, x));

/** Severidad lineal entre umbral (0.55) y saturación (1). */
function severidad(valor, umbral, saturacion) {
  if (valor < umbral) return 0;
  return 0.55 + 0.45 * limitar((valor - umbral) / Math.max(1e-9, saturacion - umbral));
}

/** Formato corto de números para las razones. */
const fmt = (x, decimales = 1) => Number(x.toFixed(decimales)).toLocaleString('es');

/** Diferencia en horas a partir de desviacionHora = (1 − cos Δ)/2. */
const horasDeDesviacion = (d) => (Math.acos(limitar(1 - 2 * d, -1, 1)) * 12) / Math.PI;

/**
 * Aplica las reglas explicables al vector de características.
 * @param {number[]} x @param {typeof REGLAS_POR_DEFECTO} reglas
 * @returns {{ severidad: number, razon: string }[]}
 */
function aplicarReglas(x, reglas) {
  const [fallosCuenta, ipsCuenta, cuentasIp, fallosIp, intervalo, , , desviacionHora, proporcion] = x;
  const activas = [];
  const agregar = (s, razon) => { if (s > 0) activas.push({ severidad: s, razon }); };
  const r = reglas;

  agregar(severidad(fallosCuenta, r.fallosCuenta.umbral, r.fallosCuenta.saturacion),
    `Ráfaga de ${fallosCuenta} intentos fallidos sobre la misma cuenta en 15 minutos`);
  if (fallosCuenta >= r.ipsPorCuenta.minFallos) {
    agregar(severidad(ipsCuenta, r.ipsPorCuenta.umbral, r.ipsPorCuenta.saturacion),
      `Dispersión anómala de ${ipsCuenta} hashes de IP sobre la misma cuenta (patrón de fuerza bruta distribuida)`);
  }
  if (proporcion >= r.cuentasPorIp.minProporcionFallos) {
    agregar(severidad(cuentasIp, r.cuentasPorIp.umbral, r.cuentasPorIp.saturacion),
      `Una misma IP probó ${cuentasIp} cuentas distintas en 15 minutos (patrón de password spraying)`);
  }
  agregar(severidad(fallosIp, r.fallosIp.umbral, r.fallosIp.saturacion),
    `${fallosIp} intentos fallidos desde la misma IP en 15 minutos`);
  if (intervalo < r.ritmo.maxSegundos && fallosIp >= r.ritmo.minFallos) {
    agregar(r.ritmo.severidad, `Ritmo automatizado: ${fmt(intervalo)} s de media entre intentos de la misma IP`);
  }
  if (proporcion >= r.proporcionFallos.umbral && fallosIp >= r.proporcionFallos.minFallos) {
    agregar(r.proporcionFallos.severidad, `${fmt(proporcion * 100, 0)} % de intentos fallidos desde la misma IP`);
  }
  if (desviacionHora >= r.horaInusual.umbral) {
    agregar(r.horaInusual.severidad, `Hora inusual: unas ${fmt(horasDeDesviacion(desviacionHora), 0)} h fuera del patrón horario de la cuenta`);
  }
  return activas.sort((a, b) => b.severidad - a.severidad);
}

/** Percentil simple sobre una copia ordenada. */
function percentil(valores, p) {
  const orden = valores.slice().sort((a, b) => a - b);
  return orden[Math.min(orden.length - 1, Math.max(0, Math.round(p * (orden.length - 1))))];
}

/**
 * Entrena el modelo del detector (bosque + calibración) a partir de vectores de tráfico normal.
 * @param {number[][]} vectores
 * @param {{ arboles?: number, muestra?: number, semilla?: number | string }} [opciones]
 * @returns {ModeloDetector}
 */
export function entrenarModelo(vectores, opciones = {}) {
  const bosque = entrenar(vectores, opciones);
  const puntuaciones = vectores.map((x) => puntuar(bosque, x));
  const base = percentil(puntuaciones, 0.99);
  return {
    tipo: 'detector-anomalias',
    version: 1,
    bosque,
    calibracion: { base, techo: Math.max(base + 0.1, 0.78), mediana: percentil(puntuaciones, 0.5) },
  };
}

/**
 * Crea un detector.
 * @param {{ modelo: ModeloDetector | import('./isolationForest.js').ModeloIsolationForest,
 *   reglas?: Partial<typeof REGLAS_POR_DEFECTO>, umbrales?: Partial<typeof UMBRALES_POR_DEFECTO>,
 *   modo?: 'bloqueo' | 'monitorizacion', opcionesCaracteristicas?: object }} config
 */
export function crearDetector({ modelo, reglas = {}, umbrales = {}, modo = 'bloqueo', opcionesCaracteristicas = {} }) {
  if (!modelo) throw new Error('Se requiere un modelo entrenado');
  if (!MODOS.has(modo)) throw new Error(`Modo no soportado: ${modo}`);
  /** @type {ModeloDetector} */
  const completo = modelo.tipo === 'isolation-forest'
    ? { tipo: 'detector-anomalias', version: 1, bosque: modelo, calibracion: { base: 0.6, techo: 0.78, mediana: 0.45 } }
    : modelo;
  const r = { ...REGLAS_POR_DEFECTO };
  for (const [clave, valor] of Object.entries(reglas)) {
    r[clave] = typeof valor === 'object' && valor !== null ? { ...REGLAS_POR_DEFECTO[clave], ...valor } : valor;
  }
  const u = { ...UMBRALES_POR_DEFECTO, ...umbrales };
  if (!(u.alerta < u.bloqueo)) throw new Error('El umbral de alerta debe ser menor que el de bloqueo');
  const { base, techo } = completo.calibracion;

  /**
   * Evalúa un intento antes (o después) de verificar el código.
   * @param {import('./caracteristicas.js').Intento} intento
   * @param {import('./caracteristicas.js').Intento[]} historial Intentos recientes anonimizados.
   * @param {number | string | Date} [ahora]
   * @returns {Evaluacion}
   */
  function evaluar(intento, historial = [], ahora) {
    const inicio = performance.now();
    const x = extraerCaracteristicas(intento, historial, ahora, opcionesCaracteristicas);
    const anomalia = puntuar(completo.bosque, x);
    const riesgoBosque = r.pesoBosque * limitar((anomalia - base) / (techo - base));
    const activas = aplicarReglas(x, r);

    // Combinación "O ruidoso": cada señal independiente reduce la probabilidad de que sea legítimo.
    let legitimo = 1 - riesgoBosque;
    for (const regla of activas) legitimo *= 1 - regla.severidad;
    const riskScore = Number((100 * (1 - legitimo)).toFixed(1));

    /** @type {Nivel} */
    const level = riskScore >= u.bloqueo ? 'alto' : riskScore >= u.alerta ? 'medio' : 'bajo';
    /** @type {Accion} */
    let action = 'permitir';
    if (level !== 'bajo') {
      if (modo === 'monitorizacion') action = 'alerta';
      else action = level === 'alto' ? 'bloqueo_temporal' : 'espera_extra';
    }

    const reasons = activas.map((a) => a.razon);
    if (riesgoBosque > 0.15) {
      reasons.push(`Isolation Forest: comportamiento atípico frente al patrón aprendido (anomalía ${fmt(anomalia, 2)}, normal ≤ ${fmt(base, 2)})`);
    }
    if (reasons.length === 0) reasons.push('Comportamiento dentro del patrón habitual');

    const inferenceMs = Number((performance.now() - inicio).toFixed(3));
    return { riskScore, level, action, reasons, inferenceMs };
  }

  return { evaluar, modelo: completo, modo, umbrales: Object.freeze(u), reglas: Object.freeze(r) };
}

/**
 * Convierte un flujo de eventos en vectores de características (cada intento con su historial).
 * @param {import('./caracteristicas.js').Intento[]} eventos
 */
export function vectorizarFlujo(eventos) {
  const vectores = [];
  recorrerFlujo(eventos, (_e, intento, historial, ahora) => vectores.push(extraerCaracteristicas(intento, historial, ahora)));
  return vectores;
}

/**
 * Entrena un detector con tráfico normal sintético reproducible (5 días laborables, 300 usuarios).
 * @param {number | string} [semilla]
 * @param {{ modo?: 'bloqueo' | 'monitorizacion', umbrales?: object, reglas?: object }} [opciones]
 */
export function entrenarDetectorPorDefecto(semilla = 42, opciones = {}) {
  const vectores = vectorizarFlujo(generarTraficoNormal({ semilla }));
  return crearDetector({ modelo: entrenarModelo(vectores, { semilla }), ...opciones });
}

/** Serializa el modelo del detector a JSON. @param {ModeloDetector} modelo */
export function serializarModelo(modelo) {
  return JSON.stringify({ ...modelo, bosque: JSON.parse(serializarBosque(modelo.bosque)) });
}

/** Recupera el modelo del detector desde JSON. @param {string | object} json @returns {ModeloDetector} */
export function deserializarModelo(json) {
  const datos = typeof json === 'string' ? JSON.parse(json) : json;
  if (datos?.tipo !== 'detector-anomalias') throw new Error('No es un modelo de detector');
  const { base, techo } = datos.calibracion ?? {};
  if (!Number.isFinite(base) || !Number.isFinite(techo) || techo <= base) throw new Error('Calibración inválida');
  return { ...datos, bosque: deserializarBosque(datos.bosque) };
}

const NIVEL_CONTRATO = { bajo: 'LOW', medio: 'MEDIUM', alto: 'HIGH' };
const ACCION_CONTRATO = { permitir: 'ALLOW', alerta: 'ALLOW', espera_extra: 'DELAY', bloqueo_temporal: 'BLOCK' };

/**
 * Adapta la evaluación al objeto `risk` de `contracts/openapi.yaml` (VerifySuccessResponse):
 * niveles LOW/MEDIUM/HIGH/CRITICAL (CRITICAL si el riesgo ≥ 90) y acciones ALLOW/DELAY/BLOCK
 * (la alerta de monitorización deja pasar el intento, por eso es ALLOW).
 * @param {Evaluacion} e
 */
export function aRiesgoContrato(e) {
  return {
    score: e.riskScore,
    level: e.level === 'alto' && e.riskScore >= 90 ? 'CRITICAL' : NIVEL_CONTRATO[e.level],
    action: ACCION_CONTRATO[e.action],
    inference_ms: e.inferenceMs,
    reasons: e.reasons,
  };
}
