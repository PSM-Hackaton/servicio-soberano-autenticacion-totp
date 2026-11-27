// Extracción de características conductuales sobre la tabla `attempts` (ya anonimizada).
// Funciones puras: reciben el intento actual y el historial reciente, no tocan base de datos ni red.

/**
 * Intento de verificación tal como se guarda en `attempts` (sin datos personales: solo hashes).
 * `resultado` puede faltar en el intento actual si se evalúa antes de verificar el código.
 * @typedef {object} Intento
 * @property {string | null} [user_ref_hash] HMAC-SHA256 de la referencia del usuario.
 * @property {string} ip_hash HMAC-SHA256 de la IP con pepper diario.
 * @property {string} [resultado] ok, invalid_code, replay, locked, anomaly_blocked, rate_limited.
 * @property {number | string | Date} [ts] Marca de tiempo (epoch ms, ISO 8601 o Date).
 */

/** Ventana de observación de las características de conteo: 15 minutos. */
export const VENTANA_MS = 15 * 60 * 1000;

/** Valor del intervalo medio cuando la IP no tiene intentos previos en la ventana (s). */
const INTERVALO_SIN_DATOS_S = VENTANA_MS / 1000;

/** Hora UTC que se toma como patrón cuando la cuenta aún no tiene historial de accesos correctos. */
export const HORA_PATRON_POR_DEFECTO = 13;

/** Mínimo de accesos correctos de la cuenta para usar su propio patrón horario. */
const MIN_ACCESOS_PATRON = 3;

/** Máximo de accesos correctos recientes que se usan para estimar el patrón horario. */
const MAX_ACCESOS_PATRON = 50;

/**
 * Nombres de las posiciones del vector de características (mismo orden que el vector).
 *
 * 0. fallosCuenta15m: intentos fallidos sobre la misma cuenta en los últimos 15 min (incluye el
 *    actual si ya trae resultado). Señal principal de fuerza bruta contra una cuenta.
 * 1. ipsPorCuenta15m: hashes de IP distintos que atacaron la misma cuenta en 15 min (incluye la IP
 *    actual). Un usuario legítimo usa 1 o 2; la fuerza bruta distribuida usa decenas.
 * 2. cuentasPorIp15m: cuentas distintas probadas desde la misma IP en 15 min (incluye la actual).
 *    Señal de password spraying (una IP contra muchas cuentas).
 * 3. fallosIp15m: intentos fallidos desde la misma IP en 15 min, sin importar la cuenta.
 * 4. intervaloMedioIp: segundos medios entre intentos consecutivos de la IP dentro de la ventana
 *    (900 si no hay intentos previos). Ritmos de pocos segundos delatan automatización.
 * 5. horaSeno: sen(2π·hora/24). Codificación circular de la hora del día (23:59 queda junto a 00:00).
 * 6. horaCoseno: cos(2π·hora/24). Complemento del anterior.
 * 7. desviacionHora: (1 − cos(Δ))/2 en [0, 1], con Δ el ángulo entre la hora actual y la hora
 *    media circular de los accesos correctos de la cuenta (o la hora patrón si no hay historial).
 *    0 = a la hora habitual, 1 = a 12 horas de distancia.
 * 8. proporcionFallosIp: fallos / intentos con resultado conocido de la IP en 15 min, en [0, 1].
 */
export const NOMBRES_CARACTERISTICAS = Object.freeze([
  'fallosCuenta15m',
  'ipsPorCuenta15m',
  'cuentasPorIp15m',
  'fallosIp15m',
  'intervaloMedioIp',
  'horaSeno',
  'horaCoseno',
  'desviacionHora',
  'proporcionFallosIp',
]);

/** Número de dimensiones del vector de características. */
export const DIMENSION = NOMBRES_CARACTERISTICAS.length;

/**
 * Normaliza una marca de tiempo a epoch ms.
 * @param {number | string | Date | undefined} ts
 */
export function aMs(ts) {
  if (typeof ts === 'number') return ts;
  if (ts instanceof Date) return ts.getTime();
  if (typeof ts === 'string') return Date.parse(ts);
  return NaN;
}

/** Un resultado cuenta como fallo si existe y no es `ok`. */
function esFallo(resultado) {
  return resultado !== undefined && resultado !== null && resultado !== 'ok';
}

/** Hora fraccional del día (0–24) en UTC desplazada por `desfaseMin`. */
function horaDelDia(ms, desfaseMin) {
  const minutos = Math.floor(ms / 60000) + desfaseMin;
  return (((minutos % 1440) + 1440) % 1440) / 60;
}

/** Hora media circular de una lista de horas (0–24). */
function horaMediaCircular(horas) {
  let s = 0;
  let c = 0;
  for (const h of horas) {
    const a = (2 * Math.PI * h) / 24;
    s += Math.sin(a);
    c += Math.cos(a);
  }
  const angulo = Math.atan2(s, c);
  return ((angulo * 24) / (2 * Math.PI) + 24) % 24;
}

/**
 * Calcula el vector numérico de características de un intento.
 * El historial puede contener intentos más antiguos que la ventana: los conteos solo usan los
 * últimos 15 min, y el patrón horario usa todos los accesos correctos de la cuenta.
 * Los intentos posteriores a `ahora` se ignoran.
 * @param {Intento} intentoActual
 * @param {Intento[]} historial Intentos previos (sin incluir el actual).
 * @param {number | string | Date} [ahora] Instante de evaluación (por defecto `intentoActual.ts` o el reloj).
 * @param {{ ventanaMs?: number, horaPatron?: number, desfaseHorarioMin?: number }} [opciones]
 * @returns {number[]}
 */
export function extraerCaracteristicas(intentoActual, historial, ahora, opciones = {}) {
  const { ventanaMs = VENTANA_MS, horaPatron = HORA_PATRON_POR_DEFECTO, desfaseHorarioMin = 0 } = opciones;
  let t = aMs(ahora ?? intentoActual.ts);
  if (!Number.isFinite(t)) t = Date.now();
  const desde = t - ventanaMs;
  const cuenta = intentoActual.user_ref_hash ?? null;
  const ip = intentoActual.ip_hash;

  let fallosCuenta = 0;
  let fallosIp = 0;
  let intentosIp = 0;
  let conocidosIp = 0;
  let primerTsIp = Infinity;
  const ipsCuenta = new Set([ip]);
  const cuentasIp = new Set(cuenta === null ? [] : [cuenta]);
  /** @type {number[]} */
  const accesosCuenta = [];

  for (const previo of historial) {
    const ts = aMs(previo.ts);
    if (!(ts <= t)) continue;
    const fallo = esFallo(previo.resultado);
    const mismaCuenta = cuenta !== null && previo.user_ref_hash === cuenta;
    if (mismaCuenta && previo.resultado === 'ok') accesosCuenta.push(ts);
    if (ts < desde) continue;
    if (mismaCuenta) {
      if (fallo) fallosCuenta++;
      ipsCuenta.add(previo.ip_hash);
    }
    if (previo.ip_hash === ip) {
      intentosIp++;
      if (previo.resultado !== undefined && previo.resultado !== null) conocidosIp++;
      if (fallo) fallosIp++;
      if (previo.user_ref_hash) cuentasIp.add(previo.user_ref_hash);
      if (ts < primerTsIp) primerTsIp = ts;
    }
  }

  if (intentoActual.resultado !== undefined && intentoActual.resultado !== null) {
    conocidosIp++;
    if (esFallo(intentoActual.resultado)) {
      fallosIp++;
      if (cuenta !== null) fallosCuenta++;
    }
  }

  const intervaloMedio = intentosIp > 0
    ? Math.min(INTERVALO_SIN_DATOS_S, (t - primerTsIp) / 1000 / intentosIp)
    : INTERVALO_SIN_DATOS_S;

  const hora = horaDelDia(t, desfaseHorarioMin);
  const angulo = (2 * Math.PI * hora) / 24;
  let patron = horaPatron;
  if (accesosCuenta.length >= MIN_ACCESOS_PATRON) {
    accesosCuenta.sort((a, b) => a - b);
    patron = horaMediaCircular(accesosCuenta.slice(-MAX_ACCESOS_PATRON).map((ms) => horaDelDia(ms, desfaseHorarioMin)));
  }
  const desviacionHora = (1 - Math.cos(angulo - (2 * Math.PI * patron) / 24)) / 2;

  return [
    fallosCuenta,
    ipsCuenta.size,
    cuentasIp.size,
    fallosIp,
    intervaloMedio,
    Math.sin(angulo),
    Math.cos(angulo),
    desviacionHora,
    conocidosIp > 0 ? fallosIp / conocidosIp : 0,
  ];
}

/**
 * Convierte el vector en un objeto con nombres legibles (para razones y depuración).
 * @param {number[]} vector
 * @returns {Record<string, number>}
 */
export function describirCaracteristicas(vector) {
  return Object.fromEntries(NOMBRES_CARACTERISTICAS.map((nombre, i) => [nombre, vector[i]]));
}

/**
 * Recorre un flujo de intentos en orden cronológico y, para cada uno, entrega el intento (sin
 * `resultado`, como se vería antes de verificar el código) y su historial: los intentos de la
 * ventana más los últimos accesos correctos de la cuenta anteriores a la ventana.
 * Sirve para entrenar y para evaluar sobre tráfico sintético sin base de datos.
 * @param {Intento[]} eventos
 * @param {(evento: Intento, intento: Intento, historial: Intento[], ahora: number, indice: number) => void} visitar
 * @param {{ ventanaMs?: number }} [opciones]
 */
export function recorrerFlujo(eventos, visitar, opciones = {}) {
  const { ventanaMs = VENTANA_MS } = opciones;
  const ordenados = eventos.slice().sort((a, b) => aMs(a.ts) - aMs(b.ts));
  /** @type {Map<string, Intento[]>} */
  const accesosAntiguos = new Map();
  let inicio = 0;
  for (let i = 0; i < ordenados.length; i++) {
    const evento = ordenados[i];
    const ahora = aMs(evento.ts);
    while (inicio < i && aMs(ordenados[inicio].ts) < ahora - ventanaMs) {
      const saliente = ordenados[inicio];
      if (saliente.resultado === 'ok' && saliente.user_ref_hash) {
        const lista = accesosAntiguos.get(saliente.user_ref_hash) ?? [];
        lista.push(saliente);
        if (lista.length > MAX_ACCESOS_PATRON) lista.shift();
        accesosAntiguos.set(saliente.user_ref_hash, lista);
      }
      inicio++;
    }
    const ventana = ordenados.slice(inicio, i);
    const antiguos = evento.user_ref_hash ? accesosAntiguos.get(evento.user_ref_hash) ?? [] : [];
    const historial = antiguos.length > 0 ? antiguos.concat(ventana) : ventana;
    const { resultado, ...intento } = evento;
    visitar(evento, intento, historial, ahora, i);
  }
}
