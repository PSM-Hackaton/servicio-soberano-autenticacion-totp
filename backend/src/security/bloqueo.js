// Bloqueo progresivo por fallos consecutivos (30 s, 2 min, 10 min, 1 h). Funciones puras.

/** Escalones por defecto en segundos. */
export const ESCALONES_BLOQUEO = Object.freeze([30, 120, 600, 3600]);

/**
 * Segundos de bloqueo que corresponden a una cantidad de fallos consecutivos.
 * Con maxIntentos=5: 0–4 → 0; 5–9 → 30; 10–14 → 120; 15–19 → 600; 20+ → 3600 (tope).
 * @param {number} fallosConsecutivos
 * @param {{ maxIntentos?: number, escalones?: readonly number[] }} [opciones]
 * @returns {number}
 */
export function calcularBloqueo(fallosConsecutivos, { maxIntentos = 5, escalones = ESCALONES_BLOQUEO } = {}) {
  if (!Number.isInteger(maxIntentos) || maxIntentos < 1) throw new RangeError('maxIntentos inválido');
  if (!Array.isArray(escalones) || escalones.length === 0) throw new RangeError('escalones inválidos');
  if (!Number.isInteger(fallosConsecutivos) || fallosConsecutivos < maxIntentos) return 0;
  const indice = Math.min(Math.floor(fallosConsecutivos / maxIntentos) - 1, escalones.length - 1);
  return escalones[indice];
}

/**
 * Calcula el instante ISO hasta el que queda bloqueado (null si no corresponde bloqueo).
 * @param {number} fallosConsecutivos
 * @param {Date | number} [ahora=new Date()]
 * @param {{ maxIntentos?: number, escalones?: readonly number[] }} [opciones]
 * @returns {string | null}
 */
export function bloqueadoHasta(fallosConsecutivos, ahora = new Date(), opciones = {}) {
  const segundos = calcularBloqueo(fallosConsecutivos, opciones);
  if (segundos === 0) return null;
  return new Date(new Date(ahora).getTime() + segundos * 1000).toISOString();
}

/**
 * Indica si un bloqueo (`locked_until` de la tabla enrollments) sigue vigente.
 * @param {string | null | undefined} lockedUntilIso
 * @param {Date | number} [ahora=new Date()]
 * @returns {boolean}
 */
export function estaBloqueado(lockedUntilIso, ahora = new Date()) {
  if (lockedUntilIso == null || lockedUntilIso === '') return false;
  const hasta = Date.parse(lockedUntilIso);
  if (Number.isNaN(hasta)) return false;
  return hasta > new Date(ahora).getTime();
}
