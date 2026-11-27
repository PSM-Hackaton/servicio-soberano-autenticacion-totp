// Códigos de recuperación legibles (formato XXXX-XXXX) generados con CSPRNG.
// Se muestran una sola vez y se guardan con `hashSecreto` sobre su forma normalizada.

import { randomInt } from 'node:crypto';

/** Alfabeto sin caracteres ambiguos (sin 0/O, 1/I/L). 31 símbolos → ~39.6 bits por código. */
export const ALFABETO_RECUPERACION = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

const LONGITUD_BLOQUE = 4;
const FORMATO = new RegExp(`^[${ALFABETO_RECUPERACION}]{${LONGITUD_BLOQUE}}-[${ALFABETO_RECUPERACION}]{${LONGITUD_BLOQUE}}$`);

/** Bloque aleatorio uniforme (randomInt evita sesgo de módulo). */
function bloque() {
  let s = '';
  for (let i = 0; i < LONGITUD_BLOQUE; i++) s += ALFABETO_RECUPERACION[randomInt(ALFABETO_RECUPERACION.length)];
  return s;
}

/**
 * Genera n códigos de recuperación distintos entre sí.
 * @param {number} [n=10]
 * @returns {string[]} códigos `XXXX-XXXX`
 */
export function generarCodigosRecuperacion(n = 10) {
  if (!Number.isInteger(n) || n < 1 || n > 100) throw new RangeError('Cantidad de códigos fuera de rango');
  const codigos = new Set();
  while (codigos.size < n) codigos.add(`${bloque()}-${bloque()}`);
  return [...codigos];
}

/**
 * Normaliza lo que escribe el usuario: mayúsculas, sin espacios ni guiones, y vuelve al formato `XXXX-XXXX`.
 * Devuelve null si no corresponde a un código válido (no lanza).
 * @param {unknown} entrada
 * @returns {string | null}
 */
export function normalizarCodigoRecuperacion(entrada) {
  if (typeof entrada !== 'string' || entrada.length > 32) return null;
  const limpio = entrada.toUpperCase().replace(/[\s-]/g, '');
  if (limpio.length !== LONGITUD_BLOQUE * 2) return null;
  const codigo = `${limpio.slice(0, LONGITUD_BLOQUE)}-${limpio.slice(LONGITUD_BLOQUE)}`;
  return FORMATO.test(codigo) ? codigo : null;
}
