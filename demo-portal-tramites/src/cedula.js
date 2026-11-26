// Cédula de identidad venezolana: identificador institucional del ciudadano en el portal.
// Forma normalizada: nacionalidad (V o E) + número sin puntos ni ceros a la izquierda, p. ej. V12345678.
// El servicio TOTP nunca recibe la cédula: solo un seudónimo HMAC derivado con un secreto del portal.

import { createHmac } from 'node:crypto';

const NACIONALIDADES = new Set(['V', 'E']);

/** Agrupa los dígitos de tres en tres con puntos: 12345678 → 12.345.678. */
export const conPuntos = (digitos) => String(digitos).replace(/\B(?=(\d{3})+(?!\d))/g, '.');

/**
 * Normaliza la cédula escrita por el ciudadano.
 * Acepta el número con o sin puntos (12345678 o 12.345.678) y, opcionalmente, con el prefijo de
 * nacionalidad en el propio campo (V-12.345.678, E 81234567); el prefijo escrito prevalece sobre el selector.
 * @param {unknown} nacionalidad 'V' | 'E' (selector del formulario)
 * @param {unknown} numero texto escrito
 * @returns {string | null} 'V12345678' / 'E12345678' o null si el formato no es válido
 */
export function normalizarCedula(nacionalidad, numero) {
  const texto = String(numero ?? '').trim().toUpperCase().replace(/\s+/g, ' ');
  const m = /^(?:([VE])\s?-?\s?)?([0-9.]{6,11})$/.exec(texto);
  if (!m) return null;
  const nac = m[1] ?? String(nacionalidad ?? 'V').trim().toUpperCase();
  if (!NACIONALIDADES.has(nac)) return null;
  const crudo = m[2];
  const digitos = crudo.replace(/\./g, '');
  if (!/^[1-9][0-9]{5,8}$/.test(digitos)) return null;
  // Con puntos, deben ser separadores de miles bien puestos (12.345.678, no 1.2345.678).
  if (crudo.includes('.') && crudo !== conPuntos(digitos)) return null;
  return nac + digitos;
}

/** V12345678 → V-12.345.678 (para mostrar). */
export function formatearCedula(normalizada) {
  const m = /^([VE])([0-9]{6,9})$/.exec(String(normalizada ?? ''));
  return m ? `${m[1]}-${conPuntos(m[2])}` : '';
}

/**
 * Seudónimo estable que el portal envía al servicio como `user_ref`: ptd- + HMAC-SHA256(cédula, secreto),
 * acortado a 128 bits en hexadecimal. Sin el secreto del portal no se puede volver a la cédula
 * ni comprobar si una cédula concreta está enrolada.
 */
export function seudonimo(normalizada, secreto) {
  if (!secreto || String(secreto).length < 32) throw new Error('Secreto de seudónimos ausente o demasiado corto');
  return `ptd-${createHmac('sha256', String(secreto)).update(String(normalizada)).digest('hex').slice(0, 32)}`;
}
