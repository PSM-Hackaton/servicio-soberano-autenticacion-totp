// Cédula de identidad venezolana como identificador institucional, sin guardarla en claro.
// Este archivo es idéntico en backend/src/core/identidad/cedula.js y sdk/src/cedula.js (una prueba
// lo comprueba): el servicio y la app integradora derivan el mismo user_ref a partir de la cédula.
//
// Reglas de normalización:
//   - nacionalidad V (venezolano) o E (extranjero), en mayúscula o minúscula;
//   - separador opcional entre la letra y el número: un guion o un espacio;
//   - número de 6 a 9 dígitos, sin ceros a la izquierda; admite puntos de miles bien agrupados
//     (12.345.678) o ningún punto (12345678);
//   - ningún otro carácter (solo se toleran espacios al principio y al final).
// Derivación (opción 'hmac' de la app): user_ref = prefijo + base64url(HMAC-SHA256(canónica, secreto)).

import { createHmac } from 'node:crypto';

const LONGITUD_MAXIMA_ENTRADA = 24;
const RE_CEDULA = /^([VvEe])[- ]?([1-9][0-9]{0,2}(?:\.[0-9]{3}){1,2}|[1-9][0-9]{5,8})$/;
/** Prefijo opcional del user_ref derivado (lo elige la app; puede ser vacío). */
export const PATRON_PREFIJO_CEDULA = /^[A-Za-z0-9_.:-]{0,32}$/;
/** Secreto de derivación: base64url de 32 a 64 bytes. */
export const PATRON_SECRETO_CEDULA = /^[A-Za-z0-9_-]{43,86}$/;
const BYTES_MINIMOS_SECRETO = 32;

/**
 * Normaliza una cédula escrita a mano (`V-12.345.678`, `v12345678`, `E 80.000.003`…).
 * @param {unknown} texto
 * @returns {{ nacionalidad: 'V' | 'E', numero: string, canonica: string, formateada: string } | null}
 *   null si no es una cédula válida.
 */
export function normalizarCedula(texto) {
  if (typeof texto !== 'string' || texto.length > LONGITUD_MAXIMA_ENTRADA) return null;
  const m = RE_CEDULA.exec(texto.trim());
  if (!m) return null;
  const numero = m[2].replaceAll('.', '');
  if (numero.length < 6 || numero.length > 9) return null;
  const nacionalidad = /** @type {'V' | 'E'} */ (m[1].toUpperCase());
  const conPuntos = numero.replace(/\B(?=(?:[0-9]{3})+$)/g, '.');
  return { nacionalidad, numero, canonica: `${nacionalidad}${numero}`, formateada: `${nacionalidad}-${conPuntos}` };
}

/**
 * Deriva el user_ref opaco de una cédula: prefijo + base64url(HMAC-SHA256(cédula canónica, secreto)).
 * La app integradora lo calcula al enrolar y el servicio lo recalcula para la búsqueda de soporte;
 * la cédula nunca viaja ni se guarda en el servicio como user_ref.
 * @param {unknown} cedula Texto de la cédula (se normaliza).
 * @param {string} secreto Secreto de derivación en base64url (32 a 64 bytes).
 * @param {string} [prefijo] Prefijo opcional (`^[A-Za-z0-9_.:-]{0,32}$`).
 * @returns {string | null} null si la cédula no es válida.
 */
export function derivarUserRefDesdeCedula(cedula, secreto, prefijo = '') {
  if (typeof secreto !== 'string' || !PATRON_SECRETO_CEDULA.test(secreto)) throw new TypeError('Secreto de derivación inválido');
  if (typeof prefijo !== 'string' || !PATRON_PREFIJO_CEDULA.test(prefijo)) throw new TypeError('Prefijo inválido');
  const c = normalizarCedula(cedula);
  if (!c) return null;
  const llave = Buffer.from(secreto, 'base64url');
  try {
    if (llave.length < BYTES_MINIMOS_SECRETO) throw new TypeError('Secreto de derivación inválido');
    return prefijo + createHmac('sha256', llave).update(c.canonica, 'utf8').digest('base64url');
  } finally {
    llave.fill(0);
  }
}
