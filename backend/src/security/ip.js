// Validación estricta y forma canónica de direcciones IP (IPv4 o IPv6) recibidas como texto,
// p. ej. el campo `client_ip` que una app integradora envía con la IP de su usuario final.
// Sin zonas (%eth0), sin puertos, sin corchetes, sin espacios, sin ceros a la izquierda en IPv4.

import { isIPv4, isIPv6 } from 'node:net';

const OCTETO = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const RE_IPV4 = new RegExp(`^${OCTETO}(?:\\.${OCTETO}){3}$`);
/** Solo caracteres posibles en una IPv6 textual (incluida la forma con IPv4 embebida). */
const RE_CARACTERES_IPV6 = /^[0-9A-Fa-f:.]{2,45}$/;

/**
 * Devuelve la forma canónica de una IP válida o null si no lo es.
 * IPv6 se canonicaliza (minúsculas, compresión de ceros RFC 5952 vía WHATWG URL) y las IPv4
 * mapeadas (::ffff:a.b.c.d) se reducen a la IPv4, para que la misma persona tenga una sola identidad.
 * @param {unknown} texto
 * @returns {string | null}
 */
export function normalizarIp(texto) {
  if (typeof texto !== 'string' || texto.length < 2 || texto.length > 45) return null;
  if (RE_IPV4.test(texto)) return isIPv4(texto) ? texto : null;
  if (!RE_CARACTERES_IPV6.test(texto) || !texto.includes(':') || !isIPv6(texto)) return null;
  let canonica;
  try {
    canonica = new URL(`http://[${texto}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
  const mapeada = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(canonica);
  if (mapeada) {
    const alto = parseInt(mapeada[1], 16);
    const bajo = parseInt(mapeada[2], 16);
    return `${alto >> 8}.${alto & 255}.${bajo >> 8}.${bajo & 255}`;
  }
  return canonica;
}

/** @param {unknown} texto */
export const esIpValida = (texto) => normalizarIp(texto) !== null;
