// Motor TOTP del autenticador (RFC 6238 sobre HOTP RFC 4226) con Web Crypto.
// Módulo puro: no toca el DOM, la red ni el almacenamiento. Funciona igual en el
// navegador y en Node 22 (globalThis.crypto.subtle). Produce exactamente los mismos
// códigos que backend/src/core/totp/totp.js.

const ALFABETO = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Nombre del algoritmo en la URI otpauth → nombre en Web Crypto. */
export const ALGORITMOS = Object.freeze({ SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' });

/** Nombre legible para mostrar en la interfaz. */
export const NOMBRE_ALGORITMO = Object.freeze({ SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' });

export const PERIODO_MIN = 15;
export const PERIODO_MAX = 60;

function sutil() {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('Web Crypto no disponible (se requiere contexto seguro)');
  return s;
}

/**
 * Base32 RFC 4648 (alfabeto estándar, sin relleno).
 * @param {Uint8Array} bytes @returns {string}
 */
export function base32Encode(bytes) {
  let salida = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = ((buffer << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      salida += ALFABETO[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) salida += ALFABETO[(buffer << (5 - bits)) & 31];
  return salida;
}

/** Quita espacios, guiones y relleno; pasa a mayúsculas. */
export function normalizarBase32(texto) {
  return String(texto).toUpperCase().replace(/[\s=-]/g, '');
}

/**
 * Decodifica Base32 (tolera espacios, guiones, relleno y minúsculas, igual que el backend).
 * @param {string} texto @returns {Uint8Array}
 */
export function base32Decode(texto) {
  const limpio = normalizarBase32(texto);
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const caracter of limpio) {
    const valor = ALFABETO.indexOf(caracter);
    if (valor === -1) throw new Error('Base32 inválido');
    buffer = ((buffer << 5) | valor) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(bytes);
}

/** @param {{ algoritmo: string, digitos: number, periodo: number }} p */
export function validarPolitica(p) {
  if (!Object.hasOwn(ALGORITMOS, p.algoritmo)) throw new Error('Algoritmo no soportado');
  if (p.digitos !== 6 && p.digitos !== 8) throw new Error('Dígitos deben ser 6 u 8');
  if (!Number.isInteger(p.periodo) || p.periodo < PERIODO_MIN || p.periodo > PERIODO_MAX) {
    throw new Error('Periodo fuera de rango');
  }
}

/**
 * Importa la semilla como llave HMAC no extraíble (la semilla no puede leerse de vuelta).
 * @param {Uint8Array} semilla @param {'SHA1'|'SHA256'|'SHA512'} algoritmo
 */
export async function importarSemilla(semilla, algoritmo) {
  if (!Object.hasOwn(ALGORITMOS, algoritmo)) throw new Error('Algoritmo no soportado');
  return sutil().importKey('raw', semilla, { name: 'HMAC', hash: ALGORITMOS[algoritmo] }, false, ['sign']);
}

/**
 * HOTP (RFC 4226): HMAC del contador de 8 bytes big-endian + truncado dinámico.
 * @param {Uint8Array | CryptoKey} semillaOLlave
 * @param {number | bigint} contador
 * @param {'SHA1'|'SHA256'|'SHA512'} algoritmo
 * @param {6 | 8} digitos
 * @returns {Promise<string>}
 */
export async function generarHotp(semillaOLlave, contador, algoritmo, digitos) {
  const llave = semillaOLlave instanceof Uint8Array ? await importarSemilla(semillaOLlave, algoritmo) : semillaOLlave;
  const mensaje = new Uint8Array(8);
  new DataView(mensaje.buffer).setBigUint64(0, BigInt(contador));
  const h = new Uint8Array(await sutil().sign('HMAC', llave, mensaje));
  const o = h[h.length - 1] & 0x0f;
  const binario = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(binario % 10 ** digitos).padStart(digitos, '0');
}

/** Paso de tiempo T = floor((ahora − T0) / periodo), con T0 = 0. */
export function pasoDeTiempo(epochMs, periodo) {
  return Math.floor(epochMs / 1000 / periodo);
}

/** Segundos (con decimales) que le quedan al código vigente. */
export function segundosRestantes(epochMs, periodo) {
  const transcurrido = (epochMs / 1000) % periodo;
  return periodo - transcurrido;
}

/**
 * TOTP (RFC 6238).
 * @param {Uint8Array | CryptoKey} semillaOLlave
 * @param {number} epochMs
 * @param {{ algoritmo: 'SHA1'|'SHA256'|'SHA512', digitos: 6|8, periodo: number }} politica
 */
export async function generarTotp(semillaOLlave, epochMs, politica) {
  validarPolitica(politica);
  return generarHotp(semillaOLlave, pasoDeTiempo(epochMs, politica.periodo), politica.algoritmo, politica.digitos);
}

/** Agrupa el código para leerlo mejor: 123 456 · 1234 5678. */
export function agruparCodigo(codigo) {
  const c = String(codigo);
  const mitad = Math.ceil(c.length / 2);
  return `${c.slice(0, mitad)} ${c.slice(mitad)}`;
}
