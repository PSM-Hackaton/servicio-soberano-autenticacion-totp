// Base32 (RFC 4648, alfabeto estándar, sin relleno). Implementación propia.
// Se usa para codificar la semilla en la URI otpauth:// y en el alta manual.

const ALFABETO = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** @param {Uint8Array} bytes @returns {string} */
export function base32Encode(bytes) {
  let salida = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      salida += ALFABETO[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) salida += ALFABETO[(buffer << (5 - bits)) & 31];
  return salida;
}

/** @param {string} texto @returns {Buffer} */
export function base32Decode(texto) {
  const limpio = texto.toUpperCase().replace(/[\s=-]/g, '');
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const caracter of limpio) {
    const valor = ALFABETO.indexOf(caracter);
    if (valor === -1) throw new Error('Base32 inválido');
    buffer = (buffer << 5) | valor;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}
