// Bóveda de semillas: cifrado en reposo con AES-256-GCM y llaves maestras versionadas.
// Solo usa node:crypto. No toca base de datos ni red.

import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { LONGITUD_SEMILLA } from '../totp/totp.js';

/** @typedef {import('../totp/totp.js').Algoritmo} Algoritmo */
/** @typedef {{ ct: Buffer, nonce: Buffer, authTag: Buffer, keyVersion: string }} RegistroCifrado */
/** @typedef {{ [version: string]: Buffer }} Llavero */

const CIFRADO = 'aes-256-gcm';
const LONGITUD_LLAVE = 32;
const LONGITUD_NONCE = 12;
const LONGITUD_TAG = 16;
const ERROR_DESCIFRADO = 'No se pudo descifrar';

/**
 * Genera una semilla aleatoria con la longitud recomendada para el algoritmo.
 * @param {Algoritmo} algoritmo
 * @returns {Buffer}
 */
export function generateSeed(algoritmo) {
  if (!Object.hasOwn(LONGITUD_SEMILLA, algoritmo)) throw new Error('Algoritmo no soportado');
  return randomBytes(LONGITUD_SEMILLA[algoritmo]);
}

/** Datos autenticados adicionales: atan el texto cifrado a su contexto y versión de llave. */
function aad(contexto, keyVersion) {
  return Buffer.from(`${contexto}:${keyVersion}`, 'utf8');
}

/**
 * Crea una bóveda con un llavero versionado. La versión activa se usa para cifrar;
 * cualquier versión presente en el llavero sirve para descifrar (rotación).
 * @param {{ llaves: Llavero, versionActiva: string }} opciones
 */
export function crearVault({ llaves, versionActiva }) {
  if (!llaves || typeof llaves !== 'object') throw new Error('Llavero inválido');
  /** @type {Map<string, Buffer>} */
  const llavero = new Map();
  for (const [version, llave] of Object.entries(llaves)) {
    if (!Buffer.isBuffer(llave) || llave.length !== LONGITUD_LLAVE) {
      throw new Error(`La llave ${version} debe tener ${LONGITUD_LLAVE} bytes`);
    }
    llavero.set(version, Buffer.from(llave));
  }
  if (!llavero.has(versionActiva)) throw new Error('La versión activa no existe en el llavero');

  /**
   * @param {Buffer} buffer @param {string} contexto
   * @returns {RegistroCifrado}
   */
  function encryptBlob(buffer, contexto) {
    if (!Buffer.isBuffer(buffer)) throw new Error('Se esperaba un Buffer');
    const keyVersion = versionActiva;
    const nonce = randomBytes(LONGITUD_NONCE);
    const cifrador = createCipheriv(CIFRADO, llavero.get(keyVersion), nonce, { authTagLength: LONGITUD_TAG });
    cifrador.setAAD(aad(contexto, keyVersion));
    const ct = Buffer.concat([cifrador.update(buffer), cifrador.final()]);
    return { ct, nonce, authTag: cifrador.getAuthTag(), keyVersion };
  }

  /**
   * Descifra un registro. Cualquier fallo produce el mismo error genérico para no filtrar la causa.
   * @param {RegistroCifrado} registro @param {string} contexto
   * @returns {Buffer}
   */
  function decryptBlob(registro, contexto) {
    try {
      const { ct, nonce, authTag, keyVersion } = registro;
      const llave = llavero.get(keyVersion);
      if (!llave) throw new Error();
      if (nonce.length !== LONGITUD_NONCE || authTag.length !== LONGITUD_TAG) throw new Error();
      const descifrador = createDecipheriv(CIFRADO, llave, nonce, { authTagLength: LONGITUD_TAG });
      descifrador.setAAD(aad(contexto, keyVersion));
      descifrador.setAuthTag(authTag);
      return Buffer.concat([descifrador.update(ct), descifrador.final()]);
    } catch {
      throw new Error(ERROR_DESCIFRADO);
    }
  }

  return {
    versionActiva,
    /** @param {string} version @returns {boolean} true si la versión está en el llavero */
    tieneVersion: (version) => llavero.has(version),
    encryptBlob,
    decryptBlob,
    /** @param {Buffer} semilla @param {string} enrollmentId */
    encryptSeed: (semilla, enrollmentId) => encryptBlob(semilla, enrollmentId),
    /** @param {RegistroCifrado} registro @param {string} enrollmentId */
    decryptSeed: (registro, enrollmentId) => decryptBlob(registro, enrollmentId),
    /**
     * Rotación: descifra con la versión del registro y vuelve a cifrar con la activa.
     * @param {RegistroCifrado} registro @param {string} contexto
     */
    reencrypt(registro, contexto) {
      const claro = decryptBlob(registro, contexto);
      try {
        return encryptBlob(claro, contexto);
      } finally {
        claro.fill(0);
      }
    },
  };
}

/**
 * Lee el llavero desde variables de entorno:
 * MASTER_KEY_VERSION=v1 y MASTER_KEY_V1_HEX=<64 caracteres hex>, MASTER_KEY_V2_HEX=..., etc.
 * @param {Record<string, string | undefined>} env
 * @returns {{ llaves: Llavero, versionActiva: string }}
 */
export function llavesDesdeEntorno(env) {
  const versionActiva = env.MASTER_KEY_VERSION;
  if (!versionActiva || !/^[A-Za-z0-9]+$/.test(versionActiva)) throw new Error('MASTER_KEY_VERSION ausente o inválida');
  /** @type {Llavero} */
  const llaves = {};
  for (const [nombre, valor] of Object.entries(env)) {
    const m = /^MASTER_KEY_([A-Z0-9]+)_HEX$/.exec(nombre);
    if (!m) continue;
    if (typeof valor !== 'string' || !/^[0-9a-fA-F]{64}$/.test(valor)) {
      throw new Error(`${nombre} debe tener 64 caracteres hexadecimales`);
    }
    const version = m[1] === versionActiva.toUpperCase() ? versionActiva : m[1].toLowerCase();
    llaves[version] = Buffer.from(valor, 'hex');
  }
  if (!(versionActiva in llaves)) {
    throw new Error(`Falta MASTER_KEY_${versionActiva.toUpperCase()}_HEX para la versión activa`);
  }
  return { llaves, versionActiva };
}

/**
 * Hash con pimienta (HMAC-SHA256) en hexadecimal.
 * @param {string | Buffer} valor @param {string | Buffer} pepper
 * @returns {string}
 */
export function hashPepper(valor, pepper) {
  return createHmac('sha256', pepper).update(valor).digest('hex');
}

/**
 * Pimienta diaria derivada: HMAC-SHA256(semillaPepper, 'YYYY-MM-DD' en UTC).
 * Sirve para anonimizar IP con rotación diaria.
 * @param {string | Buffer} semillaPepper @param {Date} [fecha]
 * @returns {Buffer}
 */
export function pepperDiario(semillaPepper, fecha = new Date()) {
  const dia = fecha.toISOString().slice(0, 10);
  return createHmac('sha256', semillaPepper).update(dia, 'utf8').digest();
}
