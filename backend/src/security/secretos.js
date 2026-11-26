// Hash y verificación de secretos con scrypt (client_secret, contraseñas de admin y códigos de recuperación).
// Solo usa node:crypto. Formato almacenado: scrypt$N$r$p$salt_b64$hash_b64

import { scrypt, scryptSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);

/** Parámetros por defecto (OWASP: N=2^14, r=8, p=1). */
export const PARAMETROS_SCRYPT = Object.freeze({ N: 16384, r: 8, p: 1, longitudSalt: 16, longitudHash: 32 });

/** Topes al leer un hash almacenado: evitan que un valor manipulado dispare un cómputo enorme. */
const MAX_N = 2 ** 20;
const MAX_R = 32;
const MAX_P = 16;
/** Longitud máxima aceptada de un secreto en texto (anti abuso de CPU/memoria). */
const MAX_LONGITUD_SECRETO = 4096;

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** Memoria máxima que scrypt necesita para N y r (128·N·r) con margen. */
function memoriaMaxima(N, r) {
  return 128 * N * r * 2;
}

/** @param {unknown} secreto */
function secretoValido(secreto) {
  return typeof secreto === 'string' && secreto.length > 0 && secreto.length <= MAX_LONGITUD_SECRETO;
}

/** @param {Buffer} salt @param {Buffer} hash */
function serializar(N, r, p, salt, hash) {
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

/**
 * Interpreta un hash almacenado. Devuelve null si el formato o los parámetros no son válidos.
 * @param {unknown} almacenado
 * @returns {{ N: number, r: number, p: number, salt: Buffer, hash: Buffer } | null}
 */
function interpretar(almacenado) {
  if (typeof almacenado !== 'string' || almacenado.length > 512) return null;
  const partes = almacenado.split('$');
  if (partes.length !== 6 || partes[0] !== 'scrypt') return null;
  const [, sN, sR, sP, sSalt, sHash] = partes;
  if (![sN, sR, sP].every((s) => /^[1-9]\d{0,7}$/.test(s))) return null;
  const N = Number(sN);
  const r = Number(sR);
  const p = Number(sP);
  // N debe ser potencia de 2 mayor que 1.
  if (N < 2 || N > MAX_N || (N & (N - 1)) !== 0 || r > MAX_R || p > MAX_P) return null;
  if (!BASE64.test(sSalt) || !BASE64.test(sHash)) return null;
  const salt = Buffer.from(sSalt, 'base64');
  const hash = Buffer.from(sHash, 'base64');
  if (salt.length < 16 || hash.length < 16 || hash.length > 64) return null;
  return { N, r, p, salt, hash };
}

/**
 * Calcula el hash scrypt de un secreto con salt aleatorio de 16 bytes.
 * Variante síncrona: bloquea el hilo ~decenas de ms; en rutas HTTP preferir `hashSecretoAsync`.
 * @param {string} secreto
 * @returns {string} `scrypt$N$r$p$salt_b64$hash_b64`
 */
export function hashSecreto(secreto) {
  if (!secretoValido(secreto)) throw new TypeError('Secreto inválido');
  const { N, r, p, longitudSalt, longitudHash } = PARAMETROS_SCRYPT;
  const salt = randomBytes(longitudSalt);
  const hash = scryptSync(secreto, salt, longitudHash, { N, r, p, maxmem: memoriaMaxima(N, r) });
  return serializar(N, r, p, salt, hash);
}

/**
 * Verifica un secreto contra su hash almacenado en tiempo constante.
 * Nunca lanza: ante formato inválido o entrada incorrecta devuelve false.
 * @param {string} secreto
 * @param {string} almacenado
 * @returns {boolean}
 */
export function verificarSecreto(secreto, almacenado) {
  const datos = interpretar(almacenado);
  if (!datos || !secretoValido(secreto)) return false;
  const { N, r, p, salt, hash } = datos;
  try {
    const calculado = scryptSync(secreto, salt, hash.length, { N, r, p, maxmem: memoriaMaxima(N, r) });
    return timingSafeEqual(calculado, hash);
  } catch {
    return false;
  }
}

/** Variante asíncrona de `hashSecreto` (no bloquea el bucle de eventos). @param {string} secreto @returns {Promise<string>} */
export async function hashSecretoAsync(secreto) {
  if (!secretoValido(secreto)) throw new TypeError('Secreto inválido');
  const { N, r, p, longitudSalt, longitudHash } = PARAMETROS_SCRYPT;
  const salt = randomBytes(longitudSalt);
  const hash = await scryptAsync(secreto, salt, longitudHash, { N, r, p, maxmem: memoriaMaxima(N, r) });
  return serializar(N, r, p, salt, /** @type {Buffer} */ (hash));
}

/** Variante asíncrona de `verificarSecreto`. @param {string} secreto @param {string} almacenado @returns {Promise<boolean>} */
export async function verificarSecretoAsync(secreto, almacenado) {
  const datos = interpretar(almacenado);
  if (!datos || !secretoValido(secreto)) return false;
  const { N, r, p, salt, hash } = datos;
  try {
    const calculado = /** @type {Buffer} */ (await scryptAsync(secreto, salt, hash.length, { N, r, p, maxmem: memoriaMaxima(N, r) }));
    return timingSafeEqual(calculado, hash);
  } catch {
    return false;
  }
}

/** client_secret nuevo: 32 bytes del CSPRNG en base64url (43 caracteres). Se muestra una sola vez. */
export function generarSecretoCliente() {
  return randomBytes(32).toString('base64url');
}

/**
 * Identificador público de aplicación cliente: `<prefijo>_<32 hex>` (128 bits aleatorios).
 * @param {string} [prefijo='app'] minúsculas y dígitos, 1 a 16 caracteres
 */
export function generarClientId(prefijo = 'app') {
  if (typeof prefijo !== 'string' || !/^[a-z0-9]{1,16}$/.test(prefijo)) throw new TypeError('Prefijo inválido');
  return `${prefijo}_${randomBytes(16).toString('hex')}`;
}
