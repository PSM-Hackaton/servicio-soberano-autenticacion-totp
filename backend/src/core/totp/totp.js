// Motor TOTP propio (RFC 6238 sobre HOTP RFC 4226). Solo usa node:crypto.
// Funciones puras: no tocan base de datos ni red.

import { createHmac, timingSafeEqual } from 'node:crypto';
import { base32Encode } from './base32.js';

/** @typedef {'SHA1' | 'SHA256' | 'SHA512'} Algoritmo */
/** @typedef {{ algoritmo: Algoritmo, digitos: 6 | 8, periodo: number }} Politica */

const HMAC = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };

/** Longitud de semilla recomendada por algoritmo (la de los vectores del RFC 6238). */
export const LONGITUD_SEMILLA = { SHA1: 20, SHA256: 32, SHA512: 64 };

/** @param {Politica} p */
function validarPolitica(p) {
  if (!(p.algoritmo in HMAC)) throw new Error('Algoritmo no soportado');
  if (p.digitos !== 6 && p.digitos !== 8) throw new Error('Dígitos deben ser 6 u 8');
  if (!Number.isInteger(p.periodo) || p.periodo < 15 || p.periodo > 60) throw new Error('Periodo fuera de rango');
}

/**
 * HOTP (RFC 4226): HMAC del contador de 8 bytes + truncado dinámico.
 * @param {Buffer} semilla @param {number | bigint} contador @param {Algoritmo} algoritmo @param {6 | 8} digitos
 */
export function generateHotp(semilla, contador, algoritmo, digitos) {
  const mensaje = Buffer.alloc(8);
  mensaje.writeBigUInt64BE(BigInt(contador));
  const hmac = createHmac(HMAC[algoritmo], semilla).update(mensaje).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binario = hmac.readUInt32BE(offset) & 0x7fffffff;
  return String(binario % 10 ** digitos).padStart(digitos, '0');
}

/** Paso de tiempo T = floor((ahora − T0) / periodo), con T0 = 0. */
export function pasoDeTiempo(epochMs, periodo) {
  return Math.floor(epochMs / 1000 / periodo);
}

/** @param {Buffer} semilla @param {number} epochMs @param {Politica} politica */
export function generateTotp(semilla, epochMs, politica) {
  validarPolitica(politica);
  return generateHotp(semilla, pasoDeTiempo(epochMs, politica.periodo), politica.algoritmo, politica.digitos);
}

/** Comparación en tiempo constante de dos códigos de igual longitud. */
function igualSeguro(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/**
 * Verifica un código con ventana, deriva y protección anti replay.
 * Recorre siempre toda la ventana (sin salir antes) para no filtrar información por tiempo.
 * @param {Buffer} semilla
 * @param {string} codigo
 * @param {number} epochMs
 * @param {Politica & { ventana: number, driftSteps?: number, lastStep?: number }} opciones
 * @returns {{ valid: boolean, matchedStep: number | null, driftSteps: number, reason?: 'formato' | 'codigo' | 'replay' }}
 */
export function verifyTotpWithDrift(semilla, codigo, epochMs, opciones) {
  validarPolitica(opciones);
  const { ventana, driftSteps = 0, lastStep = -1 } = opciones;
  if (typeof codigo !== 'string' || !new RegExp(`^\\d{${opciones.digitos}}$`).test(codigo)) {
    return { valid: false, matchedStep: null, driftSteps, reason: 'formato' };
  }
  const actual = pasoDeTiempo(epochMs, opciones.periodo);
  const centro = actual + driftSteps;
  let coincidencia = null;
  for (let paso = centro - ventana; paso <= centro + ventana; paso++) {
    if (paso < 0) continue;
    const candidato = generateHotp(semilla, paso, opciones.algoritmo, opciones.digitos);
    if (igualSeguro(candidato, codigo) && coincidencia === null) coincidencia = paso;
  }
  if (coincidencia === null) return { valid: false, matchedStep: null, driftSteps, reason: 'codigo' };
  if (coincidencia <= lastStep) return { valid: false, matchedStep: null, driftSteps, reason: 'replay' };
  return { valid: true, matchedStep: coincidencia, driftSteps: coincidencia - actual };
}

/**
 * Resincronización: busca dos códigos consecutivos en una ventana amplia (±rango pasos).
 * @param {Buffer} semilla @param {string} codigo1 @param {string} codigo2 @param {number} epochMs
 * @param {Politica & { rango?: number, lastStep?: number }} opciones
 */
export function resyncTwoConsecutiveCodes(semilla, codigo1, codigo2, epochMs, opciones) {
  validarPolitica(opciones);
  const { rango = 10, lastStep = -1 } = opciones;
  const formato = new RegExp(`^\\d{${opciones.digitos}}$`);
  if (!formato.test(String(codigo1)) || !formato.test(String(codigo2))) {
    return { valid: false, matchedStep: null, driftSteps: 0 };
  }
  const actual = pasoDeTiempo(epochMs, opciones.periodo);
  let coincidencia = null;
  for (let paso = actual - rango; paso <= actual + rango; paso++) {
    if (paso < 0) continue;
    const c1 = generateHotp(semilla, paso, opciones.algoritmo, opciones.digitos);
    const c2 = generateHotp(semilla, paso + 1, opciones.algoritmo, opciones.digitos);
    if (igualSeguro(c1, codigo1) && igualSeguro(c2, codigo2) && coincidencia === null) coincidencia = paso + 1;
  }
  if (coincidencia === null || coincidencia <= lastStep) return { valid: false, matchedStep: null, driftSteps: 0 };
  return { valid: true, matchedStep: coincidencia, driftSteps: coincidencia - actual };
}

/**
 * URI de aprovisionamiento para el código QR.
 * @param {{ semilla: Buffer, emisor: string, cuenta: string } & Politica} datos
 */
export function buildOtpauthUri({ semilla, emisor, cuenta, algoritmo, digitos, periodo }) {
  validarPolitica({ algoritmo, digitos, periodo });
  const etiqueta = `${encodeURIComponent(emisor)}:${encodeURIComponent(cuenta)}`;
  const params = new URLSearchParams({
    secret: base32Encode(semilla),
    issuer: emisor,
    algorithm: algoritmo,
    digits: String(digitos),
    period: String(periodo),
  });
  return `otpauth://totp/${etiqueta}?${params}`;
}
