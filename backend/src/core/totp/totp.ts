// Motor TOTP propio (RFC 6238 sobre HOTP RFC 4226). Solo usa node:crypto.
// Funciones puras: no tocan base de datos ni red.

import { createHmac, timingSafeEqual } from 'node:crypto';
import { base32Encode } from './base32.js';

export type Algoritmo = 'SHA1' | 'SHA256' | 'SHA512';
export type Digitos = 6 | 8;

export interface Politica {
  algoritmo: Algoritmo;
  digitos: Digitos;
  periodo: number;
}

export interface OpcionesVerificacion extends Politica {
  ventana: number;
  driftSteps?: number;
  lastStep?: number;
}

export interface OpcionesResync extends Politica {
  rango?: number;
  lastStep?: number;
}

export interface ResultadoVerificacion {
  valid: boolean;
  matchedStep: number | null;
  driftSteps: number;
  reason?: 'formato' | 'codigo' | 'replay';
}

const HMAC: Record<Algoritmo, string> = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };

/** Longitud de semilla recomendada por algoritmo (la de los vectores del RFC 6238). */
export const LONGITUD_SEMILLA: Record<Algoritmo, number> = { SHA1: 20, SHA256: 32, SHA512: 64 };

function validarPolitica(p: Politica): void {
  if (!(p.algoritmo in HMAC)) throw new Error('Algoritmo no soportado');
  if (p.digitos !== 6 && p.digitos !== 8) throw new Error('Dígitos deben ser 6 u 8');
  if (!Number.isInteger(p.periodo) || p.periodo < 15 || p.periodo > 60) throw new Error('Periodo fuera de rango');
}

/** HOTP (RFC 4226): HMAC del contador de 8 bytes + truncado dinámico. */
export function generateHotp(semilla: Buffer, contador: number | bigint, algoritmo: Algoritmo, digitos: Digitos): string {
  const mensaje = Buffer.alloc(8);
  mensaje.writeBigUInt64BE(BigInt(contador));
  const hmac = createHmac(HMAC[algoritmo], semilla).update(mensaje).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binario = hmac.readUInt32BE(offset) & 0x7fffffff;
  return String(binario % 10 ** digitos).padStart(digitos, '0');
}

/** Paso de tiempo T = floor((ahora − T0) / periodo), con T0 = 0. */
export function pasoDeTiempo(epochMs: number, periodo: number): number {
  return Math.floor(epochMs / 1000 / periodo);
}

export function generateTotp(semilla: Buffer, epochMs: number, politica: Politica): string {
  validarPolitica(politica);
  return generateHotp(semilla, pasoDeTiempo(epochMs, politica.periodo), politica.algoritmo, politica.digitos);
}

/** Comparación en tiempo constante de dos códigos de igual longitud. */
function igualSeguro(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

function formatoValido(codigo: unknown, digitos: Digitos): codigo is string {
  return typeof codigo === 'string' && new RegExp(`^\\d{${digitos}}$`).test(codigo);
}

/**
 * Verifica un código con ventana, deriva y protección anti replay.
 * Recorre siempre toda la ventana (sin salir antes) para no filtrar información por tiempo.
 */
export function verifyTotpWithDrift(
  semilla: Buffer,
  codigo: unknown,
  epochMs: number,
  opciones: OpcionesVerificacion,
): ResultadoVerificacion {
  validarPolitica(opciones);
  const { ventana, driftSteps = 0, lastStep = -1 } = opciones;
  if (!formatoValido(codigo, opciones.digitos)) {
    return { valid: false, matchedStep: null, driftSteps, reason: 'formato' };
  }
  const actual = pasoDeTiempo(epochMs, opciones.periodo);
  const centro = actual + driftSteps;
  let coincidencia: number | null = null;
  for (let paso = centro - ventana; paso <= centro + ventana; paso++) {
    if (paso < 0) continue;
    const candidato = generateHotp(semilla, paso, opciones.algoritmo, opciones.digitos);
    if (igualSeguro(candidato, codigo) && coincidencia === null) coincidencia = paso;
  }
  if (coincidencia === null) return { valid: false, matchedStep: null, driftSteps, reason: 'codigo' };
  if (coincidencia <= lastStep) return { valid: false, matchedStep: null, driftSteps, reason: 'replay' };
  return { valid: true, matchedStep: coincidencia, driftSteps: coincidencia - actual };
}

/** Resincronización: busca dos códigos consecutivos en una ventana amplia (±rango pasos). */
export function resyncTwoConsecutiveCodes(
  semilla: Buffer,
  codigo1: unknown,
  codigo2: unknown,
  epochMs: number,
  opciones: OpcionesResync,
): ResultadoVerificacion {
  validarPolitica(opciones);
  const { rango = 10, lastStep = -1 } = opciones;
  if (!formatoValido(codigo1, opciones.digitos) || !formatoValido(codigo2, opciones.digitos)) {
    return { valid: false, matchedStep: null, driftSteps: 0, reason: 'formato' };
  }
  const actual = pasoDeTiempo(epochMs, opciones.periodo);
  let coincidencia: number | null = null;
  for (let paso = actual - rango; paso <= actual + rango; paso++) {
    if (paso < 0) continue;
    const c1 = generateHotp(semilla, paso, opciones.algoritmo, opciones.digitos);
    const c2 = generateHotp(semilla, paso + 1, opciones.algoritmo, opciones.digitos);
    if (igualSeguro(c1, codigo1) && igualSeguro(c2, codigo2) && coincidencia === null) coincidencia = paso + 1;
  }
  if (coincidencia === null) return { valid: false, matchedStep: null, driftSteps: 0, reason: 'codigo' };
  if (coincidencia <= lastStep) return { valid: false, matchedStep: null, driftSteps: 0, reason: 'replay' };
  return { valid: true, matchedStep: coincidencia, driftSteps: coincidencia - actual };
}

/** URI de aprovisionamiento para el código QR. */
export function buildOtpauthUri(datos: { semilla: Buffer; emisor: string; cuenta: string } & Politica): string {
  const { semilla, emisor, cuenta, algoritmo, digitos, periodo } = datos;
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
