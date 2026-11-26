// Generador de códigos para el laboratorio: reutiliza el motor RFC 6238 propio del backend.

import { generateHotp, pasoDeTiempo } from '../../backend/src/core/totp/totp.js';
import { base32Decode } from '../../backend/src/core/totp/base32.js';

/** @typedef {{ semilla: Buffer, algoritmo: 'SHA1' | 'SHA256' | 'SHA512', digitos: 6 | 8, periodo: number, emisor: string | null, cuenta: string | null }} DatosTotp */

/**
 * Analiza una URI otpauth://totp/Emisor:cuenta?secret=...&algorithm=...&digits=...&period=...
 * @param {string} uri @returns {DatosTotp}
 */
export function analizarOtpauth(uri) {
  const u = new URL(uri);
  if (u.protocol !== 'otpauth:' || u.hostname.toLowerCase() !== 'totp') throw new Error('URI otpauth inválida');
  const secreto = u.searchParams.get('secret');
  if (!secreto) throw new Error('La URI otpauth no trae secret');
  const algoritmo = /** @type {any} */ ((u.searchParams.get('algorithm') ?? 'SHA1').toUpperCase().replace('-', ''));
  if (!['SHA1', 'SHA256', 'SHA512'].includes(algoritmo)) throw new Error(`Algoritmo no soportado: ${algoritmo}`);
  const digitos = /** @type {6 | 8} */ (Number(u.searchParams.get('digits') ?? 6));
  const periodo = Number(u.searchParams.get('period') ?? 30);
  const etiqueta = decodeURIComponent(u.pathname.replace(/^\/+/, ''));
  const [emisor, cuenta] = etiqueta.includes(':') ? etiqueta.split(':', 2) : [u.searchParams.get('issuer'), etiqueta];
  return { semilla: base32Decode(secreto), algoritmo, digitos, periodo, emisor: emisor ?? null, cuenta: cuenta ?? null };
}

/** Paso actual T para unos datos TOTP. */
export const pasoActual = (datos, ahora = Date.now()) => pasoDeTiempo(ahora, datos.periodo);

/** Código para un paso concreto. */
export const codigoEnPaso = (datos, paso) => generateHotp(datos.semilla, paso, datos.algoritmo, datos.digitos);

/** Código válido ahora. */
export const codigoActual = (datos, ahora = Date.now()) => codigoEnPaso(datos, pasoActual(datos, ahora));

/**
 * Código que con seguridad NO es válido en ±margen pasos alrededor de ahora.
 * @param {DatosTotp | null} datos si es null se devuelve un código aleatorio de 6 dígitos
 * @param {() => number} [azar]
 */
export function codigoIncorrecto(datos, { ahora = Date.now(), margen = 3, azar = Math.random } = {}) {
  const digitos = datos?.digitos ?? 6;
  const prohibidos = new Set();
  if (datos) {
    const t = pasoActual(datos, ahora);
    for (let p = t - margen; p <= t + margen; p++) if (p >= 0) prohibidos.add(codigoEnPaso(datos, p));
  }
  for (;;) {
    const c = String(Math.floor(azar() * 10 ** digitos)).padStart(digitos, '0');
    if (!prohibidos.has(c)) return c;
  }
}

/**
 * Lleva la cuenta del último paso usado de un usuario de prueba para no auto-provocar un replay.
 * El servidor centra su ventana en (paso actual + deriva), así que se respeta la deriva conocida
 * (usuario.deriva, que actualiza verificarUsuario con el drift_steps devuelto). Nunca se adelanta más
 * de un paso al reloj (como mucho T + 1) para no arrastrar la deriva hacia el futuro.
 * Si no hay paso libre en la ventana, espera al siguiente periodo.
 * @param {{ datos: DatosTotp, ultimoPaso: number, deriva?: number }} usuario @param {{ ventana?: number, esperar?: boolean }} [op]
 * @returns {Promise<{ codigo: string, paso: number } | null>}
 */
export async function codigoNuevo(usuario, { ventana = 1, esperar = true } = {}) {
  for (;;) {
    const t = pasoActual(usuario.datos);
    const deriva = usuario.deriva ?? 0;
    const paso = Math.max(usuario.ultimoPaso + 1, t + deriva - ventana);
    if (paso <= Math.min(t + deriva + ventana, t + 1)) {
      usuario.ultimoPaso = paso;
      return { codigo: codigoEnPaso(usuario.datos, paso), paso };
    }
    if (!esperar) return null;
    const msHastaSiguiente = (t + 1) * usuario.datos.periodo * 1000 - Date.now() + 50;
    await new Promise((r) => setTimeout(r, Math.max(50, msHastaSiguiente)));
  }
}
