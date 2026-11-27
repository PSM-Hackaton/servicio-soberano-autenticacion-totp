// verificarTokenLocal: validación offline de un JWT MFA con un JWKS (objeto) o una caché JWKS.

import { verificarJwtEdDsa } from './jwt.js';

/**
 * Verifica firma EdDSA, iss, aud, exp/nbf y amr sin llamar al servicio. Nunca lanza.
 * Ojo: no consume el jti. Para consumo único use cliente.validarToken() cuando haya red
 * y lleve su propio registro de jti cuando opere sin ella.
 * @param {unknown} token
 * @param {{ jwks: { keys: any[] } | { obtenerClave: (kid: string) => Promise<any> }, issuer: string, audience: string,
 *   ahora?: number, toleranciaSegundos?: number, amrRequerido?: string | null }} o
 * @returns {Promise<{ valido: true, header: Record<string, any>, claims: Record<string, any> } | { valido: false, motivo: string }>}
 */
export async function verificarTokenLocal(token, { jwks, issuer, audience, ahora, toleranciaSegundos, amrRequerido } = /** @type {any} */ ({})) {
  try {
    if (!jwks) return { valido: false, motivo: 'configuracion' };
    const buscarClave = typeof jwks.obtenerClave === 'function'
      ? (kid) => jwks.obtenerClave(kid)
      : (kid) => (Array.isArray(jwks.keys) ? jwks.keys.find((k) => k && k.kid === kid) : null);
    return await verificarJwtEdDsa(token, {
      buscarClave, issuer, audience, ahora: ahora ?? Date.now(), toleranciaSegundos: toleranciaSegundos ?? 30, amrRequerido: amrRequerido === undefined ? 'otp' : amrRequerido,
    });
  } catch {
    return { valido: false, motivo: 'error_interno' };
  }
}
