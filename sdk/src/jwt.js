// Verificación local (sin red) de JWT MFA EdDSA / Ed25519 emitidos por el servicio.
// Mismas reglas que backend/src/core/tokens/tokens.js: solo alg EdDSA, kid obligatorio,
// firma de 64 bytes, iss/aud exactos, exp/nbf con tolerancia, base64url canónico.

import { createPublicKey, verify } from 'node:crypto';

const ALG = 'EdDSA';
const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** @param {string} texto @returns {Buffer | null} */
function b64urlEstricto(texto) {
  if (typeof texto !== 'string' || !BASE64URL.test(texto) || texto.length % 4 === 1) return null;
  const bytes = Buffer.from(texto, 'base64url');
  return bytes.toString('base64url') === texto ? bytes : null;
}

/** @param {string} texto */
function jsonObjeto(texto) {
  const bytes = b64urlEstricto(texto);
  if (!bytes) return null;
  try {
    const v = JSON.parse(bytes.toString('utf8'));
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

/**
 * Decodifica cabecera y claims SIN verificar la firma. Solo para mostrar o depurar:
 * nunca tome decisiones de acceso con este resultado.
 * @param {unknown} token
 * @returns {{ header: Record<string, any>, claims: Record<string, any> } | null}
 */
export function decodificarSinVerificar(token) {
  if (typeof token !== 'string') return null;
  const partes = token.split('.');
  if (partes.length !== 3) return null;
  const header = jsonObjeto(partes[0]);
  const claims = jsonObjeto(partes[1]);
  return header && claims ? { header, claims } : null;
}

/** @param {any} jwk */
export function clavePublicaDesdeJwk(jwk) {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') return null;
  if (jwk.alg !== undefined && jwk.alg !== ALG) return null;
  if (jwk.use !== undefined && jwk.use !== 'sig') return null;
  if (b64urlEstricto(jwk.x)?.length !== 32) return null;
  try {
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
  } catch {
    return null;
  }
}

/** @param {string} motivo */
const rechazo = (motivo) => ({ valido: /** @type {const} */ (false), motivo });

/**
 * Verifica firma y claims con una función de búsqueda de clave por kid.
 * @param {unknown} token
 * @param {{ buscarClave: (kid: string) => Promise<any> | any, issuer: string, audience: string,
 *   ahora?: number, toleranciaSegundos?: number, amrRequerido?: string | null }} o
 * @returns {Promise<{ valido: true, header: Record<string, any>, claims: Record<string, any> } | { valido: false, motivo: string }>}
 */
export async function verificarJwtEdDsa(token, {
  buscarClave, issuer, audience, ahora = Date.now(), toleranciaSegundos = 30, amrRequerido = 'otp',
}) {
  if (!issuer || !audience) return rechazo('configuracion');
  if (typeof token !== 'string' || token.length === 0 || token.length > 8192) return rechazo('formato');
  const partes = token.split('.');
  if (partes.length !== 3 || partes.some((p) => p.length === 0)) return rechazo('formato');
  const [h64, p64, f64] = partes;
  const header = jsonObjeto(h64);
  const claims = jsonObjeto(p64);
  const firma = b64urlEstricto(f64);
  if (!header || !claims || !firma) return rechazo('formato');

  if (header.alg !== ALG) return rechazo('alg');
  if (header.crit !== undefined) return rechazo('formato');
  if (typeof header.kid !== 'string' || header.kid.length === 0 || header.kid.length > 256) return rechazo('kid');

  let jwk = null;
  try {
    jwk = await buscarClave(header.kid);
  } catch {
    jwk = null;
  }
  const clave = clavePublicaDesdeJwk(jwk);
  if (!clave) return rechazo('kid');

  if (firma.length !== 64) return rechazo('firma');
  let ok = false;
  try {
    ok = verify(null, Buffer.from(`${h64}.${p64}`), clave, firma);
  } catch {
    ok = false;
  }
  if (!ok) return rechazo('firma');

  if (claims.iss !== issuer) return rechazo('iss');
  const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!auds.includes(audience)) return rechazo('aud');

  const ahoraSeg = Math.floor(ahora / 1000);
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)) return rechazo('exp');
  if (ahoraSeg >= claims.exp + toleranciaSegundos) return rechazo('exp');
  if (claims.nbf !== undefined) {
    if (typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf)) return rechazo('nbf');
    if (ahoraSeg + toleranciaSegundos < claims.nbf) return rechazo('nbf');
  }
  if (amrRequerido && !(Array.isArray(claims.amr) && claims.amr.includes(amrRequerido))) return rechazo('amr');
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) return rechazo('sub');
  if (typeof claims.jti !== 'string' || claims.jti.length === 0) return rechazo('jti');

  return { valido: true, header, claims };
}
