// JWT MFA compacto (RFC 7519) firmado con EdDSA / Ed25519 (RFC 8037). Solo usa node:crypto.
// Funciones puras: no tocan base de datos ni red. El consumo único del jti lo hace la capa de persistencia.

import {
  createHash, createPublicKey, generateKeyPairSync, randomUUID, sign, verify, KeyObject,
} from 'node:crypto';

/** @typedef {{ kty: 'OKP', crv: 'Ed25519', x: string, kid?: string, use?: string, alg?: string }} JwkPublico */
/** @typedef {{ keys: JwkPublico[] }} Jwks */
/** @typedef {'formato' | 'alg' | 'kid' | 'firma' | 'iss' | 'aud' | 'exp' | 'nbf'} MotivoRechazo */

const ALG = 'EdDSA';
const LONGITUD_FIRMA = 64;
const BASE64URL = /^[A-Za-z0-9_-]*$/;

// ---------- base64url (RFC 4648 §5, sin relleno) ----------

/** @param {Buffer | Uint8Array | string} datos */
export function base64urlEncode(datos) {
  return Buffer.from(datos).toString('base64url');
}

/**
 * Decodifica base64url estricto: alfabeto válido, sin relleno y forma canónica
 * (rechaza longitudes imposibles y bits sobrantes distintos de cero).
 * @param {string} texto @returns {Buffer | null}
 */
export function base64urlDecode(texto) {
  if (typeof texto !== 'string' || !BASE64URL.test(texto) || texto.length % 4 === 1) return null;
  const bytes = Buffer.from(texto, 'base64url');
  return bytes.toString('base64url') === texto ? bytes : null;
}

/** @param {string} texto @returns {any} */
function decodificarJson(texto) {
  const bytes = base64urlDecode(texto);
  if (!bytes) return null;
  try {
    const valor = JSON.parse(bytes.toString('utf8'));
    return valor !== null && typeof valor === 'object' && !Array.isArray(valor) ? valor : null;
  } catch {
    return null;
  }
}

// ---------- claves ----------

/**
 * Identificador de clave: base64url de los primeros 16 bytes del SHA-256 del JWK público
 * canónico {crv, kty, x} (miembros requeridos en orden lexicográfico, al estilo RFC 7638).
 * @param {{ crv: string, kty: string, x: string }} jwk
 */
export function calcularKid(jwk) {
  const canonico = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return base64urlEncode(createHash('sha256').update(canonico).digest().subarray(0, 16));
}

/**
 * Genera un par Ed25519 para firmar JWT MFA.
 * @returns {{ kid: string, publicJwk: JwkPublico, privateKey: KeyObject, privatePem: string }}
 */
export function generarParFirma() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const { crv, kty, x } = /** @type {any} */ (publicKey.export({ format: 'jwk' }));
  const kid = calcularKid({ crv, kty, x });
  return {
    kid,
    publicJwk: { kty, crv, x, kid, use: 'sig', alg: ALG },
    privateKey,
    privatePem: /** @type {string} */ (privateKey.export({ format: 'pem', type: 'pkcs8' })),
  };
}

/**
 * Normaliza una clave pública a JWK OKP/Ed25519 con kid, use y alg.
 * Acepta { kid, publicJwk }, { kid, x }, { kid, publicKey: KeyObject } o un JWK completo.
 * @param {any} entrada @returns {JwkPublico}
 */
function aJwkPublico(entrada) {
  let x = entrada?.x ?? entrada?.publicJwk?.x;
  if (!x && entrada?.publicKey instanceof KeyObject) x = /** @type {any} */ (entrada.publicKey.export({ format: 'jwk' })).x;
  if (typeof x !== 'string' || base64urlDecode(x)?.length !== 32) throw new Error('Clave pública Ed25519 inválida');
  const crv = 'Ed25519';
  const kty = 'OKP';
  const kid = entrada.kid ?? entrada.publicJwk?.kid ?? calcularKid({ crv, kty, x });
  return { kty, crv, x, kid, use: 'sig', alg: ALG };
}

/**
 * JWKS público (RFC 7517) para /.well-known/jwks.json: clave activa y claves en ventana de gracia.
 * @param {any[]} clavesPublicas @returns {Jwks}
 */
export function getPublicJwks(clavesPublicas) {
  return { keys: clavesPublicas.map(aJwkPublico) };
}

/**
 * Convierte un JWK (o KeyObject) en clave pública Ed25519 utilizable; null si no sirve para EdDSA.
 * @param {any} clave @returns {KeyObject | null}
 */
function aClavePublica(clave) {
  if (clave instanceof KeyObject) {
    return clave.type === 'public' && clave.asymmetricKeyType === 'ed25519' ? clave : null;
  }
  if (!clave || clave.kty !== 'OKP' || clave.crv !== 'Ed25519' || typeof clave.x !== 'string') return null;
  if (clave.alg !== undefined && clave.alg !== ALG) return null;
  if (clave.use !== undefined && clave.use !== 'sig') return null;
  try {
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: clave.x }, format: 'jwk' });
  } catch {
    return null;
  }
}

// ---------- firma ----------

/**
 * Emite un JWT MFA firmado con Ed25519.
 * @param {{
 *   privateKey: KeyObject | string, kid: string, issuer: string, audience: string, subject: string,
 *   ttlSegundos?: number, amr?: string[], ahora?: number, extra?: Record<string, unknown>
 * }} opciones
 * @returns {string}
 */
export function signMfaJwt({
  privateKey, kid, issuer, audience, subject, ttlSegundos = 300, amr = ['otp'], ahora = Date.now(), extra = {},
}) {
  if (!kid || !issuer || !audience || !subject) throw new Error('Faltan kid, issuer, audience o subject');
  if (!Number.isInteger(ttlSegundos) || ttlSegundos <= 0) throw new Error('ttlSegundos debe ser un entero positivo');
  const iat = Math.floor(ahora / 1000);
  const header = { alg: ALG, typ: 'JWT', kid };
  const claims = {
    ...extra, iss: issuer, sub: subject, aud: audience, amr, iat, nbf: iat, exp: iat + ttlSegundos, jti: randomUUID(),
  };
  const entrada = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(claims))}`;
  const firma = sign(null, Buffer.from(entrada), privateKey);
  return `${entrada}.${base64urlEncode(firma)}`;
}

// ---------- verificación ----------

/** @param {MotivoRechazo} reason */
const rechazo = (reason) => ({ valid: /** @type {const} */ (false), reason });

/**
 * Verifica un JWT MFA. Nunca lanza por entradas malformadas: devuelve { valid: false, reason }.
 * Solo acepta alg EdDSA; 'none', HS256 y cualquier otro se rechazan con reason 'alg'.
 * @param {unknown} token
 * @param {{
 *   jwks?: Jwks, buscarClave?: (kid: string) => any, issuer: string, audience: string,
 *   ahora?: number, toleranciaSegundos?: number
 * }} opciones
 * @returns {{ valid: true, header: Record<string, unknown>, claims: Record<string, any> } | { valid: false, reason: MotivoRechazo }}
 */
export function verifyMfaJwt(token, { jwks, buscarClave, issuer, audience, ahora = Date.now(), toleranciaSegundos = 30 }) {
  if (!jwks && typeof buscarClave !== 'function') throw new Error('Se requiere jwks o buscarClave');
  if (!issuer || !audience) throw new Error('Se requieren issuer y audience');

  if (typeof token !== 'string' || token.length === 0 || token.length > 8192) return rechazo('formato');
  const partes = token.split('.');
  if (partes.length !== 3 || partes.some((p) => p.length === 0)) return rechazo('formato');
  const [h64, p64, f64] = partes;

  const header = decodificarJson(h64);
  const claims = decodificarJson(p64);
  const firma = base64urlDecode(f64);
  if (!header || !claims || !firma) return rechazo('formato');

  if (header.alg !== ALG) return rechazo('alg');
  if (header.crit !== undefined) return rechazo('formato');
  if (typeof header.kid !== 'string' || header.kid.length === 0) return rechazo('kid');

  let candidata = null;
  try {
    candidata = jwks
      ? jwks.keys?.find((k) => k && k.kid === header.kid)
      : buscarClave(header.kid);
  } catch {
    candidata = null;
  }
  const clave = aClavePublica(candidata);
  if (!clave) return rechazo('kid');

  if (firma.length !== LONGITUD_FIRMA) return rechazo('firma');
  let firmaValida = false;
  try {
    firmaValida = verify(null, Buffer.from(`${h64}.${p64}`), clave, firma);
  } catch {
    firmaValida = false;
  }
  if (!firmaValida) return rechazo('firma');

  if (claims.iss !== issuer) return rechazo('iss');
  const audiencias = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiencias.includes(audience)) return rechazo('aud');

  const ahoraSeg = Math.floor(ahora / 1000);
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)) return rechazo('exp');
  if (ahoraSeg >= claims.exp + toleranciaSegundos) return rechazo('exp');
  if (claims.nbf !== undefined) {
    if (typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf)) return rechazo('nbf');
    if (ahoraSeg + toleranciaSegundos < claims.nbf) return rechazo('nbf');
  }

  return { valid: true, header, claims };
}
