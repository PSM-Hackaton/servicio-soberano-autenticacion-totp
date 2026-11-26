// Verificador offline de JWT MFA (EdDSA / Ed25519) con caché JWKS.
// Cero dependencias npm: usa exclusivamente node:crypto.

import { createPublicKey, verify } from 'node:crypto';

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const ED25519_SIG_BYTES = 64;

/** @param {string} str @returns {Buffer | null} */
function decodeBase64Url(str) {
  if (typeof str !== 'string' || !BASE64URL_RE.test(str) || str.length % 4 === 1) return null;
  const buf = Buffer.from(str, 'base64url');
  return buf.toString('base64url') === str ? buf : null;
}

/** @param {string} str */
function decodeJsonPart(str) {
  const buf = decodeBase64Url(str);
  if (!buf) return null;
  try {
    const obj = JSON.parse(buf.toString('utf8'));
    return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : null;
  } catch {
    return null;
  }
}

/**
 * Convierte un JWK Ed25519 (OKP) en KeyObject de node:crypto.
 * @param {any} jwk
 */
function jwkToPublicKey(jwk) {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') return null;
  if (jwk.alg !== undefined && jwk.alg !== 'EdDSA') return null;
  if (jwk.use !== undefined && jwk.use !== 'sig') return null;
  try {
    return createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x },
      format: 'jwk',
    });
  } catch {
    return null;
  }
}

/**
 * Verifica criptográficamente un JWT Ed25519 contra un conjunto JWKS.
 * Nunca lanza excepciones por tokens malformados: retorna `{ valid: false, reason }`.
 *
 * @param {string} token
 * @param {{
 *   jwks: { keys: Array<Record<string, any>> },
 *   issuer: string,
 *   audience: string,
 *   nowMs?: number,
 *   clockToleranceSeconds?: number
 * }} options
 */
export function verifyJwtWithJwks(token, {
  jwks,
  issuer,
  audience,
  nowMs = Date.now(),
  clockToleranceSeconds = 30,
}) {
  if (typeof token !== 'string' || !token.length || token.length > 8192) {
    return { valid: false, reason: 'formato' };
  }
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => !p.length)) {
    return { valid: false, reason: 'formato' };
  }
  const [h64, p64, s64] = parts;
  const header = decodeJsonPart(h64);
  const claims = decodeJsonPart(p64);
  const sig = decodeBase64Url(s64);
  if (!header || !claims || !sig) return { valid: false, reason: 'formato' };

  if (header.alg !== 'EdDSA') return { valid: false, reason: 'alg' };
  if (header.crit !== undefined) return { valid: false, reason: 'formato' };
  if (typeof header.kid !== 'string' || !header.kid) return { valid: false, reason: 'kid' };

  const jwk = Array.isArray(jwks?.keys) ? jwks.keys.find((k) => k?.kid === header.kid) : null;
  const pubKey = jwkToPublicKey(jwk);
  if (!pubKey) return { valid: false, reason: 'kid' };

  if (sig.length !== ED25519_SIG_BYTES) return { valid: false, reason: 'firma' };
  let ok = false;
  try {
    ok = verify(null, Buffer.from(`${h64}.${p64}`), pubKey, sig);
  } catch {
    ok = false;
  }
  if (!ok) return { valid: false, reason: 'firma' };

  if (issuer && claims.iss !== issuer) return { valid: false, reason: 'iss' };
  if (audience) {
    const audList = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audList.includes(audience)) return { valid: false, reason: 'aud' };
  }

  const nowSec = Math.floor(nowMs / 1000);
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp)) return { valid: false, reason: 'exp' };
  if (nowSec >= claims.exp + clockToleranceSeconds) return { valid: false, reason: 'exp' };
  if (claims.nbf !== undefined) {
    if (typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf)) return { valid: false, reason: 'nbf' };
    if (nowSec + clockToleranceSeconds < claims.nbf) return { valid: false, reason: 'nbf' };
  }

  return {
    valid: true,
    header,
    claims,
    kid: header.kid,
    sub: claims.sub,
    aud: claims.aud,
    jti: claims.jti,
    amr: claims.amr,
    exp: claims.exp,
  };
}
