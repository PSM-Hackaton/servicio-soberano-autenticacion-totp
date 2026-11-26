// SDK oficial del Servicio Soberano de Autenticación TOTP (Node.js 22, 0 dependencias npm).
// Implementa timeout de 3 s, 1 reintento idempotente con Idempotency-Key, caché JWKS offline y modo fail-closed.

import { randomUUID } from 'node:crypto';
import { verifyJwtWithJwks } from './jwks-verifier.js';

export { verifyJwtWithJwks };

export class TotpServiceError extends Error {
  /**
   * @param {string} message
   * @param {{ status?: number, code?: string, retryAfterSeconds?: number | null, cause?: unknown }} [meta]
   */
  constructor(message, { status = 503, code = 'SERVICE_UNAVAILABLE', retryAfterSeconds = null, cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = 'TotpServiceError';
    this.status = status;
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * Crea un cliente SDK para integrar aplicaciones institucionales (Portal de Trámites, Reto 1, etc.).
 *
 * @param {{
 *   baseUrl: string,
 *   clientId: string,
 *   clientSecret: string,
 *   issuer?: string,
 *   audience?: string,
 *   timeoutMs?: number,
 *   maxRetries?: number,
 *   jwksCacheTtlMs?: number,
 *   fetchImpl?: typeof fetch,
 *   now?: () => number,
 * }} config
 */
export function createTotpClient({
  baseUrl,
  clientId,
  clientSecret,
  issuer = 'https://totp.soberano.local',
  audience,
  timeoutMs = 3000,
  maxRetries = 1,
  jwksCacheTtlMs = 5 * 60 * 1000,
  fetchImpl = globalThis.fetch,
  now = () => Date.now(),
}) {
  if (!baseUrl) throw new Error('baseUrl es obligatorio');
  if (!clientId || !clientSecret) throw new Error('clientId y clientSecret son obligatorios');

  const normalizedBase = baseUrl.replace(/\/+$/, '');
  const expectedAudience = audience || clientId;

  /** @type {{ jwks: { keys: any[] }, fetchedAt: number } | null} */
  let jwksCache = null;

  /**
   * Ejecuta una petición HTTP con timeout estricto y política opcional de reintento idempotente.
   * @param {string} path
   * @param {{
   *   method?: string,
   *   body?: unknown,
   *   auth?: boolean,
   *   idempotencyKey?: string,
   *   retryable?: boolean,
   * }} [options]
   */
  async function request(path, {
    method = 'GET',
    body,
    auth = true,
    idempotencyKey,
    retryable = false,
  } = {}) {
    const attemptsAllowed = retryable ? 1 + Math.max(0, maxRetries) : 1;
    let lastError = null;

    for (let attempt = 1; attempt <= attemptsAllowed; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(new Error('TIMEOUT')), timeoutMs);

      try {
        /** @type {Record<string, string>} */
        const headers = { Accept: 'application/json' };
        if (auth) {
          headers['X-Client-Id'] = clientId;
          headers['X-Client-Secret'] = clientSecret;
        }
        if (body !== undefined) headers['Content-Type'] = 'application/json';
        if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;

        const res = await fetchImpl(`${normalizedBase}${path}`, {
          method,
          headers,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });

        const payload = await res.json().catch(() => null);

        if (res.ok) {
          return payload;
        }

        const retryAfterHeader = res.headers?.get?.('retry-after');
        const retryAfter = payload?.retry_after_seconds
          ?? (retryAfterHeader ? Number(retryAfterHeader) : null);

        const err = new TotpServiceError(
          payload?.message || `Error HTTP ${res.status}`,
          {
            status: res.status,
            code: payload?.error || (res.status === 503 ? 'SERVICE_UNAVAILABLE' : 'REQUEST_FAILED'),
            retryAfterSeconds: Number.isFinite(retryAfter) ? retryAfter : null,
          },
        );

        // Solo se reintenta en 503 / 502 / 504 si la operación es idempotente
        const isTransientStatus = res.status === 503 || res.status === 502 || res.status === 504;
        if (retryable && isTransientStatus && attempt < attemptsAllowed) {
          lastError = err;
          continue;
        }
        throw err;
      } catch (err) {
        if (err instanceof TotpServiceError) throw err;
        const isTimeout = err?.name === 'AbortError' || err?.message === 'TIMEOUT';
        lastError = new TotpServiceError(
          isTimeout
            ? `Tiempo de espera agotado (${timeoutMs} ms): servicio MFA no disponible.`
            : `No se pudo contactar al servicio MFA: ${err?.message || 'error de red'}`,
          { status: 503, code: isTimeout ? 'TIMEOUT' : 'NETWORK_ERROR', cause: err },
        );
        if (attempt >= attemptsAllowed) throw lastError;
      } finally {
        clearTimeout(timer);
      }
    }

    throw lastError || new TotpServiceError('Servicio no disponible temporalmente.');
  }

  /**
   * Obtiene JWKS desde caché local o desde `/.well-known/jwks.json`.
   * Si el servidor cae pero ya existen claves cacheadas, conserva el caché para validación offline.
   * @param {{ forceRefresh?: boolean }} [opts]
   */
  async function getJwks({ forceRefresh = false } = {}) {
    const expired = !jwksCache || (now() - jwksCache.fetchedAt) > jwksCacheTtlMs;
    if (!forceRefresh && !expired) {
      return jwksCache.jwks;
    }
    try {
      const fresh = await request('/.well-known/jwks.json', { auth: false, retryable: true });
      if (fresh && Array.isArray(fresh.keys)) {
        jwksCache = { jwks: fresh, fetchedAt: now() };
        return fresh;
      }
      throw new TotpServiceError('Respuesta JWKS inválida', { status: 503, code: 'INVALID_JWKS' });
    } catch (err) {
      if (jwksCache?.jwks) {
        return jwksCache.jwks;
      }
      throw err;
    }
  }

  return {
    /** Consulta estado de disponibilidad (`/health/ready`). */
    healthReady() {
      return request('/health/ready', { auth: false, retryable: false });
    },

    /** 1. Crea enrolamiento pendiente (devuelve enrollment_id, otpauth_uri y qr_svg). */
    enroll({ userRef, accountLabel, algorithm, digits, period }) {
      /** @type {Record<string, unknown>} */
      const body = { user_ref: userRef };
      if (accountLabel !== undefined) body.account_label = accountLabel;
      if (algorithm !== undefined) body.algorithm = algorithm;
      if (digits !== undefined) body.digits = digits;
      if (period !== undefined) body.period = period;
      return request('/api/v1/enrollments', { method: 'POST', body });
    },

    /** 2. Activa el enrolamiento validando el primer código TOTP y entrega 10 códigos de recuperación. */
    activate(enrollmentId, code) {
      return request(`/api/v1/enrollments/${encodeURIComponent(enrollmentId)}/activate`, {
        method: 'POST',
        body: { code: String(code) },
      });
    },

    /**
     * 3. Verifica un código TOTP con timeout 3 s y 1 reintento idempotente automático (`Idempotency-Key`).
     * Fail-closed: ante timeout o 503 lanza TotpServiceError y nunca concede acceso.
     */
    verify({ userRef, code, idempotencyKey = randomUUID() }) {
      return request('/api/v1/verify', {
        method: 'POST',
        body: { user_ref: userRef, code: String(code) },
        idempotencyKey,
        retryable: true,
      });
    },

    /** 4a. Valida JWT en línea y consume su `jti` de un solo uso. */
    validateToken(token, { consumeJti = true } = {}) {
      return request('/api/v1/tokens/validate', {
        method: 'POST',
        body: { token, consume_jti: consumeJti },
      });
    },

    /**
     * 4b. Valida JWT localmente con JWKS en caché (funciona sin red si JWKS ya fue cacheado).
     * Si el `kid` del token no está en caché, intenta una recarga puntual para soportar rotación de llaves.
     */
    async verifyJwtOffline(token, { nowMs = now(), clockToleranceSeconds = 30 } = {}) {
      let jwks = await getJwks({ forceRefresh: false });
      let res = verifyJwtWithJwks(token, {
        jwks,
        issuer,
        audience: expectedAudience,
        nowMs,
        clockToleranceSeconds,
      });
      if (!res.valid && res.reason === 'kid') {
        try {
          jwks = await getJwks({ forceRefresh: true });
          res = verifyJwtWithJwks(token, {
            jwks,
            issuer,
            audience: expectedAudience,
            nowMs,
            clockToleranceSeconds,
          });
        } catch {
          // Mantiene el rechazo 'kid' en modo fail-closed
        }
      }
      return res;
    },

    /** Precarga o fuerza la actualización del caché JWKS local. */
    getJwks,

    /** Resincroniza deriva de reloj con 2 códigos consecutivos (±10 pasos). */
    resync(enrollmentId, { code1, code2 }) {
      return request(`/api/v1/enrollments/${encodeURIComponent(enrollmentId)}/resync`, {
        method: 'POST',
        body: { code_1: String(code1), code_2: String(code2) },
      });
    },

    /** Consume un código de recuperación de un solo uso. */
    recover({ userRef, recoveryCode }) {
      return request('/api/v1/recovery', {
        method: 'POST',
        body: { user_ref: userRef, recovery_code: String(recoveryCode) },
      });
    },

    /** Revoca definitivamente un enrolamiento TOTP. */
    revoke(enrollmentId) {
      return request(`/api/v1/enrollments/${encodeURIComponent(enrollmentId)}`, {
        method: 'DELETE',
      });
    },
  };
}
