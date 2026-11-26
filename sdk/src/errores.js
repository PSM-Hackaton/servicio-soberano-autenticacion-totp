// Errores tipados del SDK. Nunca incluyen secretos, códigos TOTP ni tokens.

/**
 * Códigos locales (generados por el SDK, no por el servicio):
 *  - TIEMPO_AGOTADO: el servicio no respondió dentro de timeoutMs.
 *  - ERROR_RED: conexión rechazada, cortada o fallo TLS.
 *  - RESPUESTA_INVALIDA: el servicio respondió algo que no cumple el contrato.
 *  - CONFIGURACION: parámetros del SDK inválidos.
 *  - ENTRADA_INVALIDA: argumentos inválidos antes de llamar al servicio.
 * El resto proviene del campo `error` del servicio (VERIFICATION_FAILED, TOO_MANY_REQUESTS,
 * SERVICE_UNAVAILABLE, UNAUTHORIZED, INVALID_REQUEST, REPLAY_DETECTED, ANOMALY_BLOCKED…).
 */
export const CODIGOS_LOCALES = Object.freeze({
  TIEMPO_AGOTADO: 'TIEMPO_AGOTADO',
  ERROR_RED: 'ERROR_RED',
  RESPUESTA_INVALIDA: 'RESPUESTA_INVALIDA',
  CONFIGURACION: 'CONFIGURACION',
  ENTRADA_INVALIDA: 'ENTRADA_INVALIDA',
});

export class ErrorTotp extends Error {
  /**
   * @param {string} mensaje
   * @param {{ status?: number | null, codigo: string, reintentarEn?: number | null, operacion?: string, causa?: unknown }} datos
   */
  constructor(mensaje, { status = null, codigo, reintentarEn = null, operacion, causa } = /** @type {any} */ ({})) {
    super(mensaje, causa ? { cause: causa } : undefined);
    this.name = 'ErrorTotp';
    /** Código HTTP del servicio, o null si no hubo respuesta (red / tiempo agotado). */
    this.status = status;
    /** Código simbólico estable para programar contra él. */
    this.codigo = codigo;
    /** Segundos que conviene esperar antes de reintentar (429 / 503), o null. */
    this.reintentarEn = reintentarEn;
    /** Operación del SDK que falló (enrolar, verificar…). */
    this.operacion = operacion ?? null;
  }

  /** El servicio no está disponible (red, tiempo agotado o 503): "intente más tarde". */
  get servicioNoDisponible() {
    return this.status === null || this.status === 503 || this.codigo === CODIGOS_LOCALES.RESPUESTA_INVALIDA;
  }

  /** Bloqueo por límite de intentos (429). */
  get bloqueado() {
    return this.status === 429;
  }

  /** El código o credencial fue rechazado (401). */
  get rechazado() {
    return this.status === 401;
  }

  toJSON() {
    return {
      name: this.name, message: this.message, status: this.status, codigo: this.codigo,
      reintentarEn: this.reintentarEn, operacion: this.operacion,
    };
  }
}
