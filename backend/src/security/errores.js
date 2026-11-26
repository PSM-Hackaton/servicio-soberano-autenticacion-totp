// Errores genéricos alineados con components.schemas.GenericError de contracts/openapi.yaml
// ({ error, message, retry_after_seconds }). Los mensajes nunca revelan si un usuario o app existe.

/** @typedef {'credenciales' | 'codigo' | 'limite' | 'no_disponible' | 'entrada'} TipoError */

const CATALOGO = Object.freeze({
  credenciales: { status: 401, error: 'UNAUTHORIZED', message: 'Credenciales inválidas.' },
  codigo: { status: 401, error: 'VERIFICATION_FAILED', message: 'No se pudo completar la verificación.' },
  limite: { status: 429, error: 'TOO_MANY_REQUESTS', message: 'Demasiados intentos. Intente más tarde.' },
  no_disponible: { status: 503, error: 'SERVICE_UNAVAILABLE', message: 'Servicio no disponible temporalmente.' },
  entrada: { status: 400, error: 'INVALID_REQUEST', message: 'Solicitud inválida.' },
});

/**
 * Construye una respuesta de error genérica. Un tipo desconocido se trata como 'no_disponible'.
 * @param {TipoError} tipo
 * @param {{ reintentarEnSegundos?: number }} [opciones] solo se usa con 'limite'
 * @returns {{ status: number, cuerpo: { error: string, message: string, retry_after_seconds?: number }, cabeceras: Record<string, string> }}
 */
export function errorGenerico(tipo, { reintentarEnSegundos } = {}) {
  const e = Object.hasOwn(CATALOGO, tipo) ? CATALOGO[tipo] : CATALOGO.no_disponible;
  /** @type {{ error: string, message: string, retry_after_seconds?: number }} */
  const cuerpo = { error: e.error, message: e.message };
  /** @type {Record<string, string>} */
  const cabeceras = {};
  if (tipo === 'limite' && Number.isFinite(reintentarEnSegundos) && reintentarEnSegundos > 0) {
    const s = Math.ceil(reintentarEnSegundos);
    cuerpo.retry_after_seconds = s;
    cabeceras['Retry-After'] = String(s);
  }
  return { status: e.status, cuerpo, cabeceras };
}
