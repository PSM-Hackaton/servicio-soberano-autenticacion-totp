// Cabeceras HTTP de seguridad para todas las respuestas del servicio.

/** Prefijo de la app autenticadora (PWA): única zona que puede usar la cámara para leer QR. */
export const PREFIJO_CON_CAMARA = '/app';

/**
 * Valor de Permissions-Policy. Por defecto todo deshabilitado; con `camara` se permite la cámara
 * solo al propio origen (`camera=(self)`); el resto de restricciones se mantiene igual.
 * @param {{ camara?: boolean }} [opciones]
 * @returns {string}
 */
export function politicaPermisos({ camara = false } = {}) {
  return `camera=${camara ? '(self)' : '()'}, microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()`;
}

/**
 * Permissions-Policy que corresponde a una ruta: `camera=(self)` solo bajo /app/ (lectura de QR
 * con getUserMedia en la PWA); la API y la consola siguen con `camera=()`.
 * @param {string} pathname
 * @returns {string}
 */
export function politicaPermisosPara(pathname) {
  const ruta = String(pathname);
  return politicaPermisos({ camara: ruta === PREFIJO_CON_CAMARA || ruta.startsWith(`${PREFIJO_CON_CAMARA}/`) });
}

/**
 * Devuelve un objeto nuevo con las cabeceras de seguridad (el llamador puede modificarlo sin efectos globales).
 * @returns {Record<string, string>}
 */
export function cabecerasSeguridad() {
  return {
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': politicaPermisos(),
  };
}
