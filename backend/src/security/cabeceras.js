// Cabeceras HTTP de seguridad para todas las respuestas del servicio.

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
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
  };
}
