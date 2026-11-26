// Bloqueo progresivo por fallos, idéntico para cuentas existentes e inexistentes.
// Las existentes usan failed_attempts / locked_until de enrollments; las inexistentes (o el
// login admin por contraseña) usan un contador en memoria acotado, para que un atacante no
// pueda distinguir unas de otras por la aparición del 429 (sin enumeración).

import { bloqueadoHasta, estaBloqueado } from '../../security/index.js';
import { crearMapaAcotado } from './comun.js';

const TTL_FANTASMA_MS = 60 * 60 * 1000;

/**
 * @param {{ repos: any, reloj: () => number, maxEntradas?: number }} deps
 */
export function crearControlBloqueos({ repos, reloj, maxEntradas = 10_000 }) {
  /** @type {ReturnType<typeof crearMapaAcotado<{ fallos: number, lockedUntil: string | null }>>} */
  const fantasmas = crearMapaAcotado({ maxEntradas, ttlMs: TTL_FANTASMA_MS, reloj });

  /** Segundos restantes de un bloqueo vigente (0 si no hay). @param {string | null | undefined} hasta @param {number} ahora */
  function segundosRestantes(hasta, ahora) {
    if (!estaBloqueado(hasta, ahora)) return 0;
    return Math.max(1, Math.ceil((Date.parse(/** @type {string} */ (hasta)) - ahora) / 1000));
  }

  return {
    segundosRestantes,

    /** Bloqueo vigente de un enrolamiento (segundos, 0 = libre). @param {any} enrol @param {number} ahora */
    restanteEnrolamiento: (enrol, ahora) => segundosRestantes(enrol.locked_until, ahora),

    /**
     * Suma un fallo al enrolamiento y fija el bloqueo si corresponde. Síncrona: puede ir dentro
     * de repos.transaccion. @param {string} enrollmentId @param {number} maxIntentos @param {number} ahora
     * @returns {string | null} locked_until resultante
     */
    falloEnrolamiento(enrollmentId, maxIntentos, ahora) {
      const actual = repos.enrollments.buscarPorId(enrollmentId);
      const fallos = (actual?.failed_attempts ?? 0) + 1;
      const hasta = bloqueadoHasta(fallos, ahora, { maxIntentos });
      repos.enrollments.registrarFallo(enrollmentId, hasta);
      return hasta;
    },

    /** Bloqueo vigente de una clave en memoria (segundos). @param {string} clave @param {number} ahora */
    restanteFantasma(clave, ahora) {
      return segundosRestantes(fantasmas.obtener(clave)?.lockedUntil, ahora);
    },

    /** @param {string} clave @param {number} maxIntentos @param {number} ahora */
    falloFantasma(clave, maxIntentos, ahora) {
      const previo = fantasmas.obtener(clave) ?? { fallos: 0, lockedUntil: null };
      const fallos = previo.fallos + 1;
      const nuevo = bloqueadoHasta(fallos, ahora, { maxIntentos });
      fantasmas.poner(clave, { fallos, lockedUntil: nuevo ?? previo.lockedUntil });
      return nuevo;
    },

    /** Éxito: reinicia el contador en memoria. @param {string} clave */
    exitoFantasma: (clave) => { fantasmas.borrar(clave); },
  };
}
