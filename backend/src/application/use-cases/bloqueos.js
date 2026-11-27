// Bloqueo progresivo por fallos, idéntico para cuentas existentes e inexistentes.
// Las existentes usan failed_attempts / locked_until de enrollments. Los usuarios sin enrolamiento
// activo se calculan a partir de sus fallos en `attempts` (persistentes: tras un reinicio el
// comportamiento es el mismo), con la misma escala de escalones, para que un atacante no pueda
// distinguir unas de otras por la aparición del 429 (sin enumeración). El login admin por
// contraseña sigue usando un contador en memoria acotado (igual para usuarios admin existentes o no).

import { bloqueadoHasta, calcularBloqueo, estaBloqueado } from '../../security/index.js';
import { crearMapaAcotado } from './comun.js';

const TTL_FANTASMA_MS = 60 * 60 * 1000;
const VENTANA_INEXISTENTES_MIN_POR_DEFECTO = 1440;

/**
 * @param {{ repos: any, reloj: () => number, maxEntradas?: number, ventanaInexistentesMin?: number }} deps
 */
export function crearControlBloqueos({ repos, reloj, maxEntradas = 10_000, ventanaInexistentesMin = VENTANA_INEXISTENTES_MIN_POR_DEFECTO }) {
  const ventanaMs = ventanaInexistentesMin * 60_000;
  /** @type {ReturnType<typeof crearMapaAcotado<{ fallos: number, lockedUntil: string | null }>>} */
  const fantasmas = crearMapaAcotado({ maxEntradas, ttlMs: TTL_FANTASMA_MS, reloj });

  /** Segundos restantes de un bloqueo vigente (0 si no hay). @param {string | null | undefined} hasta @param {number} ahora */
  function segundosRestantes(hasta, ahora) {
    if (!estaBloqueado(hasta, ahora)) return 0;
    return Math.max(1, Math.ceil((Date.parse(/** @type {string} */ (hasta)) - ahora) / 1000));
  }

  /**
   * locked_until de un usuario sin enrolamiento, reconstruido desde attempts. Equivale al de una
   * cuenta real: cada fallo n ≥ maxIntentos fija un bloqueo de calcularBloqueo(n) desde ese fallo,
   * así que basta con el número de fallos de la ventana y el instante del último.
   */
  function bloqueoInexistente(appId, userRefHash, maxIntentos, ahora) {
    const { n, ultimo } = repos.attempts.fallosSinEnrolamiento({ appId, userRefHash, desde: new Date(ahora - ventanaMs).toISOString() });
    const segundos = calcularBloqueo(n, { maxIntentos });
    if (segundos === 0 || !ultimo) return { fallos: n, hasta: null };
    return { fallos: n, hasta: new Date(Date.parse(ultimo) + segundos * 1000).toISOString() };
  }

  return {
    segundosRestantes,

    /**
     * Bloqueo vigente de un usuario sin enrolamiento activo en la app (segundos, 0 = libre).
     * @param {string} appId @param {string} userRefHash @param {number} maxIntentos @param {number} ahora
     */
    restanteInexistente: (appId, userRefHash, maxIntentos, ahora) =>
      segundosRestantes(bloqueoInexistente(appId, userRefHash, maxIntentos, ahora).hasta, ahora),

    /**
     * Tras registrar en attempts el fallo de un usuario sin enrolamiento, devuelve el locked_until
     * resultante (o null), igual que falloEnrolamiento para las cuentas reales.
     * @param {string} appId @param {string} userRefHash @param {number} maxIntentos @param {number} ahora
     * @returns {string | null}
     */
    falloInexistente: (appId, userRefHash, maxIntentos, ahora) => bloqueoInexistente(appId, userRefHash, maxIntentos, ahora).hasta,

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
