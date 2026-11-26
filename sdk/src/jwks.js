// Caché de JWKS para validación offline: TTL (10 min por defecto), refresco al ver un kid
// desconocido (con freno para no convertir kids aleatorios en una avalancha de peticiones)
// y uso de la copia vencida si el servicio no responde: así un JWT ya emitido se puede
// validar aunque el servicio haya caído.

/**
 * @param {{ obtener: () => Promise<{ keys: any[] }>, ttlMs?: number, intervaloMinRefrescoMs?: number,
 *   reloj?: () => number, alEvento?: (e: { tipo: string, detalle?: string }) => void }} o
 */
export function crearCacheJwks({
  obtener, ttlMs = 10 * 60 * 1000, intervaloMinRefrescoMs = 30 * 1000, reloj = Date.now, alEvento = () => {},
}) {
  if (typeof obtener !== 'function') throw new TypeError('crearCacheJwks requiere obtener()');
  /** @type {Map<string, any>} */
  let claves = new Map();
  let cargadoEn = 0;
  let ultimoIntento = -Infinity;
  /** @type {Promise<boolean> | null} */
  let enCurso = null;

  /** Descarga el JWKS; true si se actualizó. Nunca lanza. */
  async function refrescar() {
    if (enCurso) return enCurso;
    ultimoIntento = reloj();
    enCurso = (async () => {
      try {
        const jwks = await obtener();
        if (!jwks || !Array.isArray(jwks.keys)) throw new Error('JWKS sin keys');
        const nuevas = new Map();
        for (const k of jwks.keys) if (k && typeof k.kid === 'string') nuevas.set(k.kid, k);
        claves = nuevas;
        cargadoEn = reloj();
        alEvento({ tipo: 'jwks_actualizado', detalle: `${nuevas.size} clave(s)` });
        return true;
      } catch (e) {
        alEvento({ tipo: 'jwks_no_disponible', detalle: claves.size ? 'se usa la copia en caché' : 'sin copia en caché' });
        return false;
      } finally {
        enCurso = null;
      }
    })();
    return enCurso;
  }

  const vigente = () => cargadoEn > 0 && reloj() - cargadoEn < ttlMs;

  /** Devuelve el JWK para `kid` o null. */
  async function obtenerClave(kid) {
    if (!vigente() && reloj() - ultimoIntento >= Math.min(intervaloMinRefrescoMs, ttlMs)) await refrescar();
    if (claves.has(kid)) return claves.get(kid);
    // kid desconocido: quizá hubo rotación. Refresco inmediato, con freno.
    if (reloj() - ultimoIntento >= intervaloMinRefrescoMs) {
      await refrescar();
      if (claves.has(kid)) return claves.get(kid);
    }
    return null;
  }

  return {
    obtenerClave,
    refrescar,
    /** Estado para diagnóstico (sin material sensible: las claves son públicas). */
    estado: () => ({ kids: [...claves.keys()], cargadoEn: cargadoEn || null, vigente: vigente() }),
    /** Precarga manual (p. ej. un JWKS distribuido por archivo para operar 100 % offline). */
    cargar(jwks) {
      claves = new Map((jwks?.keys ?? []).filter((k) => k && typeof k.kid === 'string').map((k) => [k.kid, k]));
      cargadoEn = reloj();
    },
  };
}
