// Repositorio SQLite de la tabla `dispositivos` (migración 003, issue #47).
// Sentencias preparadas una sola vez; nunca se concatena entrada del usuario en SQL.
// Un enrolamiento tiene como mucho un dispositivo (UNIQUE enrollment_id).

/** @typedef {import('node:sqlite').DatabaseSync} DatabaseSync */
/** @typedef {{ id: string, enrollment_id: string, nombre: string, plataforma: 'android' | 'pwa' | 'otro',
 *   created_at: string, ultimo_uso: string | null, desvinculado_en: string | null }} FilaDispositivo */

/** @param {any} f @returns {FilaDispositivo | null} */
const copia = (f) => (f ? { ...f } : null);

/**
 * @param {DatabaseSync} db
 */
export function crearRepositorioDispositivos(db) {
  const s = {
    insertar: db.prepare(`INSERT INTO dispositivos (id, enrollment_id, nombre, plataforma, created_at)
      VALUES (?, ?, ?, ?, ?)`),
    porEnrolamiento: db.prepare('SELECT * FROM dispositivos WHERE enrollment_id = ?'),
    porId: db.prepare('SELECT * FROM dispositivos WHERE id = ?'),
    // Solo avanza: dos verificaciones concurrentes nunca retroceden la fecha.
    uso: db.prepare(`UPDATE dispositivos SET ultimo_uso = ?
      WHERE enrollment_id = ? AND desvinculado_en IS NULL AND (ultimo_uso IS NULL OR ultimo_uso < ?)`),
    desvincular: db.prepare(`UPDATE dispositivos SET desvinculado_en = ?
      WHERE enrollment_id = ? AND desvinculado_en IS NULL`),
  };

  return {
    /**
     * Vincula un dispositivo a un enrolamiento (normalmente aún pendiente).
     * @param {{ id: string, enrollment_id: string, nombre: string, plataforma: string, created_at: string }} d
     * @returns {FilaDispositivo}
     */
    crear(d) {
      s.insertar.run(d.id, d.enrollment_id, d.nombre, d.plataforma, d.created_at);
      return /** @type {FilaDispositivo} */ (copia(s.porEnrolamiento.get(d.enrollment_id)));
    },
    /** @param {string} enrollmentId */
    buscarPorEnrolamiento: (enrollmentId) => copia(s.porEnrolamiento.get(enrollmentId)),
    /** @param {string} id */
    buscarPorId: (id) => copia(s.porId.get(id)),
    /**
     * Registra el último código aceptado. @param {string} enrollmentId @param {string} ahoraIso
     * @returns {boolean} true si se actualizó la fila
     */
    registrarUso: (enrollmentId, ahoraIso) => s.uso.run(ahoraIso, enrollmentId, ahoraIso).changes === 1,
    /**
     * Marca el dispositivo como desvinculado (idempotente: conserva la primera fecha).
     * @param {string} enrollmentId @param {string} ahoraIso @returns {boolean}
     */
    desvincular: (enrollmentId, ahoraIso) => s.desvincular.run(ahoraIso, enrollmentId).changes === 1,
  };
}
