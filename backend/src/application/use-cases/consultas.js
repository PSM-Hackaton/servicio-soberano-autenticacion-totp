// Consultas de solo lectura que los repositorios actuales no exponen (historial de intentos por
// cuenta, listado de enrolamientos, intentos de riesgo alto). Si el repositorio ofrece el método
// se usa ese; si no, se recurre a una conexión SQLite opcional (deps.db) con sentencias preparadas.
// Sin ninguna de las dos opciones, devuelven listas vacías (degradación sin error).

/** @typedef {import('node:sqlite').DatabaseSync} DatabaseSync */

/** Columnas seguras de enrollments (nunca la semilla cifrada). */
const COLUMNAS_ENROL = `id, app_id, user_ref_hash, estado, algoritmo, digitos, periodo, key_version, drift_steps,
  last_step, failed_attempts, locked_until, pending_expires_at, created_at, activated_at, revoked_at`;

/** @param {any} f */
function intento(f) {
  const fila = { ...f };
  if (typeof fila.reasons_json === 'string') {
    try { fila.reasons_json = JSON.parse(fila.reasons_json); } catch { fila.reasons_json = null; }
  }
  return fila;
}

/**
 * @param {{ repos: any, db?: DatabaseSync | null }} deps
 */
export function crearConsultas({ repos, db = null }) {
  /** @type {Record<string, any>} */
  const s = {};
  if (db) {
    s.ultimosUsuario = db.prepare('SELECT * FROM attempts WHERE user_ref_hash = ? ORDER BY ts DESC, id DESC LIMIT ?');
    s.enrolTodos = db.prepare(`SELECT ${COLUMNAS_ENROL} FROM enrollments ORDER BY created_at DESC, id LIMIT ?`);
    s.enrolApp = db.prepare(`SELECT ${COLUMNAS_ENROL} FROM enrollments WHERE app_id = ? ORDER BY created_at DESC, id LIMIT ?`);
    s.enrolEstado = db.prepare(`SELECT ${COLUMNAS_ENROL} FROM enrollments WHERE estado = ? ORDER BY created_at DESC, id LIMIT ?`);
    s.enrolAppEstado = db.prepare(`SELECT ${COLUMNAS_ENROL} FROM enrollments WHERE app_id = ? AND estado = ?
      ORDER BY created_at DESC, id LIMIT ?`);
    s.riesgo = db.prepare(`SELECT * FROM attempts WHERE risk_score >= ? OR resultado = 'anomaly_blocked'
      ORDER BY ts DESC, id DESC LIMIT ?`);
  }

  return {
    /** @param {string} userRefHash @param {number} [limite] */
    ultimosPorUsuario(userRefHash, limite = 50) {
      if (typeof repos.attempts?.ultimosPorUsuario === 'function') return repos.attempts.ultimosPorUsuario(userRefHash, limite);
      return s.ultimosUsuario ? s.ultimosUsuario.all(userRefHash, limite).map(intento) : [];
    },
    /** @param {{ appId?: string, estado?: string, limite?: number }} filtro */
    listarEnrolamientos({ appId, estado, limite = 100 } = {}) {
      if (typeof repos.enrollments?.listar === 'function') return repos.enrollments.listar({ appId, estado, limite });
      if (!db) return [];
      let filas;
      if (appId && estado) filas = s.enrolAppEstado.all(appId, estado, limite);
      else if (appId) filas = s.enrolApp.all(appId, limite);
      else if (estado) filas = s.enrolEstado.all(estado, limite);
      else filas = s.enrolTodos.all(limite);
      return filas.map((f) => ({ ...f }));
    },
    /** @param {number} riesgoMinimo @param {number} [limite] */
    intentosRiesgoAlto(riesgoMinimo, limite = 50) {
      if (typeof repos.attempts?.listarRiesgoAlto === 'function') return repos.attempts.listarRiesgoAlto(riesgoMinimo, limite);
      return s.riesgo ? s.riesgo.all(riesgoMinimo, limite).map(intento) : [];
    },
  };
}
