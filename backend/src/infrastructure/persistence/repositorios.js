// Repositorios SQLite para las 8 tablas del contrato (contracts/schema.sqlite.sql).
// Sentencias preparadas una sola vez; nunca se concatena entrada del usuario en SQL.
// Convenciones:
//   - Las filas devueltas usan los nombres de columna del esquema (snake_case).
//   - Fechas: texto ISO 8601 UTC (new Date().toISOString()), comparable lexicográficamente.
//   - Material cifrado (seed_*, private_*): se recibe y se devuelve como Buffer; en disco
//     se guarda como TEXT base64 porque así lo define el contrato.
//   - Booleanos (permitir_sha1, activo): INTEGER 0/1 en disco, boolean hacia fuera.

import { randomUUID } from 'node:crypto';

/** @typedef {import('node:sqlite').DatabaseSync} DatabaseSync */
/** @typedef {Record<string, any>} Fila */

const ahoraIso = () => new Date().toISOString();

/** @param {Uint8Array} valor */
function aBase64(valor) {
  if (!(valor instanceof Uint8Array)) throw new TypeError('Se esperaba Buffer/Uint8Array');
  return Buffer.from(valor).toString('base64');
}

/** @param {string | null | undefined} texto */
const deBase64 = (texto) => (texto == null ? texto : Buffer.from(texto, 'base64'));

/** node:sqlite no acepta undefined ni boolean como parámetro: se normalizan. */
function valorSql(v) {
  if (v === undefined) return null;
  if (typeof v === 'boolean') return v ? 1 : 0;
  return v;
}

/** @param {Fila | undefined} f */
function mapearApp(f) {
  if (!f) return null;
  return { ...f, permitir_sha1: f.permitir_sha1 === 1 };
}

/** @param {Fila | undefined} f */
function mapearEnrolamiento(f) {
  if (!f) return null;
  return { ...f, seed_ct: deBase64(f.seed_ct), seed_nonce: deBase64(f.seed_nonce), seed_auth_tag: deBase64(f.seed_auth_tag) };
}

/** @param {Fila | undefined} f */
function mapearClave(f) {
  if (!f) return null;
  return {
    ...f,
    public_jwk: JSON.parse(f.public_jwk),
    private_ct: deBase64(f.private_ct),
    private_nonce: deBase64(f.private_nonce),
    private_auth_tag: deBase64(f.private_auth_tag),
  };
}

/** @param {Fila | undefined} f */
function mapearAdmin(f) {
  if (!f) return null;
  return { ...f, activo: f.activo === 1 };
}

/** @param {Fila | undefined} f */
function mapearIntento(f) {
  if (!f) return null;
  return { ...f, reasons_json: f.reasons_json == null ? null : JSON.parse(f.reasons_json) };
}

/** Copia sin prototipo de la fila (node:sqlite devuelve objetos con prototipo nulo). */
const plano = (f) => (f ? { ...f } : null);

/**
 * Crea los repositorios sobre una conexión ya migrada (ver abrirBaseDatos).
 * @param {DatabaseSync} db
 */
export function crearRepositorios(db) {
  // INSERT con solo las columnas presentes, para respetar los DEFAULT del esquema.
  // Las columnas vienen de listas blancas fijas, nunca de la entrada.
  const cacheInsert = new Map();
  /** @param {string} tabla @param {readonly string[]} permitidas @param {Fila} datos */
  function insertar(tabla, permitidas, datos) {
    const columnas = permitidas.filter((c) => datos[c] !== undefined);
    const clave = `${tabla}:${columnas.join(',')}`;
    let sentencia = cacheInsert.get(clave);
    if (!sentencia) {
      sentencia = db.prepare(`INSERT INTO ${tabla} (${columnas.join(', ')}) VALUES (${columnas.map(() => '?').join(', ')})`);
      cacheInsert.set(clave, sentencia);
    }
    return sentencia.run(...columnas.map((c) => valorSql(datos[c])));
  }

  // ---------------------------------------------------------------- transacciones
  let profundidad = 0;
  /**
   * Ejecuta fn dentro de una transacción (BEGIN IMMEDIATE / COMMIT / ROLLBACK).
   * Las llamadas anidadas usan SAVEPOINT. fn debe ser síncrona.
   * @template T @param {() => T} fn @returns {T}
   */
  function transaccion(fn) {
    const punto = `sp_${profundidad}`;
    db.exec(profundidad === 0 ? 'BEGIN IMMEDIATE' : `SAVEPOINT ${punto}`);
    profundidad++;
    try {
      const resultado = fn();
      if (resultado && typeof resultado.then === 'function') {
        throw new TypeError('transaccion() requiere una función síncrona');
      }
      profundidad--;
      db.exec(profundidad === 0 ? 'COMMIT' : `RELEASE ${punto}`);
      return resultado;
    } catch (error) {
      profundidad--;
      if (profundidad === 0) db.exec('ROLLBACK');
      else db.exec(`ROLLBACK TO ${punto}; RELEASE ${punto}`);
      throw error;
    }
  }

  // ---------------------------------------------------------------- apps
  const COLUMNAS_APP = ['id', 'nombre', 'client_id', 'secret_hash', 'algoritmo', 'digitos', 'periodo', 'ventana',
    'max_intentos', 'umbral_riesgo_bloqueo', 'modo_heuristica', 'permitir_sha1', 'estado'];
  const POLITICA_APP = ['algoritmo', 'digitos', 'periodo', 'ventana', 'max_intentos', 'umbral_riesgo_bloqueo',
    'modo_heuristica', 'permitir_sha1', 'estado'];
  const sApp = {
    porId: db.prepare('SELECT * FROM apps WHERE id = ?'),
    porClientId: db.prepare('SELECT * FROM apps WHERE client_id = ?'),
    listar: db.prepare('SELECT * FROM apps ORDER BY created_at, id'),
  };
  const apps = {
    /** @param {Fila} datos Columnas de apps; id opcional (UUID si falta). */
    crear(datos) {
      const id = datos.id ?? randomUUID();
      insertar('apps', COLUMNAS_APP, { ...datos, id });
      return apps.buscarPorId(id);
    },
    /** @param {string} id */
    buscarPorId: (id) => mapearApp(sApp.porId.get(id)),
    /** @param {string} clientId */
    buscarPorClientId: (clientId) => mapearApp(sApp.porClientId.get(clientId)),
    listar: () => sApp.listar.all().map(mapearApp),
    /**
     * Actualiza solo los campos de política presentes en cambios.
     * @param {string} id @param {Fila} cambios @returns {boolean}
     */
    actualizarPolitica(id, cambios) {
      const columnas = POLITICA_APP.filter((c) => cambios[c] !== undefined);
      if (columnas.length === 0) return false;
      const sql = `UPDATE apps SET ${columnas.map((c) => `${c} = ?`).join(', ')}, updated_at = ? WHERE id = ?`;
      const r = db.prepare(sql).run(...columnas.map((c) => valorSql(cambios[c])), ahoraIso(), id);
      return r.changes === 1;
    },
  };

  // ---------------------------------------------------------------- enrollments
  const COLUMNAS_ENROL = ['id', 'app_id', 'user_ref_hash', 'estado', 'algoritmo', 'digitos', 'periodo', 'seed_ct',
    'seed_nonce', 'seed_auth_tag', 'key_version', 'pending_expires_at'];
  const sEnrol = {
    porId: db.prepare('SELECT * FROM enrollments WHERE id = ?'),
    activoPorUsuario: db.prepare(`SELECT * FROM enrollments WHERE app_id = ? AND user_ref_hash = ? AND estado = 'activo'
      ORDER BY activated_at DESC LIMIT 1`),
    activar: db.prepare(`UPDATE enrollments SET estado = 'activo', activated_at = ?, pending_expires_at = NULL
      WHERE id = ? AND estado = 'pendiente' AND (pending_expires_at IS NULL OR pending_expires_at > ?)`),
    revocar: db.prepare(`UPDATE enrollments SET estado = 'revocado', revoked_at = ? WHERE id = ? AND estado <> 'revocado'`),
    suspender: db.prepare(`UPDATE enrollments SET estado = 'suspendido' WHERE id = ? AND estado = 'activo'`),
    // ADR-003: anti replay atómico. Solo una petición puede avanzar last_step a T.
    pasoAceptado: db.prepare(`UPDATE enrollments SET last_step = ?, drift_steps = ?, failed_attempts = 0, locked_until = NULL
      WHERE id = ? AND last_step < ?`),
    fallo: db.prepare(`UPDATE enrollments SET failed_attempts = failed_attempts + 1, locked_until = COALESCE(?, locked_until)
      WHERE id = ? RETURNING failed_attempts`),
    recifrar: db.prepare(`UPDATE enrollments SET seed_ct = ?, seed_nonce = ?, seed_auth_tag = ?, key_version = ?
      WHERE id = ? AND key_version = ?`),
  };
  const enrollments = {
    /**
     * Crea un enrolamiento en estado 'pendiente'. El id puede venir del llamador, porque
     * forma parte del AAD del cifrado (ADR-003) y se necesita antes de cifrar.
     * @param {Fila} datos seed_ct, seed_nonce y seed_auth_tag como Buffer.
     */
    crearPendiente(datos) {
      const id = datos.id ?? randomUUID();
      insertar('enrollments', COLUMNAS_ENROL, {
        ...datos,
        id,
        estado: 'pendiente',
        seed_ct: aBase64(datos.seed_ct),
        seed_nonce: aBase64(datos.seed_nonce),
        seed_auth_tag: aBase64(datos.seed_auth_tag),
      });
      return enrollments.buscarPorId(id);
    },
    /** @param {string} id */
    buscarPorId: (id) => mapearEnrolamiento(sEnrol.porId.get(id)),
    /** @param {string} appId @param {string} userRefHash */
    buscarActivoPorUsuario: (appId, userRefHash) => mapearEnrolamiento(sEnrol.activoPorUsuario.get(appId, userRefHash)),
    /**
     * Pasa de 'pendiente' a 'activo' si no ha caducado. Para consumir el primer código,
     * llamar después a registrarPasoAceptado dentro de la misma transacción.
     * @param {string} id @param {string} [ahora] @returns {boolean}
     */
    activar(id, ahora = ahoraIso()) {
      return sEnrol.activar.run(ahora, id, ahora).changes === 1;
    },
    /** @param {string} id @param {string} [ahora] @returns {boolean} */
    revocar: (id, ahora = ahoraIso()) => sEnrol.revocar.run(ahora, id).changes === 1,
    /** @param {string} id @returns {boolean} */
    suspender: (id) => sEnrol.suspender.run(id).changes === 1,
    /**
     * Registra el paso T aceptado. Devuelve true solo si last_step < T (anti replay atómico):
     * dos peticiones con el mismo código no pueden ganar las dos.
     * @param {string} id @param {number} paso @param {number} drift @returns {boolean}
     */
    registrarPasoAceptado(id, paso, drift) {
      return sEnrol.pasoAceptado.run(paso, drift, id, paso).changes === 1;
    },
    /**
     * Suma un fallo y, si se indica, fija el bloqueo. Un null no levanta un bloqueo vigente.
     * @param {string} id @param {string | null} lockedUntil @returns {number | null} Fallos acumulados.
     */
    registrarFallo(id, lockedUntil) {
      const f = sEnrol.fallo.get(valorSql(lockedUntil), id);
      return f ? f.failed_attempts : null;
    },
    /**
     * Sustituye la semilla cifrada (rotación de clave maestra). Control optimista:
     * solo aplica si la fila sigue en versionAnterior.
     * @param {string} id
     * @param {{ seed_ct: Uint8Array, seed_nonce: Uint8Array, seed_auth_tag: Uint8Array, key_version: string }} nueva
     * @param {string} versionAnterior
     * @returns {boolean}
     */
    recifrarSemilla(id, nueva, versionAnterior) {
      return sEnrol.recifrar.run(aBase64(nueva.seed_ct), aBase64(nueva.seed_nonce), aBase64(nueva.seed_auth_tag),
        nueva.key_version, id, versionAnterior).changes === 1;
    },
  };

  // ---------------------------------------------------------------- recovery_codes
  const sRec = {
    insertar: db.prepare('INSERT INTO recovery_codes (id, enrollment_id, code_hash) VALUES (?, ?, ?)'),
    noUsados: db.prepare('SELECT * FROM recovery_codes WHERE enrollment_id = ? AND used_at IS NULL ORDER BY id'),
    marcar: db.prepare('UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL'),
  };
  const recoveryCodes = {
    /** @param {string} enrollmentId @param {string[]} hashes @returns {string[]} ids creados */
    insertarLote(enrollmentId, hashes) {
      return transaccion(() => hashes.map((h) => {
        const id = randomUUID();
        sRec.insertar.run(id, enrollmentId, h);
        return id;
      }));
    },
    /** @param {string} enrollmentId */
    listarNoUsados: (enrollmentId) => sRec.noUsados.all(enrollmentId).map(plano),
    /** Atómico: true solo para el primer uso. @param {string} id @param {string} [ahora] */
    marcarUsado: (id, ahora = ahoraIso()) => sRec.marcar.run(ahora, id).changes === 1,
  };

  // ---------------------------------------------------------------- attempts
  const COLUMNAS_INTENTO = ['enrollment_id', 'app_id', 'user_ref_hash', 'ip_hash', 'resultado', 'risk_score',
    'reasons_json', 'inference_ms', 'ts'];
  const sInt = {
    fallosUsuario: db.prepare(`SELECT COUNT(*) AS n FROM attempts WHERE user_ref_hash = ? AND resultado <> 'ok' AND ts >= ?`),
    fallosIp: db.prepare(`SELECT COUNT(*) AS n FROM attempts WHERE ip_hash = ? AND resultado <> 'ok' AND ts >= ?`),
    ultimosIp: db.prepare('SELECT * FROM attempts WHERE ip_hash = ? ORDER BY ts DESC, id DESC LIMIT ?'),
    purgar: db.prepare('DELETE FROM attempts WHERE ts < ?'),
  };
  const attempts = {
    /** @param {Fila} datos reasons_json puede ser objeto o array (se serializa). @returns {number} id */
    registrar(datos) {
      const reasons = datos.reasons_json;
      const r = insertar('attempts', COLUMNAS_INTENTO, {
        ...datos,
        reasons_json: reasons == null || typeof reasons === 'string' ? reasons : JSON.stringify(reasons),
      });
      return Number(r.lastInsertRowid);
    },
    /**
     * Cuenta intentos fallidos (resultado distinto de 'ok') desde una fecha ISO.
     * @param {{ userRefHash?: string, ipHash?: string, desde: string }} filtro
     */
    contarFallosRecientes({ userRefHash, ipHash, desde }) {
      if (userRefHash != null) return sInt.fallosUsuario.get(userRefHash, desde).n;
      if (ipHash != null) return sInt.fallosIp.get(ipHash, desde).n;
      throw new Error('Indica userRefHash o ipHash');
    },
    /** @param {string} ipHash @param {number} [limite] */
    ultimosPorIp: (ipHash, limite = 50) => sInt.ultimosIp.all(ipHash, limite).map(mapearIntento),
    /** Borra intentos con más de `dias` días (retención de 30 por defecto). @returns {number} filas borradas */
    purgarAntiguos(dias = 30, ahora = Date.now()) {
      return Number(sInt.purgar.run(new Date(ahora - dias * 86_400_000).toISOString()).changes);
    },
  };

  // ---------------------------------------------------------------- consumed_jti
  const sJti = {
    consumir: db.prepare('INSERT INTO consumed_jti (jti, expira_en) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING'),
    purgar: db.prepare('DELETE FROM consumed_jti WHERE expira_en < ?'),
  };
  const consumedJti = {
    /** Un solo uso: true si se insertó, false si el jti ya estaba consumido. @param {string} jti @param {string} expiraEn */
    consumir: (jti, expiraEn) => sJti.consumir.run(jti, expiraEn).changes === 1,
    /** @param {string} [ahora] @returns {number} */
    purgarCaducados: (ahora = ahoraIso()) => Number(sJti.purgar.run(ahora).changes),
  };

  // ---------------------------------------------------------------- signing_keys
  const sClave = {
    guardar: db.prepare(`INSERT INTO signing_keys (kid, public_jwk, private_ct, private_nonce, private_auth_tag, key_version, estado)
      VALUES (?, ?, ?, ?, ?, ?, ?)`),
    activa: db.prepare(`SELECT * FROM signing_keys WHERE estado = 'activa' ORDER BY created_at DESC LIMIT 1`),
    verificables: db.prepare(`SELECT * FROM signing_keys WHERE estado IN ('activa', 'solo_verificacion') ORDER BY created_at DESC`),
    porKid: db.prepare('SELECT * FROM signing_keys WHERE kid = ?'),
    estado: db.prepare('UPDATE signing_keys SET estado = ?, rotated_at = ? WHERE kid = ?'),
  };
  const signingKeys = {
    /** @param {Fila} c public_jwk objeto o JSON; private_* como Buffer. */
    guardar(c) {
      const jwk = typeof c.public_jwk === 'string' ? c.public_jwk : JSON.stringify(c.public_jwk);
      sClave.guardar.run(c.kid, jwk, aBase64(c.private_ct), aBase64(c.private_nonce), aBase64(c.private_auth_tag),
        c.key_version ?? 'v1', c.estado ?? 'activa');
      return signingKeys.buscarPorKid(c.kid);
    },
    /** @param {string} kid */
    buscarPorKid: (kid) => mapearClave(sClave.porKid.get(kid)),
    activa: () => mapearClave(sClave.activa.get()),
    /** Claves publicables en el JWKS (activa + solo_verificacion). */
    listarVerificables: () => sClave.verificables.all().map(mapearClave),
    /**
     * @param {string} kid @param {'activa' | 'solo_verificacion' | 'retirada'} estado @param {string} [ahora]
     * @returns {boolean}
     */
    cambiarEstado(kid, estado, ahora = ahoraIso()) {
      return sClave.estado.run(estado, estado === 'activa' ? null : ahora, kid).changes === 1;
    },
  };

  // ---------------------------------------------------------------- admins
  const COLUMNAS_ADMIN = ['id', 'usuario', 'password_hash', 'rol', 'totp_enrollment_id', 'activo'];
  const sAdmin = {
    porUsuario: db.prepare('SELECT * FROM admins WHERE usuario = ?'),
    porId: db.prepare('SELECT * FROM admins WHERE id = ?'),
  };
  const admins = {
    /** @param {Fila} datos */
    crear(datos) {
      const id = datos.id ?? randomUUID();
      insertar('admins', COLUMNAS_ADMIN, { ...datos, id });
      return mapearAdmin(sAdmin.porId.get(id));
    },
    /** @param {string} usuario */
    buscarPorUsuario: (usuario) => mapearAdmin(sAdmin.porUsuario.get(usuario)),
  };

  // ---------------------------------------------------------------- audit_log
  const sAudit = {
    insertar: db.prepare(`INSERT INTO audit_log (ts, actor, accion, objetivo, detalle, prev_hash, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?)`),
    porId: db.prepare('SELECT * FROM audit_log WHERE id = ?'),
    ultimo: db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 1'),
    desdeId: db.prepare('SELECT * FROM audit_log WHERE id > ? ORDER BY id LIMIT ?'),
    desdeTs: db.prepare('SELECT * FROM audit_log WHERE ts >= ? ORDER BY id LIMIT ?'),
    todo: db.prepare('SELECT * FROM audit_log ORDER BY id'),
  };
  const auditLog = {
    /**
     * Inserta una entrada ya encadenada. `detalle` se guarda tal cual (texto) para que el
     * hash calculado por el llamador sea reproducible; si es objeto se serializa con JSON.
     * `ts` debería venir del llamador, porque forma parte del hash.
     * @param {{ ts?: string, actor: string, accion: string, objetivo?: string | null, detalle?: any, prev_hash: string, hash: string }} e
     */
    insertar(e) {
      const detalle = e.detalle == null || typeof e.detalle === 'string' ? e.detalle : JSON.stringify(e.detalle);
      const r = sAudit.insertar.run(e.ts ?? ahoraIso(), e.actor, e.accion, valorSql(e.objetivo), valorSql(detalle),
        e.prev_hash, e.hash);
      return plano(sAudit.porId.get(r.lastInsertRowid));
    },
    ultimo: () => plano(sAudit.ultimo.get()),
    /**
     * Página en orden de id. `desde` numérico = id exclusivo (cursor); texto = ts ISO inclusive.
     * @param {number | string} [desde] @param {number} [limite]
     */
    listar(desde = 0, limite = 100) {
      const s = typeof desde === 'string' ? sAudit.desdeTs : sAudit.desdeId;
      return s.all(desde, limite).map(plano);
    },
    /** Iterador perezoso de toda la cadena ordenada por id (verificación de integridad). */
    *recorrerTodo() {
      for (const f of sAudit.todo.iterate()) yield plano(f);
    },
  };

  return { transaccion, apps, enrollments, recoveryCodes, attempts, consumedJti, signingKeys, admins, auditLog };
}
