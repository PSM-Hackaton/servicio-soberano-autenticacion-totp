// Bitácora de auditoría encadenada por hashes SHA-256 (tabla audit_log).
// Desacoplada de la base de datos: recibe un almacén inyectado con `ultimo()` e `insertar(fila)`.
// Cada fila guarda el hash de la anterior (prev_hash), de modo que modificar, borrar o
// reordenar una fila intermedia rompe la cadena y es detectable.

import { createHash } from 'node:crypto';

/**
 * @typedef {{ id?: number, ts: string, actor: string, accion: string, objetivo: string | null,
 *   detalle: string | null, prev_hash: string, hash: string }} FilaAuditoria
 * @typedef {{ ultimo: () => FilaAuditoria | undefined, insertar: (fila: FilaAuditoria) => number,
 *   ahora?: () => string }} OpcionesBitacora
 */

/** Hash previo de la primera fila de la cadena. */
export const HASH_GENESIS = '0'.repeat(64);

/** Claves que nunca deben quedar en claro en `detalle` (comparación sin mayúsculas). */
export const CLAVES_SENSIBLES = Object.freeze(['secret', 'password', 'seed', 'semilla', 'code', 'codigo', 'token', 'pin']);

const OCULTO = '[oculto]';

/**
 * JSON determinista: claves de objetos ordenadas recursivamente; `undefined` en objetos se omite
 * y en arreglos se serializa como null (igual que JSON.stringify).
 * @param {unknown} valor
 * @returns {string}
 */
export function serializarCanonico(valor) {
  if (valor === null || typeof valor !== 'object') {
    const texto = JSON.stringify(valor);
    return texto === undefined ? 'null' : texto;
  }
  if (typeof (/** @type {any} */ (valor)).toJSON === 'function') {
    return serializarCanonico(/** @type {any} */ (valor).toJSON());
  }
  if (Array.isArray(valor)) return `[${valor.map((v) => serializarCanonico(v)).join(',')}]`;
  const partes = Object.keys(valor)
    .filter((k) => /** @type {any} */ (valor)[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${serializarCanonico(/** @type {any} */ (valor)[k])}`);
  return `{${partes.join(',')}}`;
}

/**
 * Una clave es sensible si alguno de sus segmentos (separados por _, -, . o camelCase) está en
 * la lista: `clientSecret`, `otp_code` o `password` se ocultan; `shipping` o `encoded` no.
 * @param {string} clave
 */
function esSensible(clave) {
  const segmentos = clave.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/);
  return segmentos.some((s) => CLAVES_SENSIBLES.includes(s));
}

/**
 * Copia profunda de `valor` con las claves sensibles reemplazadas por '[oculto]'.
 * @param {unknown} valor
 * @returns {unknown}
 */
export function filtrarSensibles(valor) {
  if (Array.isArray(valor)) return valor.map(filtrarSensibles);
  if (valor === null || typeof valor !== 'object' || valor instanceof Date) return valor;
  /** @type {Record<string, unknown>} */
  const limpio = {};
  for (const [k, v] of Object.entries(valor)) limpio[k] = esSensible(k) ? OCULTO : filtrarSensibles(v);
  return limpio;
}

/**
 * Normaliza `detalle` al texto que se persiste (columna TEXT): JSON canónico o null.
 * Un texto ya serializado (fila leída de la base) se deja tal cual.
 * @param {unknown} detalle
 * @returns {string | null}
 */
function normalizarDetalle(detalle) {
  if (detalle === undefined || detalle === null) return null;
  if (typeof detalle === 'string') return detalle;
  return serializarCanonico(detalle);
}

/**
 * Hash de una fila: SHA-256 hex de `prevHash + '|' + JSON canónico de los campos de contenido`.
 * @param {string} prevHash
 * @param {{ ts: string, actor: string, accion: string, objetivo?: string | null, detalle?: unknown }} campos
 * @returns {string}
 */
export function calcularHash(prevHash, { ts, actor, accion, objetivo = null, detalle = null }) {
  const contenido = serializarCanonico({
    ts, actor, accion, objetivo: objetivo ?? null, detalle: normalizarDetalle(detalle),
  });
  return createHash('sha256').update(`${prevHash}|${contenido}`).digest('hex');
}

/**
 * Crea la bitácora sobre un almacén inyectado. Las inserciones deben ser serializadas por el
 * llamador (en SQLite síncrono lo son de forma natural).
 * @param {OpcionesBitacora} opciones
 */
export function crearBitacora({ ultimo, insertar, ahora = () => new Date().toISOString() }) {
  if (typeof ultimo !== 'function' || typeof insertar !== 'function') {
    throw new Error('El almacén debe proveer ultimo() e insertar(fila)');
  }
  return {
    /**
     * Registra un evento. `detalle` se filtra (sin secretos) y se guarda como JSON canónico.
     * @param {{ actor: string, accion: string, objetivo?: string | null, detalle?: unknown }} evento
     * @returns {FilaAuditoria}
     */
    registrar({ actor, accion, objetivo = null, detalle = null }) {
      if (!actor || !accion) throw new Error('actor y accion son obligatorios');
      const anterior = ultimo();
      const prev_hash = anterior?.hash ?? HASH_GENESIS;
      const fila = {
        ts: ahora(),
        actor: String(actor),
        accion: String(accion),
        objetivo: objetivo === null || objetivo === undefined ? null : String(objetivo),
        detalle: normalizarDetalle(detalle === null ? null : filtrarSensibles(
          typeof detalle === 'string' ? intentarParsear(detalle) : detalle,
        )),
        prev_hash,
        hash: '',
      };
      fila.hash = calcularHash(prev_hash, fila);
      const id = insertar({ ...fila });
      return { id, ...fila };
    },
  };
}

/** Si `texto` es JSON se devuelve parseado (para poder filtrarlo); si no, se devuelve igual. */
function intentarParsear(texto) {
  try {
    return JSON.parse(texto);
  } catch {
    return texto;
  }
}

/**
 * Verifica la cadena completa. Recibe las filas ordenadas por id ascendente.
 * Detecta: contenido alterado (hash no coincide), fila borrada en medio o reordenada
 * (prev_hash no enlaza con el hash anterior). Borrar la última fila no es detectable sin un
 * ancla externa (p. ej. publicar periódicamente `lastHash`).
 * @param {FilaAuditoria[]} filasOrdenadas
 * @returns {{ intact: boolean, total: number, brokenAtId: number | null, lastHash: string | null }}
 */
export function verificarCadena(filasOrdenadas) {
  let esperado = HASH_GENESIS;
  let total = 0;
  for (const fila of filasOrdenadas) {
    total++;
    if (fila.prev_hash !== esperado || calcularHash(fila.prev_hash, fila) !== fila.hash) {
      return { intact: false, total, brokenAtId: fila.id ?? null, lastHash: null };
    }
    esperado = fila.hash;
  }
  return { intact: true, total, brokenAtId: null, lastHash: total ? esperado : null };
}

/**
 * Adapta el resultado al contrato de /admin/api/audit/verify-chain (snake_case).
 * @param {ReturnType<typeof verificarCadena>} r
 */
export function respuestaVerificacion(r) {
  return { intact: r.intact, checked_records: r.total, broken_at_id: r.brokenAtId, last_hash: r.lastHash };
}
