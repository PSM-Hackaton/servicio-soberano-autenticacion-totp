// Utilidades compartidas por los casos de uso: normalización de la entrada, respuestas,
// anonimización de IP, mapa acotado con caducidad y adaptación del riesgo al contrato.

import { createHash } from 'node:crypto';
import { hashPepper, pepperDiario } from '../../core/vault/vault.js';
import { validarCuerpo, errorGenerico } from '../../security/index.js';
import { aRiesgoContrato } from '../../heuristics/index.js';

/** @typedef {{ status: number, cuerpo: Record<string, any>, cabeceras?: Record<string, string> }} Respuesta */

/** UUID en forma canónica (minúsculas o mayúsculas). */
export const PATRON_UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Hash scrypt válido de un valor que nadie conoce: se verifica contra él cuando la cuenta o la
 * app no existe, para que el tiempo de respuesta no delate su existencia.
 */
export const HASH_FICTICIO = 'scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

/** Claves con las que el servidor puede envolver el cuerpo en lugar de pasarlo directo. */
const ENVOLTURAS = new Set(['cuerpo', 'body', 'params', 'query', 'id']);

/**
 * Separa el identificador de ruta y el cuerpo de la entrada de un caso de uso.
 * Forma canónica: `{ id, cuerpo }` para rutas con `{id}` y el cuerpo JSON directo para el resto.
 * También acepta `{ params: { id }, cuerpo | body }`.
 * @param {any} entrada
 * @returns {{ id: unknown, cuerpo: unknown }}
 */
export function separarEntrada(entrada) {
  if (entrada === null || typeof entrada !== 'object' || Array.isArray(entrada)) return { id: undefined, cuerpo: entrada };
  const claves = Object.keys(entrada);
  const envuelta = claves.length > 0 && claves.every((c) => ENVOLTURAS.has(c));
  if (!envuelta) return { id: undefined, cuerpo: entrada };
  const id = entrada.id ?? entrada.params?.id;
  const cuerpo = entrada.cuerpo ?? entrada.body ?? entrada.query ?? {};
  return { id, cuerpo };
}

/**
 * Valida con esquema cerrado. Devuelve el valor saneado o null.
 * @param {unknown} cuerpo @param {import('../../security/validacion.js').Esquema} esquema
 */
export function validar(cuerpo, esquema) {
  const r = validarCuerpo(cuerpo ?? {}, esquema);
  return r.ok ? r.valor : null;
}

/** Respuesta 400 genérica. @returns {Respuesta} */
export const errorEntrada = () => errorGenerico('entrada');

/** Respuesta 404 genérica (no revela si el recurso existe en otra app). @returns {Respuesta} */
export function noEncontrado() {
  return { status: 404, cuerpo: { error: 'NOT_FOUND', message: 'Recurso no encontrado.' }, cabeceras: {} };
}

/** Respuesta 403 genérica para RBAC. @returns {Respuesta} */
export function prohibido() {
  return { status: 403, cuerpo: { error: 'FORBIDDEN', message: 'Acceso denegado.' }, cabeceras: {} };
}

/**
 * Respuesta 409: la operación no es válida en el estado actual (transición no permitida, nombre
 * duplicado, último Administrador…). Solo se usa en la consola, nunca en la API de integradores.
 * @param {string} [mensaje] texto fijo, sin datos de la entrada
 * @returns {Respuesta}
 */
export function conflicto(mensaje = 'La operación no es válida en el estado actual.') {
  return { status: 409, cuerpo: { error: 'CONFLICT', message: mensaje }, cabeceras: {} };
}

/** @param {number} ms */
export const iso = (ms) => new Date(ms).toISOString();

/**
 * Identidad de origen de un usuario final en una app: HMAC-SHA256(app_id + ':' + ip, pepper
 * diario). `ip` es el `client_ip` que envía la app (IP del ciudadano) o, si no lo envía, la IP
 * TCP de la app: entonces todos sus usuarios comparten un único origen. Es lo que se guarda en
 * attempts.ip_hash y lo que usan el historial del detector y el bloqueo adaptativo por origen;
 * al incluir app_id, el historial de un origen es propio de cada app.
 * @param {string} appId @param {string | undefined} ip @param {string} semilla @param {number} ahora
 */
export function anonimizarOrigen(appId, ip, semilla, ahora) {
  return hashPepper(`${appId}:${String(ip || 'desconocida')}`, pepperDiario(semilla, new Date(ahora)));
}

/**
 * ip_hash = HMAC-SHA256(ip, pepper diario derivado de la semilla). La IP nunca se guarda.
 * @param {string | undefined} ip @param {string} semilla @param {number} ahora
 */
export function anonimizarIp(ip, semilla, ahora) {
  return hashPepper(String(ip || 'desconocida'), pepperDiario(semilla, new Date(ahora)));
}

/** Huella SHA-256 de un valor serializable (para comparar cuerpos idempotentes). */
export function huella(valor) {
  return createHash('sha256').update(JSON.stringify(valor ?? null)).digest('hex');
}

/**
 * Mapa en memoria con caducidad y tamaño máximo (descarta el más antiguo al llenarse).
 * @template T
 * @param {{ maxEntradas: number, ttlMs: number, reloj: () => number }} opciones
 */
export function crearMapaAcotado({ maxEntradas, ttlMs, reloj }) {
  /** @type {Map<string, { expira: number, valor: T }>} */
  const mapa = new Map();
  return {
    /** @param {string} clave @returns {T | undefined} */
    obtener(clave) {
      const e = mapa.get(clave);
      if (!e) return undefined;
      if (e.expira <= reloj()) {
        mapa.delete(clave);
        return undefined;
      }
      return e.valor;
    },
    /** @param {string} clave @param {T} valor @param {number} [ttl] */
    poner(clave, valor, ttl = ttlMs) {
      mapa.delete(clave);
      while (mapa.size >= maxEntradas) mapa.delete(mapa.keys().next().value);
      mapa.set(clave, { expira: reloj() + ttl, valor });
    },
    /** @param {string} clave */
    borrar: (clave) => mapa.delete(clave),
    get tamano() { return mapa.size; },
  };
}

/** Evaluación neutra cuando el detector falla o no está disponible (no bloquea el servicio). */
export const EVALUACION_NEUTRA = Object.freeze({
  riskScore: 0, level: 'bajo', action: 'permitir', reasons: ['Detector no disponible'], inferenceMs: 0,
});

/**
 * Objeto `risk` de VerifySuccessResponse: solo el nivel (LOW, MEDIUM, HIGH, CRITICAL). La
 * puntuación, las razones, la acción y los umbrales del detector nunca salen hacia el cliente
 * (le darían a un atacante una guía para calibrar su ataque); quedan en `attempts`, en la
 * bitácora y en /admin/api/anomalies.
 * @param {{ riskScore: number, level: string, action: string, reasons: string[], inferenceMs: number }} e
 * @returns {{ level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' }}
 */
export function riesgoContrato(e) {
  const nivel = aRiesgoContrato(e)?.level;
  return { level: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(nivel) ? nivel : 'LOW' };
}

/**
 * Tope de deriva aceptable en verify: max(|drift_steps guardado|, ventana). Solo la
 * resincronización (dos códigos consecutivos) puede fijar derivas mayores (hasta ±10).
 * @param {number | null | undefined} derivaGuardada @param {number} ventana
 */
export const topeDeriva = (derivaGuardada, ventana) => Math.max(Math.abs(derivaGuardada ?? 0), ventana);

/**
 * Deriva que se guarda tras aceptar un código en verify. Dentro de la ventana normal la deriva
 * sigue al último código aceptado; una deriva mayor fijada por resync no se reduce por un código
 * tecleado tarde (evitaría que el siguiente código del mismo dispositivo quedara fuera del tope).
 * Invariante: |resultado| <= topeDeriva(guardada, ventana), así que verify nunca la hace crecer.
 * @param {number | null | undefined} guardada @param {number} observada @param {number} ventana
 */
export function derivaAGuardar(guardada, observada, ventana) {
  const g = guardada ?? 0;
  return Math.abs(g) > ventana && Math.abs(observada) < Math.abs(g) ? g : observada;
}
