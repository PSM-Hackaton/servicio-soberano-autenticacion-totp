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

/** @param {number} ms */
export const iso = (ms) => new Date(ms).toISOString();

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
 * Objeto `risk` del contrato (VerifySuccessResponse) a partir de la evaluación del detector.
 * @param {{ riskScore: number, level: string, action: string, reasons: string[], inferenceMs: number }} e
 */
export function riesgoContrato(e) {
  const r = aRiesgoContrato(e);
  return {
    score: Number.isFinite(r.score) ? r.score : 0,
    level: r.level ?? 'LOW',
    action: r.action ?? 'ALLOW',
    inference_ms: Number.isFinite(r.inference_ms) ? r.inference_ms : 0,
    reasons: Array.isArray(r.reasons) ? r.reasons : [],
  };
}

/**
 * Forma `riskAssessment` de los mocks verify-anomaly-blocked / verify-replay-blocked.
 * @param {ReturnType<typeof riesgoContrato>} r @param {string} [accion]
 */
export function evaluacionMock(r, accion = r.action) {
  return { riskScore: r.score, level: r.level, action: accion, inferenceMs: r.inference_ms, reasons: r.reasons };
}
