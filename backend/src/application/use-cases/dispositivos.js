// Vinculación y revocación de dispositivos (issue #47, M8) para la app móvil Android y la PWA.
//
// Un enrolamiento puede llevar un dispositivo asociado: seudónimo aleatorio ('dev_' + 128 bits en
// base64url), nombre visible elegido por el usuario (saneado) y plataforma. Nunca se guardan
// identificadores de hardware ni datos personales. El integrador lo consulta con
// GET /api/v1/enrollments/{id}/device y lo desvincula con DELETE (que revoca el enrolamiento: la
// semilla de ese teléfono deja de servir). La consola lo muestra en Enrolamientos.
//
// Además prepara el bloque `provisioning` de la respuesta de enrolar: el URI otpauth:// (la semilla
// se entrega una sola vez, igual que en el QR), su caducidad, el device_id y, si el despliegue
// publica la CA (TLS_CA_PUBLIC_PATH), la huella SHA-256 del certificado para fijarlo en la app.

import { randomBytes } from 'node:crypto';
import { errorGenerico } from '../../security/index.js';
import { PATRON_UUID, errorEntrada, iso, noEncontrado, separarEntrada, validar } from './comun.js';
import { ESQUEMA_VACIO } from './esquemas.js';

/** @typedef {import('./comun.js').Respuesta} Respuesta */

export const PLATAFORMAS = Object.freeze(['android', 'pwa', 'otro']);
export const LARGO_MAXIMO_NOMBRE = 64;
export const PATRON_ID_DISPOSITIVO = /^dev_[A-Za-z0-9_-]{22}$/;
/** Huella SHA-256 en el formato de `openssl x509 -fingerprint -sha256` (hex mayúsculas con ':'). */
export const PATRON_HUELLA_CA = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;

/**
 * Caracteres que se eliminan del nombre visible: controles C0/C1 (Cc), formato e invisibles
 * (Cf: bidi, U+200B…U+200F, U+2060…, BOM), privados (Co), sin asignar (Cn), separadores de línea y
 * párrafo y los rellenos invisibles que el patrón de user_ref también rechaza.
 */
const INVISIBLES = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\u2028\u2029\u034F\u115F\u1160\u2800\u3164\uFFA0]/gu;

/**
 * Sanea el nombre visible que elige el usuario: NFC, sin caracteres invisibles o de control,
 * espacios (incluidos los no separables) colapsados a uno y recortado a 64 puntos de código.
 * @param {unknown} nombre @returns {string | null} null si no queda nada imprimible
 */
export function sanearNombreDispositivo(nombre) {
  if (typeof nombre !== 'string') return null;
  const limpio = nombre.normalize('NFC').replace(INVISIBLES, '').replace(/\s+/gu, ' ').trim();
  if (!limpio) return null;
  return [...limpio].slice(0, LARGO_MAXIMO_NOMBRE).join('').trimEnd();
}

/** Seudónimo aleatorio del dispositivo (no deriva de nada del teléfono). */
export const nuevoIdDispositivo = () => `dev_${randomBytes(16).toString('base64url')}`;

/**
 * Vista pública del dispositivo. `unlinked_at` es la desvinculación explícita o, si el enrolamiento
 * se revocó por otra vía (consola, recuperación, re-enrolamiento), la fecha de revocación.
 * @param {any} d fila de dispositivos @param {any} [enrol] fila de enrollments
 */
export function dispositivoPublico(d, enrol) {
  if (!d) return null;
  return {
    device_id: d.id,
    name: d.nombre,
    platform: d.plataforma,
    created_at: d.created_at,
    last_used_at: d.ultimo_uso ?? null,
    unlinked_at: d.desvinculado_en ?? (enrol?.estado === 'revocado' ? enrol.revoked_at ?? null : null),
  };
}

/**
 * @param {{ repos: any, bitacora: any, reloj: () => number, config: any }} d
 */
export function crearCasosDispositivos(d) {
  const { repos, bitacora, reloj, config } = d;
  const actorApp = (app) => `app:${app.client_id}`;
  const auditar = (actor, accion, objetivo, detalle) => bitacora.registrar({ actor, accion, objetivo, detalle });
  const huellaCa = typeof config?.caHuellaSha256 === 'string' && PATRON_HUELLA_CA.test(config.caHuellaSha256)
    ? config.caHuellaSha256 : null;

  function enrolamientoDeApp(id, app) {
    // nosemgrep: nodejs_scan.javascript-dos-rule-regex_dos -- no es un manejador req/res; PATRON_UUID es un literal anclado de longitud fija (36)
    if (typeof id !== 'string' || id.length !== 36 || !PATRON_UUID.test(id)) return null;
    const e = repos.enrollments.buscarPorId(id.toLowerCase());
    return e && e.app_id === app.id ? e : null;
  }

  /**
   * Normaliza el campo `device` ya validado por ESQUEMA_ENROLAR.
   * @param {{ name: string, platform?: string } | undefined} device
   * @returns {{ ok: true, datos: { nombre: string, plataforma: string } | null } | { ok: false }}
   */
  function prepararVinculo(device) {
    if (device === undefined) return { ok: true, datos: null };
    const nombre = sanearNombreDispositivo(device?.name);
    if (!nombre) return { ok: false };
    return { ok: true, datos: { nombre, plataforma: device.platform ?? 'otro' } };
  }

  /**
   * Crea la fila del dispositivo para un enrolamiento recién creado (misma transacción que el alta).
   * @param {string} enrollmentId @param {{ nombre: string, plataforma: string }} datos @param {number} ahora
   */
  function vincular(enrollmentId, datos, ahora) {
    return repos.dispositivos.crear({
      id: nuevoIdDispositivo(), enrollment_id: enrollmentId, nombre: datos.nombre, plataforma: datos.plataforma, created_at: iso(ahora),
    });
  }

  /**
   * Bloque `provisioning` de la respuesta de enrolar (la semilla viaja dentro del URI, una sola vez).
   * @param {{ otpauthUri: string, expiresAt: string, deviceId: string }} p
   */
  function provisioning({ otpauthUri, expiresAt, deviceId }) {
    const p = { otpauth_uri: otpauthUri, expires_at: expiresAt, device_id: deviceId };
    if (huellaCa) p.ca_fingerprint_sha256 = huellaCa;
    return p;
  }

  /** Último código aceptado (activación o verificación). Sin dispositivo, no hace nada. */
  const registrarUso = (enrollmentId, ahoraIso) => repos.dispositivos.registrarUso(enrollmentId, ahoraIso);

  /** Dispositivo de un enrolamiento para listados de la consola (o null). @param {any} enrol */
  const deEnrolamiento = (enrol) => dispositivoPublico(repos.dispositivos.buscarPorEnrolamiento(enrol.id), enrol);

  // ------------------------------------------------------------------ consultar
  /**
   * GET /api/v1/enrollments/{id}/device — entrada { id }.
   * 200 DeviceResponse | 400 id inválido | 404 genérico (no existe, es de otra app o no tiene dispositivo).
   * @param {unknown} entrada @param {{ app: any }} ctx @returns {Promise<Respuesta>}
   */
  async function dispositivo(entrada, ctx) {
    const { app } = ctx ?? {};
    if (!app) return errorGenerico('credenciales');
    const { id } = separarEntrada(entrada);
    if (typeof id !== 'string' || !PATRON_UUID.test(id)) return errorEntrada();
    const enrol = enrolamientoDeApp(id, app);
    const fila = enrol ? repos.dispositivos.buscarPorEnrolamiento(enrol.id) : null;
    if (!fila) return noEncontrado();
    return {
      status: 200,
      cuerpo: { enrollment_id: enrol.id, enrollment_estado: enrol.estado, ...dispositivoPublico(fila, enrol) },
      cabeceras: { 'Cache-Control': 'no-store' },
    };
  }

  // ------------------------------------------------------------------ desvincular
  /**
   * DELETE /api/v1/enrollments/{id}/device — entrada { id } (sin cuerpo).
   * Desvincula el dispositivo y revoca el enrolamiento en la misma transacción: los códigos de ese
   * teléfono dejan de valer y verify responde igual que ante un código incorrecto.
   * 200 { enrollment_id, device_id, estado: 'revocado', revoked_at, unlinked_at } | 400 | 404 genérico.
   * Idempotente: repetirlo devuelve las fechas originales.
   * @param {unknown} entrada @param {{ app: any }} ctx @returns {Promise<Respuesta>}
   */
  async function desvincularDispositivo(entrada, ctx) {
    const { app } = ctx ?? {};
    if (!app) return errorGenerico('credenciales');
    const { id, cuerpo } = separarEntrada(entrada);
    if (typeof id !== 'string' || !PATRON_UUID.test(id)) return errorEntrada();
    if (cuerpo !== undefined && cuerpo !== null && !validar(cuerpo, ESQUEMA_VACIO)) return errorEntrada();
    const enrol = enrolamientoDeApp(id, app);
    const fila = enrol ? repos.dispositivos.buscarPorEnrolamiento(enrol.id) : null;
    if (!fila) return noEncontrado();
    const ahoraIso = iso(reloj());
    const cambios = repos.transaccion(() => ({
      desvinculado: repos.dispositivos.desvincular(enrol.id, ahoraIso),
      revocado: repos.enrollments.revocar(enrol.id, ahoraIso),
    }));
    if (cambios.revocado) {
      auditar(actorApp(app), 'enrolamiento.revocado', enrol.id, { motivo: 'dispositivo_desvinculado', device_id: fila.id });
    }
    if (cambios.desvinculado) {
      auditar(actorApp(app), 'dispositivo.desvinculado', fila.id, { enrollment_id: enrol.id, plataforma: fila.plataforma });
    }
    const final = repos.enrollments.buscarPorId(enrol.id);
    const d2 = repos.dispositivos.buscarPorEnrolamiento(enrol.id);
    return {
      status: 200,
      cuerpo: {
        enrollment_id: enrol.id,
        device_id: fila.id,
        estado: 'revocado',
        revoked_at: final.revoked_at ?? ahoraIso,
        unlinked_at: d2?.desvinculado_en ?? ahoraIso,
      },
      cabeceras: {},
    };
  }

  return {
    prepararVinculo, vincular, provisioning, registrarUso, deEnrolamiento,
    casos: { dispositivo, desvincularDispositivo },
  };
}
