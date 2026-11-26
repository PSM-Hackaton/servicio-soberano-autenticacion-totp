// Sesiones en memoria con cookie HttpOnly; Secure; SameSite=Strict, CSRF por sesión
// y rotación del identificador en cada cambio de privilegio (contraseña, segundo factor).

import { randomBytes, timingSafeEqual } from 'node:crypto';

const MAX_TRAZAS = 40;
const VIDA_ABSOLUTA_MS = 8 * 60 * 60 * 1000;

/**
 * @typedef {{
 *   id: string, csrf: string, creada: number, ultimoUso: number,
 *   etapa: 'anonima' | 'contrasena' | 'autenticado', usuario: string | null,
 *   mfa: null | { en: number, jti: string, exp: number, amr: string[], kid: string, modo: string },
 *   enrolamiento: null | Record<string, any>, codigosRecuperacion: string[] | null,
 *   bloqueadoHasta: number, trazas: any[], trazasVisibles: boolean, aviso: null | { tipo: string, texto: string },
 *   comprobantes: any[]
 * }} Sesion
 */

/** @param {{ nombreCookie: string, minutosInactividad: number, trazasPorDefecto: boolean }} o */
export function crearAlmacenSesiones({ nombreCookie, minutosInactividad, trazasPorDefecto }) {
  /** @type {Map<string, Sesion>} */
  const sesiones = new Map();
  const inactividadMs = minutosInactividad * 60 * 1000;

  const nuevoId = () => randomBytes(32).toString('base64url');

  /** @returns {Sesion} */
  function crear() {
    const ahora = Date.now();
    const s = {
      id: nuevoId(), csrf: randomBytes(32).toString('base64url'), creada: ahora, ultimoUso: ahora,
      etapa: /** @type {const} */ ('anonima'), usuario: null, mfa: null, enrolamiento: null, codigosRecuperacion: null,
      bloqueadoHasta: 0, trazas: [], trazasVisibles: trazasPorDefecto, aviso: null, comprobantes: [],
    };
    sesiones.set(s.id, s);
    return s;
  }

  /** Obtiene la sesión de la cookie o crea una anónima. */
  function obtener(req) {
    const id = leerCookie(req.headers.cookie, nombreCookie);
    const s = id ? sesiones.get(id) : undefined;
    const ahora = Date.now();
    if (s && ahora - s.ultimoUso < inactividadMs && ahora - s.creada < VIDA_ABSOLUTA_MS) {
      s.ultimoUso = ahora;
      return { sesion: s, nueva: false };
    }
    if (s) sesiones.delete(s.id);
    return { sesion: crear(), nueva: true };
  }

  /** Nuevo id y nuevo CSRF conservando el estado (previene fijación de sesión). */
  function rotar(s) {
    sesiones.delete(s.id);
    s.id = nuevoId();
    s.csrf = randomBytes(32).toString('base64url');
    sesiones.set(s.id, s);
    return s;
  }

  function destruir(s) {
    sesiones.delete(s.id);
  }

  /** @param {Sesion} s */
  function cookie(s) {
    // Secure siempre: los navegadores lo aceptan también en http://localhost (contexto seguro).
    return `${nombreCookie}=${s.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(inactividadMs / 1000)}`;
  }

  function cookieBorrada() {
    return `${nombreCookie}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
  }

  // Limpieza periódica de sesiones vencidas.
  const limpieza = setInterval(() => {
    const ahora = Date.now();
    for (const [id, s] of sesiones) if (ahora - s.ultimoUso > inactividadMs || ahora - s.creada > VIDA_ABSOLUTA_MS) sesiones.delete(id);
  }, 60 * 1000);
  limpieza.unref();

  return { obtener, rotar, destruir, cookie, cookieBorrada, detener: () => clearInterval(limpieza), total: () => sesiones.size };
}

/** CSRF en tiempo constante. */
export function csrfValido(sesion, enviado) {
  if (typeof enviado !== 'string' || enviado.length !== sesion.csrf.length) return false;
  return timingSafeEqual(Buffer.from(enviado), Buffer.from(sesion.csrf));
}

/** Agrega una traza educativa a la sesión (nunca contraseñas, códigos, secretos ni tokens completos). */
export function trazar(sesion, { tipo = 'info', titulo, detalle = '', ms = null, estado = 'ok', bloque = null }) {
  if (!sesion) return;
  sesion.trazas.push({ en: Date.now(), tipo, titulo, detalle, ms, estado, bloque });
  if (sesion.trazas.length > MAX_TRAZAS) sesion.trazas.splice(0, sesion.trazas.length - MAX_TRAZAS);
}

function leerCookie(cabecera, nombre) {
  if (!cabecera) return null;
  for (const parte of cabecera.split(';')) {
    const i = parte.indexOf('=');
    if (i > 0 && parte.slice(0, i).trim() === nombre) return parte.slice(i + 1).trim();
  }
  return null;
}
