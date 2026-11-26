// Carga y validación de la configuración: backend/.env (parser propio, sin dotenv) + variables de entorno.
// Las variables del proceso tienen prioridad sobre el archivo. Falla al arrancar con mensajes claros.

import { existsSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { llavesDesdeEntorno } from '../../core/vault/vault.js';

/** Carpeta backend/ (las rutas relativas del .env se resuelven respecto a ella). */
export const CARPETA_BACKEND = fileURLToPath(new URL('../../../', import.meta.url));
const RUTA_ENV_POR_DEFECTO = resolve(CARPETA_BACKEND, '.env');

const MARCADOR_SIN_CAMBIAR = 'CHANGE_ME';
const MODOS_TLS = ['node', 'off'];
const MODOS_HEURISTICA = ['local', 'monitorizacion', 'mock'];
const LONGITUD_MINIMA_PEPPER = 32;
/** Emisor neutro del URI otpauth:// (ningún valor por defecto nombra organismos reales). */
export const EMISOR_TOTP_POR_DEFECTO = 'ServicioSoberanoTOTP';

/** Error de configuración: agrupa todos los problemas encontrados. */
export class ErrorConfiguracion extends Error {
  /** @param {string[]} problemas */
  constructor(problemas) {
    super(`Configuración inválida:\n  - ${problemas.join('\n  - ')}`);
    this.name = 'ErrorConfiguracion';
    this.problemas = problemas;
  }
}

/**
 * Parser simple de archivos .env: `CLAVE=valor`, comentarios `#`, `export` opcional,
 * comillas simples (literal) o dobles (con \n, \t, \", \\). Sin interpolación de variables.
 * @param {string} texto
 * @returns {Record<string, string>}
 */
export function parsearEnv(texto) {
  /** @type {Record<string, string>} */
  const vars = Object.create(null);
  const lineas = String(texto).replace(/^﻿/, '').split(/\r?\n/);
  lineas.forEach((original, i) => {
    let linea = original.trim();
    if (linea === '' || linea.startsWith('#')) return;
    if (linea.startsWith('export ')) linea = linea.slice(7).trim();
    const igual = linea.indexOf('=');
    if (igual <= 0) throw new Error(`.env línea ${i + 1}: se esperaba CLAVE=valor`);
    const clave = linea.slice(0, igual).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(clave)) throw new Error(`.env línea ${i + 1}: nombre de variable inválido`);
    let valor = linea.slice(igual + 1).trim();
    const comilla = valor[0];
    if (comilla === '"' || comilla === "'") {
      const cierre = valor.indexOf(comilla, 1);
      let fin = cierre;
      if (comilla === '"') {
        // Busca la comilla de cierre no escapada.
        fin = -1;
        for (let j = 1; j < valor.length; j++) {
          if (valor[j] === '\\') { j++; continue; }
          if (valor[j] === '"') { fin = j; break; }
        }
      }
      if (fin === -1) throw new Error(`.env línea ${i + 1}: comilla sin cerrar`);
      const resto = valor.slice(fin + 1).trim();
      if (resto !== '' && !resto.startsWith('#')) throw new Error(`.env línea ${i + 1}: texto tras la comilla de cierre`);
      valor = valor.slice(1, fin);
      if (comilla === '"') {
        valor = valor.replace(/\\(.)/g, (_, c) => ({ n: '\n', r: '\r', t: '\t' })[c] ?? c);
      }
    } else {
      // Comentario en línea solo si va precedido de espacio.
      const m = /\s+#/.exec(valor);
      if (m) valor = valor.slice(0, m.index).trim();
    }
    vars[clave] = valor;
  });
  return vars;
}

/**
 * Lee el .env si existe y lo combina con el entorno del proceso (el proceso gana).
 * Ruta del archivo: opción `rutaEnv`, si no la variable ENV_FILE, si no backend/.env.
 * @param {{ rutaEnv?: string, env?: Record<string, string | undefined> }} [opciones]
 * @returns {Record<string, string>}
 */
export function leerVariables({ env = process.env, rutaEnv } = {}) {
  if (rutaEnv === undefined) rutaEnv = env.ENV_FILE ? resolve(env.ENV_FILE) : RUTA_ENV_POR_DEFECTO;
  const archivo = rutaEnv && existsSync(rutaEnv) ? parsearEnv(readFileSync(rutaEnv, 'utf8')) : {};
  /** @type {Record<string, string>} */
  const combinadas = { ...archivo };
  for (const [k, v] of Object.entries(env)) if (typeof v === 'string') combinadas[k] = v;
  return combinadas;
}

/**
 * Valida las variables y produce la configuración tipada.
 * @param {Record<string, string | undefined>} vars
 * @param {{ base?: string }} [opciones] carpeta base para rutas relativas (backend/)
 */
export function validarConfig(vars, { base = CARPETA_BACKEND } = {}) {
  /** @type {string[]} */
  const problemas = [];
  const ruta = (v) => (isAbsolute(v) ? v : resolve(base, v));

  /** Lee una variable; marca error si falta (cuando es obligatoria) o si conserva CHANGE_ME. */
  function texto(nombre, { obligatoria = true, defecto } = {}) {
    const v = vars[nombre];
    if (v === undefined || v === '') {
      if (defecto !== undefined) return defecto;
      if (obligatoria) problemas.push(`Falta ${nombre}`);
      return undefined;
    }
    if (v.includes(MARCADOR_SIN_CAMBIAR)) {
      problemas.push(`${nombre} conserva el valor de ejemplo (${MARCADOR_SIN_CAMBIAR}); ejecute "npm run env" o defínalo`);
      return undefined;
    }
    return v;
  }

  function entero(nombre, { defecto, min, max }) {
    const v = texto(nombre, { defecto: String(defecto) });
    if (v === undefined) return defecto;
    if (!/^\d+$/.test(v)) {
      problemas.push(`${nombre} debe ser un entero`);
      return defecto;
    }
    const n = Number(v);
    if (n < min || n > max) problemas.push(`${nombre} debe estar entre ${min} y ${max}`);
    return n;
  }

  function opcion(nombre, permitidas, defecto) {
    const v = texto(nombre, { defecto });
    if (v !== undefined && !permitidas.includes(v)) {
      problemas.push(`${nombre} debe ser uno de: ${permitidas.join(', ')} (recibido "${v}")`);
    }
    return v;
  }

  function pepper(nombre) {
    const v = texto(nombre);
    if (v !== undefined && v.length < LONGITUD_MINIMA_PEPPER) {
      problemas.push(`${nombre} debe tener al menos ${LONGITUD_MINIMA_PEPPER} caracteres aleatorios`);
    }
    return v;
  }

  const entorno = texto('NODE_ENV', { defecto: 'development' });
  const host = texto('HOST', { defecto: '0.0.0.0' });
  const puerto = entero('PORT', { defecto: 8443, min: 0, max: 65535 });

  const modoTls = opcion('TLS_MODE', MODOS_TLS, 'node');
  /** @type {{ modo: string, cert: string | null, key: string | null }} */
  const tls = { modo: modoTls, cert: null, key: null };
  if (modoTls === 'node') {
    const cert = texto('TLS_CERT_PATH');
    const key = texto('TLS_KEY_PATH');
    if (cert) tls.cert = ruta(cert);
    if (key) tls.key = ruta(key);
  } else if (modoTls === 'off' && entorno === 'production') {
    problemas.push('TLS_MODE=off no está permitido con NODE_ENV=production');
  }

  const driver = opcion('DB_DRIVER', ['sqlite'], 'sqlite');
  const rutaDb = texto('SQLITE_DB_PATH', { defecto: './data/totp_soberano.db' });

  // Llave maestra: se valida con el mismo lector que usa la bóveda.
  /** @type {ReturnType<typeof llavesDesdeEntorno> | undefined} */
  let vault;
  const llavesSinCambiar = Object.entries(vars).filter(([k, v]) => /^MASTER_KEY_[A-Z0-9]+_HEX$/.test(k) && v?.includes(MARCADOR_SIN_CAMBIAR));
  if (llavesSinCambiar.length > 0) {
    for (const [k] of llavesSinCambiar) problemas.push(`${k} conserva el valor de ejemplo (${MARCADOR_SIN_CAMBIAR}); ejecute "npm run env"`);
  } else {
    try {
      /** @type {Record<string, string | undefined>} */
      const soloLlaves = {};
      for (const [k, v] of Object.entries(vars)) if (k === 'MASTER_KEY_VERSION' || /^MASTER_KEY_[A-Z0-9]+_HEX$/.test(k)) soloLlaves[k] = v;
      vault = llavesDesdeEntorno(soloLlaves);
    } catch (e) {
      problemas.push(e.message);
    }
  }

  const userRefPepper = pepper('USER_REF_PEPPER');
  const ipPepperSemilla = pepper('DAILY_IP_PEPPER_SEED');
  const emisorTotp = texto('TOTP_ISSUER', { defecto: EMISOR_TOTP_POR_DEFECTO });
  const emisorJwt = texto('JWT_ISSUER', { defecto: 'https://totp.soberano.local' });
  const ttlJwtSegundos = entero('JWT_TTL_SECONDS', { defecto: 300, min: 30, max: 3600 });
  const heuristicas = opcion('HEURISTICS_MODE', MODOS_HEURISTICA, 'local');

  const corsTexto = texto('CORS_ALLOWED_ORIGINS', { obligatoria: false, defecto: '' }) ?? '';
  const corsOrigenes = corsTexto.split(',').map((o) => o.trim()).filter(Boolean);
  for (const o of corsOrigenes) {
    if (!/^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/.test(o)) problemas.push(`Origen CORS inválido: "${o}" (formato esquema://host[:puerto])`);
    if (entorno === 'production' && o.startsWith('http://')) problemas.push(`Origen CORS sin TLS no permitido en producción: "${o}"`);
  }

  const adminUsuario = texto('ADMIN_SEED_USER', { defecto: 'admin_seguridad' });
  if (adminUsuario && !/^[A-Za-z0-9_.-]{3,64}$/.test(adminUsuario)) problemas.push('ADMIN_SEED_USER debe tener 3 a 64 caracteres [A-Za-z0-9_.-]');

  // QR del TOTP del admin inicial (npm run seed): ADMIN_QR_PATH o, por defecto, junto a la base de datos.
  const qrTexto = texto('ADMIN_QR_PATH', { obligatoria: false });
  const carpetaDatos = rutaDb === ':memory:' ? resolve(base, 'data') : dirname(ruta(rutaDb ?? './data/totp_soberano.db'));
  const adminRutaQr = qrTexto ? ruta(qrTexto) : resolve(carpetaDatos, 'admin-qr.svg');

  const referenciaReloj = texto('CLOCK_REFERENCE_URL', { obligatoria: false });
  if (referenciaReloj && !/^https?:\/\//.test(referenciaReloj)) problemas.push('CLOCK_REFERENCE_URL debe ser una URL http(s)');

  if (problemas.length > 0) throw new ErrorConfiguracion(problemas);

  return Object.freeze({
    entorno,
    host,
    puerto,
    tls: Object.freeze(tls),
    baseDatos: Object.freeze({ driver, ruta: rutaDb === ':memory:' ? rutaDb : ruta(rutaDb) }),
    vault,
    userRefPepper,
    ipPepperSemilla,
    emisorTotp,
    emisorJwt,
    ttlJwtSegundos,
    heuristicas,
    corsOrigenes: Object.freeze(corsOrigenes),
    admin: Object.freeze({ usuarioSemilla: adminUsuario, rutaQr: adminRutaQr }),
    referenciaReloj: referenciaReloj ?? null,
  });
}

/**
 * Carga completa: .env + entorno → configuración validada.
 * @param {{ rutaEnv?: string, env?: Record<string, string | undefined>, base?: string }} [opciones]
 */
export function cargarConfig(opciones = {}) {
  return validarConfig(leerVariables(opciones), { base: opciones.base });
}

/**
 * Subconjunto que consumen los casos de uso (interfaz acordada de crearCasosDeUso).
 * @param {ReturnType<typeof validarConfig>} config
 */
export function configCasosDeUso(config) {
  return {
    userRefPepper: config.userRefPepper,
    ipPepperSemilla: config.ipPepperSemilla,
    emisorTotp: config.emisorTotp,
    emisorJwt: config.emisorJwt,
    ttlJwtSegundos: config.ttlJwtSegundos,
    minutosPendiente: 10,
    modoHeuristica: config.heuristicas,
  };
}
