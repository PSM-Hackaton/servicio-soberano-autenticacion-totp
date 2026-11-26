// Usuarios demo del portal (ficticios). Contraseñas con scrypt; estado del segundo factor por usuario.
// La institución guarda solo el enrollment_id del servicio TOTP: nunca la semilla.

import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { normalizarCedula, formatearCedula, seudonimo } from './cedula.js';

const PARAMS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const LONGITUD = 32;

/** @returns {Promise<Buffer>} */
const derivar = (clave, sal, p = PARAMS) => new Promise((ok, mal) => {
  scrypt(String(clave).normalize('NFKC'), sal, LONGITUD, p, (e, k) => (e ? mal(e) : ok(k)));
});

/** Hash autodescriptivo: scrypt$N$r$p$sal$hash (base64url). */
export async function hashearContrasena(clave) {
  const sal = randomBytes(16);
  const k = await derivar(clave, sal);
  return `scrypt$${PARAMS.N}$${PARAMS.r}$${PARAMS.p}$${sal.toString('base64url')}$${k.toString('base64url')}`;
}

/** Comparación en tiempo constante. */
export async function verificarContrasena(clave, hash) {
  const [alg, N, r, p, sal, esperado] = String(hash).split('$');
  if (alg !== 'scrypt' || !sal || !esperado) return false;
  const ref = Buffer.from(esperado, 'base64url');
  const k = await derivar(clave, Buffer.from(sal, 'base64url'), { N: Number(N), r: Number(r), p: Number(p), maxmem: PARAMS.maxmem });
  return k.length === ref.length && timingSafeEqual(k, ref);
}

// Hash de relleno para usuarios inexistentes: mismo coste, misma respuesta (sin enumeración).
let hashRelleno = null;
async function relleno() {
  hashRelleno ??= await hashearContrasena(randomBytes(12).toString('hex'));
  return hashRelleno;
}

/**
 * Ciudadanos ficticios, identificados por cédulas de PRUEBA (series 10.000.00x y 80.000.00x, que no
 * corresponden a nadie). Las contraseñas son públicas a propósito: es una demo.
 */
export const USUARIOS_DEMO = [
  { cedula: 'V-10.000.001', nombre: 'Ana Rivera Soto', contrasena: 'Tramites-Demo-2026' },
  { cedula: 'V-10.000.002', nombre: 'Bruno Méndez Lara', contrasena: 'Tramites-Demo-2026' },
  { cedula: 'E-80.000.003', nombre: 'Carla Ortiz Peña', contrasena: 'Tramites-Demo-2026' },
];

const VERSION = 2;

/**
 * Secreto con el que se derivan los seudónimos (`user_ref`). Prioridad: el valor configurado
 * (PORTAL_SECRETO_SEUDONIMOS, al menos 32 caracteres); si no, `seudonimos.clave` junto al archivo de
 * usuarios, que se crea al azar la primera vez (0600). Cambiarlo desvincula a todos del servicio TOTP.
 */
export function secretoSeudonimos(archivo, configurado = '') {
  if (configurado) {
    if (configurado.length < 32) throw new Error('PORTAL_SECRETO_SEUDONIMOS debe tener al menos 32 caracteres');
    return configurado;
  }
  const ruta = join(dirname(archivo), 'seudonimos.clave');
  if (existsSync(ruta)) return readFileSync(ruta, 'utf8').trim();
  mkdirSync(dirname(ruta), { recursive: true });
  const nuevo = randomBytes(32).toString('hex');
  writeFileSync(ruta, `${nuevo}\n`, { mode: 0o600, flag: 'wx' });
  return nuevo;
}

/** Genera el archivo de usuarios (sobrescribe). @returns {Promise<object[]>} */
export async function generarUsuarios(archivo, lista = USUARIOS_DEMO) {
  const usuarios = [];
  for (const u of lista) {
    const cedula = normalizarCedula('V', u.cedula);
    if (!cedula) throw new Error(`Cédula de demostración no válida: ${u.cedula}`);
    usuarios.push({ cedula, nombre: u.nombre, hash: await hashearContrasena(u.contrasena), factor: null });
  }
  guardar(archivo, usuarios);
  return usuarios;
}

function guardar(archivo, usuarios) {
  mkdirSync(dirname(archivo), { recursive: true });
  const tmp = `${archivo}.${process.pid}.tmp`;
  // El seudónimo no se guarda: se deriva al abrir (cédula + secreto).
  const datos = usuarios.map(({ cedula, nombre, hash, factor }) => ({ cedula, nombre, hash, factor }));
  writeFileSync(tmp, JSON.stringify({ version: VERSION, usuarios: datos }, null, 2) + '\n', { mode: 0o600 });
  renameSync(tmp, archivo);
}

/**
 * Repositorio de usuarios sobre un JSON local, indexado por cédula normalizada (V12345678).
 * @param {string} archivo @param {{ secreto?: string }} [o]
 */
export async function abrirUsuarios(archivo, { secreto = '' } = {}) {
  const clave = secretoSeudonimos(archivo, secreto);
  // Un archivo de una versión anterior (usuarios por nombre) se regenera: son datos de demostración.
  if (!existsSync(archivo) || JSON.parse(readFileSync(archivo, 'utf8')).version !== VERSION) await generarUsuarios(archivo);
  const { usuarios } = JSON.parse(readFileSync(archivo, 'utf8'));
  for (const u of usuarios) {
    // Identificador opaco que se envía al servicio TOTP: ni la cédula ni el nombre salen del portal.
    u.userRef = seudonimo(u.cedula, clave);
    u.cedulaFormateada = formatearCedula(u.cedula);
  }
  const porCedula = new Map(usuarios.map((u) => [u.cedula, u]));

  return {
    /** Valida cédula normalizada + contraseña; null si no coincide (mismo coste exista o no). */
    async autenticar(cedula, contrasena) {
      const u = porCedula.get(String(cedula));
      const ok = await verificarContrasena(contrasena, u?.hash ?? await relleno());
      return u && ok ? u : null;
    },
    buscar: (cedula) => porCedula.get(cedula) ?? null,
    /** Registra/borra el factor TOTP del usuario (solo el enrollment_id). */
    fijarFactor(cedula, factor) {
      const u = porCedula.get(cedula);
      if (!u) return;
      u.factor = factor;
      guardar(archivo, usuarios);
    },
    listar: () => usuarios.map(({ cedula, cedulaFormateada, nombre, factor }) => ({ cedula, cedulaFormateada, nombre, conFactor: Boolean(factor) })),
  };
}
