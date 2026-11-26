// Usuarios demo del portal (ficticios). Contraseñas con scrypt; estado del segundo factor por usuario.
// La institución guarda solo el enrollment_id del servicio TOTP: nunca la semilla.

import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

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

/** Ciudadanos ficticios. Las contraseñas son públicas a propósito: es una demo. */
export const USUARIOS_DEMO = [
  { usuario: 'ana.rivera', nombre: 'Ana Rivera Soto', documento: 'DEMO-0001', contrasena: 'Tramites-Demo-2026' },
  { usuario: 'bruno.mendez', nombre: 'Bruno Méndez Lara', documento: 'DEMO-0002', contrasena: 'Tramites-Demo-2026' },
  { usuario: 'carla.ortiz', nombre: 'Carla Ortiz Peña', documento: 'DEMO-0003', contrasena: 'Tramites-Demo-2026' },
];

/** Genera el archivo de usuarios (sobrescribe). @returns {Promise<object[]>} */
export async function generarUsuarios(archivo, lista = USUARIOS_DEMO) {
  const usuarios = [];
  for (const u of lista) {
    usuarios.push({
      usuario: u.usuario,
      nombre: u.nombre,
      documento: u.documento,
      // Identificador opaco que se envía al servicio TOTP: ni nombre ni documento salen del portal.
      userRef: `ptd-${randomBytes(12).toString('hex')}`,
      hash: await hashearContrasena(u.contrasena),
      factor: null,
    });
  }
  guardar(archivo, usuarios);
  return usuarios;
}

function guardar(archivo, usuarios) {
  mkdirSync(dirname(archivo), { recursive: true });
  const tmp = `${archivo}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ version: 1, usuarios }, null, 2) + '\n', { mode: 0o600 });
  renameSync(tmp, archivo);
}

/** Repositorio de usuarios sobre un JSON local. */
export async function abrirUsuarios(archivo) {
  if (!existsSync(archivo)) await generarUsuarios(archivo);
  const { usuarios } = JSON.parse(readFileSync(archivo, 'utf8'));
  const porNombre = new Map(usuarios.map((u) => [u.usuario, u]));

  return {
    /** Valida usuario + contraseña; null si no coincide (mismo coste exista o no el usuario). */
    async autenticar(usuario, clave) {
      const u = porNombre.get(String(usuario).trim().toLowerCase());
      const ok = await verificarContrasena(clave, u?.hash ?? await relleno());
      return u && ok ? u : null;
    },
    buscar: (usuario) => porNombre.get(usuario) ?? null,
    /** Registra/borra el factor TOTP del usuario (solo el enrollment_id). */
    fijarFactor(usuario, factor) {
      const u = porNombre.get(usuario);
      if (!u) return;
      u.factor = factor;
      guardar(archivo, usuarios);
    },
    listar: () => usuarios.map(({ usuario, nombre, factor }) => ({ usuario, nombre, conFactor: Boolean(factor) })),
  };
}
