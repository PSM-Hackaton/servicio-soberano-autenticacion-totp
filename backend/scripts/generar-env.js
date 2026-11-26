// Crea backend/.env a partir de .env.example sustituyendo cada CHANGE_ME por valores aleatorios
// fuertes del CSPRNG (node:crypto) y fijando el emisor TOTP neutro. Nunca sobrescribe un .env existente.
// Uso: node scripts/generar-env.js [--salida <ruta>]

import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { EMISOR_TOTP_POR_DEFECTO } from '../src/infrastructure/config/config.js';

const CARPETA_BACKEND = fileURLToPath(new URL('../', import.meta.url));
const PLANTILLA = resolve(CARPETA_BACKEND, '..', '.env.example');

/**
 * Variables cuyo valor generado es siempre el neutro del backend, aunque la plantilla traiga otro
 * (p. ej. un emisor con el nombre de un organismo real). Para personalizarlas, edite el .env creado.
 */
const VALORES_FIJOS = Object.freeze({ TOTP_ISSUER: EMISOR_TOTP_POR_DEFECTO });

/** Valor aleatorio adecuado para cada variable: llaves maestras de 256 bits en hex; el resto, base64url. */
function valorAleatorio(nombre) {
  if (/^MASTER_KEY_[A-Z0-9]+_HEX$/.test(nombre)) return randomBytes(32).toString('hex'); // 64 hex = 256 bits
  return randomBytes(32).toString('base64url'); // peppers: 256 bits
}

/**
 * Genera el contenido del .env desde el texto de la plantilla.
 * @param {string} plantilla
 * @returns {string}
 */
export function generarContenido(plantilla) {
  return plantilla.split(/\r?\n/).map((linea) => {
    const m = /^(\s*)([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(linea);
    if (!m) return linea;
    const [, sangria, nombre, valor] = m;
    if (Object.hasOwn(VALORES_FIJOS, nombre)) return `${sangria}${nombre}=${VALORES_FIJOS[nombre]}`;
    if (!valor.includes('CHANGE_ME')) return linea;
    return `${sangria}${nombre}=${valorAleatorio(nombre)}`;
  }).join('\n');
}

function principal(argv) {
  const i = argv.indexOf('--salida');
  const destino = i >= 0 && argv[i + 1] ? resolve(argv[i + 1]) : resolve(CARPETA_BACKEND, '.env');
  if (existsSync(destino)) {
    console.log(`Ya existe ${destino}: no se sobrescribe. Bórrelo a mano si quiere regenerarlo.`);
    return 0;
  }
  const contenido = generarContenido(readFileSync(PLANTILLA, 'utf8'));
  // 'wx' falla si el archivo apareció entretanto; 0600: solo el propietario puede leerlo.
  writeFileSync(destino, contenido.endsWith('\n') ? contenido : `${contenido}\n`, { flag: 'wx', mode: 0o600 });
  console.log(`Creado ${destino} con secretos aleatorios (permisos 600). No lo suba nunca al repositorio.`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = principal(process.argv.slice(2));
}
