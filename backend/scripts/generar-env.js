// Crea backend/.env a partir de .env.example sustituyendo cada CHANGE_ME por valores aleatorios
// fuertes del CSPRNG (node:crypto). Nunca sobrescribe un .env existente.
// Uso: node scripts/generar-env.js [--salida <ruta>]

import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const CARPETA_BACKEND = fileURLToPath(new URL('../', import.meta.url));
const PLANTILLA = resolve(CARPETA_BACKEND, '..', '.env.example');

/** Valor aleatorio adecuado para cada variable conocida. */
function valorAleatorio(nombre) {
  if (/^MASTER_KEY_[A-Z0-9]+_HEX$/.test(nombre)) return randomBytes(32).toString('hex'); // 64 hex = 256 bits
  if (nombre === 'ADMIN_SESSION_SECRET') return randomBytes(64).toString('base64url');
  return randomBytes(32).toString('base64url'); // peppers y demás: 256 bits
}

/**
 * Genera el contenido del .env desde el texto de la plantilla.
 * @param {string} plantilla
 * @returns {string}
 */
export function generarContenido(plantilla) {
  return plantilla.split(/\r?\n/).map((linea) => {
    const m = /^(\s*)([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(linea);
    if (!m || !m[3].includes('CHANGE_ME')) return linea;
    const [, sangria, nombre, valor] = m;
    if (nombre === 'ADMIN_SEED_PASS') {
      // La semilla genera la contraseña del admin y la muestra una sola vez; no se guarda aquí.
      return `${sangria}# ${nombre}: no se usa; "npm run seed" genera una contraseña aleatoria y la muestra una vez.`;
    }
    // Sustituye solo el marcador (p. ej. dentro de DATABASE_URL) o el valor completo.
    const nuevo = /^CHANGE_ME[A-Z0-9_]*$/.test(valor.trim())
      ? valorAleatorio(nombre)
      : valor.replace(/CHANGE_ME[A-Z0-9_]*/g, () => randomBytes(24).toString('hex'));
    return `${sangria}${nombre}=${nuevo}`;
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
