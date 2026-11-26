// Bóveda cifrada de cuentas. Las semillas y los metadatos se guardan en IndexedDB
// únicamente como texto cifrado AES-256-GCM con una llave derivada del PIN (PBKDF2-SHA256).
// La llave vive solo en memoria mientras la app está desbloqueada y no es extraíble.

import { escribir, eliminarTodo, leer } from './almacen.js';
import { ITERACIONES_PBKDF2, bytesAleatorios, cifrarJson, derivarLlave, descifrarJson } from './cripto.js';

const AAD = 'autenticador-soberano/boveda/v1';
const CLAVE_BOVEDA = 'boveda';
const CLAVE_INTENTOS = 'intentos';
const CLAVE_AJUSTES = 'ajustes';

/** Espera progresiva tras fallos de PIN (alineada con la política del servicio: 30 s, 2 min, 10 min, 1 h). */
const LIBRES = 4;
const ESPERAS_MS = [30_000, 120_000, 600_000, 3_600_000];

export const PIN_MIN = 6;
export const PIN_MAX = 12;

/** @type {CryptoKey | null} */
let llave = null;
/** @type {any[] | null} */
let cuentas = null;
let registro = null;

/** Comprueba la calidad del PIN. Devuelve un mensaje de error o null. */
export function problemaDePin(pin) {
  if (!/^\d+$/.test(pin)) return 'El PIN solo puede tener números.';
  if (pin.length < PIN_MIN) return `El PIN debe tener al menos ${PIN_MIN} dígitos.`;
  if (pin.length > PIN_MAX) return `El PIN puede tener como máximo ${PIN_MAX} dígitos.`;
  if (/^(\d)\1+$/.test(pin)) return 'Evita repetir el mismo número: es fácil de adivinar.';
  const asc = '01234567890123456789';
  const desc = '98765432109876543210';
  if (asc.includes(pin) || desc.includes(pin)) return 'Evita secuencias como 123456: son fáciles de adivinar.';
  return null;
}

export function esperaParaFallos(fallos) {
  if (fallos <= LIBRES) return 0;
  return ESPERAS_MS[Math.min(fallos - LIBRES - 1, ESPERAS_MS.length - 1)];
}

export async function existe() {
  return Boolean(await leer(CLAVE_BOVEDA));
}

export function abierta() {
  return llave !== null && cuentas !== null;
}

export async function leerIntentos() {
  return (await leer(CLAVE_INTENTOS)) ?? { fallos: 0, bloqueadoHasta: 0 };
}

export async function leerAjustes() {
  return { bloqueoMin: 2, ...((await leer(CLAVE_AJUSTES)) ?? {}) };
}

export async function guardarAjustes(ajustes) {
  await escribir(CLAVE_AJUSTES, ajustes);
}

async function sellar(nuevas) {
  const { iv, datos } = await cifrarJson(llave, { version: 1, cuentas: nuevas }, AAD);
  await escribir(CLAVE_BOVEDA, { ...registro, iv, datos });
  cuentas = nuevas;
}

/** Crea la bóveda vacía con un PIN nuevo. */
export async function crear(pin) {
  const problema = problemaDePin(pin);
  if (problema) throw new Error(problema);
  const sal = bytesAleatorios(16);
  llave = await derivarLlave(pin, sal, ITERACIONES_PBKDF2);
  registro = { version: 1, kdf: { nombre: 'PBKDF2', hash: 'SHA-256', iteraciones: ITERACIONES_PBKDF2, sal } };
  await sellar([]);
  await escribir(CLAVE_INTENTOS, { fallos: 0, bloqueadoHasta: 0 });
  // Pide al navegador que no desaloje los datos por falta de espacio.
  try { await navigator.storage?.persist?.(); } catch { /* opcional */ }
}

/**
 * Intenta desbloquear. El fallo se anota ANTES de derivar la llave, de modo que cerrar la
 * pestaña a mitad del intento no lo borra; solo un acierto pone el contador a cero.
 * @returns {Promise<{ ok: true } | { ok: false, fallos: number, esperaMs: number }>}
 */
export async function desbloquear(pin) {
  const intentos = await leerIntentos();
  const ahora = Date.now();
  if (intentos.bloqueadoHasta > ahora) {
    return { ok: false, fallos: intentos.fallos, esperaMs: intentos.bloqueadoHasta - ahora };
  }
  const fallos = intentos.fallos + 1;
  const espera = esperaParaFallos(fallos);
  await escribir(CLAVE_INTENTOS, { fallos, bloqueadoHasta: espera ? ahora + espera : 0 });

  const guardado = await leer(CLAVE_BOVEDA);
  if (!guardado) throw new Error('No hay bóveda creada.');
  try {
    const candidata = await derivarLlave(String(pin), guardado.kdf.sal, guardado.kdf.iteraciones);
    const contenido = await descifrarJson(candidata, guardado, AAD);
    llave = candidata;
    registro = { version: guardado.version, kdf: guardado.kdf };
    cuentas = Array.isArray(contenido.cuentas) ? contenido.cuentas : [];
    await escribir(CLAVE_INTENTOS, { fallos: 0, bloqueadoHasta: 0 });
    return { ok: true };
  } catch {
    return { ok: false, fallos, esperaMs: espera };
  }
}

/** Olvida la llave y las cuentas descifradas. */
export function bloquear() {
  llave = null;
  cuentas = null;
  registro = null;
}

export function obtenerCuentas() {
  if (!abierta()) throw new Error('La bóveda está bloqueada.');
  return cuentas.map((c) => ({ ...c }));
}

/** Reemplaza la lista de cuentas y la vuelve a cifrar con un nonce nuevo. */
export async function guardarCuentas(nuevas) {
  if (!abierta()) throw new Error('La bóveda está bloqueada.');
  await sellar(nuevas.map((c) => ({ ...c })));
}

/** Cambia el PIN: comprueba el actual, deriva una llave nueva con sal nueva y vuelve a cifrar. */
export async function cambiarPin(actual, nuevo) {
  if (!abierta()) throw new Error('La bóveda está bloqueada.');
  const problema = problemaDePin(nuevo);
  if (problema) throw new Error(problema);
  const guardado = await leer(CLAVE_BOVEDA);
  try {
    const comprobacion = await derivarLlave(String(actual), guardado.kdf.sal, guardado.kdf.iteraciones);
    await descifrarJson(comprobacion, guardado, AAD);
  } catch {
    throw new Error('El PIN actual no es correcto.');
  }
  const sal = bytesAleatorios(16);
  llave = await derivarLlave(nuevo, sal, ITERACIONES_PBKDF2);
  registro = { version: 1, kdf: { nombre: 'PBKDF2', hash: 'SHA-256', iteraciones: ITERACIONES_PBKDF2, sal } };
  await sellar(cuentas);
}

/** Borra la bóveda, los ajustes y el contador. No se puede deshacer. */
export async function borrarTodo() {
  bloquear();
  await eliminarTodo();
}
