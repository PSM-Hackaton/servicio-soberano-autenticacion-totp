// Primitivas de cifrado del autenticador con Web Crypto (sin dependencias).
// PBKDF2-SHA256 deriva una llave AES-256-GCM no extraíble a partir del PIN o de la
// contraseña de respaldo. Módulo puro: se prueba en Node 22.

/** OWASP (2023) recomienda ≥ 600 000 iteraciones para PBKDF2-HMAC-SHA256. */
export const ITERACIONES_PBKDF2 = 600_000;
export const ITERACIONES_MINIMAS = 310_000;

const codificador = new TextEncoder();
const decodificador = new TextDecoder();

function sutil() {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('Web Crypto no disponible (se requiere contexto seguro)');
  return s;
}

/** @param {number} n */
export function bytesAleatorios(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** @param {Uint8Array} bytes */
export function aBase64(bytes) {
  let binario = '';
  for (const b of bytes) binario += String.fromCharCode(b);
  return btoa(binario);
}

/** @param {string} texto */
export function deBase64(texto) {
  const binario = atob(texto);
  const bytes = new Uint8Array(binario.length);
  for (let i = 0; i < binario.length; i++) bytes[i] = binario.charCodeAt(i);
  return bytes;
}

/**
 * Deriva una llave AES-GCM de 256 bits (no extraíble) con PBKDF2-SHA256.
 * @param {string} secreto PIN o contraseña
 * @param {Uint8Array} sal 16 bytes aleatorios
 * @param {number} iteraciones
 */
export async function derivarLlave(secreto, sal, iteraciones = ITERACIONES_PBKDF2) {
  const material = await sutil().importKey('raw', codificador.encode(secreto), 'PBKDF2', false, ['deriveKey']);
  return sutil().deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: sal, iterations: iteraciones },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Cifra un objeto JSON con AES-256-GCM (nonce aleatorio de 96 bits y datos asociados).
 * @param {CryptoKey} llave @param {unknown} objeto @param {string} aad
 * @returns {Promise<{ iv: Uint8Array, datos: Uint8Array }>}
 */
export async function cifrarJson(llave, objeto, aad) {
  const iv = bytesAleatorios(12);
  const datos = await sutil().encrypt(
    { name: 'AES-GCM', iv, additionalData: codificador.encode(aad), tagLength: 128 },
    llave,
    codificador.encode(JSON.stringify(objeto)),
  );
  return { iv, datos: new Uint8Array(datos) };
}

/**
 * Descifra y verifica (la etiqueta GCM falla si la llave o los datos asociados no coinciden).
 * @param {CryptoKey} llave @param {{ iv: Uint8Array, datos: Uint8Array }} sobre @param {string} aad
 */
export async function descifrarJson(llave, sobre, aad) {
  const claro = await sutil().decrypt(
    { name: 'AES-GCM', iv: sobre.iv, additionalData: codificador.encode(aad), tagLength: 128 },
    llave,
    sobre.datos,
  );
  return JSON.parse(decodificador.decode(claro));
}

const AAD_RESPALDO = 'autenticador-soberano/respaldo/v1';
export const FORMATO_RESPALDO = 'autenticador-soberano-respaldo';

/**
 * Respaldo portátil: todo en un JSON con la sal, las iteraciones y el texto cifrado en Base64.
 * @param {unknown} objeto @param {string} contrasena
 */
export async function cifrarRespaldo(objeto, contrasena, iteraciones = ITERACIONES_PBKDF2) {
  const sal = bytesAleatorios(16);
  const llave = await derivarLlave(contrasena, sal, iteraciones);
  const { iv, datos } = await cifrarJson(llave, objeto, AAD_RESPALDO);
  return {
    formato: FORMATO_RESPALDO,
    version: 1,
    kdf: { nombre: 'PBKDF2', hash: 'SHA-256', iteraciones, sal: aBase64(sal) },
    cifrado: { nombre: 'AES-GCM', iv: aBase64(iv), datos: aBase64(datos) },
    creado: new Date().toISOString(),
  };
}

/** @param {any} sobre @param {string} contrasena */
export async function descifrarRespaldo(sobre, contrasena) {
  if (
    !sobre || sobre.formato !== FORMATO_RESPALDO || sobre.version !== 1 ||
    sobre.kdf?.nombre !== 'PBKDF2' || sobre.kdf?.hash !== 'SHA-256' || sobre.cifrado?.nombre !== 'AES-GCM'
  ) {
    throw new Error('El archivo no es un respaldo válido del Autenticador Soberano.');
  }
  const iteraciones = sobre.kdf.iteraciones;
  if (!Number.isInteger(iteraciones) || iteraciones < ITERACIONES_MINIMAS || iteraciones > 10_000_000) {
    throw new Error('El respaldo usa parámetros de derivación no admitidos.');
  }
  const llave = await derivarLlave(contrasena, deBase64(sobre.kdf.sal), iteraciones);
  try {
    return await descifrarJson(llave, { iv: deBase64(sobre.cifrado.iv), datos: deBase64(sobre.cifrado.datos) }, AAD_RESPALDO);
  } catch {
    throw new Error('Contraseña incorrecta o archivo alterado.');
  }
}
