// Verificación independiente de la bitácora encadenada en el navegador (Web Crypto).
// Reproduce exactamente el algoritmo de backend/src/audit/cadena.js:
//   hash = SHA-256_hex( prev_hash + '|' + JSON canónico { accion, actor, detalle, objetivo, ts } )
// Así la consola no tiene que confiar ciegamente en la respuesta del servidor.

export const HASH_GENESIS = '0'.repeat(64);

/** JSON determinista con claves ordenadas (igual que serializarCanonico del servidor). */
export function serializarCanonico(valor) {
  if (valor === null || typeof valor !== 'object') {
    const texto = JSON.stringify(valor);
    return texto === undefined ? 'null' : texto;
  }
  if (Array.isArray(valor)) return `[${valor.map((v) => serializarCanonico(v)).join(',')}]`;
  const partes = Object.keys(valor)
    .filter((k) => valor[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${serializarCanonico(valor[k])}`);
  return `{${partes.join(',')}}`;
}

function normalizarDetalle(detalle) {
  if (detalle === undefined || detalle === null) return null;
  if (typeof detalle === 'string') return detalle;
  return serializarCanonico(detalle);
}

/** ¿Está disponible Web Crypto? (requiere contexto seguro: HTTPS o localhost). */
export const hayWebCrypto = () => Boolean(globalThis.crypto?.subtle);

/** SHA-256 hexadecimal de un texto. */
export async function sha256Hex(texto) {
  const datos = new TextEncoder().encode(texto);
  const digest = await crypto.subtle.digest('SHA-256', datos);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Hash esperado de una fila. */
export function calcularHash(prevHash, { ts, actor, accion, objetivo = null, detalle = null }) {
  const contenido = serializarCanonico({ ts, actor, accion, objetivo: objetivo ?? null, detalle: normalizarDetalle(detalle) });
  return sha256Hex(`${prevHash}|${contenido}`);
}

/**
 * Verifica una secuencia contigua de filas (ordenadas por id ascendente).
 * @param {any[]} filas
 * @param {string | null} [prevEsperado] hash de la fila anterior a la primera (null = no comprobar el enlace inicial)
 * @returns {Promise<{ intacta: boolean, rotaEnId: number | null, porFila: Map<number, boolean>, ultimoHash: string | null }>}
 */
export async function verificarFilas(filas, prevEsperado = null) {
  const porFila = new Map();
  let esperado = prevEsperado;
  let rotaEnId = null;
  for (const fila of filas) {
    const enlaza = esperado === null || fila.prev_hash === esperado;
    const recalculado = await calcularHash(fila.prev_hash, fila);
    const ok = enlaza && recalculado === fila.hash;
    porFila.set(fila.id, ok);
    if (!ok && rotaEnId === null) rotaEnId = fila.id ?? null;
    esperado = fila.hash;
  }
  return { intacta: rotaEnId === null, rotaEnId, porFila, ultimoHash: filas.length ? filas[filas.length - 1].hash : null };
}
