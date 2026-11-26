// Generador pseudoaleatorio determinista con semilla (mulberry32).
// No es criptográfico: solo sirve para que el entrenamiento y el tráfico sintético sean reproducibles.

/**
 * @typedef {object} Aleatorio
 * @property {() => number} siguiente Flotante uniforme en [0, 1).
 * @property {(min: number, max: number) => number} rango Flotante uniforme en [min, max).
 * @property {(min: number, max: number) => number} entero Entero uniforme en [min, max] (ambos incluidos).
 * @property {(p: number) => boolean} bernoulli Verdadero con probabilidad p.
 * @property {(media?: number, desviacion?: number) => number} normal Muestra gaussiana (Box-Muller).
 * @property {<T>(lista: T[]) => T} elegir Elemento uniforme de la lista.
 * @property {<T>(lista: T[]) => T[]} barajar Copia barajada (Fisher-Yates).
 */

/**
 * Convierte una semilla (número o texto) en un entero de 32 bits. Los textos usan FNV-1a.
 * @param {number | string} semilla
 */
export function semillaANumero(semilla) {
  if (typeof semilla === 'number' && Number.isFinite(semilla)) return Math.trunc(semilla) >>> 0;
  const texto = String(semilla);
  let h = 0x811c9dc5;
  for (let i = 0; i < texto.length; i++) {
    h ^= texto.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/**
 * Crea un generador determinista: la misma semilla produce siempre la misma secuencia.
 * @param {number | string} [semilla]
 * @returns {Aleatorio}
 */
export function crearAleatorio(semilla = 1) {
  let estado = semillaANumero(semilla);
  const siguiente = () => {
    estado = (estado + 0x6d2b79f5) >>> 0;
    let t = estado;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const rango = (min, max) => min + siguiente() * (max - min);
  const entero = (min, max) => min + Math.floor(siguiente() * (max - min + 1));
  return {
    siguiente,
    rango,
    entero,
    bernoulli: (p) => siguiente() < p,
    normal(media = 0, desviacion = 1) {
      const u = 1 - siguiente();
      const v = siguiente();
      return media + desviacion * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
    },
    elegir: (lista) => lista[Math.floor(siguiente() * lista.length)],
    barajar(lista) {
      const copia = lista.slice();
      for (let i = copia.length - 1; i > 0; i--) {
        const j = Math.floor(siguiente() * (i + 1));
        [copia[i], copia[j]] = [copia[j], copia[i]];
      }
      return copia;
    },
  };
}
