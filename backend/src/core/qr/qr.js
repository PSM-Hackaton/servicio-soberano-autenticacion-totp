// Codificador QR propio (ISO/IEC 18004:2015). Sin dependencias: solo JavaScript.
// Modo byte (UTF-8), niveles L/M/Q/H, versiones 1 a 40 con selección automática de la mínima.
// Funciones puras: reciben texto y devuelven una matriz de módulos o un SVG.

import { correccionRs } from './reedSolomon.js';

/** @typedef {'L' | 'M' | 'Q' | 'H'} Nivel */
/** @typedef {{ version: number, tamano: number, nivel: Nivel, mascara: number, modulos: boolean[][] }} Qr */

export const VERSION_MIN = 1;
export const VERSION_MAX = 40;

/** Bits de nivel en la información de formato (tabla 12 de la norma). */
export const BITS_NIVEL = { L: 0b01, M: 0b00, Q: 0b11, H: 0b10 };

// Tabla 9 de la norma: bytes de corrección por bloque, por nivel y versión (índice 0 sin uso).
const CORRECCION_POR_BLOQUE = {
  L: [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  M: [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  Q: [0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  H: [0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
};

// Tabla 9 de la norma: número total de bloques de corrección, por nivel y versión.
const NUMERO_DE_BLOQUES = {
  L: [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  M: [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  Q: [0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  H: [0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
};

const PENALIZACION = { N1: 3, N2: 3, N3: 40, N4: 10 };

/** Lado de la matriz en módulos: 17 + 4·versión. @param {number} version */
export function tamanoDeVersion(version) {
  return 17 + 4 * version;
}

/**
 * Centros de los patrones de alineación (anexo E de la norma), calculados en lugar de tabulados.
 * @param {number} version
 * @returns {number[]}
 */
export function posicionesAlineacion(version) {
  if (version === 1) return [];
  const cantidad = Math.floor(version / 7) + 2;
  const paso = Math.floor((version * 8 + cantidad * 3 + 5) / (cantidad * 4 - 4)) * 2;
  const posiciones = [6];
  for (let p = tamanoDeVersion(version) - 7; posiciones.length < cantidad; p -= paso) posiciones.splice(1, 0, p);
  return posiciones;
}

/** Módulos disponibles para datos y corrección (todo menos patrones de función y formato/versión). */
function modulosDeDatos(version) {
  let n = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const a = Math.floor(version / 7) + 2;
    n -= (25 * a - 10) * a - 55;
    if (version >= 7) n -= 36;
  }
  return n;
}

/** Total de bytes (datos + corrección) que caben en una versión. */
function bytesTotales(version) {
  return Math.floor(modulosDeDatos(version) / 8);
}

/** Bytes de datos útiles para una versión y nivel. @param {number} version @param {Nivel} nivel */
export function capacidadDatos(version, nivel) {
  return bytesTotales(version) - CORRECCION_POR_BLOQUE[nivel][version] * NUMERO_DE_BLOQUES[nivel][version];
}

/** Bits del indicador de longitud en modo byte: 8 hasta la versión 9, 16 desde la 10. */
function bitsDeLongitud(version) {
  return version <= 9 ? 8 : 16;
}

/**
 * Versión mínima en la que caben n bytes en modo byte con el nivel indicado.
 * @param {number} n @param {Nivel} nivel
 */
export function versionMinima(n, nivel) {
  for (let v = VERSION_MIN; v <= VERSION_MAX; v++) {
    if (4 + bitsDeLongitud(v) + 8 * n <= capacidadDatos(v, nivel) * 8) return v;
  }
  throw new Error('Texto demasiado largo para un código QR');
}

/** Acumulador de bits en orden MSB primero. */
class Bits {
  constructor() {
    /** @type {number[]} */
    this.bits = [];
  }

  /** @param {number} valor @param {number} longitud */
  agregar(valor, longitud) {
    for (let i = longitud - 1; i >= 0; i--) this.bits.push((valor >>> i) & 1);
  }
}

/**
 * Secuencia de bytes de datos: indicador de modo, longitud, contenido, terminador y relleno (sección 7.4).
 * @param {Uint8Array} contenido @param {number} version @param {Nivel} nivel
 */
function codificarDatos(contenido, version, nivel) {
  const capacidadBits = capacidadDatos(version, nivel) * 8;
  const b = new Bits();
  b.agregar(0b0100, 4); // modo byte
  b.agregar(contenido.length, bitsDeLongitud(version));
  for (const byte of contenido) b.agregar(byte, 8);
  b.agregar(0, Math.min(4, capacidadBits - b.bits.length)); // terminador
  b.agregar(0, (8 - (b.bits.length % 8)) % 8); // alineación a byte
  const bytes = [];
  for (let i = 0; i < b.bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | b.bits[i + j];
    bytes.push(byte);
  }
  for (let relleno = 0xec; bytes.length < capacidadBits / 8; relleno ^= 0xec ^ 0x11) bytes.push(relleno);
  return bytes;
}

/**
 * Divide los datos en bloques, añade la corrección Reed-Solomon de cada uno y entrelaza (sección 7.6).
 * Los bloques cortos van primero; los largos tienen un byte de datos más.
 * @param {number[]} datos @param {number} version @param {Nivel} nivel
 * @returns {number[]}
 */
export function construirCodewords(datos, version, nivel) {
  const nBloques = NUMERO_DE_BLOQUES[nivel][version];
  const nCorreccion = CORRECCION_POR_BLOQUE[nivel][version];
  const total = bytesTotales(version);
  const nCortos = nBloques - (total % nBloques);
  const largoCorto = Math.floor(total / nBloques); // datos + corrección de un bloque corto
  if (datos.length !== capacidadDatos(version, nivel)) throw new Error('Longitud de datos inconsistente');

  const bloquesDatos = [];
  const bloquesCorreccion = [];
  let k = 0;
  for (let i = 0; i < nBloques; i++) {
    const nDatos = largoCorto - nCorreccion + (i < nCortos ? 0 : 1);
    const bloque = datos.slice(k, k + nDatos);
    k += nDatos;
    bloquesDatos.push(bloque);
    bloquesCorreccion.push(correccionRs(bloque, nCorreccion));
  }

  const salida = [];
  const maxDatos = largoCorto - nCorreccion + 1;
  for (let j = 0; j < maxDatos; j++) {
    for (const bloque of bloquesDatos) if (j < bloque.length) salida.push(bloque[j]);
  }
  for (let j = 0; j < nCorreccion; j++) {
    for (const bloque of bloquesCorreccion) salida.push(bloque[j]);
  }
  return salida;
}

/** Resto BCH de valor·x^grado módulo el polinomio indicado. */
function restoBch(valor, polinomio, grado) {
  let r = valor << grado;
  for (let i = 31 - Math.clz32(r); i >= grado; i--) {
    if ((r >>> i) & 1) r ^= polinomio << (i - grado);
  }
  return r;
}

/**
 * 15 bits de formato: 2 de nivel + 3 de máscara, BCH(15,5) con 0x537 y máscara XOR 0x5412 (sección 7.9).
 * @param {Nivel} nivel @param {number} mascara
 */
export function bitsDeFormato(nivel, mascara) {
  const datos = (BITS_NIVEL[nivel] << 3) | mascara;
  return ((datos << 10) | restoBch(datos, 0x537, 10)) ^ 0x5412;
}

/** 18 bits de versión: 6 de versión + BCH(18,6) con 0x1F25 (sección 7.10). @param {number} version */
export function bitsDeVersion(version) {
  return (version << 12) | restoBch(version, 0x1f25, 12);
}

/** Condiciones de las 8 máscaras (tabla 10); x = columna, y = fila. */
const MASCARAS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

/** Matriz en construcción: módulos y marca de qué celdas pertenecen a patrones de función. */
class Matriz {
  /** @param {number} version */
  constructor(version) {
    this.version = version;
    this.tamano = tamanoDeVersion(version);
    this.modulos = Array.from({ length: this.tamano }, () => new Array(this.tamano).fill(false));
    this.funcion = Array.from({ length: this.tamano }, () => new Array(this.tamano).fill(false));
  }

  /** Fija un módulo de función. @param {number} x columna @param {number} y fila @param {boolean} oscuro */
  fijar(x, y, oscuro) {
    this.modulos[y][x] = oscuro;
    this.funcion[y][x] = true;
  }

  /** Patrón de búsqueda 7×7 con su separador claro alrededor, centrado en (cx, cy). */
  busqueda(cx, cy) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        if (x < 0 || y < 0 || x >= this.tamano || y >= this.tamano) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy)); // distancia de Chebyshev al centro
        this.fijar(x, y, d !== 2 && d !== 4);
      }
    }
  }

  /** Patrón de alineación 5×5 centrado en (cx, cy). */
  alineacion(cx, cy) {
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) this.fijar(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }

  /** Dibuja todos los patrones de función y reserva las zonas de formato y versión. */
  patronesDeFuncion() {
    const n = this.tamano;
    for (let i = 0; i < n; i++) {
      this.fijar(6, i, i % 2 === 0); // temporización vertical
      this.fijar(i, 6, i % 2 === 0); // temporización horizontal
    }
    this.busqueda(3, 3);
    this.busqueda(n - 4, 3);
    this.busqueda(3, n - 4);
    const pos = posicionesAlineacion(this.version);
    const ultimo = pos.length - 1;
    for (let i = 0; i <= ultimo; i++) {
      for (let j = 0; j <= ultimo; j++) {
        // se omiten las tres esquinas ocupadas por patrones de búsqueda
        if ((i === 0 && j === 0) || (i === 0 && j === ultimo) || (i === ultimo && j === 0)) continue;
        this.alineacion(pos[i], pos[j]);
      }
    }
    this.formato(0); // reserva provisional; se reescribe con la máscara elegida
    this.versionInfo();
  }

  /** Escribe las dos copias de la información de formato y el módulo oscuro. @param {number} bits */
  formatoBits(bits) {
    const n = this.tamano;
    const bit = (i) => ((bits >>> i) & 1) === 1;
    // copia junto al patrón superior izquierdo
    for (let i = 0; i <= 5; i++) this.fijar(8, i, bit(i));
    this.fijar(8, 7, bit(6));
    this.fijar(8, 8, bit(7));
    this.fijar(7, 8, bit(8));
    for (let i = 9; i < 15; i++) this.fijar(14 - i, 8, bit(i));
    // copia repartida entre los patrones superior derecho e inferior izquierdo
    for (let i = 0; i < 8; i++) this.fijar(n - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) this.fijar(8, n - 15 + i, bit(i));
    this.fijar(8, n - 8, true); // módulo oscuro
  }

  /** @param {number} mascara @param {Nivel} [nivel] */
  formato(mascara, nivel = 'M') {
    this.formatoBits(bitsDeFormato(nivel, mascara));
  }

  /** Información de versión (solo versión ≥ 7): dos bloques de 6×3. */
  versionInfo() {
    if (this.version < 7) return;
    const bits = bitsDeVersion(this.version);
    const n = this.tamano;
    for (let i = 0; i < 18; i++) {
      const oscuro = ((bits >>> i) & 1) === 1;
      const a = n - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.fijar(a, b, oscuro); // superior derecha
      this.fijar(b, a, oscuro); // inferior izquierda
    }
  }

  /** Coloca los codewords en zigzag de columnas dobles, de abajo arriba y de derecha a izquierda (sección 7.7.3). */
  colocar(codewords) {
    const n = this.tamano;
    const totalBits = codewords.length * 8;
    let i = 0;
    for (let derecha = n - 1; derecha >= 1; derecha -= 2) {
      if (derecha === 6) derecha = 5; // la columna de temporización no se usa
      const subiendo = ((derecha + 1) & 2) === 0;
      for (let k = 0; k < n; k++) {
        const y = subiendo ? n - 1 - k : k;
        for (let j = 0; j < 2; j++) {
          const x = derecha - j;
          if (this.funcion[y][x]) continue;
          // los módulos sobrantes (bits de resto) quedan claros
          if (i < totalBits) this.modulos[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
          i++;
        }
      }
    }
  }

  /** Aplica (o deshace, por ser XOR) una máscara sobre los módulos que no son de función. */
  aplicarMascara(mascara) {
    const condicion = MASCARAS[mascara];
    for (let y = 0; y < this.tamano; y++) {
      for (let x = 0; x < this.tamano; x++) {
        if (!this.funcion[y][x] && condicion(x, y)) this.modulos[y][x] = !this.modulos[y][x];
      }
    }
  }
}

/**
 * Penalización de una matriz según las reglas N1–N4 (sección 7.8.3).
 * N3 considera la zona silenciosa clara alrededor del símbolo.
 * @param {boolean[][]} m
 * @returns {number}
 */
export function penalizacion(m) {
  const n = m.length;
  let total = 0;
  const celda = (x, y) => x >= 0 && y >= 0 && x < n && y < n && m[y][x];
  // patrón 1:1:3:1:1 (oscuro-claro-oscuro×3-claro-oscuro)
  const PATRON = [true, false, true, true, true, false, true];

  for (const horizontal of [true, false]) {
    const get = horizontal ? (i, j) => celda(j, i) : (i, j) => celda(i, j);
    for (let i = 0; i < n; i++) {
      // N1: tramos de 5 o más módulos iguales
      let racha = 1;
      for (let j = 1; j <= n; j++) {
        if (j < n && get(i, j) === get(i, j - 1)) {
          racha++;
        } else {
          if (racha >= 5) total += PENALIZACION.N1 + (racha - 5);
          racha = 1;
        }
      }
      // N3: patrón tipo búsqueda con 4 módulos claros a un lado
      for (let j = -4; j < n; j++) {
        let coincide = true;
        for (let k = 0; k < 7 && coincide; k++) coincide = get(i, j + k) === PATRON[k];
        if (!coincide) continue;
        const claro = (desde) => [0, 1, 2, 3].every((k) => !get(i, desde + k));
        if (claro(j - 4)) total += PENALIZACION.N3;
        if (claro(j + 7)) total += PENALIZACION.N3;
      }
    }
  }

  // N2: bloques 2×2 del mismo color
  for (let y = 0; y < n - 1; y++) {
    for (let x = 0; x < n - 1; x++) {
      const c = m[y][x];
      if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) total += PENALIZACION.N2;
    }
  }

  // N4: desviación de la proporción de oscuros respecto al 50 %, en pasos de 5 %
  let oscuros = 0;
  for (const fila of m) for (const c of fila) if (c) oscuros++;
  const k = Math.floor(Math.abs((oscuros * 100) / (n * n) - 50) / 5);
  total += k * PENALIZACION.N4;
  return total;
}

/**
 * Codifica un texto como símbolo QR en modo byte (UTF-8).
 * @param {string} texto
 * @param {{ nivel?: Nivel, mascara?: number }} [opciones] `mascara` fuerza una máscara (0–7); si no, se elige la de menor penalización.
 * @returns {Qr}
 */
export function encodeQr(texto, { nivel = 'M', mascara } = {}) {
  if (typeof texto !== 'string') throw new TypeError('El texto debe ser una cadena');
  if (!(nivel in BITS_NIVEL)) throw new Error('Nivel de corrección no soportado');
  if (mascara !== undefined && !(Number.isInteger(mascara) && mascara >= 0 && mascara <= 7)) {
    throw new Error('Máscara fuera de rango');
  }
  const contenido = new TextEncoder().encode(texto);
  const version = versionMinima(contenido.length, nivel);
  const codewords = construirCodewords(codificarDatos(contenido, version, nivel), version, nivel);

  const matriz = new Matriz(version);
  matriz.patronesDeFuncion();
  matriz.colocar(codewords);

  let elegida = mascara;
  if (elegida === undefined) {
    let mejor = Infinity;
    for (let k = 0; k < 8; k++) {
      matriz.aplicarMascara(k);
      matriz.formato(k, nivel);
      const p = penalizacion(matriz.modulos);
      if (p < mejor) {
        mejor = p;
        elegida = k;
      }
      matriz.aplicarMascara(k); // deshace la máscara
    }
  }
  matriz.aplicarMascara(elegida);
  matriz.formato(elegida, nivel);
  return { version, tamano: matriz.tamano, nivel, mascara: elegida, modulos: matriz.modulos };
}

/** Escapa un valor para un atributo XML. */
function atributo(valor) {
  return String(valor).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/**
 * Representa un QR como SVG con un único `<path>`; cada tramo horizontal de oscuros es un rectángulo.
 * El viewBox está en unidades de módulo e incluye el margen (zona silenciosa, 4 módulos por norma).
 * @param {Qr} qr
 * @param {{ escala?: number, margen?: number, oscuro?: string, claro?: string }} [opciones]
 * @returns {string}
 */
export function qrToSvg(qr, { escala = 4, margen = 4, oscuro = '#000', claro = '#fff' } = {}) {
  if (!(escala > 0) || !Number.isInteger(margen) || margen < 0) throw new Error('Escala o margen no válidos');
  const lado = qr.tamano + 2 * margen;
  const px = lado * escala;
  let d = '';
  qr.modulos.forEach((fila, y) => {
    for (let x = 0; x < fila.length; x++) {
      if (!fila[x]) continue;
      const inicio = x;
      while (x + 1 < fila.length && fila[x + 1]) x++;
      d += `M${inicio + margen},${y + margen}h${x - inicio + 1}v1h-${x - inicio + 1}z`;
    }
  });
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" width="${px}" height="${px}" viewBox="0 0 ${lado} ${lado}" shape-rendering="crispEdges">`
    + `<rect width="${lado}" height="${lado}" fill="${atributo(claro)}"/>`
    + `<path fill="${atributo(oscuro)}" d="${d}"/>`
    + '</svg>'
  );
}
