// Isolation Forest propio (Liu, Ting y Zhou, 2008), sin librerías externas.
// Idea: las anomalías son pocas y distintas, así que particiones aleatorias las aíslan con pocos
// cortes. La puntuación es s(x, ψ) = 2^(−E[h(x)] / c(ψ)), donde h(x) es la profundidad de
// aislamiento y c(ψ) la longitud media de búsqueda fallida en un árbol binario de ψ elementos.

import { crearAleatorio, semillaANumero } from './aleatorio.js';

/** Constante de Euler-Mascheroni (aproximación del número armónico H(i) ≈ ln(i) + γ). */
const EULER_GAMMA = 0.5772156649015329;

/** Versión del formato serializado. */
const VERSION_MODELO = 1;

/**
 * Árbol en representación plana (rápida de recorrer y de serializar).
 * Para el nodo i: `f[i]` es el índice de la característica (−1 si es hoja), `v[i]` el umbral de
 * corte (o el tamaño de la hoja), `l[i]` / `r[i]` los hijos izquierdo (x < v) y derecho (x ≥ v).
 * @typedef {{ f: number[], v: number[], l: number[], r: number[] }} Arbol
 */

/**
 * @typedef {object} ModeloIsolationForest
 * @property {'isolation-forest'} tipo
 * @property {number} version
 * @property {number} muestra Tamaño ψ de la submuestra usada por árbol.
 * @property {number} dimension Número de características.
 * @property {number} alturaMaxima Límite de profundidad l = ceil(log2 ψ).
 * @property {number} semilla
 * @property {Arbol[]} arboles
 */

/**
 * Longitud media de un camino de búsqueda fallida en un BST de n elementos:
 * c(n) = 2·H(n−1) − 2(n−1)/n, con c(2) = 1 y c(n ≤ 1) = 0.
 * @param {number} n
 */
export function c(n) {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  return 2 * (Math.log(n - 1) + EULER_GAMMA) - (2 * (n - 1)) / n;
}

/**
 * Construye un árbol de aislamiento sobre los índices dados.
 * @param {number[][]} datos @param {number[]} indices @param {number} alturaMaxima
 * @param {number} dimension @param {import('./aleatorio.js').Aleatorio} azar
 * @returns {Arbol}
 */
function construirArbol(datos, indices, alturaMaxima, dimension, azar) {
  /** @type {Arbol} */
  const arbol = { f: [], v: [], l: [], r: [] };
  const nuevoNodo = () => {
    arbol.f.push(-1);
    arbol.v.push(0);
    arbol.l.push(-1);
    arbol.r.push(-1);
    return arbol.f.length - 1;
  };
  /** Pila explícita para no depender de la recursión. */
  const pendientes = [{ nodo: nuevoNodo(), indices, profundidad: 0 }];
  while (pendientes.length > 0) {
    const { nodo, indices: grupo, profundidad } = pendientes.pop();
    const hoja = () => { arbol.f[nodo] = -1; arbol.v[nodo] = grupo.length; };
    if (profundidad >= alturaMaxima || grupo.length <= 1) { hoja(); continue; }

    // Característica aleatoria entre las que no son constantes en este nodo.
    const candidatas = [];
    const minimos = new Array(dimension);
    const maximos = new Array(dimension);
    for (let q = 0; q < dimension; q++) {
      let min = Infinity;
      let max = -Infinity;
      for (const i of grupo) {
        const x = datos[i][q];
        if (x < min) min = x;
        if (x > max) max = x;
      }
      minimos[q] = min;
      maximos[q] = max;
      if (max > min) candidatas.push(q);
    }
    if (candidatas.length === 0) { hoja(); continue; }

    const q = azar.elegir(candidatas);
    let p = azar.rango(minimos[q], maximos[q]);
    if (!(p > minimos[q])) p = (minimos[q] + maximos[q]) / 2;
    const izquierda = [];
    const derecha = [];
    for (const i of grupo) (datos[i][q] < p ? izquierda : derecha).push(i);

    const l = nuevoNodo();
    const r = nuevoNodo();
    arbol.f[nodo] = q;
    arbol.v[nodo] = p;
    arbol.l[nodo] = l;
    arbol.r[nodo] = r;
    pendientes.push({ nodo: l, indices: izquierda, profundidad: profundidad + 1 });
    pendientes.push({ nodo: r, indices: derecha, profundidad: profundidad + 1 });
  }
  return arbol;
}

/**
 * Entrena un Isolation Forest. Determinista: misma semilla y mismos datos dan el mismo modelo.
 * @param {number[][]} datos Matriz n × d de características (solo tráfico considerado normal).
 * @param {{ arboles?: number, muestra?: number, semilla?: number | string }} [opciones]
 * @returns {ModeloIsolationForest}
 */
export function entrenar(datos, { arboles = 100, muestra = 256, semilla = 42 } = {}) {
  if (!Array.isArray(datos) || datos.length === 0) throw new Error('Se requieren datos de entrenamiento');
  const dimension = datos[0].length;
  if (dimension === 0 || datos.some((x) => x.length !== dimension)) throw new Error('Dimensiones inconsistentes');
  if (!Number.isInteger(arboles) || arboles < 1) throw new Error('Número de árboles inválido');
  const psi = Math.min(Math.max(2, Math.trunc(muestra)), datos.length);
  const alturaMaxima = Math.ceil(Math.log2(Math.max(2, psi)));
  const semillaNum = semillaANumero(semilla);
  const azar = crearAleatorio(semillaNum);
  const todos = datos.map((_, i) => i);

  const bosque = [];
  for (let t = 0; t < arboles; t++) {
    // Submuestra sin reemplazo (Fisher-Yates parcial).
    const indices = todos.slice();
    for (let i = 0; i < psi; i++) {
      const j = i + Math.floor(azar.siguiente() * (indices.length - i));
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    bosque.push(construirArbol(datos, indices.slice(0, psi), alturaMaxima, dimension, azar));
  }
  return { tipo: 'isolation-forest', version: VERSION_MODELO, muestra: psi, dimension, alturaMaxima, semilla: semillaNum, arboles: bosque };
}

/**
 * Profundidad de aislamiento h(x) en un árbol, con la corrección c(tamaño) en la hoja.
 * @param {Arbol} arbol @param {number[]} x
 */
function longitudCamino(arbol, x) {
  const { f, v, l, r } = arbol;
  let nodo = 0;
  let profundidad = 0;
  while (f[nodo] !== -1) {
    nodo = x[f[nodo]] < v[nodo] ? l[nodo] : r[nodo];
    profundidad++;
  }
  return profundidad + c(v[nodo]);
}

/**
 * Puntuación de anomalía en [0, 1]: cerca de 1 = anomalía clara, ≤ 0.5 = normal.
 * @param {ModeloIsolationForest} modelo
 * @param {number[]} x
 */
export function puntuar(modelo, x) {
  if (x.length !== modelo.dimension) throw new Error('Dimensión del vector distinta a la del modelo');
  let suma = 0;
  for (const arbol of modelo.arboles) suma += longitudCamino(arbol, x);
  const media = suma / modelo.arboles.length;
  return 2 ** (-media / c(modelo.muestra));
}

/**
 * Serializa el modelo a JSON (para guardarlo en disco o en BD y recargarlo sin reentrenar).
 * @param {ModeloIsolationForest} modelo
 */
export function serializar(modelo) {
  return JSON.stringify(modelo);
}

/**
 * Reconstruye un modelo serializado validando su estructura.
 * @param {string | object} json
 * @returns {ModeloIsolationForest}
 */
export function deserializar(json) {
  const modelo = typeof json === 'string' ? JSON.parse(json) : json;
  if (!modelo || modelo.tipo !== 'isolation-forest') throw new Error('No es un modelo Isolation Forest');
  if (modelo.version !== VERSION_MODELO) throw new Error('Versión de modelo no soportada');
  if (!Array.isArray(modelo.arboles) || modelo.arboles.length === 0) throw new Error('Modelo sin árboles');
  for (const a of modelo.arboles) {
    const n = a?.f?.length;
    if (!n || a.v.length !== n || a.l.length !== n || a.r.length !== n) throw new Error('Árbol mal formado');
  }
  return modelo;
}
