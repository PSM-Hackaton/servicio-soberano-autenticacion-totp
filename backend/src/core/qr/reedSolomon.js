// Aritmética en GF(256) y códigos Reed-Solomon para QR (ISO/IEC 18004, sección 7.5).
// Polinomio primitivo del campo: x^8 + x^4 + x^3 + x^2 + 1 (0x11D). Elemento generador α = 2.

/** Tablas de exponenciales y logaritmos de GF(256). EXP se duplica para evitar el módulo 255. */
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
}

/** Producto de dos elementos de GF(256). @param {number} a @param {number} b */
export function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

/** α^n en GF(256). @param {number} n */
export function gfPow2(n) {
  return EXP[((n % 255) + 255) % 255];
}

/**
 * Polinomio generador de grado n: (x − α^0)(x − α^1)···(x − α^(n−1)).
 * Se devuelven los n coeficientes tras el principal (que vale 1), del de mayor grado al de menor.
 * @param {number} grado
 * @returns {Uint8Array}
 */
export function generadorRs(grado) {
  if (!Number.isInteger(grado) || grado < 1 || grado > 255) throw new Error('Grado fuera de rango');
  const coef = new Uint8Array(grado);
  coef[grado - 1] = 1; // empieza en el polinomio constante 1
  let raiz = 1;
  for (let i = 0; i < grado; i++) {
    // multiplica por (x − raiz); en GF(2^8) la resta es XOR
    for (let j = 0; j < grado; j++) {
      coef[j] = gfMul(coef[j], raiz);
      if (j + 1 < grado) coef[j] ^= coef[j + 1];
    }
    raiz = gfMul(raiz, 2);
  }
  return coef;
}

/**
 * Bytes de corrección: resto de dividir datos·x^n entre el polinomio generador de grado n.
 * @param {ArrayLike<number>} datos
 * @param {number} grado número de bytes de corrección
 * @returns {Uint8Array}
 */
export function correccionRs(datos, grado) {
  const generador = generadorRs(grado);
  const resto = new Uint8Array(grado);
  for (const byte of datos) {
    const factor = byte ^ resto[0];
    resto.copyWithin(0, 1);
    resto[grado - 1] = 0;
    for (let i = 0; i < grado; i++) resto[i] ^= gfMul(generador[i], factor);
  }
  return resto;
}

/**
 * Evalúa en x un polinomio dado por sus coeficientes de mayor a menor grado (método de Horner).
 * Útil para comprobar que un bloque completo (datos + corrección) se anula en las raíces del generador.
 * @param {ArrayLike<number>} coeficientes @param {number} x
 */
export function evaluarPolinomio(coeficientes, x) {
  let y = 0;
  for (const c of coeficientes) y = gfMul(y, x) ^ c;
  return y;
}
