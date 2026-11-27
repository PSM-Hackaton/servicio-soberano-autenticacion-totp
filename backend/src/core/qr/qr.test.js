import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { correccionRs, generadorRs, evaluarPolinomio, gfPow2 } from './reedSolomon.js';
import {
  encodeQr, qrToSvg, tamanoDeVersion, versionMinima, capacidadDatos, posicionesAlineacion, bitsDeFormato, bitsDeVersion,
  BITS_NIVEL, penalizacion,
} from './qr.js';
import { buildOtpauthUri } from '../totp/totp.js';

const NIVELES = ['L', 'M', 'Q', 'H'];

/** Patrón de búsqueda esperado 7×7: anillo oscuro, anillo claro y núcleo 3×3 oscuro. */
function esBusqueda(m, x0, y0) {
  for (let dy = 0; dy < 7; dy++) {
    for (let dx = 0; dx < 7; dx++) {
      const d = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
      if (m[y0 + dy][x0 + dx] !== (d !== 2)) return false;
    }
  }
  return true;
}

/** Lee las dos copias de los 15 bits de formato directamente de la matriz (figura 25 de la norma). */
function leerFormato(m) {
  const n = m.length;
  const coord1 = [];
  for (let i = 0; i <= 5; i++) coord1.push([8, i]);
  coord1.push([8, 7], [8, 8], [7, 8]);
  for (let i = 9; i < 15; i++) coord1.push([14 - i, 8]);
  const coord2 = [];
  for (let i = 0; i < 8; i++) coord2.push([n - 1 - i, 8]);
  for (let i = 8; i < 15; i++) coord2.push([8, n - 15 + i]);
  const leer = (coords) => coords.reduce((acc, [x, y], i) => acc | ((m[y][x] ? 1 : 0) << i), 0);
  return [leer(coord1), leer(coord2)];
}

/** Decodifica 15 bits de formato por distancia de Hamming mínima frente a los 32 válidos. */
function decodificarFormato(bits) {
  let mejor = null;
  for (const nivel of NIVELES) {
    for (let mascara = 0; mascara < 8; mascara++) {
      let x = bits ^ bitsDeFormato(nivel, mascara);
      let d = 0;
      for (; x; x &= x - 1) d++;
      if (!mejor || d < mejor.distancia) mejor = { nivel, mascara, distancia: d };
    }
  }
  return mejor;
}

/** BCH(15,5) calculado a mano por división larga, independiente de la implementación. */
function formatoManual(nivelBits, mascara) {
  const datos = (nivelBits << 3) | mascara;
  let r = datos << 10;
  for (let i = 14; i >= 10; i--) if (r & (1 << i)) r ^= 0b10100110111 << (i - 10);
  return ((datos << 10) | r) ^ 0b101010000010010;
}

test('tamaño = 17 + 4·versión', () => {
  for (let v = 1; v <= 40; v++) assert.equal(tamanoDeVersion(v), 17 + 4 * v);
  for (const texto of ['a', 'x'.repeat(100), 'y'.repeat(300)]) {
    const qr = encodeQr(texto);
    assert.equal(qr.tamano, 17 + 4 * qr.version);
    assert.equal(qr.modulos.length, qr.tamano);
    for (const fila of qr.modulos) assert.equal(fila.length, qr.tamano);
  }
});

test('patrones de búsqueda y temporización correctos', () => {
  for (const texto of ['HELLO WORLD', 'z'.repeat(150), 'w'.repeat(250)]) {
    const { modulos: m, tamano: n } = encodeQr(texto);
    assert.ok(esBusqueda(m, 0, 0), 'superior izquierda');
    assert.ok(esBusqueda(m, n - 7, 0), 'superior derecha');
    assert.ok(esBusqueda(m, 0, n - 7), 'inferior izquierda');
    // separadores claros
    for (let i = 0; i < 8; i++) {
      assert.equal(m[7][i], false);
      assert.equal(m[i][7], false);
      assert.equal(m[7][n - 1 - i], false);
      assert.equal(m[n - 8][i], false);
    }
    // temporización alternada y módulo oscuro
    for (let i = 8; i < n - 8; i++) {
      assert.equal(m[6][i], i % 2 === 0);
      assert.equal(m[i][6], i % 2 === 0);
    }
    assert.equal(m[n - 8][8], true, 'módulo oscuro');
  }
});

test('bits de formato coinciden con la tabla de la norma (cálculo BCH independiente)', () => {
  // Ejemplo del anexo C de la norma: nivel M, máscara 5 → 100000011001110
  assert.equal(bitsDeFormato('M', 5), 0b100000011001110);
  for (const nivel of NIVELES) {
    for (let k = 0; k < 8; k++) assert.equal(bitsDeFormato(nivel, k), formatoManual(BITS_NIVEL[nivel], k));
  }
});

test('bits de formato del símbolo decodificables y coherentes con nivel y máscara usados', () => {
  for (const nivel of NIVELES) {
    for (let mascara = 0; mascara < 8; mascara++) {
      const qr = encodeQr('otpauth://totp/Prueba:ana?secret=JBSWY3DPEHPK3PXP', { nivel, mascara });
      const [copia1, copia2] = leerFormato(qr.modulos);
      assert.equal(copia1, copia2, 'las dos copias son iguales');
      const sinMascara = copia1 ^ 0x5412;
      assert.equal(sinMascara >>> 13, BITS_NIVEL[nivel], 'bits de nivel');
      assert.equal((sinMascara >>> 10) & 7, mascara, 'bits de máscara');
      const d = decodificarFormato(copia1);
      assert.deepEqual(d, { nivel, mascara, distancia: 0 });
    }
  }
  const auto = encodeQr('HELLO WORLD');
  assert.deepEqual(decodificarFormato(leerFormato(auto.modulos)[0]), { nivel: 'M', mascara: auto.mascara, distancia: 0 });
});

test('información de versión (≥ 7) con BCH(18,6) en ambas esquinas', () => {
  // Valor de referencia de la tabla D.1 de la norma para la versión 7
  assert.equal(bitsDeVersion(7), 0b000111110010010100);
  assert.equal(bitsDeVersion(40), 0b101000110001101001);
  const qr = encodeQr('v'.repeat(200));
  assert.ok(qr.version >= 7);
  const n = qr.tamano;
  let arriba = 0;
  let abajo = 0;
  for (let i = 0; i < 18; i++) {
    const a = n - 11 + (i % 3);
    const b = Math.floor(i / 3);
    arriba |= (qr.modulos[b][a] ? 1 : 0) << i;
    abajo |= (qr.modulos[a][b] ? 1 : 0) << i;
  }
  assert.equal(arriba, bitsDeVersion(qr.version));
  assert.equal(abajo, bitsDeVersion(qr.version));
});

test('patrones de alineación según la tabla E.1', () => {
  assert.deepEqual(posicionesAlineacion(1), []);
  assert.deepEqual(posicionesAlineacion(2), [6, 18]);
  assert.deepEqual(posicionesAlineacion(7), [6, 22, 38]);
  assert.deepEqual(posicionesAlineacion(10), [6, 28, 50]);
  assert.deepEqual(posicionesAlineacion(15), [6, 26, 48, 70]);
  assert.deepEqual(posicionesAlineacion(32), [6, 34, 60, 86, 112, 138]);
  const { modulos: m } = encodeQr('a'.repeat(60)); // versión 4 con M
  // centro oscuro, anillo claro y borde oscuro en (26, 26)
  assert.equal(m[26][26], true);
  assert.equal(m[25][26], false);
  assert.equal(m[24][26], true);
});

test('capacidades en modo byte de la tabla 7 y versión mínima', () => {
  // bytes máximos en modo byte por (versión, nivel)
  const tabla7 = { 1: [17, 14, 11, 7], 2: [32, 26, 20, 14], 7: [154, 122, 86, 64], 10: [271, 213, 151, 119], 15: [520, 412, 292, 220] };
  for (const [v, maximos] of Object.entries(tabla7)) {
    NIVELES.forEach((nivel, i) => {
      assert.equal(versionMinima(maximos[i], nivel), Number(v), `${maximos[i]} bytes ${nivel}`);
      assert.equal(versionMinima(maximos[i] + 1, nivel), Number(v) + 1, `${maximos[i] + 1} bytes ${nivel}`);
    });
  }
  assert.equal(capacidadDatos(1, 'M'), 16);
  assert.equal(encodeQr('HELLO WORLD').version, 1);
  assert.equal(encodeQr('HELLO WORLD', { nivel: 'Q' }).version, 1);
  assert.equal(encodeQr('HELLO WORLD', { nivel: 'H' }).version, 2); // 13 bytes > 9 de 1-H
  assert.equal(encodeQr('x'.repeat(15)).version, 2);
  assert.throws(() => encodeQr('x'.repeat(2400)), /demasiado largo/);
  assert.throws(() => encodeQr('a', { nivel: 'X' }), /Nivel/);
});

test('URI otpauth con semilla SHA-512 de 64 bytes se codifica', () => {
  const uri = buildOtpauthUri({
    semilla: randomBytes(64), emisor: 'Servicio Soberano', cuenta: 'usuaria@ejemplo.cl', algoritmo: 'SHA512', digitos: 8, periodo: 30,
  });
  assert.ok(uri.length > 180);
  const qr = encodeQr(uri);
  assert.ok(qr.version >= 8 && qr.version <= 11, `versión ${qr.version}`);
  assert.equal(qr.tamano, 17 + 4 * qr.version);
  // la lectura de vuelta recupera el texto exacto
  assert.equal(leerDeVuelta(qr), uri);
  for (const nivel of NIVELES) assert.equal(leerDeVuelta(encodeQr(uri, { nivel })), uri);
});

test('Reed-Solomon: vectores de referencia y divisibilidad por el generador', () => {
  // Ejemplo del anexo I de la norma ("01234567", 1-M)
  const datosIso = [16, 32, 12, 86, 97, 128, 236, 17, 236, 17, 236, 17, 236, 17, 236, 17];
  assert.deepEqual([...correccionRs(datosIso, 10)], [165, 36, 212, 193, 237, 54, 199, 135, 44, 85]);
  // "HELLO WORLD" alfanumérico 1-M (ejemplo clásico de la literatura de QR)
  const datosHello = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17];
  assert.deepEqual([...correccionRs(datosHello, 10)], [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]);
  // generador de grado 7: α^0, α^87, α^229, α^146, α^149, α^238, α^102, α^21
  assert.deepEqual([...generadorRs(7)], [87, 229, 146, 149, 238, 102, 21].map(gfPow2));
  // propiedad: datos·x^n + resto se anula en α^0…α^(n−1)
  for (const n of [7, 10, 18, 22, 30]) {
    const datos = [...randomBytes(40)];
    const bloque = [...datos, ...correccionRs(datos, n)];
    for (let i = 0; i < n; i++) assert.equal(evaluarPolinomio(bloque, gfPow2(i)), 0, `n=${n}, raíz α^${i}`);
  }
});

test('las 8 máscaras producen símbolos legibles y la automática minimiza la penalización', () => {
  const texto = 'Prueba de máscaras ñandú';
  for (let mascara = 0; mascara < 8; mascara++) assert.equal(leerDeVuelta(encodeQr(texto, { mascara })), texto);
  const auto = encodeQr(texto);
  const pAuto = penalizacion(auto.modulos);
  for (let mascara = 0; mascara < 8; mascara++) assert.ok(pAuto <= penalizacion(encodeQr(texto, { mascara }).modulos));
});

test('SVG válido con un único path', () => {
  const svg = qrToSvg(encodeQr('HELLO WORLD'), { escala: 5 });
  assert.ok(svg.startsWith('<svg'));
  assert.ok(svg.endsWith('</svg>'));
  assert.equal(svg.match(/<path/g).length, 1);
  assert.match(svg, /shape-rendering="crispEdges"/);
  assert.match(svg, /viewBox="0 0 29 29"/);
  assert.match(svg, /width="145"/);
  assert.match(qrToSvg(encodeQr('a'), { oscuro: '"><x' }), /fill="&#34;&#62;&#60;x"/);
});

// ---------------------------------------------------------------------------
// Lector de verificación: recorre la matriz al revés (quita máscara, lee el zigzag,
// desentrelaza, comprueba síndromes Reed-Solomon nulos y analiza el modo byte).
// Reconstruye por su cuenta qué módulos son de función.

const CONDICIONES = [
  (x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, (x) => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0, (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

function mapaFuncion(version) {
  const n = 17 + 4 * version;
  const f = Array.from({ length: n }, () => new Array(n).fill(false));
  const rect = (x0, y0, w, h) => {
    for (let y = y0; y < y0 + h; y++) for (let x = x0; x < x0 + w; x++) if (x >= 0 && y >= 0 && x < n && y < n) f[y][x] = true;
  };
  rect(0, 0, 9, 9); rect(n - 8, 0, 8, 9); rect(0, n - 8, 9, 8); // búsqueda + separador + formato
  rect(6, 0, 1, n); rect(0, 6, n, 1); // temporización
  const pos = posicionesAlineacion(version);
  const ult = pos.length - 1;
  pos.forEach((cy, i) => pos.forEach((cx, j) => {
    const esquina = (i === 0 && j === 0) || (i === 0 && j === ult) || (i === ult && j === 0);
    if (!esquina) rect(cx - 2, cy - 2, 5, 5);
  }));
  if (version >= 7) { rect(n - 11, 0, 3, 6); rect(0, n - 11, 6, 3); }
  return f;
}

/** @param {{ version: number, modulos: boolean[][] }} qr */
function leerDeVuelta(qr) {
  const { version, modulos: m } = qr;
  const n = m.length;
  const { nivel, mascara, distancia } = decodificarFormato(leerFormato(m)[0]);
  assert.equal(distancia, 0);
  const f = mapaFuncion(version);
  const bits = [];
  let col = n - 1;
  let haciaArriba = true;
  while (col > 0) {
    if (col === 6) col--;
    for (let k = 0; k < n; k++) {
      const y = haciaArriba ? n - 1 - k : k;
      for (const x of [col, col - 1]) if (!f[y][x]) bits.push(m[y][x] !== CONDICIONES[mascara](x, y) ? 1 : 0);
    }
    haciaArriba = !haciaArriba;
    col -= 2;
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  const datos = desentrelazar(bytes, capacidadDatos(version, nivel));
  // análisis del flujo de bits: modo byte
  const flujo = datos.flatMap((b) => [7, 6, 5, 4, 3, 2, 1, 0].map((i) => (b >>> i) & 1));
  const tomar = (() => { let p = 0; return (len) => { let v = 0; for (let i = 0; i < len; i++) v = (v << 1) | flujo[p++]; return v; }; })();
  assert.equal(tomar(4), 0b0100, 'modo byte');
  const largo = tomar(version <= 9 ? 8 : 16);
  const contenido = Uint8Array.from({ length: largo }, () => tomar(8));
  return new TextDecoder('utf-8', { fatal: true }).decode(contenido);
}

/**
 * Prueba cada número de bloques compatible con los totales y acepta el único reparto en que
 * todos los bloques tienen síndromes Reed-Solomon nulos. Devuelve los bytes de datos en orden.
 */
function desentrelazar(bytes, datosTotales) {
  const total = bytes.length;
  const corrTotal = total - datosTotales;
  for (let nBloques = 1; nBloques <= 81; nBloques++) {
    if (corrTotal % nBloques) continue;
    const porBloque = corrTotal / nBloques;
    const nCortos = nBloques - (total % nBloques);
    const largoCorto = Math.floor(total / nBloques);
    const bloques = Array.from({ length: nBloques }, (_, i) => ({ datos: [], corr: [], nd: largoCorto - porBloque + (i < nCortos ? 0 : 1) }));
    let k = 0;
    for (let j = 0; j <= largoCorto - porBloque; j++) for (const b of bloques) if (j < b.nd) b.datos.push(bytes[k++]);
    for (let j = 0; j < porBloque; j++) for (const b of bloques) b.corr.push(bytes[k++]);
    const validos = bloques.every((b) => {
      const cw = [...b.datos, ...b.corr];
      for (let i = 0; i < porBloque; i++) if (evaluarPolinomio(cw, gfPow2(i)) !== 0) return false;
      return true;
    });
    if (validos) return bloques.flatMap((b) => b.datos);
  }
  throw new Error('Ningún reparto de bloques supera la comprobación Reed-Solomon');
}
