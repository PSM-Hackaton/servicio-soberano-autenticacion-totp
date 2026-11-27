// Impresión en consola: tablas alineadas y colores ANSI opcionales (se desactivan con
// --sin-color, NO_COLOR o cuando la salida no es una terminal).

const CODIGOS = { rojo: 31, verde: 32, amarillo: 33, azul: 34, magenta: 35, cian: 36, gris: 90, negrita: 1 };
const ANSI = /\x1b\[[0-9;]*m/g;

let colorActivo = process.stdout.isTTY === true && !process.env.NO_COLOR;

/** Activa o desactiva los colores globalmente. */
export function usarColor(activo) { colorActivo = Boolean(activo); }

/** Aplica un color si están activos. @param {keyof typeof CODIGOS} nombre @param {unknown} texto */
export function color(nombre, texto) {
  const t = String(texto);
  return colorActivo ? `\x1b[${CODIGOS[nombre]}m${t}\x1b[0m` : t;
}

/** Longitud visible (sin secuencias ANSI). */
export const anchoVisible = (t) => [...String(t).replace(ANSI, '')].length;
/** Quita colores. */
export const sinAnsi = (t) => String(t).replace(ANSI, '');

/** "OK" en verde o "FALLO" en rojo (o "INFO" en amarillo si ok es null). */
export const marca = (ok) => (ok === null || ok === undefined ? color('amarillo', 'INFO') : ok ? color('verde', 'OK') : color('rojo', 'FALLO'));

/**
 * Construye una tabla de texto.
 * @param {string[]} encabezados @param {unknown[][]} filas @param {{ anchoMax?: number }} [op]
 * @returns {string}
 */
export function tabla(encabezados, filas, { anchoMax = 60 } = {}) {
  const recortar = (t) => {
    const s = String(t ?? '');
    if (anchoVisible(s) <= anchoMax) return s;
    const plano = [...sinAnsi(s)];
    return `${plano.slice(0, anchoMax - 1).join('')}…`;
  };
  const celdas = filas.map((f) => f.map(recortar));
  const anchos = encabezados.map((e, i) => Math.max(anchoVisible(e), ...celdas.map((f) => anchoVisible(f[i] ?? ''))));
  const rellenar = (t, n) => t + ' '.repeat(Math.max(0, n - anchoVisible(t)));
  const linea = (izq, med, der) => izq + anchos.map((n) => '─'.repeat(n + 2)).join(med) + der;
  const fila = (f) => `│ ${anchos.map((n, i) => rellenar(String(f[i] ?? ''), n)).join(' │ ')} │`;
  return [
    linea('┌', '┬', '┐'),
    fila(encabezados.map((e) => color('negrita', e))),
    linea('├', '┼', '┤'),
    ...celdas.map(fila),
    linea('└', '┴', '┘'),
  ].join('\n');
}

/** Título de sección. */
export function titulo(texto) {
  return `\n${color('cian', '══')} ${color('negrita', texto)} ${color('cian', '═'.repeat(Math.max(2, 60 - anchoVisible(texto))))}`;
}

/** Registro con hora (para el modo detallado y la demo en vivo). */
export function registro(...partes) {
  const hora = new Date().toISOString().slice(11, 23);
  console.log(color('gris', hora), ...partes);
}
