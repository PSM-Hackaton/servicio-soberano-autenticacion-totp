// Utilidades de métricas: percentiles, tasas, distribución de estados y ejecución concurrente.

/**
 * Percentil por interpolación lineal (p entre 0 y 100). Devuelve null si no hay datos.
 * @param {number[]} valores @param {number} p
 */
export function percentil(valores, p) {
  const v = valores.filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  if (v.length === 0) return null;
  if (p <= 0) return v[0];
  if (p >= 100) return v[v.length - 1];
  const pos = (p / 100) * (v.length - 1);
  const i = Math.floor(pos);
  const f = pos - i;
  return i + 1 < v.length ? v[i] + (v[i + 1] - v[i]) * f : v[i];
}

/** Redondeo a n decimales (null se mantiene). */
export const redondear = (x, n = 1) => (x === null || x === undefined || !Number.isFinite(x) ? null : Math.round(x * 10 ** n) / 10 ** n);

/** Resumen de latencias en ms. @param {number[]} ms */
export function resumenLatencias(ms) {
  const v = ms.filter((x) => Number.isFinite(x));
  const suma = v.reduce((a, b) => a + b, 0);
  return {
    n: v.length,
    min: redondear(v.length ? Math.min(...v) : null),
    p50: redondear(percentil(v, 50)),
    p95: redondear(percentil(v, 95)),
    p99: redondear(percentil(v, 99)),
    max: redondear(v.length ? Math.max(...v) : null),
    media: redondear(v.length ? suma / v.length : null),
  };
}

/** Tasa en porcentaje (0–100) con 1 decimal; 0 si total es 0. */
export const tasa = (parte, total) => (total > 0 ? redondear((parte / total) * 100, 1) : 0);

/**
 * Cuenta respuestas por etiqueta (status HTTP o código de error de red).
 * @param {{ status: number, error?: string | null }[]} respuestas
 * @returns {Record<string, number>}
 */
export function distribucionEstados(respuestas) {
  /** @type {Record<string, number>} */
  const d = {};
  for (const r of respuestas) {
    const k = r.status ? String(r.status) : String(r.error ?? 'ERROR');
    d[k] = (d[k] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(d).sort(([a], [b]) => a.localeCompare(b)));
}

/** Formatea una distribución {"200": 3, "429": 5} como "200×3 429×5". */
export const formatearDistribucion = (d) => Object.entries(d).map(([k, v]) => `${k}×${v}`).join(' ') || '—';

/**
 * Ejecuta `total` tareas con a lo sumo `concurrencia` en vuelo.
 * @template T @param {number} total @param {number} concurrencia @param {(i: number) => Promise<T>} tarea
 * @returns {Promise<T[]>}
 */
export async function enParalelo(total, concurrencia, tarea) {
  const resultados = new Array(total);
  let siguiente = 0;
  const trabajadores = Array.from({ length: Math.min(concurrencia, total) }, async () => {
    while (siguiente < total) {
      const i = siguiente++;
      resultados[i] = await tarea(i);
    }
  });
  await Promise.all(trabajadores);
  return resultados;
}

/** Pausa en ms. */
export const dormir = (ms) => new Promise((r) => setTimeout(r, ms));

/** Cronómetro de alta resolución. */
export function cronometro() {
  const inicio = performance.now();
  return { ms: () => performance.now() - inicio, s: () => (performance.now() - inicio) / 1000 };
}
