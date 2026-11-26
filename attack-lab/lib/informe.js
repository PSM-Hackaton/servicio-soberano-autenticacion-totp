// Generación del informe: JSON completo y HTML autocontenido (sin recursos externos, sin scripts).

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { formatearValor } from './escenario.js';

/** Escapa texto para HTML. */
export const escaparHtml = (t) => String(t ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

/** Marca de fecha para nombres de archivo: 2026-11-26T15-04-05. */
export const marcaFecha = (d = new Date()) => d.toISOString().slice(0, 19).replace(/:/g, '-');

const etiqueta = (ok) => (ok === null ? '<span class="info">INFO</span>' : ok ? '<span class="ok">OK</span>' : '<span class="fallo">FALLO</span>');

/**
 * @param {{ generado: string, destino: string, resultados: any[], resumen: any, entorno: any }} informe
 * @returns {string}
 */
export function generarHtml(informe) {
  const { resultados, resumen } = informe;
  const filasResumen = resultados.map((r) => `
      <tr><td><a href="#${escaparHtml(r.id)}">${escaparHtml(r.nombre)}</a></td><td>${escaparHtml(r.demuestra)}</td>
      <td class="num">${r.verificaciones.filter((v) => v.ok === true).length}/${r.verificaciones.filter((v) => v.ok !== null).length}</td>
      <td class="num">${(r.duracionMs / 1000).toFixed(1)} s</td><td>${etiqueta(r.omitido ? null : r.ok)}</td></tr>`).join('');

  const secciones = resultados.map((r) => `
  <section id="${escaparHtml(r.id)}">
    <h2>${escaparHtml(r.nombre)} ${etiqueta(r.omitido ? null : r.ok)}</h2>
    <p class="demuestra">${escaparHtml(r.demuestra)}</p>
    <table>
      <thead><tr><th>Verificación</th><th>Esperado</th><th>Obtenido</th><th>Resultado</th></tr></thead>
      <tbody>${r.verificaciones.map((v) => `
        <tr class="${v.ok === false ? 'fila-fallo' : ''}"><td>${escaparHtml(v.descripcion)}</td><td>${escaparHtml(v.esperado)}</td><td><code>${escaparHtml(v.obtenido)}</code></td><td>${etiqueta(v.ok)}</td></tr>`).join('')}
      </tbody>
    </table>
    ${Object.keys(r.metricas).length ? `
    <table class="metricas">
      <thead><tr><th>Métrica</th><th>Valor</th></tr></thead>
      <tbody>${Object.entries(r.metricas).map(([k, v]) => `<tr><td>${escaparHtml(k)}</td><td><code>${escaparHtml(formatearValor(v))}</code></td></tr>`).join('')}</tbody>
    </table>` : ''}
    ${r.notas.length ? `<ul class="notas">${r.notas.map((n) => `<li>${escaparHtml(n)}</li>`).join('')}</ul>` : ''}
    ${r.hallazgos.length ? `<ul class="hallazgos">${r.hallazgos.map((n) => `<li>${escaparHtml(n)}</li>`).join('')}</ul>` : ''}
  </section>`).join('');

  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Laboratorio de ataques — informe</title>
<style>
  :root { --fondo: #f7f7f5; --texto: #1d1d1b; --tenue: #66665f; --borde: #d9d9d3; --ok: #11733b; --fallo: #b3261e; --info: #8a5a00; --tarjeta: #fff; }
  @media (prefers-color-scheme: dark) { :root { --fondo: #161615; --texto: #ececea; --tenue: #a3a39b; --borde: #3a3a36; --ok: #5cd08a; --fallo: #ff8a80; --info: #f0c060; --tarjeta: #1f1f1d; } }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 24px 16px 64px; background: var(--fondo); color: var(--texto); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width: 1100px; margin: 0 auto; }
  h1 { font-size: 1.6rem; margin: 0 0 4px; }
  h2 { font-size: 1.15rem; margin: 0 0 4px; display: flex; gap: 10px; align-items: center; }
  .sub, .demuestra { color: var(--tenue); margin: 0 0 12px; }
  .cifras { display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0 24px; }
  .cifra { background: var(--tarjeta); border: 1px solid var(--borde); border-radius: 8px; padding: 10px 16px; min-width: 140px; }
  .cifra b { display: block; font-size: 1.5rem; }
  section { background: var(--tarjeta); border: 1px solid var(--borde); border-radius: 8px; padding: 16px; margin: 0 0 18px; overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 0.92rem; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--borde); vertical-align: top; }
  th { color: var(--tenue); font-weight: 600; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  code { font: 0.86rem/1.4 ui-monospace, "SFMono-Regular", Menlo, monospace; word-break: break-word; }
  .ok, .fallo, .info { font-weight: 700; font-size: 0.8rem; padding: 1px 8px; border-radius: 10px; border: 1px solid currentColor; white-space: nowrap; }
  .ok { color: var(--ok); } .fallo { color: var(--fallo); } .info { color: var(--info); }
  tr.fila-fallo td { background: color-mix(in srgb, var(--fallo) 8%, transparent); }
  .notas li { color: var(--info); } .hallazgos li { color: var(--fallo); font-weight: 600; }
  a { color: inherit; }
</style>
</head>
<body>
<main>
  <h1>Laboratorio de ataques simulados y caos</h1>
  <p class="sub">Servicio soberano TOTP · destino ${escaparHtml(informe.destino)} · generado ${escaparHtml(informe.generado)} · Node ${escaparHtml(informe.entorno?.node ?? '')}</p>
  <div class="cifras">
    <div class="cifra"><b>${resumen.correctos}/${resumen.evaluados}</b>escenarios OK</div>
    <div class="cifra"><b>${resumen.verificacionesOk}/${resumen.verificaciones}</b>verificaciones OK</div>
    <div class="cifra"><b>${resumen.hallazgos}</b>hallazgos</div>
    <div class="cifra"><b>${(resumen.duracionMs / 1000).toFixed(0)} s</b>duración total</div>
  </div>
  <section>
    <h2>Resumen</h2>
    <table>
      <thead><tr><th>Escenario</th><th>Qué demuestra</th><th>Verificaciones</th><th>Duración</th><th>Resultado</th></tr></thead>
      <tbody>${filasResumen}</tbody>
    </table>
  </section>
  ${secciones}
</main>
</body>
</html>
`;
}

/** Calcula el resumen agregado. */
export function resumir(resultados, duracionMs) {
  const evaluables = resultados.filter((r) => !r.omitido);
  const verifs = resultados.flatMap((r) => r.verificaciones.filter((v) => v.ok !== null));
  return {
    evaluados: evaluables.length,
    correctos: evaluables.filter((r) => r.ok).length,
    fallidos: evaluables.filter((r) => !r.ok).map((r) => r.id),
    omitidos: resultados.filter((r) => r.omitido).map((r) => r.id),
    verificaciones: verifs.length,
    verificacionesOk: verifs.filter((v) => v.ok).length,
    hallazgos: resultados.reduce((n, r) => n + r.hallazgos.length, 0),
    duracionMs,
  };
}

/** Escribe informe-<fecha>.json e informe-<fecha>.html en `carpeta`. Devuelve las rutas. */
export function escribirInforme(informe, carpeta) {
  mkdirSync(carpeta, { recursive: true });
  const base = `informe-${marcaFecha(new Date(informe.generado))}`;
  const json = join(carpeta, `${base}.json`);
  const html = join(carpeta, `${base}.html`);
  writeFileSync(json, `${JSON.stringify(informe, null, 2)}\n`);
  writeFileSync(html, generarHtml(informe));
  return { json, html };
}
