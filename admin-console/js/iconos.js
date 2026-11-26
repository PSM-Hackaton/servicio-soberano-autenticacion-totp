// Juego de iconos propio (24×24, trazo). Dibujados a mano para la consola; sin fuentes ni CDNs.
import { s } from './dom.js';

/** @type {Record<string, [string, Record<string, any>][]>} */
const FORMAS = {
  panel: [['rect', { x: 3.5, y: 3.5, width: 7, height: 9, rx: 1.5 }], ['rect', { x: 13.5, y: 3.5, width: 7, height: 5, rx: 1.5 }], ['rect', { x: 13.5, y: 11.5, width: 7, height: 9, rx: 1.5 }], ['rect', { x: 3.5, y: 15.5, width: 7, height: 5, rx: 1.5 }]],
  aplicaciones: [['path', { d: 'M12 3.5 3.5 8 12 12.5 20.5 8z' }], ['path', { d: 'm3.5 12 8.5 4.5 8.5-4.5' }], ['path', { d: 'm3.5 16 8.5 4.5 8.5-4.5' }]],
  enrolamientos: [['circle', { cx: 9, cy: 8, r: 3.5 }], ['path', { d: 'M2.5 19.5c.7-3.4 3.3-5.5 6.5-5.5 1.6 0 3 .5 4.1 1.4' }], ['rect', { x: 14.5, y: 13.5, width: 7, height: 6.5, rx: 1.3 }], ['path', { d: 'M16 13.5v-1.6a2 2 0 0 1 4 0v1.6' }]],
  anomalias: [['path', { d: 'M3 12h3.5l2.5-6 4 12 2.5-6H21' }]],
  llaves: [['circle', { cx: 8, cy: 15, r: 4.5 }], ['path', { d: 'm11.3 11.7 8.7-8.7' }], ['path', { d: 'm16.5 6.5 2.5 2.5' }], ['path', { d: 'm14 9 2 2' }]],
  auditoria: [['path', { d: 'M6 3.5h9l3.5 3.5v13.5H6z' }], ['path', { d: 'M14.5 3.5V7h4' }], ['path', { d: 'M9 12h6M9 15.5h6M9 8.5h2.5' }]],
  salir: [['path', { d: 'M14 4.5H6.5a1 1 0 0 0-1 1v13a1 1 0 0 0 1 1H14' }], ['path', { d: 'M10.5 12h10M17 8.5l3.5 3.5-3.5 3.5' }]],
  menu: [['path', { d: 'M4 7h16M4 12h16M4 17h16' }]],
  cerrar: [['path', { d: 'm6 6 12 12M18 6 6 18' }]],
  actualizar: [['path', { d: 'M19.5 12a7.5 7.5 0 1 1-2.2-5.3' }], ['path', { d: 'M19.5 4v4.5H15' }]],
  pausa: [['path', { d: 'M9 6v12M15 6v12' }]],
  ok: [['circle', { cx: 12, cy: 12, r: 8.5 }], ['path', { d: 'm8.5 12.2 2.4 2.4 4.8-5' }]],
  check: [['path', { d: 'm5 12.5 4.5 4.5L19 7.5' }]],
  aviso: [['path', { d: 'M12 4 2.8 19.5h18.4z' }], ['path', { d: 'M12 10v4.5' }], ['circle', { cx: 12, cy: 17, r: 0.4, fill: 'currentColor' }]],
  error: [['circle', { cx: 12, cy: 12, r: 8.5 }], ['path', { d: 'm9 9 6 6m0-6-6 6' }]],
  info: [['circle', { cx: 12, cy: 12, r: 8.5 }], ['path', { d: 'M12 11v5.5' }], ['circle', { cx: 12, cy: 7.8, r: 0.4, fill: 'currentColor' }]],
  escudo: [['path', { d: 'M12 3 4.5 6v5.6c0 4.6 3.1 8.2 7.5 9.4 4.4-1.2 7.5-4.8 7.5-9.4V6z' }], ['path', { d: 'm8.8 12 2.3 2.3 4.2-4.4' }]],
  escudoRoto: [['path', { d: 'M12 3 4.5 6v5.6c0 4.6 3.1 8.2 7.5 9.4 4.4-1.2 7.5-4.8 7.5-9.4V6z' }], ['path', { d: 'm12 7-1.5 4h3L12 16' }]],
  copiar: [['rect', { x: 8.5, y: 8.5, width: 11, height: 11, rx: 1.8 }], ['path', { d: 'M15.5 8.5v-3a1 1 0 0 0-1-1h-9a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h3' }]],
  candado: [['rect', { x: 5, y: 10.5, width: 14, height: 10, rx: 2 }], ['path', { d: 'M8 10.5V8a4 4 0 0 1 8 0v2.5' }], ['path', { d: 'M12 14.5v2' }]],
  buscar: [['circle', { cx: 10.5, cy: 10.5, r: 6 }], ['path', { d: 'm15 15 5 5' }]],
  izquierda: [['path', { d: 'm14.5 6-6 6 6 6' }]],
  derecha: [['path', { d: 'm9.5 6 6 6-6 6' }]],
  editar: [['path', { d: 'M4.5 19.5 5.3 15.6 15.8 5.1a1.9 1.9 0 0 1 2.7 0l.4.4a1.9 1.9 0 0 1 0 2.7L8.4 18.7z' }], ['path', { d: 'm13.8 7.1 3.1 3.1' }]],
  sol: [['circle', { cx: 12, cy: 12, r: 4 }], ['path', { d: 'M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4' }]],
  luna: [['path', { d: 'M19.5 14.5A8 8 0 0 1 9.5 4.5a8 8 0 1 0 10 10z' }]],
  auto: [['circle', { cx: 12, cy: 12, r: 8.5 }], ['path', { d: 'M12 3.5v17a8.5 8.5 0 0 0 0-17z', fill: 'currentColor', stroke: 'none' }]],
  reloj: [['circle', { cx: 12, cy: 12, r: 8.5 }], ['path', { d: 'M12 7.5V12l3 2' }]],
  servidor: [['rect', { x: 4, y: 4.5, width: 16, height: 6, rx: 1.5 }], ['rect', { x: 4, y: 13.5, width: 16, height: 6, rx: 1.5 }], ['path', { d: 'M7.5 7.5h.01M7.5 16.5h.01' }]],
  ojo: [['path', { d: 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z' }], ['circle', { cx: 12, cy: 12, r: 3 }]],
  ojoNo: [['path', { d: 'M4 4l16 16' }], ['path', { d: 'M9.9 5.8A9.5 9.5 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a16 16 0 0 1-2.6 3.4M6.4 7.2C3.9 8.9 2.5 12 2.5 12s3.5 6.5 9.5 6.5c1.4 0 2.6-.3 3.7-.8' }], ['path', { d: 'M10 10a3 3 0 0 0 4 4' }]],
  cadena: [['path', { d: 'M10 14a3.5 3.5 0 0 0 5 0l3-3a3.5 3.5 0 0 0-5-5l-.8.8' }], ['path', { d: 'M14 10a3.5 3.5 0 0 0-5 0l-3 3a3.5 3.5 0 0 0 5 5l.8-.8' }]],
  sinConexion: [['path', { d: 'M4 4l16 16' }], ['path', { d: 'M8.5 16a5 5 0 0 1 7 0M5 12.5a10 10 0 0 1 4-2.3M19 12.5a10 10 0 0 0-3.2-2M2 9a14 14 0 0 1 4.3-2.6M22 9A14 14 0 0 0 11 5.6' }], ['circle', { cx: 12, cy: 19.5, r: 0.5, fill: 'currentColor' }]],
  rotar: [['path', { d: 'M4.5 12a7.5 7.5 0 0 1 12.8-5.3L19.5 9' }], ['path', { d: 'M19.5 4v5h-5' }], ['path', { d: 'M19.5 12a7.5 7.5 0 0 1-12.8 5.3L4.5 15' }], ['path', { d: 'M4.5 20v-5h5' }]],
  usuario: [['circle', { cx: 12, cy: 8.5, r: 4 }], ['path', { d: 'M4.5 20c.9-3.8 3.9-6 7.5-6s6.6 2.2 7.5 6' }]],
  filtro: [['path', { d: 'M4 5h16l-6.2 7.5V19l-3.6-1.8v-4.7z' }]],
  suspender: [['circle', { cx: 12, cy: 12, r: 8.5 }], ['path', { d: 'M10 9v6M14 9v6' }]],
  reactivar: [['circle', { cx: 12, cy: 12, r: 8.5 }], ['path', { d: 'm10 8.5 5.5 3.5-5.5 3.5z' }]],
  revocar: [['circle', { cx: 12, cy: 12, r: 8.5 }], ['path', { d: 'm6 6 12 12' }]],
  descargar: [['path', { d: 'M12 4v11M7.5 10.5 12 15l4.5-4.5' }], ['path', { d: 'M4.5 19.5h15' }]],
  marca: [['path', { d: 'M12 3 4.8 5.8v5.8c0 4.4 3 8.1 7.2 9.4 4.2-1.3 7.2-5 7.2-9.4V5.8z' }], ['path', { d: 'M12 8.5V12l2.6 1.6' }]],
};

/**
 * Devuelve un SVG de icono decorativo (aria-hidden) o con título accesible.
 * @param {string} nombre @param {{ titulo?: string, clase?: string }} [opciones]
 */
export function icono(nombre, { titulo, clase } = {}) {
  const formas = FORMAS[nombre] ?? FORMAS.info;
  const svg = s('svg', {
    viewBox: '0 0 24 24', width: 20, height: 20, fill: 'none', stroke: 'currentColor',
    'stroke-width': 1.75, 'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    class: ['icono', clase].filter(Boolean).join(' '),
    'aria-hidden': titulo ? null : 'true', role: titulo ? 'img' : null, focusable: 'false',
  });
  if (titulo) svg.append(s('title', { text: titulo }));
  for (const [etiqueta, atributos] of formas) svg.append(s(etiqueta, atributos));
  return svg;
}

/** Sustituye los marcadores <span data-icono="x"> del HTML estático por el icono. */
export function hidratarIconos(raiz = document) {
  for (const el of raiz.querySelectorAll('[data-icono]')) {
    if (el.firstChild) continue;
    el.append(icono(el.dataset.icono));
  }
}
