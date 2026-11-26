// Gráficos SVG propios generados en el cliente (sin bibliotecas). Se redibujan al cambiar el
// ancho del contenedor. Colores por clase CSS para respetar el modo claro/oscuro.
import { h, s, hora, numero, decimal } from './dom.js';

const ALTO = 200;
const MARGEN = { arriba: 12, derecha: 12, abajo: 26, izquierda: 40 };

/** Escala "bonita" para el eje Y. */
function maximoBonito(v) {
  if (v <= 0) return 1;
  const exp = 10 ** Math.floor(Math.log10(v));
  const f = v / exp;
  const paso = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
  return paso * exp;
}

/**
 * Monta un gráfico responsive con tooltip.
 * @param {HTMLElement} contenedor
 * @param {(ancho: number, tooltip: (x: number, y: number, contenido: any) => void, ocultar: () => void) => SVGElement} dibujar
 */
function montar(contenedor, dibujar) {
  contenedor.classList.add('grafico');
  const lienzo = h('div.grafico-lienzo');
  const burbuja = h('div.grafico-burbuja', { role: 'presentation', hidden: true });
  contenedor.replaceChildren(lienzo, burbuja);
  const tooltip = (x, y, contenido) => {
    burbuja.replaceChildren(contenido);
    burbuja.hidden = false;
    const ancho = lienzo.clientWidth;
    const bw = burbuja.offsetWidth;
    burbuja.style.left = `${Math.max(0, Math.min(ancho - bw, x - bw / 2))}px`;
    burbuja.style.top = `${Math.max(0, y - burbuja.offsetHeight - 10)}px`;
  };
  const ocultar = () => { burbuja.hidden = true; };
  let ultimoAncho = 0;
  const redibujar = () => {
    const ancho = Math.max(260, Math.floor(lienzo.clientWidth || contenedor.clientWidth || 600));
    if (ancho === ultimoAncho && lienzo.firstChild) return;
    ultimoAncho = ancho;
    lienzo.replaceChildren(dibujar(ancho, tooltip, ocultar));
  };
  const ro = new ResizeObserver(() => redibujar());
  ro.observe(contenedor);
  redibujar();
  return { desmontar: () => ro.disconnect(), forzar: () => { ultimoAncho = 0; redibujar(); } };
}

function ejeY(g, maximo, ancho, alto, formato) {
  for (let i = 0; i <= 4; i++) {
    const v = (maximo / 4) * i;
    const y = MARGEN.arriba + alto - (alto * i) / 4;
    g.append(s('line', { x1: MARGEN.izquierda, x2: ancho - MARGEN.derecha, y1: y, y2: y, class: i === 0 ? 'eje-base' : 'eje-rejilla' }));
    g.append(s('text', { x: MARGEN.izquierda - 8, y: y + 4, 'text-anchor': 'end', class: 'eje-texto', text: formato(v) }));
  }
}

function etiquetasX(g, serie, xDe, alto, ancho) {
  const cada = Math.max(1, Math.ceil(serie.length / Math.max(2, Math.floor((ancho - 60) / 70))));
  serie.forEach((p, i) => {
    if (i % cada !== 0 && i !== serie.length - 1) return;
    if (i !== serie.length - 1 && serie.length - 1 - i < cada * 0.6) return;
    g.append(s('text', { x: xDe(i), y: MARGEN.arriba + alto + 18, 'text-anchor': 'middle', class: 'eje-texto', text: hora(p.ts) }));
  });
}

function contenidoBurbuja(p, claves) {
  return h('div', null,
    h('strong.num', { text: hora(p.ts) }),
    ...claves.map((c) => h('div.burbuja-fila', null, h('span', { class: `punto punto--${c.tono}` }), h('span', { text: c.etiqueta }), h('span.num', { text: c.formato ? c.formato(p[c.clave]) : numero(p[c.clave]) }))));
}

/**
 * Columnas apiladas por intervalo.
 * @param {HTMLElement} contenedor
 * @param {{ ts: string, [k: string]: any }[]} serie
 * @param {{ clave: string, etiqueta: string, tono: string }[]} claves
 */
export function columnasApiladas(contenedor, serie, claves) {
  return montar(contenedor, (ancho, tooltip, ocultar) => {
    const alto = ALTO - MARGEN.arriba - MARGEN.abajo;
    const util = ancho - MARGEN.izquierda - MARGEN.derecha;
    const totales = serie.map((p) => claves.reduce((a, c) => a + (Number(p[c.clave]) || 0), 0));
    const maximo = maximoBonito(Math.max(1, ...totales));
    const paso = util / Math.max(1, serie.length);
    const anchoCol = Math.max(2, Math.min(18, paso * 0.68));
    const xDe = (i) => MARGEN.izquierda + paso * i + paso / 2;
    const svg = s('svg', { width: ancho, height: ALTO, viewBox: `0 0 ${ancho} ${ALTO}`, 'aria-hidden': 'true', focusable: 'false' });
    const g = s('g');
    ejeY(g, maximo, ancho, alto, (v) => numero(v));
    serie.forEach((p, i) => {
      let base = MARGEN.arriba + alto;
      const col = s('g', { class: 'columna' });
      claves.forEach((c, j) => {
        const v = Number(p[c.clave]) || 0;
        if (v <= 0) return;
        const hh = (v / maximo) * alto;
        base -= hh;
        const esUltimo = claves.slice(j + 1).every((k) => !(Number(p[k.clave]) > 0));
        col.append(s('rect', { x: xDe(i) - anchoCol / 2, y: base, width: anchoCol, height: Math.max(0.5, hh - (esUltimo ? 0 : 1)), rx: esUltimo ? 1.5 : 0, class: `serie serie--${c.tono}` }));
      });
      const zona = s('rect', { x: MARGEN.izquierda + paso * i, y: MARGEN.arriba, width: paso, height: alto, class: 'zona-activa' });
      zona.addEventListener('pointerenter', () => { col.classList.add('resaltada'); tooltip(xDe(i), MARGEN.arriba + alto - (totales[i] / maximo) * alto, contenidoBurbuja(p, claves)); });
      zona.addEventListener('pointerleave', () => { col.classList.remove('resaltada'); ocultar(); });
      g.append(col, zona);
    });
    etiquetasX(g, serie, xDe, alto, ancho);
    svg.append(g);
    return svg;
  });
}

/**
 * Líneas (latencia) con umbral opcional de referencia.
 * @param {HTMLElement} contenedor
 * @param {{ ts: string, [k: string]: any }[]} serie
 * @param {{ clave: string, etiqueta: string, tono: string }[]} claves
 * @param {{ umbral?: number, etiquetaUmbral?: string }} [opciones]
 */
export function lineas(contenedor, serie, claves, { umbral, etiquetaUmbral } = {}) {
  const fmt = (v) => `${decimal(v, 1)} ms`;
  const conFormato = claves.map((c) => ({ ...c, formato: fmt }));
  return montar(contenedor, (ancho, tooltip, ocultar) => {
    const alto = ALTO - MARGEN.arriba - MARGEN.abajo;
    const util = ancho - MARGEN.izquierda - MARGEN.derecha;
    const valores = serie.flatMap((p) => claves.map((c) => Number(p[c.clave]) || 0));
    const maximo = maximoBonito(Math.max(1, ...valores, umbral ? umbral * 1.1 : 0));
    const xDe = (i) => MARGEN.izquierda + (serie.length <= 1 ? util / 2 : (util * i) / (serie.length - 1));
    const yDe = (v) => MARGEN.arriba + alto - (v / maximo) * alto;
    const svg = s('svg', { width: ancho, height: ALTO, viewBox: `0 0 ${ancho} ${ALTO}`, 'aria-hidden': 'true', focusable: 'false' });
    const g = s('g');
    ejeY(g, maximo, ancho, alto, (v) => numero(v));
    if (umbral) {
      const y = yDe(umbral);
      g.append(s('line', { x1: MARGEN.izquierda, x2: ancho - MARGEN.derecha, y1: y, y2: y, class: 'umbral' }));
      g.append(s('text', { x: ancho - MARGEN.derecha, y: y - 5, 'text-anchor': 'end', class: 'umbral-texto', text: etiquetaUmbral ?? `Objetivo ${numero(umbral)} ms` }));
    }
    claves.forEach((c, j) => {
      const d = serie.map((p, i) => `${i ? 'L' : 'M'}${xDe(i).toFixed(1)},${yDe(Number(p[c.clave]) || 0).toFixed(1)}`).join('');
      if (j === 0 && serie.length > 1) {
        g.append(s('path', { d: `${d}L${xDe(serie.length - 1).toFixed(1)},${MARGEN.arriba + alto}L${xDe(0).toFixed(1)},${MARGEN.arriba + alto}Z`, class: `area area--${c.tono}` }));
      }
      g.append(s('path', { d, class: `linea linea--${c.tono}` }));
    });
    const guia = s('line', { y1: MARGEN.arriba, y2: MARGEN.arriba + alto, class: 'guia', visibility: 'hidden' });
    const puntos = claves.map((c) => s('circle', { r: 3.5, class: `marcador marcador--${c.tono}`, visibility: 'hidden' }));
    g.append(guia, ...puntos);
    const zona = s('rect', { x: MARGEN.izquierda, y: MARGEN.arriba, width: util, height: alto, class: 'zona-activa' });
    zona.addEventListener('pointermove', (ev) => {
      const caja = svg.getBoundingClientRect();
      const x = ((ev.clientX - caja.left) / caja.width) * ancho;
      const i = Math.max(0, Math.min(serie.length - 1, Math.round(((x - MARGEN.izquierda) / util) * (serie.length - 1))));
      const p = serie[i];
      guia.setAttribute('x1', xDe(i)); guia.setAttribute('x2', xDe(i)); guia.setAttribute('visibility', 'visible');
      claves.forEach((c, j) => { puntos[j].setAttribute('cx', xDe(i)); puntos[j].setAttribute('cy', yDe(Number(p[c.clave]) || 0)); puntos[j].setAttribute('visibility', 'visible'); });
      tooltip(xDe(i), yDe(Math.max(...claves.map((c) => Number(p[c.clave]) || 0))), contenidoBurbuja(p, conFormato));
    });
    zona.addEventListener('pointerleave', () => { guia.setAttribute('visibility', 'hidden'); puntos.forEach((pt) => pt.setAttribute('visibility', 'hidden')); ocultar(); });
    g.append(zona);
    etiquetasX(g, serie, xDe, alto, ancho);
    svg.append(g);
    return svg;
  });
}

/**
 * Barra apilada horizontal (proporciones) en HTML; anchos por variable CSS.
 * @param {{ etiqueta: string, valor: number, tono: string }[]} segmentos
 */
export function barraProporcion(segmentos) {
  const total = segmentos.reduce((a, x) => a + x.valor, 0) || 1;
  return h('div.barra-proporcion', { role: 'img', 'aria-label': segmentos.map((x) => `${x.etiqueta}: ${numero(x.valor)}`).join('; ') },
    segmentos.filter((x) => x.valor > 0).map((x) => h('span', { class: `segmento segmento--${x.tono}`, vars: { peso: x.valor / total }, title: `${x.etiqueta}: ${numero(x.valor)}` })));
}

/** Medidor semicircular sencillo (0–100) para el puntaje de riesgo. */
export function medidor(valor, tono) {
  const v = Math.max(0, Math.min(100, Number(valor) || 0));
  const r = 20;
  const largo = Math.PI * r;
  return s('svg', { viewBox: '0 0 48 28', width: 56, height: 32, class: 'medidor', 'aria-hidden': 'true' },
    s('path', { d: 'M4 24a20 20 0 0 1 40 0', class: 'medidor-pista' }),
    s('path', { d: 'M4 24a20 20 0 0 1 40 0', class: `medidor-valor medidor-valor--${tono}`, 'stroke-dasharray': `${(largo * v) / 100} ${largo}` }));
}

/** Tabla accesible con los datos del gráfico (alternativa textual). */
export function tablaDatos(titulo, serie, claves, formato = numero) {
  return h('details.datos-grafico', null,
    h('summary', { text: 'Ver datos en tabla' }),
    h('div.tabla-contenedor', null,
      h('table.tabla.tabla--compacta', null,
        h('caption.solo-lectores', { text: titulo }),
        h('thead', null, h('tr', null, h('th', { scope: 'col', text: 'Hora' }), claves.map((c) => h('th.num', { scope: 'col', text: c.etiqueta })))),
        h('tbody', null, serie.slice().reverse().map((p) => h('tr', null, h('td.num', { text: hora(p.ts) }), claves.map((c) => h('td.num', { text: formato(p[c.clave]) }))))))));
}
