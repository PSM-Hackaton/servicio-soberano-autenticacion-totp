// Utilidades DOM y de formato. Todo el contenido se construye con nodos (nunca innerHTML),
// lo que elimina por diseño la inyección de HTML desde datos del servidor.

const NS_SVG = 'http://www.w3.org/2000/svg';
const PROPIEDADES = new Set(['value', 'checked', 'disabled', 'hidden', 'selected', 'indeterminate', 'open', 'required', 'readOnly', 'tabIndex']);

/**
 * Crea un elemento HTML.
 * @param {string} etiqueta  admite atajos "div.clase1.clase2"
 * @param {Record<string, any> | null} [atributos]
 * @param {...any} hijos
 * @returns {HTMLElement}
 */
export function h(etiqueta, atributos, ...hijos) {
  const [nombre, ...clases] = etiqueta.split('.');
  const el = document.createElement(nombre || 'div');
  if (clases.length) el.classList.add(...clases);
  aplicar(el, atributos);
  anexar(el, hijos);
  return el;
}

/**
 * Crea un elemento SVG.
 * @param {string} etiqueta @param {Record<string, any> | null} [atributos] @param {...any} hijos
 * @returns {SVGElement}
 */
export function s(etiqueta, atributos, ...hijos) {
  const el = document.createElementNS(NS_SVG, etiqueta);
  aplicar(el, atributos, true);
  anexar(el, hijos);
  return el;
}

function aplicar(el, atributos, esSvg = false) {
  if (!atributos) return;
  for (const [clave, valor] of Object.entries(atributos)) {
    if (valor === undefined || valor === null || valor === false) continue;
    if (clave === 'class') {
      const lista = (Array.isArray(valor) ? valor : [valor]).filter(Boolean).flatMap((c) => String(c).split(/\s+/)).filter(Boolean);
      if (lista.length) el.classList.add(...lista);
    } else if (clave === 'text') {
      el.textContent = String(valor);
    } else if (clave === 'on') {
      for (const [evento, fn] of Object.entries(valor)) el.addEventListener(evento, fn);
    } else if (clave === 'dataset') {
      for (const [k, v] of Object.entries(valor)) if (v !== undefined && v !== null) el.dataset[k] = String(v);
    } else if (clave === 'vars') {
      // Variables CSS por CSSOM (permitido por la CSP; no usa el atributo style).
      for (const [k, v] of Object.entries(valor)) el.style.setProperty(`--${k}`, String(v));
    } else if (!esSvg && PROPIEDADES.has(clave)) {
      el[clave] = valor;
    } else {
      el.setAttribute(clave, valor === true ? '' : String(valor));
    }
  }
}

function anexar(el, hijos) {
  for (const hijo of hijos.flat(Infinity)) {
    if (hijo === null || hijo === undefined || hijo === false) continue;
    el.append(hijo instanceof Node ? hijo : document.createTextNode(String(hijo)));
  }
}

/** Vacía un nodo y le pone nuevos hijos. */
export function reemplazar(el, ...hijos) {
  el.replaceChildren();
  anexar(el, hijos);
  return el;
}

/** Selector abreviado. @returns {any} */
export const $ = (sel, raiz = document) => raiz.querySelector(sel);

let contadorId = 0;
/** Identificador único para relacionar etiquetas y campos. */
export const idUnico = (prefijo = 'id') => `${prefijo}-${++contadorId}`;

// ------------------------------------------------------------------ formato
const LOCALE = 'es';
const fmtEntero = new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 0 });
const fmtDecimal = new Intl.NumberFormat(LOCALE, { minimumFractionDigits: 1, maximumFractionDigits: 1 });
const fmtFecha = new Intl.DateTimeFormat(LOCALE, { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const fmtHora = new Intl.DateTimeFormat(LOCALE, { hour: '2-digit', minute: '2-digit', hour12: false });
const fmtRelativo = new Intl.RelativeTimeFormat(LOCALE, { numeric: 'auto' });

export const numero = (n) => (Number.isFinite(Number(n)) ? fmtEntero.format(Number(n)) : '—');
export const decimal = (n, dec = 1) => {
  if (!Number.isFinite(Number(n))) return '—';
  return dec === 1 ? fmtDecimal.format(Number(n)) : new Intl.NumberFormat(LOCALE, { minimumFractionDigits: dec, maximumFractionDigits: dec }).format(Number(n));
};
export const porcentaje = (n, dec = 1) => (Number.isFinite(Number(n)) ? `${decimal(n, dec)} %` : '—');
export const ms = (n) => {
  if (!Number.isFinite(Number(n))) return '—';
  const v = Number(n);
  return v >= 100 ? `${numero(v)} ms` : `${decimal(v, 1)} ms`;
};

export function fecha(valor) {
  const d = new Date(valor);
  return Number.isNaN(d.getTime()) ? '—' : fmtFecha.format(d).replace(',', '');
}
const fmtCorta = new Intl.DateTimeFormat(LOCALE, { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });
/** "26/11 11:14" para tablas densas (la fecha completa va en el título). */
export function fechaCorta(valor) {
  const d = new Date(valor);
  return Number.isNaN(d.getTime()) ? '—' : fmtCorta.format(d).replace(',', '');
}
export function hora(valor) {
  const d = new Date(valor);
  return Number.isNaN(d.getTime()) ? '—' : fmtHora.format(d);
}

/** "hace 3 min", "hace 2 h"… */
export function relativo(valor, ahora = Date.now()) {
  const t = new Date(valor).getTime();
  if (Number.isNaN(t)) return '—';
  const seg = Math.round((t - ahora) / 1000);
  const abs = Math.abs(seg);
  if (abs < 45) return fmtRelativo.format(seg, 'second');
  if (abs < 2700) return fmtRelativo.format(Math.round(seg / 60), 'minute');
  if (abs < 86400 * 1.5) return fmtRelativo.format(Math.round(seg / 3600), 'hour');
  return fmtRelativo.format(Math.round(seg / 86400), 'day');
}

/** Elemento <time> con fecha absoluta y relativa en el título. */
export function tiempo(valor, { relativa = false, corta = false } = {}) {
  if (!valor) return h('span.tenue', { text: '—' });
  const d = new Date(valor);
  if (Number.isNaN(d.getTime())) return h('span.tenue', { text: '—' });
  const texto = relativa ? relativo(valor) : corta ? fechaCorta(valor) : fecha(valor);
  return h('time', { datetime: d.toISOString(), title: relativa || corta ? fecha(valor) : relativo(valor), class: 'num', text: texto });
}

/** Acorta un hash largo dejando principio y final. */
export function hashCorto(hash, ini = 10, fin = 6) {
  if (!hash) return '—';
  const t = String(hash);
  return t.length <= ini + fin + 1 ? t : `${t.slice(0, ini)}…${t.slice(-fin)}`;
}

/** Copia texto al portapapeles (si el contexto lo permite). */
export async function copiar(texto) {
  try {
    await navigator.clipboard.writeText(texto);
    return true;
  } catch {
    return false;
  }
}

/** Limita la frecuencia de una función. */
export function rebote(fn, espera = 200) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), espera);
  };
}

/** Lectura y escritura seguras de almacenamiento local (puede no estar disponible). */
export const almacen = {
  leer(clave, defecto = null) {
    try {
      const v = localStorage.getItem(clave);
      return v === null ? defecto : JSON.parse(v);
    } catch {
      return defecto;
    }
  },
  escribir(clave, valor) {
    try {
      localStorage.setItem(clave, JSON.stringify(valor));
      return true;
    } catch {
      return false;
    }
  },
  borrar(clave) {
    try { localStorage.removeItem(clave); } catch { /* sin almacenamiento */ }
  },
};
