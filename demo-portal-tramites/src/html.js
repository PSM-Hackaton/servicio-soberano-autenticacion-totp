// Plantillas HTML con escape automático: toda interpolación se escapa salvo que sea Crudo.

class Crudo {
  constructor(texto) { this.texto = texto; }
  toString() { return this.texto; }
}

/** Marca un fragmento ya seguro (p. ej. el resultado de otra plantilla html``). */
export const crudo = (texto) => new Crudo(String(texto));

const MAPA = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };

/** @param {unknown} v */
export function escapar(v) {
  return String(v ?? '').replace(/[&<>"'`]/g, (c) => MAPA[c]);
}

function valor(v) {
  if (v === null || v === undefined || v === false) return '';
  if (v instanceof Crudo) return v.texto;
  if (Array.isArray(v)) return v.map(valor).join('');
  return escapar(v);
}

/** Etiqueta de plantilla: html`<p>${texto}</p>` devuelve Crudo con todo escapado. */
export function html(partes, ...valores) {
  let salida = partes[0];
  for (let i = 0; i < valores.length; i++) salida += valor(valores[i]) + partes[i + 1];
  return new Crudo(salida);
}
