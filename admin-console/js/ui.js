// Componentes de interfaz reutilizables: notificaciones, diálogos, insignias, estados vacíos,
// tarjetas de indicadores y cabeceras de página.
import { h, $, idUnico, copiar } from './dom.js';
import { icono } from './iconos.js';

// ------------------------------------------------------------------ notificaciones
/** @param {string} mensaje @param {'ok' | 'aviso' | 'peligro' | 'info'} [tono] */
export function notificar(mensaje, tono = 'info', duracion = 5000) {
  const zona = $('#notificaciones');
  const nombreIcono = { ok: 'ok', aviso: 'aviso', peligro: 'error', info: 'info' }[tono];
  const cerrar = h('button.boton-icono.boton-icono--mini', { type: 'button', 'aria-label': 'Cerrar notificación' }, icono('cerrar'));
  const nodo = h('div', { class: `notificacion notificacion--${tono}`, role: tono === 'peligro' ? 'alert' : 'status' },
    icono(nombreIcono), h('p', { text: mensaje }), cerrar);
  const quitar = () => { nodo.classList.add('saliendo'); setTimeout(() => nodo.remove(), 180); };
  cerrar.addEventListener('click', quitar);
  zona.append(nodo);
  if (duracion) setTimeout(quitar, duracion);
  return quitar;
}

// ------------------------------------------------------------------ diálogos
const dialogo = () => /** @type {HTMLDialogElement} */ ($('#dialogo'));
let generacion = 0;

/**
 * Abre el diálogo modal con contenido arbitrario. Devuelve una función para cerrarlo.
 * @param {{ titulo: string, contenido: Node | Node[], pie?: Node | Node[], tono?: string, ancho?: 'normal' | 'ancho', alCerrar?: () => void }} op
 */
export function abrirDialogo({ titulo, contenido, pie, tono, ancho = 'normal', alCerrar }) {
  const d = dialogo();
  const idTitulo = idUnico('dlg');
  d.className = `dialogo dialogo--${ancho}${tono ? ` dialogo--${tono}` : ''}`;
  d.setAttribute('aria-labelledby', idTitulo);
  const cerrarBtn = h('button.boton-icono', { type: 'button', 'aria-label': 'Cerrar' }, icono('cerrar'));
  d.replaceChildren(
    h('header.dialogo-cabecera', null, h('h2', { id: idTitulo, text: titulo }), cerrarBtn),
    h('div.dialogo-cuerpo', null, contenido),
    pie ? h('footer.dialogo-pie', null, pie) : null,
  );
  const gen = ++generacion;
  const cerrar = () => { if (d.open && gen === generacion) d.close(); };
  cerrarBtn.addEventListener('click', cerrar);
  d.addEventListener('close', () => {
    // Si entretanto se abrió otro diálogo, no se borra su contenido.
    if (gen === generacion && !d.open) d.replaceChildren();
    alCerrar?.();
  }, { once: true });
  d.onclick = (ev) => { if (ev.target === d) cerrar(); };
  if (!d.open) d.showModal();
  const primero = d.querySelector('[autofocus]') ?? d.querySelector('.dialogo-cuerpo input, .dialogo-cuerpo select, .dialogo-pie .boton--primario, .dialogo-pie .boton--peligro');
  primero?.focus();
  return cerrar;
}

/**
 * Confirmación simple. Resuelve true si se acepta.
 * @param {{ titulo: string, mensaje: string | Node, confirmar?: string, tono?: 'primario' | 'peligro', detalle?: Node }} op
 */
export function confirmar({ titulo, mensaje, confirmar: texto = 'Confirmar', tono = 'primario', detalle }) {
  return new Promise((resolver) => {
    let aceptado = false;
    const ok = h('button', { type: 'button', class: `boton boton--${tono}`, text: texto });
    const cancelar = h('button.boton.boton--secundario', { type: 'button', text: 'Cancelar' });
    const cerrar = abrirDialogo({
      titulo,
      tono: tono === 'peligro' ? 'peligro' : undefined,
      contenido: [typeof mensaje === 'string' ? h('p', { text: mensaje }) : mensaje, detalle ?? null].filter(Boolean),
      pie: [cancelar, ok],
      alCerrar: () => resolver(aceptado),
    });
    cancelar.addEventListener('click', cerrar);
    ok.addEventListener('click', () => { aceptado = true; cerrar(); });
    ok.focus();
  });
}

// ------------------------------------------------------------------ piezas
const TONOS_ESTADO = {
  activo: 'ok', activa: 'ok', ok: 'ok', integra: 'ok',
  pendiente: 'neutro', solo_verificacion: 'info', monitorizacion: 'info',
  suspendido: 'aviso', degradado: 'aviso',
  revocado: 'peligro', retirada: 'neutro', bloqueo: 'neutro', error: 'peligro',
};
const TEXTO_ESTADO = {
  activo: 'Activo', activa: 'Activa', pendiente: 'Pendiente', suspendido: 'Suspendido', revocado: 'Revocado',
  solo_verificacion: 'Solo verificación', retirada: 'Retirada', monitorizacion: 'Monitorización', bloqueo: 'Bloqueo',
};

/** Insignia de estado con punto de color y texto (nunca solo color). */
export function insigniaEstado(estado, texto) {
  const tono = TONOS_ESTADO[estado] ?? 'neutro';
  return h('span', { class: `estado estado--${tono}` }, h('span.estado-punto', { 'aria-hidden': 'true' }), texto ?? TEXTO_ESTADO[estado] ?? String(estado));
}

const NIVELES = {
  LOW: { texto: 'Bajo', tono: 'neutro' },
  MEDIUM: { texto: 'Medio', tono: 'aviso' },
  HIGH: { texto: 'Alto', tono: 'peligro' },
  CRITICAL: { texto: 'Crítico', tono: 'critico' },
};
export const nivelInfo = (n) => NIVELES[n] ?? NIVELES.LOW;
export function insigniaNivel(nivel) {
  const n = nivelInfo(nivel);
  return h('span', { class: `nivel nivel--${n.tono}`, text: n.texto });
}
const ACCIONES = {
  ALLOW: { texto: 'Permitir', tono: 'neutro', icono: 'check' },
  DELAY: { texto: 'Espera adicional', tono: 'aviso', icono: 'reloj' },
  WARN: { texto: 'Alerta', tono: 'aviso', icono: 'aviso' },
  BLOCK: { texto: 'Bloqueo temporal', tono: 'peligro', icono: 'candado' },
};
export function etiquetaAccion(accion) {
  const a = ACCIONES[accion] ?? ACCIONES.ALLOW;
  return h('span', { class: `accion accion--${a.tono}` }, icono(a.icono), a.texto);
}

/** Cabecera de página con título, descripción y acciones. */
export function cabeceraPagina({ titulo, descripcion, acciones = [] }) {
  return h('header.pagina-cabecera', null,
    h('div', null, h('h1', { text: titulo }), descripcion ? h('p.pagina-descripcion', { text: descripcion }) : null),
    acciones.length ? h('div.pagina-acciones', null, acciones) : null);
}

/** Tarjeta de indicador (KPI). */
export function tarjetaKpi({ etiqueta, valor, unidad, detalle, tono, icono: nombreIcono, ayuda }) {
  return h('article', { class: ['kpi', tono ? `kpi--${tono}` : ''] },
    h('header.kpi-cabecera', null,
      h('h3.kpi-etiqueta', { text: etiqueta }),
      nombreIcono ? h('span.kpi-icono', null, icono(nombreIcono)) : null),
    h('p.kpi-valor', null, h('span.num', { text: valor }), unidad ? h('span.kpi-unidad', { text: unidad }) : null),
    detalle ? h('p.kpi-detalle', { title: ayuda ?? null }, detalle) : null);
}

/** Estado vacío. */
export function vacio(titulo, texto, nombreIcono = 'info') {
  return h('div.vacio', null, h('span.vacio-icono', null, icono(nombreIcono)), h('p.vacio-titulo', { text: titulo }), texto ? h('p.vacio-texto', { text: texto }) : null);
}

/** Estado de error con botón de reintento. */
export function estadoError(mensaje, alReintentar) {
  return h('div.vacio.vacio--error', { role: 'alert' },
    h('span.vacio-icono', null, icono('aviso')),
    h('p.vacio-titulo', { text: 'No se pudieron cargar los datos' }),
    h('p.vacio-texto', { text: mensaje }),
    alReintentar ? h('button.boton.boton--secundario', { type: 'button', on: { click: alReintentar } }, icono('actualizar'), 'Reintentar') : null);
}

/** Bloques de carga (esqueleto). */
export function esqueleto(lineas = 4) {
  return h('div.esqueleto', { 'aria-busy': 'true', 'aria-label': 'Cargando' }, Array.from({ length: lineas }, () => h('span.esqueleto-linea')));
}

/** Tarjeta contenedora con título. */
export function tarjeta({ titulo, subtitulo, acciones, clase }, ...contenido) {
  return h('section', { class: ['tarjeta', clase] },
    titulo ? h('header.tarjeta-cabecera', null,
      h('div', null, h('h2.tarjeta-titulo', { text: titulo }), subtitulo ? h('p.tarjeta-subtitulo', { text: subtitulo }) : null),
      acciones ? h('div.tarjeta-acciones', null, acciones) : null) : null,
    ...contenido);
}

/** Valor hash en monoespaciado con botón de copia. */
export function valorHash(hash, { corto = true, etiqueta = 'hash' } = {}) {
  if (!hash) return h('span.tenue', { text: '—' });
  const texto = corto ? `${hash.slice(0, 12)}…${hash.slice(-6)}` : hash;
  const boton = h('button.boton-icono.boton-icono--mini', { type: 'button', 'aria-label': `Copiar ${etiqueta}`, title: 'Copiar' }, icono('copiar'));
  boton.addEventListener('click', async () => {
    const ok = await copiar(hash);
    notificar(ok ? 'Copiado al portapapeles.' : 'No se pudo copiar.', ok ? 'ok' : 'aviso', 2500);
  });
  return h('span.hash', null, h('code', { title: hash, text: texto }), boton);
}

/** Botón que respeta permisos: deshabilitado con explicación si el rol no lo permite. */
export function botonConPermiso({ permitido, motivo, ...atributos }, ...hijos) {
  const b = h('button', { type: 'button', ...atributos }, ...hijos);
  if (!permitido) {
    b.disabled = true;
    b.title = motivo;
    b.setAttribute('aria-disabled', 'true');
    b.classList.add('sin-permiso');
  }
  return b;
}
