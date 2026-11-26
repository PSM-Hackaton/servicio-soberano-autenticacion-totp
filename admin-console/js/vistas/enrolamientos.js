// Enrolamientos TOTP: listado con filtros por estado, aplicación y búsqueda; suspensión,
// reactivación y revocación según rol (si la API expone estas acciones).
import { h, reemplazar, numero, tiempo, hashCorto, rebote, idUnico } from '../dom.js';
import { icono } from '../iconos.js';
import { api, mensajeDeError, capacidades } from '../api.js';
import { cabeceraPagina, tarjeta, estadoError, esqueleto, insigniaEstado, vacio, confirmar, notificar, valorHash, botonConPermiso } from '../ui.js';

const ESTADOS = [
  { valor: '', texto: 'Todos' },
  { valor: 'activo', texto: 'Activos' },
  { valor: 'pendiente', texto: 'Pendientes' },
  { valor: 'suspendido', texto: 'Suspendidos' },
  { valor: 'revocado', texto: 'Revocados' },
];
const POR_PAGINA = 12;
const NOMBRE_ALG = { SHA256: 'SHA-256', SHA512: 'SHA-512', SHA1: 'SHA-1' };

export function montar(raiz, ctx) {
  const puedeSuspender = ctx.puede('enrolamientos.suspender');
  const puedeRevocar = ctx.puede('enrolamientos.revocar');
  const filtros = { estado: '', app_id: '', texto: '' };
  let pagina = 1;
  let todos = [];
  let apps = [];

  const zona = h('div', null, esqueleto(8));
  const chips = h('div.chips', { role: 'group', 'aria-label': 'Filtrar por estado' });
  const idApp = idUnico('app');
  const idBuscar = idUnico('buscar');
  const selectApp = h('select', { id: idApp }, h('option', { value: '', text: 'Todas las aplicaciones' }));
  const buscar = h('input', { id: idBuscar, type: 'search', placeholder: 'Identificador o hash de usuario', autocomplete: 'off', spellcheck: 'false' });
  const resumen = h('p.resumen-tabla', { role: 'status' });

  reemplazar(raiz,
    cabeceraPagina({ titulo: 'Enrolamientos', descripcion: 'Factores TOTP registrados por las aplicaciones. Los usuarios aparecen solo como hash HMAC (sin datos personales).' }),
    !capacidades.accionesEnrolamiento
      ? h('p.aviso-rol', null, icono('info'), 'Vista de supervisión. La revocación la ejecuta cada aplicación integradora (DELETE /api/v1/enrollments/{id}) y queda registrada en la bitácora.')
      : !puedeSuspender ? h('p.aviso-rol', null, icono('candado'), `Tu rol (${ctx.sesion.rol}) permite consultar los enrolamientos, no modificarlos.`) : null,
    tarjeta({ clase: 'tarjeta--tabla' },
      h('div.barra-filtros', null,
        chips,
        h('div.filtros-derecha', null,
          h('div.campo.campo--en-linea', null, h('label.solo-lectores', { for: idApp, text: 'Aplicación' }), selectApp),
          h('div.campo.campo--en-linea.campo--buscar', null, h('label.solo-lectores', { for: idBuscar, text: 'Buscar' }), icono('buscar'), buscar))),
      resumen,
      zona));

  function filtrados() {
    const t = filtros.texto.trim().toLowerCase();
    return todos.filter((e) => (!filtros.estado || e.estado === filtros.estado)
      && (!t || e.id?.toLowerCase().includes(t) || e.user_ref_hash?.toLowerCase().includes(t)));
  }

  function pintarChips() {
    const cuenta = (v) => (v ? todos.filter((e) => e.estado === v).length : todos.length);
    reemplazar(chips, ESTADOS.map((x) => {
      const activo = filtros.estado === x.valor;
      const b = h('button', { type: 'button', 'aria-pressed': String(activo), class: ['chip-filtro', activo ? 'activo' : ''] },
        x.valor ? h('span', { class: `estado-punto estado-punto--${x.valor}`, 'aria-hidden': 'true' }) : null,
        x.texto, h('span.chip-cuenta.num', { text: numero(cuenta(x.valor)) }));
      b.addEventListener('click', () => { filtros.estado = x.valor; pagina = 1; pintarChips(); pintar(); });
      return b;
    }));
  }

  function acciones(e) {
    if (!capacidades.accionesEnrolamiento) return null;
    if (e.estado === 'revocado') return h('span.tenue', { text: '—' });
    const grupo = h('div.grupo-acciones');
    if (e.estado === 'activo' || e.estado === 'pendiente') {
      const b = botonConPermiso({ permitido: puedeSuspender, motivo: ctx.motivo('enrolamientos.suspender'), class: 'boton boton--fantasma boton--compacto', 'aria-label': `Suspender enrolamiento ${hashCorto(e.id, 8, 0)}`, title: 'Suspender' }, icono('suspender'), h('span.texto-accion', { text: 'Suspender' }));
      b.addEventListener('click', () => ejecutar(e, 'suspend'));
      grupo.append(b);
    } else if (e.estado === 'suspendido') {
      const b = botonConPermiso({ permitido: puedeSuspender, motivo: ctx.motivo('enrolamientos.suspender'), class: 'boton boton--fantasma boton--compacto', 'aria-label': `Reactivar enrolamiento ${hashCorto(e.id, 8, 0)}`, title: 'Reactivar' }, icono('reactivar'), h('span.texto-accion', { text: 'Reactivar' }));
      b.addEventListener('click', () => ejecutar(e, 'reactivate'));
      grupo.append(b);
    }
    const r = botonConPermiso({ permitido: puedeRevocar, motivo: ctx.motivo('enrolamientos.revocar'), class: 'boton boton--fantasma-peligro boton--compacto', 'aria-label': `Revocar enrolamiento ${hashCorto(e.id, 8, 0)}`, title: 'Revocar' }, icono('revocar'), h('span.texto-accion', { text: 'Revocar' }));
    r.addEventListener('click', () => ejecutar(e, 'revoke'));
    grupo.append(r);
    return grupo;
  }

  function pintar() {
    const lista = filtrados();
    const paginas = Math.max(1, Math.ceil(lista.length / POR_PAGINA));
    pagina = Math.min(pagina, paginas);
    const vista = lista.slice((pagina - 1) * POR_PAGINA, pagina * POR_PAGINA);
    resumen.textContent = lista.length
      ? `Mostrando ${numero((pagina - 1) * POR_PAGINA + 1)}–${numero((pagina - 1) * POR_PAGINA + vista.length)} de ${numero(lista.length)} enrolamientos`
      : '';
    if (!lista.length) {
      reemplazar(zona, vacio('Sin resultados', todos.length ? 'Ningún enrolamiento coincide con los filtros aplicados.' : 'Todavía no hay enrolamientos registrados.', 'filtro'));
      return;
    }
    reemplazar(zona,
      h('div.tabla-contenedor', null, h('table.tabla.tabla--apilable', null,
        h('caption.solo-lectores', { text: 'Enrolamientos TOTP' }),
        h('thead', null, h('tr', null,
          ['Enrolamiento', 'Usuario (hash)', 'Aplicación', 'Estado', 'Deriva', 'Fallos', 'Creado', 'Último uso'].map((t, i) => h('th', { scope: 'col', class: i === 4 || i === 5 ? 'num' : null, text: t })),
          h('th', null, h('span.solo-lectores', { text: 'Acciones' })))),
        h('tbody', null, vista.map((e) => h('tr', { class: e.estado === 'revocado' ? 'fila-apagada' : null },
          h('td', { dataset: { etiqueta: 'Enrolamiento' } }, valorHash(e.id, { etiqueta: 'identificador' })),
          h('td', { dataset: { etiqueta: 'Usuario' } }, h('code.tenue', { title: e.user_ref_hash, text: hashCorto(e.user_ref_hash, 14, 4) })),
          h('td', { dataset: { etiqueta: 'Aplicación' } }, h('div.celda-principal.celda-principal--enr', null,
            h('span', { text: e.app_nombre ?? apps.find((a) => a.id === e.app_id)?.nombre ?? '—' }),
            h('span.tenue.texto-pequeno.num', { text: `${NOMBRE_ALG[e.algoritmo] ?? e.algoritmo ?? '—'} · ${e.digitos ?? '—'} dígitos` }))),
          h('td', { dataset: { etiqueta: 'Estado' } }, insigniaEstado(e.estado)),
          h('td.num', { dataset: { etiqueta: 'Deriva' }, title: 'Pasos de deriva de reloj compensados', text: e.drift_steps > 0 ? `+${e.drift_steps}` : String(e.drift_steps) }),
          h('td.num', { dataset: { etiqueta: 'Fallos' }, class: e.failed_attempts >= 3 ? 'texto-aviso' : null, text: numero(e.failed_attempts) }),
          h('td', { dataset: { etiqueta: 'Creado' } }, tiempo(e.created_at, { corta: true })),
          h('td', { dataset: { etiqueta: 'Último uso' } }, tiempo(e.last_used_at, { relativa: true })),
          h('td.celda-acciones', null, acciones(e))))))),
      paginador(paginas));
  }

  function paginador(paginas) {
    if (paginas <= 1) return null;
    const ant = h('button.boton.boton--secundario.boton--compacto', { type: 'button', disabled: pagina <= 1, 'aria-label': 'Página anterior' }, icono('izquierda'), h('span.ocultar-movil', { text: 'Anterior' }));
    const sig = h('button.boton.boton--secundario.boton--compacto', { type: 'button', disabled: pagina >= paginas, 'aria-label': 'Página siguiente' }, h('span.ocultar-movil', { text: 'Siguiente' }), icono('derecha'));
    ant.addEventListener('click', () => { pagina--; pintar(); });
    sig.addEventListener('click', () => { pagina++; pintar(); });
    return h('nav.paginador', { 'aria-label': 'Paginación' }, ant, h('span.num', { text: `Página ${pagina} de ${paginas}` }), sig);
  }

  async function ejecutar(e, accion) {
    const textos = {
      suspend: { titulo: 'Suspender enrolamiento', mensaje: 'El usuario no podrá verificar códigos hasta que se reactive. Puede revertirse.', boton: 'Suspender', tono: 'primario', ok: 'Enrolamiento suspendido.' },
      reactivate: { titulo: 'Reactivar enrolamiento', mensaje: 'El factor volverá a aceptar códigos válidos.', boton: 'Reactivar', tono: 'primario', ok: 'Enrolamiento reactivado.' },
      revoke: { titulo: 'Revocar enrolamiento', mensaje: 'La revocación es definitiva: la semilla queda inutilizable y el usuario deberá enrolarse de nuevo.', boton: 'Revocar definitivamente', tono: 'peligro', ok: 'Enrolamiento revocado.' },
    }[accion];
    const ok = await confirmar({
      titulo: textos.titulo, mensaje: textos.mensaje, confirmar: textos.boton, tono: textos.tono,
      detalle: h('dl.datos-clave', null, h('dt', { text: 'Enrolamiento' }), h('dd', null, h('code', { text: e.id })), h('dt', { text: 'Usuario (hash)' }), h('dd', null, h('code', { text: e.user_ref_hash }))),
    });
    if (!ok) return;
    try {
      const r = await api.accionEnrolamiento(e.id, accion);
      Object.assign(e, { estado: r.estado ?? { suspend: 'suspendido', reactivate: 'activo', revoke: 'revocado' }[accion], revoked_at: r.revoked_at ?? e.revoked_at });
      pintarChips();
      pintar();
      notificar(textos.ok, 'ok');
    } catch (err) {
      notificar(err?.status === 404 || err?.status === 405 ? 'La API del servicio no expone esta acción.' : mensajeDeError(err), err?.status === 403 ? 'aviso' : 'peligro');
    }
  }

  async function cargar() {
    try {
      const [lista, listaApps] = await Promise.all([api.enrolamientos({ app_id: filtros.app_id }), apps.length ? apps : api.apps().catch(() => [])]);
      todos = lista;
      if (!apps.length && listaApps.length) {
        apps = listaApps;
        for (const a of apps) selectApp.append(h('option', { value: a.id, text: a.nombre }));
        selectApp.value = filtros.app_id;
      }
      pintarChips();
      pintar();
    } catch (e) {
      if (e?.status !== 401) reemplazar(zona, estadoError(mensajeDeError(e), cargar));
    }
  }

  selectApp.addEventListener('change', () => { filtros.app_id = selectApp.value; pagina = 1; reemplazar(zona, esqueleto(6)); cargar(); });
  buscar.addEventListener('input', rebote(() => { filtros.texto = buscar.value; pagina = 1; pintar(); }, 180));
  cargar();
  return { refrescar: cargar };
}
