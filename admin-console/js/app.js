// Arranque de la consola: sesión, enrutado por hash, navegación lateral, cabecera,
// avisos de resiliencia (sin conexión, 503, 429, expiración de sesión) y tema.
import { h, $, reemplazar, almacen, hora } from './dom.js';
import { icono, hidratarIconos } from './iconos.js';
import { api, eventosApi, fijarCsrf, esMock, mensajeDeError } from './api.js';
import { puede, motivoSinPermiso, DESCRIPCION_ROL } from './rbac.js';
import { notificar, confirmar, abrirDialogo } from './ui.js';
import { montarLogin } from './vistas/login.js';

const SECCIONES = [
  { ruta: 'panel', texto: 'Panel', icono: 'panel', permiso: 'panel.ver', cargar: () => import('./vistas/panel.js') },
  { ruta: 'aplicaciones', texto: 'Aplicaciones', icono: 'aplicaciones', permiso: 'apps.ver', cargar: () => import('./vistas/aplicaciones.js') },
  { ruta: 'enrolamientos', texto: 'Enrolamientos', icono: 'enrolamientos', permiso: 'enrolamientos.ver', cargar: () => import('./vistas/enrolamientos.js') },
  { ruta: 'anomalias', texto: 'Detector de anomalías', icono: 'anomalias', permiso: 'anomalias.ver', cargar: () => import('./vistas/anomalias.js') },
  { ruta: 'llaves', texto: 'Llaves de firma', icono: 'llaves', permiso: 'llaves.ver', cargar: () => import('./vistas/llaves.js') },
  { ruta: 'auditoria', texto: 'Auditoría', icono: 'auditoria', permiso: 'auditoria.ver', cargar: () => import('./vistas/auditoria.js') },
  { ruta: 'administradores', texto: 'Administradores', icono: 'usuario', permiso: 'admins.ver', cargar: () => import('./vistas/administradores.js') },
];

const INACTIVIDAD_MS = 15 * 60 * 1000;
const AVISO_EXPIRACION_MS = 2 * 60 * 1000;
const INTERVALO_SALUD_MS = 15_000;

/** Estado global mínimo de la consola. */
const estado = {
  sesion: null,
  vista: null,
  rutaActual: null,
  ultimaActividad: Date.now(),
  salud: null,
  conectado: navigator.onLine,
};
export const eventosConsola = new EventTarget();

// ===================================================================== tema
const TEMAS = ['auto', 'claro', 'oscuro'];
function aplicarTema(tema) {
  const raiz = document.documentElement;
  if (tema === 'auto') raiz.removeAttribute('data-tema');
  else raiz.dataset.tema = tema;
  const b = $('#boton-tema');
  if (b) {
    const nombre = { auto: 'Tema automático', claro: 'Tema claro', oscuro: 'Tema oscuro' }[tema];
    b.replaceChildren(icono({ auto: 'auto', claro: 'sol', oscuro: 'luna' }[tema]));
    b.setAttribute('aria-label', `${nombre}. Pulsa para cambiar`);
    b.title = nombre;
  }
}
function iniciarTema() {
  const url = new URLSearchParams(location.search).get('tema');
  let tema = TEMAS.includes(url) ? url : almacen.leer('consola.tema', 'auto');
  if (!TEMAS.includes(tema)) tema = 'auto';
  aplicarTema(tema);
  $('#boton-tema').addEventListener('click', () => {
    tema = TEMAS[(TEMAS.indexOf(tema) + 1) % TEMAS.length];
    almacen.escribir('consola.tema', tema);
    aplicarTema(tema);
  });
}

// ===================================================================== avisos globales
const avisos = new Map();
/**
 * @param {string} clave
 * @param {{ tono: 'aviso' | 'peligro' | 'info', icono: string, titulo: string, texto?: string | Node, acciones?: Node[] }} op
 */
function mostrarAviso(clave, { tono, icono: nombreIcono, titulo, texto, acciones = [] }) {
  const nodo = h('div', { class: `aviso aviso--${tono}`, role: tono === 'peligro' ? 'alert' : 'status', dataset: { clave } },
    icono(nombreIcono),
    h('div.aviso-texto', null, h('strong', { text: titulo }), texto ? h('span', null, ' ', texto) : null),
    acciones.length ? h('div.aviso-acciones', null, acciones) : null);
  const previo = avisos.get(clave);
  if (previo) previo.replaceWith(nodo);
  else $('#avisos').append(nodo);
  avisos.set(clave, nodo);
  document.body.classList.toggle('con-avisos', avisos.size > 0);
}
function quitarAviso(clave) {
  avisos.get(clave)?.remove();
  avisos.delete(clave);
  document.body.classList.toggle('con-avisos', avisos.size > 0);
}

/** Cuenta atrás reutilizable para avisos con reintento. */
const cuentas = new Map();
function cuentaAtras(clave, segundos, alActualizar, alTerminar) {
  clearInterval(cuentas.get(clave));
  let restante = Math.max(1, Math.round(segundos));
  alActualizar(restante);
  const t = setInterval(() => {
    restante--;
    if (restante <= 0) {
      clearInterval(t);
      cuentas.delete(clave);
      alTerminar();
    } else alActualizar(restante);
  }, 1000);
  cuentas.set(clave, t);
}

function avisoSinConexion(activo) {
  estado.conectado = !activo;
  if (activo) {
    mostrarAviso('conexion', { tono: 'peligro', icono: 'sinConexion', titulo: 'Sin conexión.', texto: 'Los datos mostrados pueden estar desactualizados; la consola reintentará al recuperar la red.' });
  } else if (avisos.has('conexion')) {
    quitarAviso('conexion');
    notificar('Conexión restablecida.', 'ok', 3000);
    estado.vista?.refrescar?.();
  }
  pintarEstadoServicio();
}

function avisoNoDisponible(segundos) {
  const reintentar = h('button.boton.boton--compacto.boton--secundario', { type: 'button', text: 'Reintentar ahora' });
  const texto = h('span');
  reintentar.addEventListener('click', () => { quitarAviso('servicio'); refrescarSalud(); estado.vista?.refrescar?.(); });
  mostrarAviso('servicio', { tono: 'peligro', icono: 'servidor', titulo: 'Servicio no disponible temporalmente.', texto, acciones: [reintentar] });
  cuentaAtras('servicio', segundos ?? 15, (n) => { texto.textContent = `El servicio respondió 503. Reintento automático en ${n} s.`; }, () => {
    refrescarSalud();
    estado.vista?.refrescar?.();
  });
}

function avisoLimite(segundos) {
  const texto = h('span');
  mostrarAviso('limite', { tono: 'aviso', icono: 'reloj', titulo: 'Demasiadas solicitudes.', texto });
  cuentaAtras('limite', segundos ?? 30, (n) => { texto.textContent = `El servicio aplicó limitación de tasa. Reintento en ${n} s.`; }, () => {
    quitarAviso('limite');
    estado.vista?.refrescar?.();
  });
}

function escucharRed() {
  window.addEventListener('offline', () => avisoSinConexion(true));
  window.addEventListener('online', () => avisoSinConexion(false));
  eventosApi.addEventListener('conexion', (e) => {
    if (!e.detail.ok && !avisos.has('conexion')) avisoSinConexion(true);
    else if (e.detail.ok && avisos.has('conexion')) avisoSinConexion(false);
  });
  eventosApi.addEventListener('disponible', (e) => {
    if (e.detail.ok) {
      if (avisos.has('servicio')) { quitarAviso('servicio'); clearInterval(cuentas.get('servicio')); }
    } else if (!avisos.has('servicio')) avisoNoDisponible(e.detail.segundos);
  });
  eventosApi.addEventListener('limite', (e) => { if (!avisos.has('limite')) avisoLimite(e.detail.segundos); });
  eventosApi.addEventListener('sesion-expirada', () => {
    if (estado.sesion) terminarSesion('Tu sesión expiró o fue cerrada. Inicia sesión de nuevo.', false);
  });
}

// ===================================================================== estado del servicio (cabecera)
function pintarEstadoServicio() {
  const el = $('#estado-servicio');
  if (!el) return;
  let tono = 'neutro';
  let texto = 'Comprobando…';
  if (!estado.conectado) { tono = 'peligro'; texto = 'Sin conexión'; }
  else if (estado.salud?.error) { tono = 'peligro'; texto = 'No disponible'; }
  else if (estado.salud) { tono = estado.salud.listo ? 'ok' : 'aviso'; texto = estado.salud.listo ? 'Operativo' : 'Degradado'; }
  el.className = `estado-servicio estado-servicio--${tono}`;
  el.title = estado.salud?.comprobado ? `Última comprobación: ${hora(estado.salud.comprobado)}` : '';
  reemplazar(el, h('span.estado-servicio-punto', { 'aria-hidden': 'true' }), h('span.ocultar-movil', { text: 'Servicio: ' }), h('strong', { text: texto }));
}

let temporizadorSalud = null;
async function refrescarSalud() {
  try {
    const s = await api.salud();
    estado.salud = { ...s, comprobado: Date.now() };
  } catch (e) {
    estado.salud = { listo: false, error: true, status: 'no_disponible', checks: null, comprobado: Date.now(), mensaje: mensajeDeError(e) };
  }
  pintarEstadoServicio();
  eventosConsola.dispatchEvent(new CustomEvent('salud', { detail: estado.salud }));
}
function programarSalud() {
  clearInterval(temporizadorSalud);
  refrescarSalud();
  temporizadorSalud = setInterval(() => { if (!document.hidden) refrescarSalud(); }, INTERVALO_SALUD_MS);
}

// ===================================================================== inactividad y expiración
let temporizadorInactividad = null;
function registrarActividad() { estado.ultimaActividad = Date.now(); }
function vigilarInactividad() {
  for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart']) window.addEventListener(ev, registrarActividad, { passive: true });
  clearInterval(temporizadorInactividad);
  temporizadorInactividad = setInterval(() => {
    if (!estado.sesion) return;
    const restante = INACTIVIDAD_MS - (Date.now() - estado.ultimaActividad);
    if (restante <= 0) {
      terminarSesion('Tu sesión se cerró por inactividad.', true);
    } else if (restante <= AVISO_EXPIRACION_MS) {
      const seg = Math.ceil(restante / 1000);
      const mm = Math.floor(seg / 60);
      const ss = String(seg % 60).padStart(2, '0');
      const mantener = h('button.boton.boton--compacto.boton--primario', { type: 'button', text: 'Mantener sesión' });
      mantener.addEventListener('click', async () => {
        registrarActividad();
        quitarAviso('sesion');
        try { await api.sesion(); notificar('Sesión renovada.', 'ok', 2500); } catch { /* el 401 lo gestiona el bus */ }
      });
      mostrarAviso('sesion', { tono: 'aviso', icono: 'reloj', titulo: 'Tu sesión está a punto de expirar.', texto: `Se cerrará por inactividad en ${mm}:${ss}.`, acciones: [mantener] });
    } else if (avisos.has('sesion')) quitarAviso('sesion');
  }, 1000);
}

// ===================================================================== sesión
async function terminarSesion(mensaje, llamarServidor) {
  if (llamarServidor) await api.cerrarSesion();
  estado.sesion = null;
  fijarCsrf(null);
  estado.vista?.desmontar?.();
  estado.vista = null;
  estado.rutaActual = null;
  clearInterval(temporizadorSalud);
  quitarAviso('sesion');
  mostrarLogin(mensaje);
}

function mostrarLogin(mensaje) {
  $('#pantalla-carga').hidden = true;
  $('#consola').hidden = true;
  $('#pantalla-login').hidden = false;
  document.title = 'Acceso · Consola administrativa';
  montarLogin({
    mensaje,
    esMock,
    alEntrar: (sesion) => iniciarConsola(sesion),
  });
}

function iniciarConsola(sesion) {
  estado.sesion = sesion;
  fijarCsrf(sesion.csrf_token);
  registrarActividad();
  $('#pantalla-carga').hidden = true;
  $('#pantalla-login').hidden = true;
  $('#consola').hidden = false;
  pintarUsuario();
  pintarNavegacion();
  programarSalud();
  if (!location.hash || location.hash === '#/' || location.hash === '#/login') history.replaceState(null, '', `${location.pathname}${location.search}#/panel`);
  enrutar();
}

function pintarUsuario() {
  const { usuario, rol } = estado.sesion;
  $('#usuario-nombre').textContent = usuario;
  const rolEl = $('#usuario-rol');
  rolEl.textContent = rol;
  rolEl.className = `insignia insignia--rol insignia--${rol.toLowerCase()}`;
  rolEl.title = DESCRIPCION_ROL[rol] ?? '';
  $('#usuario-avatar').textContent = usuario.slice(0, 2).toUpperCase();
}

// ===================================================================== navegación
function pintarNavegacion() {
  const ul = $('#navegacion');
  reemplazar(ul, SECCIONES.filter((s) => puede(estado.sesion.rol, s.permiso)).map((s) => h('li', null,
    h('a.nav-enlace', { href: `#/${s.ruta}`, dataset: { ruta: s.ruta } }, icono(s.icono), h('span', { text: s.texto })))));
  const pie = $('#pie-modo');
  reemplazar(pie, esMock
    ? h('span.pie-demo', null, icono('info'), 'Modo demostración · datos simulados')
    : h('span.pie-conectado', null, icono('candado'), 'Conectado al servicio local'));
}

function marcarNavegacion(ruta) {
  for (const a of document.querySelectorAll('.nav-enlace')) {
    if (a.dataset.ruta === ruta) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
}

function alternarMenu(abrir) {
  const barra = $('#barra-lateral');
  const boton = $('#boton-menu');
  const abierto = abrir ?? !barra.classList.contains('abierta');
  barra.classList.toggle('abierta', abierto);
  $('#velo').hidden = !abierto;
  boton.setAttribute('aria-expanded', String(abierto));
  boton.setAttribute('aria-label', abierto ? 'Cerrar navegación' : 'Abrir navegación');
  if (abierto) barra.querySelector('.nav-enlace')?.focus();
}

async function enrutar() {
  if (!estado.sesion) return;
  const ruta = (location.hash.replace(/^#\/?/, '').split(/[/?]/)[0]) || 'panel';
  const seccion = SECCIONES.find((s) => s.ruta === ruta);
  const contenido = $('#contenido');
  alternarMenu(false);
  if (!seccion) {
    location.replace('#/panel');
    return;
  }
  if (estado.rutaActual === ruta && estado.vista) return;
  estado.vista?.desmontar?.();
  estado.vista = null;
  estado.rutaActual = ruta;
  marcarNavegacion(ruta);
  $('#cabecera-seccion').textContent = seccion.texto;
  document.title = `${seccion.texto} · Consola administrativa`;

  if (!puede(estado.sesion.rol, seccion.permiso)) {
    reemplazar(contenido, h('div.vacio.vacio--grande', { role: 'alert' },
      h('span.vacio-icono', null, icono('candado')),
      h('p.vacio-titulo', { text: 'Sin permisos para esta sección' }),
      h('p.vacio-texto', { text: `${motivoSinPermiso(seccion.permiso)}. Tu rol actual es ${estado.sesion.rol}.` })));
    return;
  }
  reemplazar(contenido, h('div.cargando-vista', { role: 'status' }, h('span.spinner', { 'aria-hidden': 'true' }), 'Cargando…'));
  try {
    const modulo = await seccion.cargar();
    if (estado.rutaActual !== ruta) return;
    const contenedor = h('div.vista');
    reemplazar(contenido, contenedor);
    estado.vista = modulo.montar(contenedor, contexto()) ?? null;
    contenido.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  } catch (e) {
    console.error(e);
    reemplazar(contenido, h('div.vacio', { role: 'alert' }, h('p.vacio-titulo', { text: 'No se pudo cargar la sección.' })));
  }
}

/** Contexto que reciben las vistas. */
function contexto() {
  return {
    sesion: estado.sesion,
    puede: (permiso) => puede(estado.sesion?.rol, permiso),
    motivo: motivoSinPermiso,
    salud: () => estado.salud,
    eventos: eventosConsola,
    esMock,
  };
}

// ===================================================================== arranque
async function arrancar() {
  hidratarIconos();
  for (const m of document.querySelectorAll('.marca-icono')) m.replaceChildren(icono('marca'));
  iniciarTema();
  escucharRed();
  vigilarInactividad();
  if (!navigator.onLine) avisoSinConexion(true);

  $('#boton-menu').replaceChildren(icono('menu'));
  $('#boton-menu').addEventListener('click', () => alternarMenu());
  $('#velo').addEventListener('click', () => alternarMenu(false));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && $('#barra-lateral').classList.contains('abierta')) { alternarMenu(false); $('#boton-menu').focus(); }
  });
  $('#boton-salir').addEventListener('click', async () => {
    const ok = await confirmar({ titulo: 'Cerrar sesión', mensaje: 'Se cerrará la sesión administrativa en este navegador.', confirmar: 'Cerrar sesión' });
    if (ok) { await terminarSesion('Sesión cerrada correctamente.', true); }
  });
  window.addEventListener('hashchange', enrutar);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && estado.sesion) refrescarSalud();
  });

  // Atajo de demostración: mostrar el diálogo de permisos del rol.
  $('.usuario').addEventListener('click', () => {
    if (!estado.sesion) return;
    const { rol } = estado.sesion;
    const filas = SECCIONES.map((s) => h('li', null, puede(rol, s.permiso) ? icono('check', { clase: 'icono--ok' }) : icono('candado', { clase: 'icono--tenue' }), s.texto));
    abrirDialogo({ titulo: `Rol: ${rol}`, contenido: [h('p', { text: DESCRIPCION_ROL[rol] }), h('ul.lista-permisos', null, filas), h('p.ayuda', { text: 'El servidor aplica estos mismos permisos; la interfaz solo oculta lo que no corresponde.' })] });
  });

  try {
    const sesion = await api.sesion();
    if (sesion) iniciarConsola(sesion);
    else mostrarLogin();
  } catch (e) {
    mostrarLogin(e?.status && e.status !== 401 ? mensajeDeError(e) : undefined);
  }
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', arrancar);
else arrancar();
