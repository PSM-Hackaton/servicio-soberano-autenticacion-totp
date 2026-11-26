// Controlador de la interfaz del Autenticador Soberano.
// Nunca se usa innerHTML con datos: todo el contenido variable se inserta con textContent.

import * as boveda from './boveda.js';
import { ErrorCuenta, analizarOtpauth, extraerDeEnlace, limpiarTexto, validarCuenta } from './otpauth.js';
import { NOMBRE_ALGORITMO, agruparCodigo, base32Decode, generarHotp, importarSemilla, pasoDeTiempo, segundosRestantes } from './totp.js';
import { cifrarRespaldo, descifrarRespaldo } from './cripto.js';
import { detenerEscaner, escanerDisponible, iniciarEscaner } from './escaner.js';

const SVG = 'http://www.w3.org/2000/svg';
const UMBRAL_SIGUIENTE = 5;
const UMBRAL_DESFASE = 15;
const ACCESO = new Set(['cargando', 'crear-pin', 'desbloquear']);

const $ = (id) => document.getElementById(id);
const movimientoReducido = matchMedia('(prefers-reduced-motion: reduce)');

const estado = {
  pantalla: 'cargando',
  /** @type {any[]} */ cuentas: [],
  /** @type {Map<string, CryptoKey>} */ llaves: new Map(),
  /** @type {Map<string, { paso: number, actual: string, siguiente: string }>} */ cache: new Map(),
  /** @type {Map<string, any>} */ vistas: new Map(),
  /** @type {{ datos: any, origen: string } | null} */ pendiente: null,
  /** @type {string | null} */ enlacePendiente: null,
  /** @type {string | null} */ detalleId: null,
  detalleVista: null,
  vistaPrevia: null,
  desfaseMs: 0,
  ultimaActividad: Date.now(),
  bloqueoMs: 120_000,
  sesion: 0,
  calculando: false,
  ignorarOcultar: false,
  esperaHasta: 0,
};

/* ——— Utilidades ——— */

function mensajeDe(error) {
  if (error instanceof ErrorCuenta) return error.message;
  return error?.message || 'Algo salió mal. Inténtalo de nuevo.';
}

function mostrarError(id, texto) {
  $(id).textContent = texto || '';
}

let temporizadorAviso = 0;
function avisar(texto) {
  const aviso = $('aviso');
  aviso.textContent = '';
  aviso.classList.remove('es-visible');
  requestAnimationFrame(() => {
    aviso.textContent = texto;
    aviso.classList.add('es-visible');
  });
  clearTimeout(temporizadorAviso);
  temporizadorAviso = setTimeout(() => aviso.classList.remove('es-visible'), 2800);
}

function nombreDe(c) {
  return c.emisor || c.cuenta || 'Cuenta';
}

function iniciales(c) {
  const palabras = (c.emisor || c.cuenta || '?')
    .split(/[\s._@-]+/)
    .filter((p) => p && !/^(de|del|la|el|los|las|y)$/i.test(p));
  const letras = palabras.slice(0, 2).map((p) => Array.from(p)[0]).join('');
  return (letras || '?').toUpperCase();
}

function deletreado(codigo) {
  return codigo.split('').join(' ');
}

function normalizar(texto) {
  return texto.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
}

function formatearEspera(ms) {
  const s = Math.ceil(ms / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return r ? `${m} min ${r} s` : `${m} min`;
}

function icono(nombre) {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG, 'use');
  use.setAttribute('href', `#i-${nombre}`);
  svg.append(use);
  return svg;
}

function el(etiqueta, clase, texto) {
  const nodo = document.createElement(etiqueta);
  if (clase) nodo.className = clase;
  if (texto !== undefined) nodo.textContent = texto;
  return nodo;
}

function ahora() {
  return Date.now() + estado.desfaseMs;
}

/* ——— Navegación entre pantallas ——— */

function irA(nombre, { enfocar = true } = {}) {
  if (estado.pantalla === 'agregar' && nombre !== 'agregar') detenerCamara();
  for (const seccion of document.querySelectorAll('.pantalla')) seccion.hidden = seccion.id !== `p-${nombre}`;
  estado.pantalla = nombre;
  const acceso = ACCESO.has(nombre);
  $('barra').hidden = acceso;
  document.querySelector('.marco').classList.toggle('es-acceso', acceso);
  for (const boton of document.querySelectorAll('.nav-boton[data-ir]')) {
    if (boton.dataset.ir === nombre) boton.setAttribute('aria-current', 'page');
    else boton.removeAttribute('aria-current');
  }
  if (nombre !== 'detalle') { estado.detalleId = null; estado.detalleVista = null; }
  if (nombre !== 'confirmar') estado.vistaPrevia = null;
  window.scrollTo(0, 0);
  if (enfocar) {
    const titulo = document.querySelector(`#p-${nombre} h1`);
    if (titulo) titulo.focus({ preventScroll: true });
  }
}

/* ——— Esfera de cuenta regresiva (SVG) ——— */

const RADIO = 19;
const CIRCUNFERENCIA = 2 * Math.PI * RADIO;

function crearEsfera(grande) {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 44 44');
  svg.setAttribute('focusable', 'false');
  const pista = document.createElementNS(SVG, 'circle');
  for (const [k, v] of [['cx', 22], ['cy', 22], ['r', RADIO]]) pista.setAttribute(k, v);
  pista.setAttribute('class', 'esfera-pista');
  svg.append(pista);
  if (grande) {
    for (let i = 0; i < 12; i++) {
      const a = (i / 12) * 2 * Math.PI;
      const linea = document.createElementNS(SVG, 'line');
      linea.setAttribute('x1', (22 + Math.sin(a) * 14.6).toFixed(2));
      linea.setAttribute('y1', (22 - Math.cos(a) * 14.6).toFixed(2));
      linea.setAttribute('x2', (22 + Math.sin(a) * (i % 3 === 0 ? 16.8 : 16)).toFixed(2));
      linea.setAttribute('y2', (22 - Math.cos(a) * (i % 3 === 0 ? 16.8 : 16)).toFixed(2));
      linea.setAttribute('class', 'esfera-marca');
      svg.append(linea);
    }
  }
  const arco = document.createElementNS(SVG, 'circle');
  for (const [k, v] of [['cx', 22], ['cy', 22], ['r', RADIO]]) arco.setAttribute(k, v);
  arco.setAttribute('class', 'esfera-arco');
  arco.setAttribute('transform', 'rotate(-90 22 22)');
  arco.setAttribute('stroke-dasharray', CIRCUNFERENCIA.toFixed(3));
  const cifra = document.createElementNS(SVG, 'text');
  cifra.setAttribute('x', '22');
  cifra.setAttribute('y', '22.5');
  cifra.setAttribute('class', 'esfera-cifra');
  svg.append(arco, cifra);
  return { svg, arco, cifra, grande, ultimoSegundo: -1 };
}

function pintarEsfera(esfera, restante, periodo) {
  const fraccion = Math.max(0, Math.min(1, restante / periodo));
  // Con movimiento reducido el arco avanza a saltos de un segundo.
  const valor = movimientoReducido.matches ? Math.ceil(restante) / periodo : fraccion;
  esfera.arco.style.strokeDashoffset = (CIRCUNFERENCIA * (1 - valor)).toFixed(3);
  const segundo = Math.ceil(restante);
  if (segundo !== esfera.ultimoSegundo) {
    esfera.ultimoSegundo = segundo;
    esfera.cifra.textContent = esfera.grande ? `${segundo} s` : String(segundo);
  }
}

/* ——— Cálculo de códigos ——— */

async function llaveDe(c) {
  let llave = estado.llaves.get(c.id);
  if (!llave) {
    llave = await importarSemilla(base32Decode(c.secreto), c.algoritmo);
    estado.llaves.set(c.id, llave);
  }
  return llave;
}

async function codigosDe(c, instante) {
  const paso = pasoDeTiempo(instante, c.periodo);
  const previo = estado.cache.get(c.id);
  if (previo && previo.paso === paso) return previo;
  const llave = await llaveDe(c);
  const [actual, siguiente] = await Promise.all([
    generarHotp(llave, paso, c.algoritmo, c.digitos),
    generarHotp(llave, paso + 1, c.algoritmo, c.digitos),
  ]);
  const nuevo = { paso, actual, siguiente };
  estado.cache.set(c.id, nuevo);
  return nuevo;
}

function pintarSiguiente(nodo, urgente, siguiente) {
  if (urgente) {
    if (nodo.dataset.valor === siguiente) return;
    nodo.dataset.valor = siguiente;
    const b = el('b', '', agruparCodigo(siguiente));
    nodo.replaceChildren('Siguiente: ', b);
  } else if (nodo.dataset.valor) {
    nodo.dataset.valor = '';
    nodo.replaceChildren();
  }
}

async function actualizarCodigos() {
  if (estado.calculando || !boveda.abierta()) return;
  estado.calculando = true;
  const sesion = estado.sesion;
  try {
    const instante = ahora();
    const visibles = [];
    if (estado.pantalla === 'lista') visibles.push(...estado.cuentas);
    else if (estado.pantalla === 'detalle' && estado.detalleId) {
      const c = estado.cuentas.find((x) => x.id === estado.detalleId);
      if (c) visibles.push(c);
    }
    const resultados = await Promise.all(visibles.map((c) => codigosDe(c, instante)));
    if (sesion !== estado.sesion) return;

    visibles.forEach((c, i) => {
      const k = resultados[i];
      const restante = segundosRestantes(instante, c.periodo);
      const urgente = restante <= UMBRAL_SIGUIENTE;
      const v = estado.pantalla === 'lista' ? estado.vistas.get(c.id) : estado.detalleVista;
      if (!v) return;
      if (v.codigo !== k.actual) {
        v.codigo = k.actual;
        v.numero.textContent = agruparCodigo(k.actual);
        if (v.boton) v.boton.setAttribute('aria-label', `Copiar código ${deletreado(k.actual)} de ${nombreDe(c)}`);
      }
      v.raiz.classList.toggle('es-urgente', urgente);
      pintarSiguiente(v.siguiente, urgente, k.siguiente);
      pintarEsfera(v.esfera, restante, c.periodo);
    });

    if (estado.pantalla === 'confirmar' && estado.vistaPrevia) {
      const p = estado.vistaPrevia;
      const paso = pasoDeTiempo(instante, p.datos.periodo);
      if (p.paso !== paso) {
        p.paso = paso;
        const codigo = await generarHotp(p.llave, paso, p.datos.algoritmo, p.datos.digitos);
        if (sesion === estado.sesion && estado.vistaPrevia === p) $('c-codigo').textContent = agruparCodigo(codigo);
      }
    }
  } catch (error) {
    console.error('No se pudo calcular un código', error);
  } finally {
    estado.calculando = false;
  }
}

/* ——— Lista ——— */

function crearFila(c) {
  const li = el('li', 'cuenta');
  li.dataset.id = c.id;

  const monograma = el('span', 'monograma', iniciales(c));
  monograma.setAttribute('aria-hidden', 'true');

  const ident = el('div', 'cuenta-ident');
  const emisor = el('p', 'cuenta-emisor');
  emisor.append(el('span', 'cuenta-emisor-texto', nombreDe(c)));
  const insignia = el('span', c.algoritmo === 'SHA1' ? 'insignia' : 'insignia insignia-fuerte', NOMBRE_ALGORITMO[c.algoritmo]);
  insignia.title = `Algoritmo ${NOMBRE_ALGORITMO[c.algoritmo]}`;
  ident.append(emisor);
  if (c.emisor && c.cuenta) ident.append(el('p', 'cuenta-usuario', c.cuenta));

  const boton = el('button', 'codigo');
  boton.type = 'button';
  const numero = el('span', 'codigo-numero', c.digitos === 8 ? '•••• ••••' : '••• •••');
  const copiado = el('span', 'codigo-copiado', 'Copiado');
  copiado.setAttribute('aria-hidden', 'true');
  boton.append(numero, copiado);
  boton.addEventListener('click', () => copiar(c, boton));

  const esfera = crearEsfera(false);
  const contenedor = el('div', 'esfera');
  contenedor.setAttribute('aria-hidden', 'true');
  contenedor.append(esfera.svg);

  const pie = el('div', 'cuenta-pie');
  const siguiente = el('p', 'siguiente');
  const mas = el('button', 'cuenta-mas');
  mas.type = 'button';
  mas.append(el('span', '', 'Detalles'), icono('detalle'));
  mas.setAttribute('aria-label', `Detalles de ${nombreDe(c)}`);
  mas.addEventListener('click', () => abrirDetalle(c.id));
  pie.append(siguiente, mas);

  li.append(monograma, ident, insignia, boton, contenedor, pie);
  estado.vistas.set(c.id, { raiz: li, numero, boton, siguiente, esfera, codigo: null });
  return li;
}

function renderLista() {
  const ul = $('cuentas');
  ul.replaceChildren();
  estado.vistas.clear();
  const n = estado.cuentas.length;
  $('vacio').hidden = n > 0;
  $('buscador').hidden = n <= 4;
  $('nota-lista').hidden = n === 0;
  if (n <= 4) $('buscar').value = '';
  ul.classList.toggle('es-unica', n === 1);
  for (const c of estado.cuentas) ul.append(crearFila(c));
  filtrar();
  actualizarCodigos();
}

function filtrar() {
  const q = normalizar($('buscar').value.trim());
  let visibles = 0;
  for (const c of estado.cuentas) {
    const v = estado.vistas.get(c.id);
    if (!v) continue;
    const coincide = !q || normalizar(`${c.emisor} ${c.cuenta}`).includes(q);
    v.raiz.hidden = !coincide;
    if (coincide) visibles++;
  }
  $('sin-resultados').hidden = !(q && visibles === 0 && estado.cuentas.length > 0);
}

/** Copia con la API Clipboard; si el navegador la niega, usa una selección temporal. */
async function escribirPortapapeles(texto) {
  try {
    await navigator.clipboard.writeText(texto);
    return;
  } catch {
    const area = document.createElement('textarea');
    area.value = texto;
    area.setAttribute('readonly', '');
    area.className = 'oculto';
    document.body.append(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    if (!ok) throw new Error('sin portapapeles');
  }
}

async function copiar(c, boton) {
  const k = estado.cache.get(c.id);
  if (!k) return;
  try {
    await escribirPortapapeles(k.actual);
    if (boton) {
      boton.classList.add('es-copiado');
      setTimeout(() => boton.classList.remove('es-copiado'), 1600);
    }
    avisar(`Código de ${nombreDe(c)} copiado`);
  } catch {
    avisar('No se pudo copiar. Selecciona el código y cópialo a mano.');
  }
}

/* ——— Detalle ——— */

function abrirDetalle(id) {
  const c = estado.cuentas.find((x) => x.id === id);
  if (!c) return;
  irA('detalle');
  estado.detalleId = id;
  $('t-detalle').textContent = nombreDe(c);
  $('d-algoritmo').textContent = NOMBRE_ALGORITMO[c.algoritmo];
  $('d-digitos').textContent = String(c.digitos);
  $('d-periodo').textContent = `${c.periodo} s`;
  $('d-creada').textContent = c.creada ? new Intl.DateTimeFormat('es', { dateStyle: 'medium' }).format(new Date(c.creada)) : '—';
  $('r-emisor').value = c.emisor;
  $('r-cuenta').value = c.cuenta;
  mostrarError('renombrar-error', '');

  const esfera = crearEsfera(true);
  $('d-esfera').replaceChildren(esfera.svg);
  $('d-codigo').textContent = '';
  $('d-siguiente').replaceChildren();
  $('d-siguiente').dataset.valor = '';
  estado.detalleVista = {
    raiz: document.querySelector('.detalle-codigo'),
    numero: $('d-codigo'),
    boton: null,
    siguiente: $('d-siguiente'),
    esfera,
    codigo: null,
  };
  actualizarCodigos();
}

async function guardarLista(nuevas) {
  await boveda.guardarCuentas(nuevas);
  estado.cuentas = boveda.obtenerCuentas();
}

/* ——— Diálogo de confirmación ——— */

function confirmar({ titulo, texto, aceptar, exigir = null, peligro = true }) {
  const dialogo = $('dialogo');
  $('dialogo-titulo').textContent = titulo;
  $('dialogo-texto').textContent = texto;
  const botonAceptar = $('dialogo-aceptar');
  botonAceptar.textContent = aceptar;
  botonAceptar.className = `boton ${peligro ? 'boton-peligro' : 'boton-primario'}`;
  const campo = $('dialogo-campo');
  const entrada = $('dialogo-entrada');
  campo.hidden = !exigir;
  entrada.value = '';
  botonAceptar.disabled = Boolean(exigir);
  if (exigir) $('dialogo-etiqueta').textContent = `Escribe ${exigir} para confirmar`;
  const alEscribir = () => { botonAceptar.disabled = entrada.value.trim().toUpperCase() !== exigir; };
  const alTecla = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (!botonAceptar.disabled) botonAceptar.click();
    }
  };
  entrada.addEventListener('input', alEscribir);
  entrada.addEventListener('keydown', alTecla);
  dialogo.returnValue = '';
  dialogo.showModal();
  (exigir ? entrada : $('dialogo-cancelar')).focus();
  return new Promise((resolver) => {
    dialogo.addEventListener('close', () => {
      entrada.removeEventListener('input', alEscribir);
      entrada.removeEventListener('keydown', alTecla);
      resolver(dialogo.returnValue === 'aceptar' && (!exigir || entrada.value.trim().toUpperCase() === exigir));
    }, { once: true });
  });
}

/* ——— Alta de cuentas ——— */

const ORIGENES = {
  portal: 'Enlace del Portal',
  enlace: 'Enlace pegado',
  uri: 'URI pegada',
  manual: 'Clave manual',
  camara: 'Código QR',
};

async function mostrarConfirmacion(datos, origen) {
  estado.pendiente = { datos, origen };
  irA('confirmar');
  $('c-monograma').textContent = iniciales(datos);
  $('c-emisor').textContent = datos.emisor || 'Sin emisor';
  $('c-cuenta').textContent = datos.cuenta || '—';
  $('c-algoritmo').textContent = NOMBRE_ALGORITMO[datos.algoritmo];
  $('c-digitos').textContent = String(datos.digitos);
  $('c-periodo').textContent = `${datos.periodo} s`;
  $('c-origen').textContent = ORIGENES[origen] ?? origen;
  $('c-codigo').textContent = '';
  $('c-duplicado').hidden = !estado.cuentas.some((c) => c.secreto === datos.secreto);
  const llave = await importarSemilla(base32Decode(datos.secreto), datos.algoritmo);
  estado.vistaPrevia = { datos, llave, paso: -1 };
  actualizarCodigos();
}

function limpiarAlta() {
  for (const id of ['f-enlace', 'f-pegar', 'f-manual']) $(id).reset();
  for (const id of ['enlace-error', 'pegar-error', 'manual-error', 'camara-error']) mostrarError(id, '');
  for (const id of ['enlace', 'uri', 'm-secreto']) $(id).removeAttribute('aria-invalid');
}

async function guardarPendiente() {
  if (!estado.pendiente) return;
  const { datos, origen } = estado.pendiente;
  const boton = $('boton-guardar-cuenta');
  boton.disabled = true;
  try {
    const nueva = { id: crypto.randomUUID(), ...datos, origen, creada: new Date().toISOString() };
    await guardarLista([...estado.cuentas, nueva]);
    estado.pendiente = null;
    limpiarAlta();
    renderLista();
    irA('lista');
    const fila = estado.vistas.get(nueva.id)?.raiz;
    if (fila) {
      fila.classList.add('es-nueva');
      fila.scrollIntoView({ block: 'nearest', behavior: movimientoReducido.matches ? 'auto' : 'smooth' });
    }
    avisar(`Cuenta de ${nombreDe(nueva)} guardada`);
  } catch (error) {
    avisar(mensajeDe(error));
  } finally {
    boton.disabled = false;
  }
}

function cancelarPendiente() {
  const origen = estado.pendiente?.origen;
  estado.pendiente = null;
  irA(origen === 'portal' || estado.cuentas.length ? 'lista' : 'agregar');
}

function procesarEnlacePendiente() {
  if (!estado.enlacePendiente) return false;
  const crudo = estado.enlacePendiente;
  estado.enlacePendiente = null;
  for (const n of document.querySelectorAll('[data-pendiente]')) n.hidden = true;
  try {
    let uri;
    try { uri = decodeURIComponent(crudo); } catch { throw new ErrorCuenta('El enlace está mal codificado.'); }
    mostrarConfirmacion(analizarOtpauth(uri), 'portal');
  } catch (error) {
    irA('agregar');
    seleccionarPestana('enlace');
    mostrarError('enlace-error', `No se pudo usar el enlace del Portal: ${mensajeDe(error)}`);
  }
  return true;
}

function capturarEnlace() {
  const hash = location.hash;
  if (!hash.startsWith('#add=')) return false;
  estado.enlacePendiente = hash.slice(5);
  // La URI contiene la semilla: se quita del historial de inmediato.
  history.replaceState(null, '', location.pathname + location.search);
  return true;
}

/* ——— Pestañas de alta ——— */

const PESTANAS = ['enlace', 'pegar', 'manual', 'camara'];

function seleccionarPestana(nombre, enfocar = false) {
  for (const p of PESTANAS) {
    const tab = $(`tab-${p}`);
    const activa = p === nombre;
    tab.setAttribute('aria-selected', String(activa));
    tab.tabIndex = activa ? 0 : -1;
    $(`panel-${p}`).hidden = !activa;
    if (activa && enfocar) tab.focus();
  }
  if (nombre !== 'camara') detenerCamara();
}

function pestanasVisibles() {
  return PESTANAS.filter((p) => !$(`tab-${p}`).hidden);
}

/* ——— Cámara ——— */

function detenerCamara() {
  detenerEscaner($('video'));
  $('boton-camara').hidden = false;
  $('boton-camara-parar').hidden = true;
}

async function activarCamara() {
  mostrarError('camara-error', '');
  try {
    $('boton-camara').hidden = true;
    $('boton-camara-parar').hidden = false;
    await iniciarEscaner($('video'), (texto) => {
      detenerCamara();
      try {
        mostrarConfirmacion(analizarOtpauth(extraerDeEnlace(texto)), 'camara');
      } catch (error) {
        mostrarError('camara-error', mensajeDe(error));
      }
    });
  } catch (error) {
    detenerCamara();
    mostrarError('camara-error', error?.name === 'NotAllowedError'
      ? 'Sin permiso para usar la cámara. Actívalo en los ajustes del navegador.'
      : 'No se pudo abrir la cámara.');
  }
}

/* ——— Bloqueo ——— */

function limpiarSensibles() {
  limpiarAlta();
  for (const id of ['f-crear-pin', 'f-desbloquear', 'f-cambiar-pin', 'f-exportar', 'f-importar']) $(id).reset();
  for (const id of ['cambiar-pin-error', 'exportar-error', 'importar-error']) mostrarError(id, '');
  $('cuentas').replaceChildren();
  $('d-codigo').textContent = '';
  $('c-codigo').textContent = '';
  $('d-esfera').replaceChildren();
  $('resultado-hora').hidden = true;
  for (const d of document.querySelectorAll('details.desplegable')) d.open = false;
}

function bloquearApp(motivo) {
  if (!boveda.abierta()) return;
  boveda.bloquear();
  estado.sesion++;
  estado.cuentas = [];
  estado.llaves.clear();
  estado.cache.clear();
  estado.vistas.clear();
  estado.pendiente = null;
  estado.vistaPrevia = null;
  estado.desfaseMs = 0;
  detenerCamara();
  if ($('dialogo').open) $('dialogo').close();
  limpiarSensibles();
  irA('desbloquear', { enfocar: motivo === 'manual' });
  mostrarError('desbloquear-error', '');
  if (motivo === 'inactividad') avisar('Se bloqueó por inactividad');
  if (motivo === 'manual') avisar('App bloqueada');
}

function registrarActividad() {
  estado.ultimaActividad = Date.now();
}

/* ——— Acceso con PIN ——— */

let temporizadorEspera = 0;
function iniciarEspera(hasta) {
  clearInterval(temporizadorEspera);
  estado.esperaHasta = hasta;
  const entrada = $('pin-acceso');
  const boton = $('boton-desbloquear');
  const pintar = () => {
    const falta = estado.esperaHasta - Date.now();
    if (falta <= 0) {
      clearInterval(temporizadorEspera);
      entrada.disabled = false;
      boton.disabled = false;
      boton.textContent = 'Desbloquear';
      mostrarError('desbloquear-error', '');
      return;
    }
    entrada.disabled = true;
    boton.disabled = true;
    boton.textContent = `Espera ${formatearEspera(falta)}`;
    mostrarError('desbloquear-error', 'Demasiados intentos fallidos. Por seguridad, espera antes de volver a intentarlo.');
  };
  pintar();
  temporizadorEspera = setInterval(pintar, 1000);
}

async function abrirSesion() {
  estado.sesion++;
  estado.cuentas = boveda.obtenerCuentas();
  const ajustes = await boveda.leerAjustes();
  estado.bloqueoMs = ajustes.bloqueoMin * 60_000;
  $('a-bloqueo').value = String(ajustes.bloqueoMin);
  registrarActividad();
  $('f-desbloquear').reset();
  $('f-crear-pin').reset();
  renderLista();
  if (!procesarEnlacePendiente()) irA('lista');
}

async function alCrearPin(evento) {
  evento.preventDefault();
  const pin = $('pin-nuevo').value;
  const repetido = $('pin-repetido').value;
  const problema = boveda.problemaDePin(pin);
  $('pin-nuevo').setAttribute('aria-invalid', String(Boolean(problema)));
  if (problema) return mostrarError('crear-pin-error', problema);
  if (pin !== repetido) {
    $('pin-repetido').setAttribute('aria-invalid', 'true');
    return mostrarError('crear-pin-error', 'Los dos PIN no coinciden.');
  }
  mostrarError('crear-pin-error', '');
  const boton = evento.submitter ?? $('f-crear-pin').querySelector('button');
  boton.disabled = true;
  boton.textContent = 'Cifrando la bóveda…';
  try {
    await boveda.crear(pin);
    await abrirSesion();
    avisar('PIN creado');
  } catch (error) {
    mostrarError('crear-pin-error', mensajeDe(error));
  } finally {
    boton.disabled = false;
    boton.textContent = 'Crear PIN y continuar';
  }
}

async function alDesbloquear(evento) {
  evento.preventDefault();
  const entrada = $('pin-acceso');
  const pin = entrada.value;
  if (!pin) return mostrarError('desbloquear-error', 'Escribe tu PIN.');
  const boton = $('boton-desbloquear');
  boton.disabled = true;
  entrada.disabled = true;
  boton.textContent = 'Comprobando…';
  mostrarError('desbloquear-error', '');
  let resultado;
  try {
    resultado = await boveda.desbloquear(pin);
  } catch (error) {
    resultado = { ok: false, fallos: 0, esperaMs: 0, error };
  }
  entrada.disabled = false;
  boton.disabled = false;
  boton.textContent = 'Desbloquear';
  if (resultado.ok) {
    await abrirSesion();
    return;
  }
  entrada.value = '';
  entrada.setAttribute('aria-invalid', 'true');
  if (resultado.error) return mostrarError('desbloquear-error', mensajeDe(resultado.error));
  if (resultado.esperaMs > 0) return iniciarEspera(Date.now() + resultado.esperaMs);
  const libres = 5 - resultado.fallos;
  mostrarError('desbloquear-error', `PIN incorrecto. ${libres === 1 ? 'Te queda 1 intento' : `Te quedan ${libres} intentos`} antes de una espera obligatoria.`);
  entrada.focus();
}

/* ——— Ajustes ——— */

async function comprobarHora() {
  const boton = $('boton-hora');
  const caja = $('resultado-hora');
  boton.disabled = true;
  caja.hidden = false;
  caja.className = 'resultado';
  caja.replaceChildren('Consultando la hora del servidor…');
  try {
    const t0 = Date.now();
    const respuesta = await fetch('/health', { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    const t1 = Date.now();
    const fecha = respuesta.headers.get('Date');
    const servidor = fecha ? Date.parse(fecha) : NaN;
    if (Number.isNaN(servidor)) throw new Error('sin fecha');
    // La cabecera Date tiene resolución de 1 s: se toma la mitad del segundo y la mitad del viaje.
    const desfase = Math.round(((t0 + t1) / 2 - (servidor + 500)) / 1000);
    const magnitud = Math.abs(desfase);
    if (magnitud <= UMBRAL_DESFASE) {
      caja.className = 'resultado resultado-bien';
      const texto = el('div');
      texto.append(el('strong', '', 'La hora de tu dispositivo es correcta.'),
        magnitud === 0 ? 'Coincide con la del servidor.' : `Diferencia con el servidor: ${magnitud} s.`);
      caja.replaceChildren(icono('ok'), texto);
    } else {
      caja.className = 'resultado resultado-mal';
      const texto = el('div');
      const sentido = desfase > 0 ? 'adelantado' : 'atrasado';
      texto.append(
        el('strong', '', `Tu reloj va ${formatearEspera(magnitud * 1000)} ${sentido}.`),
        'El servicio podría rechazar tus códigos. Activa la hora automática en los ajustes del sistema.',
      );
      const compensar = el('button', 'boton boton-secundario', 'Usar la hora del servidor en esta sesión');
      compensar.type = 'button';
      compensar.addEventListener('click', () => {
        estado.desfaseMs = -desfase * 1000;
        estado.cache.clear();
        compensar.disabled = true;
        avisar('Los códigos usan la hora del servidor hasta que bloquees la app');
      });
      texto.append(el('br'), compensar);
      caja.replaceChildren(icono('alerta'), texto);
    }
  } catch {
    caja.className = 'resultado resultado-mal';
    const texto = el('div');
    texto.append(el('strong', '', 'No se pudo consultar la hora.'), 'Esta comprobación necesita conexión con el servidor del servicio.');
    caja.replaceChildren(icono('alerta'), texto);
  } finally {
    boton.disabled = false;
  }
}

async function alCambiarPin(evento) {
  evento.preventDefault();
  const actual = $('cp-actual').value;
  const nuevo = $('cp-nuevo').value;
  if (nuevo !== $('cp-repetido').value) return mostrarError('cambiar-pin-error', 'Los dos PIN nuevos no coinciden.');
  const problema = boveda.problemaDePin(nuevo);
  if (problema) return mostrarError('cambiar-pin-error', problema);
  const boton = evento.submitter ?? $('f-cambiar-pin').querySelector('button');
  boton.disabled = true;
  mostrarError('cambiar-pin-error', '');
  try {
    await boveda.cambiarPin(actual, nuevo);
    $('f-cambiar-pin').reset();
    $('cambiar-pin').open = false;
    avisar('PIN cambiado');
  } catch (error) {
    mostrarError('cambiar-pin-error', mensajeDe(error));
  } finally {
    boton.disabled = false;
  }
}

async function alExportar(evento) {
  evento.preventDefault();
  const clave = $('e-clave').value;
  if (clave.length < 10) return mostrarError('exportar-error', 'La contraseña debe tener al menos 10 caracteres.');
  if (clave !== $('e-clave2').value) return mostrarError('exportar-error', 'Las contraseñas no coinciden.');
  if (!estado.cuentas.length) return mostrarError('exportar-error', 'No hay cuentas que respaldar.');
  const boton = evento.submitter ?? $('f-exportar').querySelector('button');
  boton.disabled = true;
  mostrarError('exportar-error', '');
  try {
    const cuentas = estado.cuentas.map(({ emisor, cuenta, secreto, algoritmo, digitos, periodo, creada }) =>
      ({ emisor, cuenta, secreto, algoritmo, digitos, periodo, creada }));
    const sobre = await cifrarRespaldo({ version: 1, cuentas }, clave);
    const blob = new Blob([JSON.stringify(sobre, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const enlace = document.createElement('a');
    enlace.href = url;
    enlace.download = `respaldo-autenticador-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.append(enlace);
    enlace.click();
    enlace.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    $('f-exportar').reset();
    avisar('Respaldo cifrado descargado');
  } catch (error) {
    mostrarError('exportar-error', mensajeDe(error));
  } finally {
    boton.disabled = false;
  }
}

async function alImportar(evento) {
  evento.preventDefault();
  estado.ignorarOcultar = false;
  const archivo = $('i-archivo').files?.[0];
  if (!archivo) return mostrarError('importar-error', 'Elige el archivo de respaldo.');
  if (archivo.size > 1_000_000) return mostrarError('importar-error', 'El archivo es demasiado grande para ser un respaldo.');
  const boton = evento.submitter ?? $('f-importar').querySelector('button');
  boton.disabled = true;
  mostrarError('importar-error', '');
  try {
    let sobre;
    try { sobre = JSON.parse(await archivo.text()); } catch { throw new Error('El archivo no es un respaldo válido.'); }
    const contenido = await descifrarRespaldo(sobre, $('i-clave').value);
    if (!Array.isArray(contenido?.cuentas)) throw new Error('El respaldo no contiene cuentas.');
    const existentes = new Set(estado.cuentas.map((c) => `${c.secreto}|${c.algoritmo}|${c.digitos}|${c.periodo}`));
    const nuevas = [];
    let repetidas = 0;
    for (const item of contenido.cuentas) {
      const datos = validarCuenta(item);
      const clave = `${datos.secreto}|${datos.algoritmo}|${datos.digitos}|${datos.periodo}`;
      if (existentes.has(clave)) { repetidas++; continue; }
      existentes.add(clave);
      nuevas.push({ id: crypto.randomUUID(), ...datos, origen: 'respaldo', creada: item.creada || new Date().toISOString() });
    }
    await guardarLista([...estado.cuentas, ...nuevas]);
    renderLista();
    $('f-importar').reset();
    avisar(`Se importaron ${nuevas.length} cuentas${repetidas ? ` (${repetidas} ya existían)` : ''}`);
  } catch (error) {
    mostrarError('importar-error', mensajeDe(error));
  } finally {
    boton.disabled = false;
  }
}

async function borrarTodo() {
  const ok = await confirmar({
    titulo: '¿Borrar todo?',
    texto: 'Se eliminarán el PIN y todas las cuentas de este dispositivo. Para volver a entrar en tus servicios necesitarás tus códigos de recuperación.',
    aceptar: 'Borrar todo',
    exigir: 'BORRAR',
  });
  if (!ok) return;
  await boveda.borrarTodo();
  estado.sesion++;
  estado.cuentas = [];
  estado.llaves.clear();
  estado.cache.clear();
  limpiarSensibles();
  clearInterval(temporizadorEspera);
  $('pin-acceso').disabled = false;
  $('boton-desbloquear').disabled = false;
  $('boton-desbloquear').textContent = 'Desbloquear';
  mostrarError('desbloquear-error', '');
  irA('crear-pin');
  avisar('Se borró todo el contenido');
}

/* ——— Eventos ——— */

function conectarEventos() {
  for (const boton of document.querySelectorAll('[data-ir]')) {
    boton.addEventListener('click', () => {
      const destino = boton.dataset.ir;
      if (destino === 'agregar') { limpiarAlta(); seleccionarPestana('enlace'); }
      if (destino === 'lista') renderLista();
      irA(destino);
    });
  }
  $('boton-bloquear').addEventListener('click', () => bloquearApp('manual'));

  $('f-crear-pin').addEventListener('submit', alCrearPin);
  $('f-desbloquear').addEventListener('submit', alDesbloquear);
  $('boton-borrar-olvido').addEventListener('click', borrarTodo);
  for (const id of ['pin-nuevo', 'pin-repetido', 'pin-acceso']) {
    $(id).addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/\D/g, '');
      e.target.removeAttribute('aria-invalid');
    });
  }

  $('buscar').addEventListener('input', filtrar);

  // Pestañas con teclado (patrón WAI-ARIA)
  for (const p of PESTANAS) {
    const tab = $(`tab-${p}`);
    tab.addEventListener('click', () => seleccionarPestana(p));
    tab.addEventListener('keydown', (e) => {
      const lista = pestanasVisibles();
      const i = lista.indexOf(p);
      let destino = null;
      if (e.key === 'ArrowRight') destino = lista[(i + 1) % lista.length];
      if (e.key === 'ArrowLeft') destino = lista[(i - 1 + lista.length) % lista.length];
      if (e.key === 'Home') destino = lista[0];
      if (e.key === 'End') destino = lista[lista.length - 1];
      if (destino) { e.preventDefault(); seleccionarPestana(destino, true); }
    });
  }

  $('f-enlace').addEventListener('submit', (e) => {
    e.preventDefault();
    try {
      const valor = $('enlace').value;
      mostrarConfirmacion(analizarOtpauth(extraerDeEnlace(valor)), 'enlace');
    } catch (error) {
      $('enlace').setAttribute('aria-invalid', 'true');
      mostrarError('enlace-error', mensajeDe(error));
    }
  });

  $('f-pegar').addEventListener('submit', (e) => {
    e.preventDefault();
    try {
      mostrarConfirmacion(analizarOtpauth(extraerDeEnlace($('uri').value)), 'uri');
    } catch (error) {
      $('uri').setAttribute('aria-invalid', 'true');
      mostrarError('pegar-error', mensajeDe(error));
    }
  });

  $('boton-portapapeles').addEventListener('click', async () => {
    try {
      const texto = await navigator.clipboard.readText();
      $('uri').value = texto.trim();
      $('f-pegar').requestSubmit();
    } catch {
      mostrarError('pegar-error', 'El navegador no permitió leer el portapapeles. Mantén pulsado el cuadro y elige «Pegar».');
    }
  });

  $('f-manual').addEventListener('submit', (e) => {
    e.preventDefault();
    try {
      const datos = validarCuenta({
        emisor: $('m-emisor').value,
        cuenta: $('m-cuenta').value,
        secreto: $('m-secreto').value,
        algoritmo: document.querySelector('input[name="m-algoritmo"]:checked')?.value,
        digitos: document.querySelector('input[name="m-digitos"]:checked')?.value,
        periodo: $('m-periodo').value,
      });
      mostrarConfirmacion(datos, 'manual');
    } catch (error) {
      if (/clave/i.test(mensajeDe(error))) $('m-secreto').setAttribute('aria-invalid', 'true');
      mostrarError('manual-error', mensajeDe(error));
    }
  });
  for (const id of ['enlace', 'uri', 'm-secreto']) $(id).addEventListener('input', () => $(id).removeAttribute('aria-invalid'));

  $('boton-camara').addEventListener('click', activarCamara);
  $('boton-camara-parar').addEventListener('click', detenerCamara);

  $('boton-guardar-cuenta').addEventListener('click', guardarPendiente);
  $('boton-cancelar-cuenta').addEventListener('click', cancelarPendiente);
  $('confirmar-volver').addEventListener('click', cancelarPendiente);

  $('d-copiar').addEventListener('click', () => {
    const c = estado.cuentas.find((x) => x.id === estado.detalleId);
    if (c) copiar(c, null);
  });

  $('f-renombrar').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = estado.detalleId;
    try {
      const emisor = limpiarTexto($('r-emisor').value, 'emisor');
      const cuenta = limpiarTexto($('r-cuenta').value, 'nombre de la cuenta');
      if (!emisor && !cuenta) throw new ErrorCuenta('Indica al menos el emisor o el nombre de la cuenta.');
      await guardarLista(estado.cuentas.map((c) => (c.id === id ? { ...c, emisor, cuenta } : c)));
      mostrarError('renombrar-error', '');
      $('t-detalle').textContent = emisor || cuenta;
      avisar('Nombre guardado');
    } catch (error) {
      mostrarError('renombrar-error', mensajeDe(error));
    }
  });

  $('d-eliminar').addEventListener('click', async () => {
    const id = estado.detalleId;
    const c = estado.cuentas.find((x) => x.id === id);
    if (!c) return;
    const ok = await confirmar({
      titulo: `¿Eliminar ${nombreDe(c)}?`,
      texto: 'Dejarás de ver sus códigos en este dispositivo. Si el segundo factor sigue activo en el servicio, necesitarás un código de recuperación para entrar.',
      aceptar: 'Eliminar cuenta',
    });
    if (!ok || !boveda.abierta()) return;
    await guardarLista(estado.cuentas.filter((x) => x.id !== id));
    estado.llaves.delete(id);
    estado.cache.delete(id);
    renderLista();
    irA('lista');
    avisar(`Cuenta de ${nombreDe(c)} eliminada`);
  });

  $('a-bloqueo').addEventListener('change', async () => {
    const bloqueoMin = Number($('a-bloqueo').value);
    if (![1, 2, 5].includes(bloqueoMin)) return;
    estado.bloqueoMs = bloqueoMin * 60_000;
    await boveda.guardarAjustes({ ...(await boveda.leerAjustes()), bloqueoMin });
    avisar(`Bloqueo tras ${bloqueoMin} min sin uso`);
  });
  $('f-cambiar-pin').addEventListener('submit', alCambiarPin);
  $('boton-hora').addEventListener('click', comprobarHora);
  $('f-exportar').addEventListener('submit', alExportar);
  $('f-importar').addEventListener('submit', alImportar);
  // Abrir el selector de archivos oculta la página en algunos móviles: no se bloquea por eso.
  $('i-archivo').addEventListener('click', () => { estado.ignorarOcultar = true; });
  $('i-archivo').addEventListener('change', () => { setTimeout(() => { estado.ignorarOcultar = false; }, 500); });
  window.addEventListener('focus', () => { setTimeout(() => { estado.ignorarOcultar = false; }, 1500); });
  $('boton-borrar-todo').addEventListener('click', borrarTodo);

  for (const tipo of ['pointerdown', 'keydown', 'touchstart', 'wheel', 'input']) {
    document.addEventListener(tipo, registrarActividad, { capture: true, passive: true });
  }
  document.addEventListener('visibilitychange', () => {
    if (document.hidden && !estado.ignorarOcultar) bloquearApp('oculta');
  });
  window.addEventListener('pagehide', () => bloquearApp('oculta'));

  window.addEventListener('hashchange', () => {
    if (capturarEnlace() && boveda.abierta()) procesarEnlacePendiente();
    else if (estado.enlacePendiente) for (const n of document.querySelectorAll('[data-pendiente]')) n.hidden = false;
  });
}

/* ——— Arranque ——— */

function registrarServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  navigator.serviceWorker.register('./sw.js', { scope: './', updateViaCache: 'none' }).catch(() => {
    /* sin service worker la app sigue funcionando en línea */
  });
}

async function iniciar() {
  capturarEnlace();
  conectarEventos();
  registrarServiceWorker();

  if (!globalThis.crypto?.subtle || !('indexedDB' in globalThis)) {
    $('cargando-texto').textContent = 'Este navegador no ofrece cifrado seguro (Web Crypto) o almacenamiento local. Abre la app con HTTPS en un navegador actualizado.';
    return;
  }

  if (!(await escanerDisponible())) {
    $('tab-camara').hidden = true;
    $('panel-camara').hidden = true;
    $('nota-camara').hidden = false;
  }

  try {
    const existe = await boveda.existe();
    for (const n of document.querySelectorAll('[data-pendiente]')) n.hidden = !estado.enlacePendiente;
    irA(existe ? 'desbloquear' : 'crear-pin');
    if (existe) {
      const intentos = await boveda.leerIntentos();
      if (intentos.bloqueadoHasta > Date.now()) iniciarEspera(intentos.bloqueadoHasta);
    }
  } catch {
    $('cargando-texto').textContent = 'No se pudo abrir el almacenamiento local. Si navegas en modo privado, abre la app en una ventana normal.';
  }

  setInterval(() => {
    if (!boveda.abierta()) return;
    if (Date.now() - estado.ultimaActividad > estado.bloqueoMs) {
      bloquearApp('inactividad');
      return;
    }
    actualizarCodigos();
  }, 250);
}

iniciar();
