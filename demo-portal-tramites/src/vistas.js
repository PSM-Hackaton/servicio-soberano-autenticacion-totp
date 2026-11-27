// Vistas del Portal de Trámites (HTML renderizado en el servidor; sin estilos ni scripts en línea).

import { html, crudo } from './html.js';
import { TRAMITES } from './tramites.js';
import { formatearCedula } from './cedula.js';

const ICONOS = {
  documento: '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5"/><path d="M10 13h6M10 17h6"/>',
  banco: '<path d="M3 10l9-6 9 6"/><path d="M5 10v8M9 10v8M15 10v8M19 10v8"/><path d="M3 21h18"/>',
  lista: '<path d="M9 6h11M9 12h11M9 18h11"/><path d="M4 6h.01M4 12h.01M4 18h.01"/>',
  llave: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M15 8l2 2"/>',
  candado: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  escudo: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  telefono: '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>',
  alerta: '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18h.01"/>',
  reloj: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  nube: '<path d="M7 18a5 5 0 1 1 1-9.9A6 6 0 0 1 19 10a4 4 0 0 1 0 8z"/><path d="M4 4l16 16"/>',
  ok: '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
  menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
  cerrar: '<path d="M6 6l12 12M18 6L6 18"/>',
  flecha: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  casa: '<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
  ayuda: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.3a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.4M12 16.8h.01"/>',
  usuario: '<circle cx="12" cy="8" r="4"/><path d="M4.5 20.5c1.4-3.7 4.2-5.5 7.5-5.5s6.1 1.8 7.5 5.5"/>',
  servidor: '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M8 7.5h.01M8 16.5h.01M12 7.5h4M12 16.5h4"/>',
  codigo: '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M10 9h4M10 12h4M10 15h2"/>',
  tramites: '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/>',
};

export function icono(nombre, clase = 'icono') {
  return crudo(`<svg class="${clase}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${ICONOS[nombre] ?? ''}</svg>`);
}

const fechaHora = (ms) => new Date(ms).toLocaleString('es', { dateStyle: 'medium', timeStyle: 'short' });
const hora = (ms) => new Date(ms).toLocaleTimeString('es', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

/** Campo oculto CSRF. */
const csrf = (s) => html`<input type="hidden" name="_csrf" value="${s.csrf}">`;

/** Indicador de pasos del ingreso. @param {number} actual 1..3 */
function pasos(actual, segundo = 'Segundo factor') {
  const items = ['Cédula y contraseña', segundo, 'Acceso a trámites'];
  return html`<ol class="pasos" aria-label="Progreso del ingreso">${items.map((t, i) => html`
    <li class="${i + 1 < actual ? 'hecho' : i + 1 === actual ? 'actual' : ''}" ${i + 1 === actual ? crudo('aria-current="step"') : ''}>
      <span class="pasos-num">${i + 1 < actual ? '✓' : i + 1}</span><span>${t}</span></li>`)}
  </ol>`;
}

/** Aviso accesible. */
export function aviso(tipo, titulo, texto, extra = '') {
  const ic = { error: 'alerta', exito: 'ok', info: 'escudo', bloqueo: 'reloj', caido: 'nube' }[tipo] ?? 'escudo';
  const rol = tipo === 'error' || tipo === 'bloqueo' || tipo === 'caido' ? 'alert' : 'status';
  return html`<div class="aviso aviso-${tipo}" role="${rol}">${icono(ic, 'icono aviso-icono')}<div><strong>${titulo}</strong>${texto ? html`<p>${texto}</p>` : ''}${extra}</div></div>`;
}

/** Mensaje de error del segundo factor según el resultado de la verificación. */
export function avisoSegundoFactor(r) {
  if (!r || r.ok) return '';
  if (r.tipo === 'bloqueo') {
    return aviso('bloqueo', 'Demasiados intentos', null, html`<p>Por seguridad, la verificación está bloqueada temporalmente. Podrá intentarlo de nuevo en
      <span class="cuenta-atras" data-cuenta-atras="${r.reintentarEn}" aria-live="polite">${formatoMinutos(r.reintentarEn)}</span></p>`);
  }
  if (r.tipo === 'servicio') {
    return aviso('caido', 'No se puede verificar en este momento', 'El servicio de autenticación no responde. Intente más tarde. Por seguridad, no se concede acceso sin verificar el segundo factor.');
  }
  if (r.tipo === 'token') {
    return aviso('error', 'Verificación no válida', 'La constancia de verificación no superó los controles del portal. No se concedió el acceso.');
  }
  return aviso('error', 'Código incorrecto', 'Revise el código de 6 dígitos que muestra su autenticador e inténtelo de nuevo. Si el código acaba de cambiar, use el nuevo.');
}

export const formatoMinutos = (s) => `${Math.floor(s / 60)}:${String(Math.max(0, s % 60)).padStart(2, '0')}`;

/** Campo de código TOTP accesible. */
function campoCodigo({ etiqueta = 'Código de 6 dígitos', ayuda = 'Lo muestra su app autenticadora y cambia cada 30 segundos.', deshabilitado = false, id = 'codigo' } = {}) {
  return html`<div class="campo">
    <label for="${id}">${etiqueta}</label>
    <input class="entrada-codigo" id="${id}" name="codigo" type="text" inputmode="numeric" autocomplete="one-time-code"
      pattern="[0-9]{6,8}" minlength="6" maxlength="8" required aria-describedby="${id}-ayuda" ${deshabilitado ? crudo('disabled') : ''} data-codigo>
    <p class="ayuda" id="${id}-ayuda">${ayuda}</p>
  </div>`;
}

// ---------------------------------------------------------------- layout

const ZONA = 'America/Caracas';
const fechaLarga = (d) => new Intl.DateTimeFormat('es-VE', { timeZone: ZONA, weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }).format(d);
const fechaIso = (d) => new Intl.DateTimeFormat('en-CA', { timeZone: ZONA }).format(d);

/** Bandera nacional (SVG propio: tres franjas y arco de ocho estrellas, sin escudo). */
const bandera = (clase, ancho = 48) => html`<img class="${clase}" src="/publico/bandera.svg" alt="" width="${ancho}" height="${Math.round((ancho * 2) / 3)}">`;

/** Migas de pan. @param {Array<[string, string?]>} items [texto, enlace?]; el último es la página actual. */
export function migas(items) {
  return html`<nav class="migas" aria-label="Migas de pan"><ol>
    <li><a href="/">${icono('casa', 'icono icono-mini')}<span>Inicio</span></a></li>${items.map(([t, h], i) => html`
    <li>${i === items.length - 1 || !h ? html`<span aria-current="page">${t}</span>` : html`<a href="${h}">${t}</a>`}</li>`)}
  </ol></nav>`;
}

/** Menú principal: solo vistas existentes y anclas. */
function menu({ autenticado, ruta }) {
  const enTramites = ruta.startsWith('/tramites/') || ruta.startsWith('/comprobantes/');
  const items = [
    { t: 'Inicio', h: '/', ic: 'casa', activo: (ruta === '/ingresar' || ruta === '/panel') },
    { t: 'Trámites en línea', h: autenticado ? '/panel#tramites' : '/ingresar#tramites', ic: 'tramites', activo: enTramites },
    { t: 'Seguridad de su cuenta', h: autenticado ? '/panel#seguridad' : '/ingresar#como-protege', ic: 'escudo', activo: false },
    { t: 'Ayuda', h: '/ayuda', ic: 'ayuda', activo: ruta === '/ayuda' },
  ];
  return html`<ul class="menu-lista">${items.map((i) => html`
    <li><a class="menu-enlace" href="${i.h}" ${i.activo ? crudo('aria-current="page"') : ''}>${icono(i.ic, 'icono icono-chico')}<span>${i.t}</span></a></li>`)}
  </ul>`;
}

/**
 * @param {{ titulo: string, sesion: any, usuario?: any, contenido: any, ancho?: 'estrecho' | 'amplio' | 'portada', ruta: string }} o
 */
export function layout({ titulo, sesion, usuario, contenido, ancho = 'estrecho', ruta }) {
  const conTrazas = sesion.trazasVisibles;
  const conSesion = Boolean(usuario) && sesion.etapa !== 'anonima';
  const autenticado = conSesion && sesion.etapa === 'autenticado';
  const hoy = new Date();
  return `<!doctype html>${html`
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="theme-color" content="#00247D">
<title>${titulo} · Portal de Trámites del Estado</title>
<link rel="icon" href="/publico/emblema.svg" type="image/svg+xml">
<link rel="stylesheet" href="/publico/estilos.css">
<script src="/publico/app.js" defer></script>
</head>
<body>
<a class="saltar" href="#contenido">Saltar al contenido</a>
<header class="encabezado">
  <div class="cintillo">
    <div class="contenedor cintillo-fila">
      <a class="cintillo-marca" href="/" aria-label="Portal de Trámites del Estado, República Bolivariana de Venezuela. Ir al inicio">
        ${bandera('cintillo-bandera', 54)}
        <span class="cintillo-textos">
          <span class="cintillo-pais">República Bolivariana de Venezuela</span>
          <span class="cintillo-portal">Portal de Trámites del Estado</span>
        </span>
      </a>
      <div class="cintillo-datos">
        <time class="cintillo-fecha" datetime="${fechaIso(hoy)}">${fechaLarga(hoy)}</time>
        <span class="cintillo-servicio">${icono('escudo', 'icono icono-chico')}<span>Servicio Soberano de Autenticación</span></span>
      </div>
    </div>
  </div>
  <div class="franja-tricolor" aria-hidden="true"></div>
  <nav class="menu" aria-label="Menú principal" data-menu>
    <div class="contenedor menu-fila">
      <button type="button" class="menu-boton" aria-expanded="false" aria-controls="menu-panel" hidden data-menu-boton>
        ${icono('menu', 'icono menu-icono-abrir')}${icono('cerrar', 'icono menu-icono-cerrar')}<span>Menú</span>
      </button>
      <div class="menu-panel" id="menu-panel">
        ${menu({ autenticado, ruta })}
        <div class="menu-acciones">
          <form method="post" action="/trazas" class="form-en-linea">
            ${csrf(sesion)}<input type="hidden" name="volver" value="${ruta}">
            <button type="submit" class="boton-trazas" aria-pressed="${conTrazas ? 'true' : 'false'}">
              <span class="interruptor" aria-hidden="true"></span><span>Lo que ocurre por dentro</span>
            </button>
          </form>
          ${conSesion ? html`
          <form method="post" action="/salir" class="form-en-linea">
            ${csrf(sesion)}
            <button type="submit" class="boton-salir">${icono('usuario', 'icono icono-chico')}<span>Salir</span></button>
          </form>` : ''}
        </div>
      </div>
    </div>
  </nav>
</header>
<div class="franja-demo" role="note"><div class="contenedor franja-demo-fila">${icono('alerta', 'icono icono-chico')}<span><strong>Sitio de demostración.</strong> Institución, personas, cédulas y datos son ficticios; no es un sitio oficial.</span></div></div>
<div class="contenedor disposicion ${conTrazas ? 'con-trazas' : ''}">
  <main id="contenido" class="principal principal-${ancho}" tabindex="-1">
    ${contenido}
  </main>
  ${conTrazas ? panelTrazas(sesion) : ''}
</div>
<footer class="pie">
  <div class="franja-tricolor" aria-hidden="true"></div>
  <div class="contenedor pie-rejilla">
    <section class="pie-columna pie-marca" aria-labelledby="pie-servicio">
      <div class="pie-marca-fila">${bandera('pie-bandera', 42)}<h2 id="pie-servicio" class="pie-titulo">Servicio Soberano de Autenticación</h2></div>
      <p>Portal de Trámites del Estado: demostración de un portal institucional que protege sus trámites con un segundo factor TOTP verificado en infraestructura propia.</p>
    </section>
    <section class="pie-columna" aria-labelledby="pie-enlaces">
      <h2 id="pie-enlaces" class="pie-subtitulo">Enlaces</h2>
      <ul class="pie-enlaces">
        <li><a href="#">Términos de uso</a></li>
        <li><a href="#">Política de privacidad</a></li>
        <li><a href="#">Accesibilidad</a></li>
        <li><a href="#">Código fuente (AGPL-3.0)</a></li>
      </ul>
    </section>
    <section class="pie-columna" id="ayuda" aria-labelledby="pie-ayuda" tabindex="-1">
      <h2 id="pie-ayuda" class="pie-subtitulo">Ayuda</h2>
      <ul class="pie-enlaces">
        <li><a href="/recuperar">¿Perdió su teléfono? Use un código de recuperación</a></li>
        <li><span>¿El código no funciona? Verifique que la hora de su teléfono sea automática.</span></li>
        <li><span>Ingrese con su cédula: V o E y el número, con o sin puntos.</span></li>
      </ul>
    </section>
    <section class="pie-columna" aria-labelledby="pie-garantias">
      <h2 id="pie-garantias" class="pie-subtitulo">Garantías</h2>
      <ul class="pie-sellos">
        <li>${icono('documento', 'icono icono-chico')}<span>Software libre · AGPL-3.0</span></li>
        <li>${icono('servidor', 'icono icono-chico')}<span>Infraestructura nacional · Sin dependencias extranjeras</span></li>
        <li>${icono('candado', 'icono icono-chico')}<span>Sin rastreadores ni recursos externos</span></li>
      </ul>
    </section>
  </div>
  <div class="pie-legal">
    <div class="contenedor pie-legal-fila">
      <p><strong>Sitio de demostración.</strong> Institución, personas y datos son ficticios. El segundo factor se verifica en un servicio propio, en infraestructura local.</p>
      <p>Portal de Trámites del Estado · ${String(hoy.getFullYear())}</p>
    </div>
  </div>
</footer>
</body>
</html>`}`;
}

function panelTrazas(sesion) {
  const trazas = [...sesion.trazas].reverse();
  return html`<aside class="trazas" aria-labelledby="trazas-titulo">
    <div class="trazas-cabecera">
      <h2 id="trazas-titulo">Lo que ocurre por dentro</h2>
      <p>Traza educativa de esta sesión: llamadas al servicio TOTP, tiempos y decisiones. Nunca se muestran contraseñas, códigos ni secretos.</p>
    </div>
    ${trazas.length === 0 ? html`<p class="trazas-vacio">Aún no hay eventos. Ingrese con un usuario de demostración para ver el flujo.</p>` : html`
    <p class="trazas-orden">Más reciente arriba</p>
    <ol class="trazas-lista">${trazas.map((t) => html`
      <li class="traza traza-${t.tipo} traza-${t.estado}">
        <div class="traza-meta"><span class="traza-etiqueta">${ETIQUETAS[t.tipo] ?? t.tipo}</span><time>${hora(t.en)}</time>${t.ms !== null ? html`<span class="traza-ms">${t.ms} ms</span>` : ''}</div>
        <p class="traza-titulo">${t.titulo}</p>
        ${t.detalle ? html`<p class="traza-detalle">${t.detalle}</p>` : ''}
        ${t.bloque ? html`<pre class="traza-bloque">${t.bloque}</pre>` : ''}
      </li>`)}
    </ol>`}
  </aside>`;
}

const ETIQUETAS = { servicio: 'Servicio TOTP', local: 'Portal', jwt: 'JWT', decision: 'Decisión', info: 'Info' };

// ---------------------------------------------------------------- páginas

/** Servicios destacados de la portada (accesos rápidos). */
const SERVICIOS = [
  { icono: 'documento', titulo: 'Solicitud de certificado', texto: 'Residencia, antecedentes o estado civil con validez digital.', sello: 'Confirmación con código' },
  { icono: 'banco', titulo: 'Cambio de datos bancarios', texto: 'Actualice la cuenta donde recibe pagos y devoluciones.', sello: 'Confirmación con código' },
  { icono: 'lista', titulo: 'Consulta de trámites', texto: 'Revise el estado de sus solicitudes y comprobantes.', sello: 'Consulta' },
  { icono: 'escudo', titulo: 'Seguridad de la cuenta', texto: 'Vincule, cambie o revoque su autenticador.', sello: 'Segundo factor' },
];

export function paginaIngresar({ sesion, error, errorCedula = false, previo = {}, demo = [], captcha = false }) {
  const nac = previo.nacionalidad === 'E' ? 'E' : 'V';
  return html`
  <section class="portada" aria-labelledby="portada-titulo">
    <div class="portada-texto">
      <p class="portada-sobretitulo">Oficina virtual del ciudadano</p>
      <h1 id="portada-titulo">Trámites en línea seguros con segundo factor soberano</h1>
      <p class="portada-entradilla">Ingrese con su cédula de identidad y confirme con el código de 6 dígitos de su app autenticadora. Su cuenta queda protegida aunque alguien conozca su contraseña.</p>
      <ul class="portada-claves">
        <li>${icono('codigo', 'icono')}<span>Código que cambia cada 30 segundos</span></li>
        <li>${icono('servidor', 'icono')}<span>Verificado en infraestructura nacional</span></li>
        <li>${icono('candado', 'icono')}<span>Sus claves no salen de su teléfono</span></li>
      </ul>
    </div>
    <div class="acceso" id="acceso">
      <h2 class="acceso-titulo">${icono('usuario', 'icono')}<span>Ingresar al portal</span></h2>
      ${pasos(1, 'Código')}
      ${error ? aviso(error.tipo ?? 'error', error.titulo, error.texto) : ''}
      ${sesion.aviso ? aviso(sesion.aviso.tipo, sesion.aviso.texto, null) : ''}
      <form method="post" action="/ingresar" class="formulario" data-un-envio ${captcha ? crudo('data-captcha') : ''}>
        ${csrf(sesion)}
        ${captcha ? crudo('<input type="hidden" name="captcha_token" value="">') : ''}
        <fieldset class="campo campo-cedula">
          <legend>Cédula de identidad</legend>
          <div class="cedula-fila">
            <label class="solo-lectores" for="nacionalidad">Nacionalidad</label>
            <select id="nacionalidad" name="nacionalidad" class="cedula-nacionalidad" data-cedula-nacionalidad>
              <option value="V" ${nac === 'V' ? crudo('selected') : ''}>V</option>
              <option value="E" ${nac === 'E' ? crudo('selected') : ''}>E</option>
            </select>
            <label class="solo-lectores" for="cedula">Número de cédula</label>
            <input id="cedula" name="cedula" type="text" inputmode="numeric" autocomplete="username" spellcheck="false" required
              maxlength="14" placeholder="12.345.678" value="${previo.cedula ?? ''}"
              pattern="(?:[VvEe](?:-| )?)?(?:[1-9][0-9]{2}[.]?[0-9]{3}|[1-9][0-9]{0,2}[.]?[0-9]{3}[.]?[0-9]{3})"
              aria-describedby="cedula-ayuda" ${errorCedula ? crudo('aria-invalid="true"') : ''} data-cedula>
          </div>
          <p class="ayuda" id="cedula-ayuda" data-cedula-ayuda>V venezolano o E extranjero, y de 6 a 9 dígitos, con o sin puntos.</p>
        </fieldset>
        <div class="campo">
          <label for="contrasena">Contraseña</label>
          <input id="contrasena" name="contrasena" type="password" autocomplete="current-password" required maxlength="128">
        </div>
        ${captcha ? html`<p class="ayuda" data-captcha-estado aria-live="polite">Protegido por verificación humana soberana (sin servicios externos): se comprueba al pulsar «Continuar».</p>` : ''}
        <button type="submit" class="boton boton-primario boton-ancho">Continuar${icono('flecha', 'icono icono-chico')}</button>
      </form>
      ${captcha ? crudo('<script src="/publico/captcha.js" defer></script>') : ''}
    </div>
    ${demo.length ? html`
    <section class="demo" aria-labelledby="demo-titulo">
      <h2 id="demo-titulo" class="demo-titulo">Cuentas de demostración</h2>
      <p class="demo-nota">Personas y cédulas ficticias. Contraseña de todas: <code>Tramites-Demo-2026</code></p>
      <ul class="lista-demo">${demo.map((u) => html`<li><code>${u.cedulaFormateada}</code><span class="lista-demo-nombre">${u.nombre}</span><span class="etiqueta ${u.conFactor ? 'etiqueta-ok' : ''}">${u.conFactor ? 'Con segundo factor' : 'Sin segundo factor'}</span></li>`)}</ul>
    </section>` : ''}
  </section>

  <section class="bloque" id="tramites" aria-labelledby="servicios-titulo" tabindex="-1">
    <div class="bloque-cabecera">
      <h2 id="servicios-titulo" class="titulo-bloque">Trámites en línea</h2>
      <p>Disponibles las 24 horas tras ingresar. Las operaciones sensibles se confirman con un código nuevo.</p>
    </div>
    <ul class="servicios">${SERVICIOS.map((t) => html`
      <li class="servicio">
        <span class="servicio-icono">${icono(t.icono)}</span>
        <h3><a href="#acceso">${t.titulo}</a></h3>
        <p>${t.texto}</p>
        <span class="servicio-pie"><span class="etiqueta">${t.sello}</span><span class="servicio-ir">Ingresar${icono('flecha', 'icono icono-mini')}</span></span>
      </li>`)}
    </ul>
  </section>

  <section class="bloque bloque-info" id="como-protege" aria-labelledby="como-titulo" tabindex="-1">
    <div class="bloque-cabecera">
      <h2 id="como-titulo" class="titulo-bloque">¿Cómo protege su cuenta el segundo factor?</h2>
      <p>Dos pruebas distintas: algo que usted sabe y algo que usted tiene.</p>
    </div>
    <ol class="pasos-info">
      <li><span class="pasos-info-num">1</span><div><h3>Ingrese su cédula y contraseña</h3><p>Es el primer factor, propio del portal. Por sí solo no basta para entrar.</p></div></li>
      <li><span class="pasos-info-num">2</span><div><h3>Confirme con el código de su teléfono</h3><p>Su app autenticadora genera un código de 6 dígitos que cambia cada 30 segundos, incluso sin conexión.</p></div></li>
      <li><span class="pasos-info-num">3</span><div><h3>Los trámites sensibles piden otro código</h3><p>Antes de emitir un certificado o cambiar sus datos bancarios, se le pide un código nuevo.</p></div></li>
    </ol>
  </section>`;
}

export function paginaEnrolar({ sesion, usuario, enrolamiento, resultado, autenticadorUrl, errorServicio }) {
  if (errorServicio) {
    return html`${migas([['Ingreso', '/ingresar'], ['Vincular autenticador']])}${pasos(2, 'Vincular autenticador')}
    <section class="tarjeta">
      <h1>Vincule su autenticador</h1>
      ${avisoSegundoFactor({ ok: false, tipo: 'servicio' })}
      <p>No es posible iniciar la vinculación ahora. Sus datos están seguros; vuelva a intentarlo en unos minutos.</p>
      <a class="boton boton-secundario" href="/enrolar">Reintentar</a>
    </section>`;
  }
  const enlace = `${autenticadorUrl}#add=${encodeURIComponent(enrolamiento.otpauthUri)}`;
  const clave = (enrolamiento.claveManual ?? '').replace(/(.{4})/g, '$1 ').trim();
  const qrData = `data:image/svg+xml;base64,${Buffer.from(enrolamiento.qrSvg).toString('base64')}`;
  return html`
  ${migas([['Ingreso', '/ingresar'], ['Vincular autenticador']])}
  ${pasos(2, 'Vincular autenticador')}
  <section class="tarjeta">
    <h1>Vincule su autenticador</h1>
    <p class="entradilla">Hola, ${usuario.nombre.split(' ')[0]}. Su cuenta aún no tiene segundo factor. Vincúlelo una sola vez; tarda menos de un minuto.</p>
    ${avisoSegundoFactor(resultado)}
    <div class="enrolar">
      <div class="enrolar-qr">
        <span class="numero-paso">1</span>
        <h2 class="titulo-chico">Escanee el código QR</h2>
        <img class="qr" src="${qrData}" alt="Código QR para vincular el autenticador. Si no puede escanearlo, use el botón o la clave manual." width="220" height="220">
        <a class="boton boton-primario boton-ancho" href="${enlace}" target="_blank" rel="noopener noreferrer">
          ${icono('telefono')}<span>Abrir en el Autenticador Soberano</span></a>
        <details class="clave-manual">
          <summary>¿No puede escanear? Use la clave manual</summary>
          <p class="ayuda">Escriba esta clave en su app (tipo «basada en tiempo», ${enrolamiento.algoritmo ?? 'SHA256'}, ${enrolamiento.digitos ?? 6} dígitos, ${enrolamiento.periodo ?? 30} s).</p>
          <div class="clave-fila">
            <code class="clave" id="clave-manual">${clave}</code>
            <button type="button" class="boton boton-secundario boton-chico" data-copiar="#clave-manual">Copiar</button>
          </div>
        </details>
      </div>
      <div class="enrolar-codigo">
        <span class="numero-paso">2</span>
        <h2 class="titulo-chico">Confirme con el primer código</h2>
        <p class="ayuda">Así comprobamos que su autenticador quedó bien configurado.</p>
        <form method="post" action="/enrolar/activar" class="formulario" data-un-envio>
          ${csrf(sesion)}
          ${campoCodigo({ etiqueta: 'Código que muestra su app' })}
          <button type="submit" class="boton boton-primario boton-ancho">Activar segundo factor</button>
        </form>
        <p class="ayuda vence">${icono('reloj', 'icono icono-chico')} Este alta vence a las <time>${hora(Date.parse(enrolamiento.expiraEn))}</time></p>
      </div>
    </div>
  </section>`;
}

export function paginaCodigosRecuperacion({ sesion, codigos }) {
  return html`
  ${migas([['Ingreso', '/ingresar'], ['Códigos de recuperación']])}
  ${pasos(2, 'Vincular autenticador')}
  <section class="tarjeta">
    ${aviso('exito', 'Segundo factor activado', 'Su autenticador quedó vinculado a la cuenta.')}
    <h1>Guarde sus códigos de recuperación</h1>
    <p class="entradilla">Si pierde el teléfono, cada código le permite entrar <strong>una sola vez</strong>. Se muestran ahora y no se volverán a mostrar.</p>
    <ol class="codigos" id="codigos-recuperacion">${codigos.map((c) => html`<li><code>${c}</code></li>`)}</ol>
    <div class="acciones">
      <button type="button" class="boton boton-secundario" data-copiar="#codigos-recuperacion">Copiar códigos</button>
      <button type="button" class="boton boton-secundario" data-imprimir>Imprimir</button>
    </div>
    <form method="post" action="/enrolar/confirmar" class="formulario confirmar-codigos">
      ${csrf(sesion)}
      <label class="casilla"><input type="checkbox" name="guardados" value="si" required> He guardado los códigos en un lugar seguro.</label>
      <button type="submit" class="boton boton-primario">Continuar al ingreso</button>
    </form>
  </section>`;
}

export function paginaVerificar({ sesion, usuario, resultado }) {
  const bloqueado = resultado?.tipo === 'bloqueo';
  return html`
  ${migas([['Ingreso', '/ingresar'], ['Verificación en dos pasos']])}
  ${pasos(2)}
  <section class="tarjeta">
    <h1>Verificación en dos pasos</h1>
    <p class="entradilla">${usuario.nombre.split(' ')[0]}, abra su app autenticadora e ingrese el código vigente para <strong>Portal de Trámites</strong>.</p>
    ${sesion.aviso ? aviso(sesion.aviso.tipo, sesion.aviso.texto, null) : ''}
    ${avisoSegundoFactor(resultado)}
    <form method="post" action="/verificar" class="formulario" data-un-envio ${bloqueado ? crudo('data-bloqueado') : ''}>
      ${csrf(sesion)}
      ${campoCodigo({ deshabilitado: bloqueado })}
      <button type="submit" class="boton boton-primario boton-ancho" ${bloqueado ? crudo('disabled') : ''}>Verificar y entrar</button>
    </form>
    <div class="enlaces-ayuda">
      <a href="/recuperar">¿No tiene su teléfono? Use un código de recuperación</a>
    </div>
  </section>`;
}

export function paginaRecuperar({ sesion, resultado }) {
  return html`
  ${migas([['Ingreso', '/ingresar'], ['Código de recuperación']])}
  ${pasos(2)}
  <section class="tarjeta">
    <h1>Ingresar con un código de recuperación</h1>
    <p class="entradilla">Use uno de los 10 códigos que guardó al activar el segundo factor. Después deberá vincular un autenticador nuevo.</p>
    ${resultado && !resultado.ok ? (resultado.tipo === 'codigo'
    ? aviso('error', 'Código de recuperación no válido', 'Compruebe que lo escribió completo, con el guion. Cada código sirve una sola vez.')
    : avisoSegundoFactor(resultado)) : ''}
    <form method="post" action="/recuperar" class="formulario" data-un-envio>
      ${csrf(sesion)}
      <div class="campo">
        <label for="recuperacion">Código de recuperación</label>
        <input id="recuperacion" name="recuperacion" type="text" autocomplete="off" autocapitalize="characters" spellcheck="false" required minlength="8" maxlength="32" placeholder="XXXX-XXXX">
      </div>
      <button type="submit" class="boton boton-primario boton-ancho">Usar código</button>
    </form>
    <div class="enlaces-ayuda"><a href="/verificar">Volver a ingresar con el autenticador</a></div>
  </section>`;
}

export function paginaPanel({ sesion, usuario }) {
  const mfa = sesion.mfa;
  const cedula = usuario.cedulaFormateada ?? formatearCedula(usuario.cedula);
  return html`
  ${migas([['Oficina virtual']])}
  <section class="oficina" aria-labelledby="oficina-titulo">
    <div class="oficina-identidad">
      <span class="oficina-avatar">${icono('usuario')}</span>
      <div>
        <p class="oficina-sobretitulo">Oficina virtual</p>
        <h1 id="oficina-titulo">Hola, ${usuario.nombre}</h1>
        <p class="oficina-datos">Cédula de identidad <strong>${cedula}</strong></p>
      </div>
    </div>
    <p class="oficina-estado">${icono('escudo', 'icono icono-chico')}<span>Sesión protegida con verificación en dos pasos</span></p>
  </section>
  ${sesion.aviso ? aviso(sesion.aviso.tipo, sesion.aviso.texto, null) : ''}
  <div class="oficina-rejilla">
    <section id="tramites" aria-labelledby="tramites-titulo" tabindex="-1">
      <h2 id="tramites-titulo" class="titulo-bloque">Trámites en línea</h2>
      <ul class="rejilla-tramites">${TRAMITES.map((t) => html`
        <li class="tramite ${t.peligro ? 'tramite-peligro' : ''}">
          <div class="tramite-icono">${icono(t.icono)}</div>
          <div class="tramite-cuerpo">
            <h3><a href="/tramites/${t.id}">${t.titulo}</a></h3>
            <p>${t.resumen}</p>
            ${t.sensible ? html`<span class="etiqueta etiqueta-sensible">${icono('candado', 'icono icono-mini')} Requiere confirmar con código</span>` : html`<span class="etiqueta">Consulta</span>`}
          </div>
        </li>`)}
      </ul>
    </section>
    <aside class="seguridad" id="seguridad" aria-labelledby="seguridad-titulo" tabindex="-1">
      <h2 id="seguridad-titulo" class="seguridad-titulo">${icono('escudo', 'icono')}<span>Seguridad de su cuenta</span></h2>
      <dl class="estado-sesion">
        <div><dt>Segundo factor</dt><dd>Verificado a las ${hora(mfa.en)}</dd></div>
        <div><dt>Método</dt><dd>${(mfa.amr ?? []).join(', ').toUpperCase() || 'OTP'} · firma EdDSA</dd></div>
        <div><dt>Constancia</dt><dd>${mfa.modo}</dd></div>
      </dl>
      <p class="ayuda">El servicio de autenticación no conoce su cédula: solo recibe un seudónimo.</p>
      <ul class="seguridad-enlaces">
        <li><a href="/tramites/consulta">Ver mis trámites y comprobantes</a></li>
        <li><a href="/tramites/desactivar-factor">Cambié de teléfono: revocar el autenticador</a></li>
      </ul>
    </aside>
  </div>`;
}

export function paginaTramite({ sesion, tramite, resultado, error, valores = {} }) {
  return html`
  ${migas([['Oficina virtual', '/panel'], [tramite.titulo]])}
  <section class="tarjeta">
    <h1>${tramite.titulo}</h1>
    <p class="entradilla">${tramite.resumen}</p>
    ${error ? aviso('error', error, null) : ''}
    ${avisoSegundoFactor(resultado)}
    <form method="post" action="/tramites/${tramite.id}" class="formulario" data-un-envio ${resultado?.tipo === 'bloqueo' ? crudo('data-bloqueado') : ''}>
      ${csrf(sesion)}
      ${tramite.campos.map((c) => html`<div class="campo">
        <label for="c-${c.nombre}">${c.etiqueta}</label>
        ${c.tipo === 'select'
    ? html`<select id="c-${c.nombre}" name="${c.nombre}" required>${c.opciones.map((o) => html`<option ${valores[c.nombre] === o ? crudo('selected') : ''}>${o}</option>`)}</select>`
    : html`<input id="c-${c.nombre}" name="${c.nombre}" type="text" required maxlength="${c.max ?? 80}" ${c.patron ? html`pattern="${c.patron}" inputmode="numeric"` : ''} value="${valores[c.nombre] ?? ''}" ${c.ayuda ? html`aria-describedby="c-${c.nombre}-ayuda"` : ''}>`}
        ${c.ayuda ? html`<p class="ayuda" id="c-${c.nombre}-ayuda">${c.ayuda}</p>` : ''}
      </div>`)}
      ${tramite.peligro ? aviso('info', 'Esta acción revoca su autenticador', 'Los códigos que genere su app dejarán de servir para este portal. Se cerrará la sesión.') : ''}
      <fieldset class="confirmacion">
        <legend>${icono('candado', 'icono icono-chico')} Confirme que es usted</legend>
        <p class="ayuda">Esta es una operación sensible. Aunque ya ingresó, le pedimos un código nuevo de su autenticador.</p>
        ${campoCodigo({ etiqueta: 'Código de su autenticador', ayuda: 'Use el código vigente; el que usó al entrar ya no es válido.', deshabilitado: resultado?.tipo === 'bloqueo' })}
      </fieldset>
      <div class="acciones">
        <button type="submit" class="boton ${tramite.peligro ? 'boton-peligro' : 'boton-primario'}" ${resultado?.tipo === 'bloqueo' ? crudo('disabled') : ''}>${tramite.peligro ? 'Revocar segundo factor' : 'Confirmar y enviar'}</button>
        <a class="boton boton-secundario" href="/panel">Cancelar</a>
      </div>
    </form>
  </section>`;
}

export function paginaComprobante({ comprobante }) {
  return html`
  ${migas([['Oficina virtual', '/panel'], [`Comprobante ${comprobante.folio}`]])}
  <section class="tarjeta comprobante">
    ${aviso('exito', 'Trámite completado', comprobante.mensaje)}
    <h1>Comprobante ${comprobante.folio}</h1>
    <dl class="datos">
      <div><dt>Trámite</dt><dd>${comprobante.titulo}</dd></div>
      <div><dt>Fecha</dt><dd>${fechaHora(comprobante.en)}</dd></div>
      <div><dt>Confirmado con</dt><dd>Código TOTP verificado por el servicio soberano (jti ${comprobante.jti.slice(0, 8)}…)</dd></div>
    </dl>
    <div class="acciones">
      <a class="boton boton-primario" href="/panel">Volver a la oficina virtual</a>
      <button type="button" class="boton boton-secundario" data-imprimir>Imprimir comprobante</button>
    </div>
  </section>`;
}

export function paginaConsulta({ sesion }) {
  return html`
  ${migas([['Oficina virtual', '/panel'], ['Consulta de mis trámites']])}
  <section class="tarjeta">
    <h1>Consulta de mis trámites</h1>
    ${sesion.comprobantes.length === 0
    ? html`<p class="entradilla">No tiene trámites en esta sesión. Pruebe la solicitud de certificado o el cambio de datos bancarios.</p>`
    : html`<table class="tabla"><caption class="solo-lectores">Trámites de esta sesión</caption>
      <thead><tr><th scope="col">Folio</th><th scope="col">Trámite</th><th scope="col">Fecha</th><th scope="col">Estado</th></tr></thead>
      <tbody>${[...sesion.comprobantes].reverse().map((c) => html`<tr><td><code>${c.folio}</code></td><td>${c.titulo}</td><td>${fechaHora(c.en)}</td><td><span class="etiqueta etiqueta-ok">Completado</span></td></tr>`)}</tbody></table>`}
    <div class="acciones"><a class="boton boton-secundario" href="/panel">Volver</a></div>
  </section>`;
}

/** Centro de ayuda ciudadano con preguntas frecuentes sobre el segundo factor (Issue #53 · F6). */
export function paginaAyuda({ autenticado = false } = {}) {
  const destinoVolver = autenticado ? '/panel' : '/ingresar';
  const preguntas = [
    {
      q: '¿Qué es el segundo factor de autenticación (TOTP)?',
      a: 'Es un código temporal de 6 u 8 dígitos que cambia cada 30 segundos en su app autenticadora soberana. Incluso si alguien conociera su contraseña, no podría ingresar ni completar trámites sensibles sin este código generado en su propio dispositivo.',
    },
    {
      q: 'Perdí mi teléfono: ¿cómo uso los códigos de recuperación?',
      a: 'Al activar su segundo factor recibió 10 códigos de recuperación de un solo uso. En la pantalla de verificación pulse «Usar código de recuperación», ingrese uno de los códigos guardados y el portal le pedirá vincular de inmediato un nuevo dispositivo por seguridad.',
    },
    {
      q: 'Cambié de teléfono: ¿cómo traslado mi autenticador?',
      a: 'Si aún tiene acceso a su sesión o a un código de recuperación, desactive el factor anterior desde su oficina virtual o recupere el acceso, y luego escanee el nuevo código QR (o use el enlace directo o clave manual) desde el Autenticador Soberano en su teléfono nuevo.',
    },
    {
      q: 'El código no funciona: ¿qué debo revisar?',
      a: 'Los códigos TOTP dependen de la hora exacta. Verifique que la fecha, hora y zona horaria automática (America/Caracas) estén activadas en su teléfono. Además, cada código solo sirve una vez: si acaba de usarlo, espere al siguiente ciclo de 30 segundos.',
    },
    {
      q: '¿Cómo desactivar o renovar el segundo factor?',
      a: 'Ingrese a su oficina virtual y seleccione «Desactivar segundo factor» en la sección de seguridad. Por protección, el sistema le pedirá confirmar con un código TOTP vigente (step-up) antes de revocar el enrolamiento actual.',
    },
  ];
  return html`
    ${migas([['Centro de ayuda']])}
    <section class="tarjeta" id="ayuda" aria-labelledby="ayuda-titulo">
      <h1 id="ayuda-titulo">${icono('ayuda', 'icono')} Centro de ayuda sobre el segundo factor</h1>
      <p class="entradilla">Respuestas claras para enrolar, usar y recuperar su Autenticador Soberano TOTP.</p>
      ${preguntas.map((p, i) => html`
        <details ${i === 0 ? crudo('open') : ''}>
          <summary><strong>${p.q}</strong></summary>
          <p>${p.a}</p>
        </details>
      `)}
      <div class="acciones">
        <a class="boton boton-primario" href="${destinoVolver}">${autenticado ? 'Volver a la oficina virtual' : 'Ir a ingresar'}</a>
        <a class="boton boton-secundario" href="/recuperar">Tengo un código de recuperación</a>
      </div>
    </section>
  `;
}

export function paginaMensaje({ titulo, texto, tipo = 'info', enlace = '/', textoEnlace = 'Volver al inicio' }) {
  return html`<section class="tarjeta">${aviso(tipo, titulo, texto)}<a class="boton boton-secundario" href="${enlace}">${textoEnlace}</a></section>`;
}
