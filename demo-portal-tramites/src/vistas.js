// Vistas del Portal de Trámites (HTML renderizado en el servidor; sin estilos ni scripts en línea).

import { html, crudo } from './html.js';
import { TRAMITES } from './tramites.js';

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
  const items = ['Usuario y contraseña', segundo, 'Acceso a trámites'];
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

/**
 * @param {{ titulo: string, sesion: any, usuario?: any, contenido: any, ancho?: 'estrecho' | 'amplio', ruta: string }} o
 */
export function layout({ titulo, sesion, usuario, contenido, ancho = 'estrecho', ruta }) {
  const conTrazas = sesion.trazasVisibles;
  return `<!doctype html>${html`
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>${titulo} · Portal de Trámites del Estado</title>
<link rel="icon" href="/publico/emblema.svg" type="image/svg+xml">
<link rel="stylesheet" href="/publico/estilos.css">
<script src="/publico/app.js" defer></script>
</head>
<body>
<a class="saltar" href="#contenido">Saltar al contenido</a>
<div class="franja-demo"><div class="contenedor">Sitio de demostración. Institución, personas y datos son ficticios.</div></div>
<header class="cabecera">
  <div class="contenedor cabecera-fila">
    <a class="marca" href="/" aria-label="Portal de Trámites del Estado, inicio">
      <img class="marca-emblema" src="/publico/emblema.svg" alt="" width="40" height="40">
      <span class="marca-texto"><strong>Portal de Trámites</strong><span>del Estado</span></span>
    </a>
    <div class="cabecera-acciones">
      <form method="post" action="/trazas" class="form-en-linea">
        ${csrf(sesion)}<input type="hidden" name="volver" value="${ruta}">
        <button type="submit" class="boton-trazas" aria-pressed="${conTrazas ? 'true' : 'false'}">
          <span class="interruptor" aria-hidden="true"></span><span>Lo que ocurre por dentro</span>
        </button>
      </form>
      ${usuario && sesion.etapa !== 'anonima' ? html`
      <form method="post" action="/salir" class="form-en-linea">
        ${csrf(sesion)}
        <button type="submit" class="boton boton-secundario boton-chico">Salir</button>
      </form>` : ''}
    </div>
  </div>
</header>
<div class="contenedor disposicion ${conTrazas ? 'con-trazas' : ''}">
  <main id="contenido" class="principal principal-${ancho}" tabindex="-1">
    ${contenido}
  </main>
  ${conTrazas ? panelTrazas(sesion) : ''}
</div>
<footer class="pie">
  <div class="contenedor pie-fila">
    <p>Portal de Trámites del Estado · Demostración de integración con el Servicio Soberano de Autenticación TOTP.</p>
    <p>Sin rastreadores ni recursos externos. El segundo factor se verifica en un servicio propio, en infraestructura local.</p>
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

export function paginaIngresar({ sesion, error, usuario = '', demo = [] }) {
  return html`
  ${pasos(1)}
  <section class="tarjeta">
    <h1>Ingresar al portal</h1>
    <p class="entradilla">Acceda con su usuario y contraseña. Después le pediremos un código de su app autenticadora.</p>
    ${error ? aviso(error.tipo ?? 'error', error.titulo, error.texto) : ''}
    ${sesion.aviso ? aviso(sesion.aviso.tipo, sesion.aviso.texto, null) : ''}
    <form method="post" action="/ingresar" class="formulario" data-un-envio>
      ${csrf(sesion)}
      <div class="campo">
        <label for="usuario">Usuario</label>
        <input id="usuario" name="usuario" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="64" value="${usuario}">
      </div>
      <div class="campo">
        <label for="contrasena">Contraseña</label>
        <input id="contrasena" name="contrasena" type="password" autocomplete="current-password" required maxlength="128">
      </div>
      <button type="submit" class="boton boton-primario boton-ancho">Continuar</button>
    </form>
  </section>
  ${demo.length ? html`
  <section class="tarjeta tarjeta-suave" aria-labelledby="demo-titulo">
    <h2 id="demo-titulo" class="titulo-chico">Cuentas de demostración</h2>
    <p class="ayuda">Personas ficticias. Contraseña de todas: <code>Tramites-Demo-2026</code></p>
    <ul class="lista-demo">${demo.map((u) => html`<li><code>${u.usuario}</code><span>${u.nombre}</span><span class="etiqueta ${u.conFactor ? 'etiqueta-ok' : ''}">${u.conFactor ? 'Con segundo factor' : 'Sin segundo factor'}</span></li>`)}</ul>
  </section>` : ''}`;
}

export function paginaEnrolar({ sesion, usuario, enrolamiento, resultado, autenticadorUrl, errorServicio }) {
  if (errorServicio) {
    return html`${pasos(2, 'Vincular autenticador')}
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
  return html`
  <section class="bienvenida">
    <div>
      <p class="sobretitulo">Área personal</p>
      <h1>Hola, ${usuario.nombre}</h1>
      <p class="entradilla">Documento ${usuario.documento} · Sesión protegida con verificación en dos pasos.</p>
    </div>
    <dl class="estado-sesion">
      <div><dt>Segundo factor</dt><dd>${icono('escudo', 'icono icono-chico')} Verificado a las ${hora(mfa.en)}</dd></div>
      <div><dt>Método</dt><dd>${(mfa.amr ?? []).join(', ').toUpperCase() || 'OTP'} · firma EdDSA</dd></div>
      <div><dt>Constancia</dt><dd>${mfa.modo}</dd></div>
    </dl>
  </section>
  ${sesion.aviso ? aviso(sesion.aviso.tipo, sesion.aviso.texto, null) : ''}
  <section aria-labelledby="tramites-titulo">
    <h2 id="tramites-titulo" class="titulo-seccion">Trámites disponibles</h2>
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
  </section>`;
}

export function paginaTramite({ sesion, tramite, resultado, error, valores = {} }) {
  return html`
  <nav class="migas" aria-label="Ruta"><a href="/panel">Área personal</a><span aria-hidden="true">›</span><span>${tramite.titulo}</span></nav>
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
  <nav class="migas" aria-label="Ruta"><a href="/panel">Área personal</a><span aria-hidden="true">›</span><span>Comprobante</span></nav>
  <section class="tarjeta comprobante">
    ${aviso('exito', 'Trámite completado', comprobante.mensaje)}
    <h1>Comprobante ${comprobante.folio}</h1>
    <dl class="datos">
      <div><dt>Trámite</dt><dd>${comprobante.titulo}</dd></div>
      <div><dt>Fecha</dt><dd>${fechaHora(comprobante.en)}</dd></div>
      <div><dt>Confirmado con</dt><dd>Código TOTP verificado por el servicio soberano (jti ${comprobante.jti.slice(0, 8)}…)</dd></div>
    </dl>
    <div class="acciones">
      <a class="boton boton-primario" href="/panel">Volver al área personal</a>
      <button type="button" class="boton boton-secundario" data-imprimir>Imprimir comprobante</button>
    </div>
  </section>`;
}

export function paginaConsulta({ sesion }) {
  return html`
  <nav class="migas" aria-label="Ruta"><a href="/panel">Área personal</a><span aria-hidden="true">›</span><span>Consulta de mis trámites</span></nav>
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

export function paginaMensaje({ titulo, texto, tipo = 'info', enlace = '/', textoEnlace = 'Volver al inicio' }) {
  return html`<section class="tarjeta">${aviso(tipo, titulo, texto)}<a class="boton boton-secundario" href="${enlace}">${textoEnlace}</a></section>`;
}
