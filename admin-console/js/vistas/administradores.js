// Cuentas de la consola (solo Administrador): listado, alta con contraseña aleatoria y TOTP propio
// (entregados una sola vez) y deshabilitación. El servidor impide deshabilitar la propia cuenta y
// al último Administrador activo, y cierra las sesiones de la cuenta deshabilitada.
import { h, reemplazar, tiempo, idUnico } from '../dom.js';
import { icono } from '../iconos.js';
import { api, mensajeDeError } from '../api.js';
import { ROLES, DESCRIPCION_ROL } from '../rbac.js';
import { cabeceraPagina, tarjeta, estadoError, esqueleto, insigniaEstado, vacio, abrirDialogo, notificar, botonConPermiso, confirmar, mostrarUnaVez } from '../ui.js';

const RE_USUARIO = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const TEXTO_TOTP = { activo: 'Activo', suspendido: 'Suspendido', revocado: 'Revocado', pendiente: 'Pendiente', sin_totp: 'Sin factor' };

/** Imagen del QR a partir del SVG del servidor, como data: URI (sin insertar marcado en el documento). */
function imagenQr(svg, usuario) {
  const bytes = new TextEncoder().encode(String(svg));
  let binario = '';
  for (const b of bytes) binario += String.fromCharCode(b);
  return h('img.qr-totp', { src: `data:image/svg+xml;base64,${btoa(binario)}`, alt: `Código QR del factor TOTP de ${usuario}`, width: 200, height: 200 });
}

export function montar(raiz, ctx) {
  const puedeEditar = ctx.puede('admins.editar');
  const zona = h('div', null, esqueleto(5));
  let admins = [];

  const crear = botonConPermiso({ permitido: puedeEditar, motivo: ctx.motivo('admins.editar'), class: 'boton boton--primario' }, icono('usuario'), h('span', { text: 'Crear administrador' }));
  crear.addEventListener('click', () => crearCuenta());

  reemplazar(raiz,
    cabeceraPagina({ titulo: 'Administradores', descripcion: 'Cuentas de la consola. Cada una entra con contraseña y su propio factor TOTP.', acciones: [crear] }),
    tarjeta({ titulo: 'Cuentas registradas', clase: 'tarjeta--tabla' }, zona));

  const activosAdministrador = () => admins.filter((a) => a.activo && a.rol === 'Administrador').length;

  function fila(a) {
    const esYo = a.usuario === ctx.sesion.usuario;
    const ultimo = a.rol === 'Administrador' && a.activo && activosAdministrador() <= 1;
    const motivo = !a.activo ? 'La cuenta ya está deshabilitada' : esYo ? 'No puedes deshabilitar tu propia cuenta' : ultimo ? 'Es el último Administrador activo' : ctx.motivo('admins.editar');
    const deshabilitar = botonConPermiso({
      permitido: puedeEditar && a.activo && !esYo && !ultimo, motivo,
      class: 'boton boton--fantasma-peligro boton--compacto', 'aria-label': `Deshabilitar la cuenta ${a.usuario}`, title: 'Deshabilitar',
    }, icono('candado'), h('span.texto-accion', { text: 'Deshabilitar' }));
    deshabilitar.addEventListener('click', () => deshabilitarCuenta(a));
    return h('tr', { class: a.activo ? null : 'fila-apagada' },
      h('td', { dataset: { etiqueta: 'Usuario' } }, h('div.celda-principal', null, h('strong', { text: a.usuario }), esYo ? h('span.tenue.texto-pequeno', { text: 'Tu cuenta' }) : null)),
      h('td', { dataset: { etiqueta: 'Rol' } }, h('span', { class: `insignia insignia--rol insignia--${a.rol.toLowerCase()}`, text: a.rol })),
      h('td', { dataset: { etiqueta: 'Estado' } }, insigniaEstado(a.activo ? 'activo' : 'revocado', a.activo ? 'Activa' : 'Deshabilitada')),
      h('td', { dataset: { etiqueta: 'Factor TOTP' } }, insigniaEstado(a.totp_estado, TEXTO_TOTP[a.totp_estado] ?? a.totp_estado)),
      h('td', { dataset: { etiqueta: 'Creada' } }, tiempo(a.created_at, { corta: true })),
      h('td.celda-acciones', null, h('div.grupo-acciones', null, deshabilitar)));
  }

  function pintar() {
    reemplazar(zona, admins.length
      ? h('div.tabla-contenedor', null, h('table.tabla.tabla--apilable', null,
        h('caption.solo-lectores', { text: 'Cuentas de la consola administrativa' }),
        h('thead', null, h('tr', null, ['Usuario', 'Rol', 'Estado', 'Factor TOTP', 'Creada'].map((t) => h('th', { scope: 'col', text: t })), h('th', null, h('span.solo-lectores', { text: 'Acciones' })))),
        h('tbody', null, admins.map(fila))))
      : vacio('Sin cuentas', 'No hay cuentas registradas.'));
  }

  async function cargar() {
    try {
      admins = await api.administradores();
      pintar();
    } catch (e) {
      if (e?.status !== 401) reemplazar(zona, estadoError(mensajeDeError(e), cargar));
    }
  }

  function crearCuenta() {
    const datos = { usuario: '', rol: 'Operador' };
    const idUsuario = idUnico('usuario');
    const usuario = h('input', { id: idUsuario, type: 'text', required: true, maxlength: 32, autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', 'aria-describedby': `${idUsuario}-ayuda ${idUsuario}-error` });
    const error = h('p.campo-error', { id: `${idUsuario}-error`, hidden: true, text: 'De 3 a 32 caracteres: minúsculas, números y . _ - (empieza por letra o número).' });
    const nombreRol = idUnico('rol');
    const roles = h('fieldset.segmentado', null, h('legend', { text: 'Rol' }),
      h('div.segmentado-opciones', null, ROLES.map((rol) => {
        const id = idUnico('rol');
        const radio = h('input', { type: 'radio', name: nombreRol, id, value: rol, checked: rol === datos.rol });
        radio.addEventListener('change', () => { datos.rol = rol; });
        return h('label.segmentado-opcion', { for: id }, radio, h('span.segmentado-texto', null, h('strong', { text: rol }), h('small', { text: DESCRIPCION_ROL[rol] })));
      })));
    const formulario = h('form.formulario', { novalidate: true },
      h('div.campo', null, h('label', { for: idUsuario, text: 'Usuario' }), usuario,
        h('p.ayuda', { id: `${idUsuario}-ayuda`, text: 'Identificador de acceso. No se puede cambiar después.' }), error),
      roles,
      h('div.alerta.alerta--info', { role: 'note' }, icono('info'),
        h('p', null, 'El servicio genera una contraseña aleatoria y un factor TOTP propio, ya activo. Se muestran una sola vez: entrégalos al titular por un canal separado. Su primer inicio de sesión (contraseña y código) confirma que el factor quedó bien instalado.')));
    const cancelar = h('button.boton.boton--secundario', { type: 'button', text: 'Cancelar' });
    const enviar = h('button.boton.boton--primario', { type: 'button', text: 'Crear cuenta' });
    const cerrar = abrirDialogo({ titulo: 'Crear administrador', contenido: formulario, pie: [cancelar, enviar] });
    cancelar.addEventListener('click', cerrar);
    usuario.focus();

    const enviarFormulario = async () => {
      datos.usuario = usuario.value.trim();
      const ok = RE_USUARIO.test(datos.usuario);
      usuario.setAttribute('aria-invalid', String(!ok));
      error.hidden = ok;
      if (!ok) { usuario.focus(); return; }
      enviar.disabled = true;
      enviar.replaceChildren(h('span.spinner.spinner--claro', { 'aria-hidden': 'true' }), 'Creando…');
      try {
        const r = await api.crearAdministrador(datos.usuario, datos.rol);
        admins.push(r.admin);
        pintar();
        cerrar();
        mostrarUnaVez({
          titulo: 'Cuenta creada',
          intro: h('p', null, 'Datos de acceso de ', h('strong', { text: r.admin.usuario }), ' (', r.admin.rol, '). El código TOTP del minuto de alta ya se usó: el primer inicio de sesión debe esperar al siguiente código.'),
          datos: [
            { etiqueta: 'Usuario', valor: r.admin.usuario },
            { etiqueta: 'Contraseña inicial', valor: r.password },
            { etiqueta: 'URI otpauth', valor: r.otpauth_uri },
          ],
          extra: r.qr_svg ? h('figure.qr-figura', null, imagenQr(r.qr_svg, r.admin.usuario), h('figcaption.ayuda', { text: 'Escanéalo con la aplicación autenticadora del titular.' })) : null,
        });
        notificar(`Cuenta «${r.admin.usuario}» creada.`, 'ok');
      } catch (e) {
        enviar.disabled = false;
        enviar.textContent = 'Crear cuenta';
        if (e?.status === 409) { error.textContent = mensajeDeError(e); error.hidden = false; usuario.setAttribute('aria-invalid', 'true'); usuario.focus(); return; }
        notificar(mensajeDeError(e), e?.status === 403 ? 'aviso' : 'peligro');
      }
    };
    formulario.addEventListener('submit', (e) => { e.preventDefault(); enviarFormulario(); });
    enviar.addEventListener('click', enviarFormulario);
  }

  async function deshabilitarCuenta(a) {
    const ok = await confirmar({
      titulo: 'Deshabilitar cuenta',
      mensaje: h('p', null, 'La cuenta ', h('strong', { text: a.usuario }), ' no podrá volver a iniciar sesión y sus sesiones abiertas se cerrarán de inmediato.'),
      confirmar: 'Deshabilitar',
      tono: 'peligro',
    });
    if (!ok) return;
    try {
      const r = await api.deshabilitarAdministrador(a.id);
      Object.assign(a, { activo: false, ...(r.id ? r : {}) });
      pintar();
      notificar(`Cuenta «${a.usuario}» deshabilitada.`, 'ok');
    } catch (e) {
      notificar(mensajeDeError(e), e?.status === 403 || e?.status === 409 ? 'aviso' : 'peligro');
    }
  }

  cargar();
  return { refrescar: cargar };
}
