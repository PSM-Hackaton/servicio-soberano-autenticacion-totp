// Aplicaciones integradoras y su política TOTP: listado y edición validada con confirmación.
import { h, reemplazar, numero, decimal, tiempo, idUnico } from '../dom.js';
import { icono } from '../iconos.js';
import { api, mensajeDeError } from '../api.js';
import { cabeceraPagina, tarjeta, estadoError, esqueleto, insigniaEstado, vacio, abrirDialogo, notificar, botonConPermiso } from '../ui.js';

const ALGORITMOS = [
  { valor: 'SHA256', texto: 'SHA-256', ayuda: 'Recomendado' },
  { valor: 'SHA512', texto: 'SHA-512', ayuda: 'Máxima robustez' },
  { valor: 'SHA1', texto: 'SHA-1', ayuda: 'Solo heredado' },
];
const NOMBRE_ALG = { SHA256: 'SHA-256', SHA512: 'SHA-512', SHA1: 'SHA-1' };
const LIMITES = {
  periodo: { min: 15, max: 60, texto: 'Entre 15 y 60 segundos.' },
  ventana: { min: 0, max: 3, texto: 'Entre 0 y 3 pasos.' },
  max_intentos: { min: 3, max: 15, texto: 'Entre 3 y 15 intentos.' },
  umbral_riesgo_bloqueo: { min: 40, max: 100, texto: 'Entre 40 y 100.' },
};
const ETIQUETAS = {
  algoritmo: 'Algoritmo', digitos: 'Dígitos', periodo: 'Periodo', ventana: 'Ventana de tolerancia', max_intentos: 'Máximo de intentos',
  umbral_riesgo_bloqueo: 'Umbral de riesgo', modo_heuristica: 'Modo del detector', estado: 'Estado', permitir_sha1: 'Permitir SHA-1',
};
const formatoValor = (campo, v) => {
  if (campo === 'algoritmo') return NOMBRE_ALG[v] ?? v;
  if (campo === 'periodo') return `${v} s`;
  if (campo === 'ventana') return `±${v} pasos`;
  if (campo === 'modo_heuristica') return v === 'bloqueo' ? 'Bloqueo' : 'Monitorización';
  if (campo === 'estado') return v === 'activo' ? 'Activa' : 'Suspendida';
  if (campo === 'permitir_sha1') return v ? 'Sí' : 'No';
  if (campo === 'umbral_riesgo_bloqueo') return decimal(v, 0);
  return String(v);
};

export function montar(raiz, ctx) {
  const puedeEditar = ctx.puede('apps.editar');
  const zona = h('div', null, esqueleto(6));
  let apps = [];

  reemplazar(raiz,
    cabeceraPagina({ titulo: 'Aplicaciones integradoras', descripcion: 'Sistemas que consumen el servicio y la política TOTP que se les aplica.' }),
    puedeEditar ? null : h('p.aviso-rol', null, icono('candado'), `Tu rol (${ctx.sesion.rol}) permite consultar las políticas, no modificarlas.`),
    tarjeta({ titulo: 'Aplicaciones registradas', clase: 'tarjeta--tabla' }, zona));

  function fila(app) {
    const editar = botonConPermiso({ permitido: puedeEditar, motivo: ctx.motivo('apps.editar'), class: 'boton boton--secundario boton--compacto', 'aria-label': `Editar política de ${app.nombre}`, title: 'Editar política' }, icono('editar'), h('span.texto-accion', { text: 'Editar' }));
    editar.addEventListener('click', () => editarPolitica(app));
    return h('tr', null,
      h('td', { dataset: { etiqueta: 'Aplicación' } }, h('div.celda-principal.celda-principal--app', null, h('strong', { text: app.nombre }), h('code.tenue', { text: app.client_id }))),
      h('td', { dataset: { etiqueta: 'Código' } }, h('div.celda-codigo', null,
        h('span', { class: `chip${app.algoritmo === 'SHA1' ? ' chip--aviso' : ''}` }, app.algoritmo === 'SHA1' ? icono('aviso') : null, NOMBRE_ALG[app.algoritmo] ?? app.algoritmo),
        h('span.num', { text: `${app.digitos} díg. · ${app.periodo} s` }))),
      h('td', { dataset: { etiqueta: 'Verificación' } }, h('span.celda-codigo', { title: 'Ventana de tolerancia (pasos) y máximo de intentos fallidos' }, h('span.num', { text: `±${app.ventana} pasos` }), h('span.tenue', { text: '·' }), h('span.num', { text: `${numero(app.max_intentos)} intentos` }))),
      h('td.num', { dataset: { etiqueta: 'Umbral riesgo' } }, h('span.celda-barra', null, h('span.mini-barra.mini-barra--riesgo', { vars: { peso: (app.umbral_riesgo_bloqueo - 40) / 60 }, 'aria-hidden': 'true' }), decimal(app.umbral_riesgo_bloqueo, 0))),
      h('td', { dataset: { etiqueta: 'Detector' } }, insigniaEstado(app.modo_heuristica)),
      h('td', { dataset: { etiqueta: 'Estado' } }, insigniaEstado(app.estado, app.estado === 'activo' ? 'Activa' : 'Suspendida')),
      h('td', { dataset: { etiqueta: 'Actualizada' } }, tiempo(app.updated_at, { relativa: true })),
      h('td.celda-acciones', null, h('div.grupo-acciones', null, editar)));
  }

  function pintar() {
    reemplazar(zona, apps.length
      ? h('div.tabla-contenedor', null, h('table.tabla.tabla--apilable', null,
        h('caption.solo-lectores', { text: 'Aplicaciones integradoras y su política' }),
        h('thead', null, h('tr', null, ['Aplicación', 'Código', 'Verificación', 'Umbral riesgo', 'Detector', 'Estado', 'Actualizada'].map((t, i) => h('th', { scope: 'col', class: i === 3 ? 'num' : null, text: t })), h('th', null, h('span.solo-lectores', { text: 'Acciones' })))),
        h('tbody', null, apps.map(fila))))
      : vacio('Sin aplicaciones', 'Aún no se ha registrado ninguna aplicación integradora.'));
  }

  async function cargar() {
    try {
      apps = await api.apps();
      pintar();
    } catch (e) {
      if (e?.status !== 401) reemplazar(zona, estadoError(mensajeDeError(e), cargar));
    }
  }

  // ---------------------------------------------------------------- edición
  function editarPolitica(app, inicial = app) {
    const borrador = { ...inicial };
    const errores = new Map();

    const campoNumero = (campo, etiqueta, ayuda, sufijo) => {
      const id = idUnico(campo);
      const lim = LIMITES[campo];
      const input = h('input', { id, type: 'number', inputmode: 'numeric', min: lim.min, max: lim.max, step: 1, value: borrador[campo], required: true, 'aria-describedby': `${id}-ayuda ${id}-error` });
      const error = h('p.campo-error', { id: `${id}-error`, hidden: true });
      input.addEventListener('input', () => { borrador[campo] = input.value === '' ? NaN : Number(input.value); validarCampo(campo, input, error); });
      return h('div.campo', null, h('label', { for: id, text: etiqueta }),
        h('div.campo-con-sufijo', null, input, sufijo ? h('span.sufijo', { text: sufijo }) : null),
        h('p.ayuda', { id: `${id}-ayuda`, text: ayuda }), error);
    };

    function validarCampo(campo, input, error) {
      const v = borrador[campo];
      const lim = LIMITES[campo];
      const ok = Number.isInteger(v) && v >= lim.min && v <= lim.max;
      input.setAttribute('aria-invalid', String(!ok));
      error.hidden = ok;
      error.textContent = ok ? '' : `Valor no válido. ${lim.texto}`;
      if (ok) errores.delete(campo); else errores.set(campo, input);
      return ok;
    }

    const segmentado = (nombre, leyenda, opciones, alCambiar) => h('fieldset.segmentado', null,
      h('legend', { text: leyenda }),
      h('div.segmentado-opciones', null, opciones.map((o) => {
        const id = idUnico(nombre);
        const radio = h('input', { type: 'radio', name: nombre, id, value: o.valor, checked: String(borrador[nombre]) === String(o.valor) });
        radio.addEventListener('change', () => { borrador[nombre] = typeof borrador[nombre] === 'number' ? Number(o.valor) : o.valor; alCambiar?.(); });
        return h('label.segmentado-opcion', { for: id }, radio, h('span.segmentado-texto', null, h('strong', { text: o.texto }), o.ayuda ? h('small', { text: o.ayuda }) : null));
      })));

    // Advertencia SHA-1
    const idSha1 = idUnico('sha1');
    const casillaSha1 = h('input', { type: 'checkbox', id: idSha1, checked: borrador.permitir_sha1 });
    const errorSha1 = h('p.campo-error', { hidden: true, text: 'Debes confirmar que comprendes el riesgo para usar SHA-1.' });
    casillaSha1.addEventListener('change', () => { borrador.permitir_sha1 = casillaSha1.checked; errorSha1.hidden = true; });
    const avisoSha1 = h('div.alerta.alerta--aviso', { role: 'note' }, icono('aviso'),
      h('div', null,
        h('p', null, h('strong', { text: 'SHA-1 se considera obsoleto. ' }), 'Úsalo solo para autenticadores heredados que no admitan SHA-256. Los nuevos enrolamientos de esta aplicación quedarían con una garantía criptográfica menor.'),
        h('label.casilla-linea', { for: idSha1 }, casillaSha1, 'Entiendo el riesgo y autorizo SHA-1 para esta aplicación'),
        errorSha1));
    const actualizarSha1 = () => { avisoSha1.hidden = borrador.algoritmo !== 'SHA1'; };
    actualizarSha1();

    const idUmbral = idUnico('umbral');
    const salidaUmbral = h('output.salida-rango.num', { for: idUmbral, text: decimal(borrador.umbral_riesgo_bloqueo, 0) });
    const rango = h('input', { type: 'range', id: idUmbral, min: 40, max: 100, step: 1, value: borrador.umbral_riesgo_bloqueo, 'aria-describedby': `${idUmbral}-ayuda` });
    rango.addEventListener('input', () => { borrador.umbral_riesgo_bloqueo = Number(rango.value); salidaUmbral.textContent = rango.value; });

    const formulario = h('form.formulario.formulario--politica', { novalidate: true },
      h('p.dialogo-intro', null, h('strong', { text: app.nombre }), ' · ', h('code', { text: app.client_id })),
      h('div.grupo-form', null,
        h('h3.grupo-titulo', { text: 'Generación del código' }),
        segmentado('algoritmo', 'Algoritmo HMAC', ALGORITMOS, actualizarSha1),
        avisoSha1,
        h('div.rejilla-campos', null,
          segmentado('digitos', 'Dígitos', [{ valor: 6, texto: '6' }, { valor: 8, texto: '8' }]),
          campoNumero('periodo', 'Periodo', 'Duración de cada código.', 's')),
        h('p.ayuda', { text: 'Algoritmo, dígitos y periodo se aplican a los nuevos enrolamientos; los existentes conservan su configuración.' })),
      h('div.grupo-form', null,
        h('h3.grupo-titulo', { text: 'Verificación y bloqueo' }),
        h('div.rejilla-campos', null,
          campoNumero('ventana', 'Ventana de tolerancia', 'Pasos aceptados antes y después del actual.', '± pasos'),
          campoNumero('max_intentos', 'Máximo de intentos', 'Fallos antes del bloqueo progresivo.', 'intentos')),
        h('div.campo', null,
          h('label', { for: idUmbral }, 'Umbral de riesgo para bloqueo ', salidaUmbral),
          rango,
          h('p.ayuda', { id: `${idUmbral}-ayuda`, text: 'Puntaje del detector (0–100) a partir del cual se bloquea el intento. Más bajo = más estricto.' })),
        segmentado('modo_heuristica', 'Modo del detector de anomalías', [
          { valor: 'monitorizacion', texto: 'Monitorización', ayuda: 'Registra y alerta, no bloquea' },
          { valor: 'bloqueo', texto: 'Bloqueo', ayuda: 'Bloquea al superar el umbral' },
        ]),
        segmentado('estado', 'Estado de la aplicación', [
          { valor: 'activo', texto: 'Activa', ayuda: 'Acepta solicitudes' },
          { valor: 'suspendido', texto: 'Suspendida', ayuda: 'Rechaza todas las solicitudes' },
        ])));

    const cancelar = h('button.boton.boton--secundario', { type: 'button', text: 'Cancelar' });
    const revisar = h('button.boton.boton--primario', { type: 'button', text: 'Revisar cambios' });
    const cerrar = abrirDialogo({ titulo: 'Editar política', contenido: formulario, pie: [cancelar, revisar], ancho: 'ancho' });
    cancelar.addEventListener('click', cerrar);
    formulario.addEventListener('submit', (e) => { e.preventDefault(); revisar.click(); });

    revisar.addEventListener('click', () => {
      for (const input of formulario.querySelectorAll('input[type="number"]')) input.dispatchEvent(new Event('input'));
      if (borrador.algoritmo === 'SHA1' && !borrador.permitir_sha1) { errorSha1.hidden = false; casillaSha1.focus(); return; }
      if (errores.size) { [...errores.values()][0].focus(); return; }
      if (borrador.algoritmo !== 'SHA1' && app.algoritmo !== 'SHA1') borrador.permitir_sha1 = app.permitir_sha1;
      const cambios = {};
      for (const campo of Object.keys(ETIQUETAS)) if (borrador[campo] !== app[campo]) cambios[campo] = borrador[campo];
      if (!Object.keys(cambios).length) { notificar('No hay cambios que guardar.', 'info', 2500); return; }
      confirmarCambios(app, cambios, () => editarPolitica(app, { ...borrador }));
    });
  }

  function confirmarCambios(app, cambios, volver) {
    const base = app;
    const filas = Object.entries(cambios).map(([campo, valor]) => h('tr', null,
      h('th', { scope: 'row', text: ETIQUETAS[campo] }),
      h('td.tachado', { text: formatoValor(campo, base[campo]) }),
      h('td', null, h('strong', { text: formatoValor(campo, valor) }))));
    const criticos = ['estado', 'algoritmo', 'modo_heuristica'].some((c) => c in cambios);
    const atras = h('button.boton.boton--secundario', { type: 'button', text: 'Volver' });
    const aplicar = h('button.boton.boton--primario', { type: 'button', text: 'Aplicar cambios' });
    const cerrar = abrirDialogo({
      titulo: 'Confirmar cambios de política',
      contenido: [
        h('p', null, 'Se modificará la política de ', h('strong', { text: app.nombre }), '. El cambio queda registrado en la bitácora de auditoría.'),
        h('table.tabla.tabla--compacta.tabla--cambios', null,
          h('thead', null, h('tr', null, h('th', { scope: 'col', text: 'Campo' }), h('th', { scope: 'col', text: 'Actual' }), h('th', { scope: 'col', text: 'Nuevo' }))),
          h('tbody', null, filas)),
        criticos ? h('div.alerta.alerta--aviso', null, icono('aviso'), h('p', { text: cambios.estado === 'suspendido' ? 'Suspender la aplicación rechazará de inmediato todas sus verificaciones.' : 'Este cambio afecta a la seguridad de la aplicación. Revísalo antes de aplicarlo.' })) : null,
      ],
      pie: [atras, aplicar],
    });
    atras.addEventListener('click', () => { cerrar(); volver(); });
    aplicar.addEventListener('click', async () => {
      aplicar.disabled = true;
      aplicar.replaceChildren(h('span.spinner.spinner--claro', { 'aria-hidden': 'true' }), 'Aplicando…');
      try {
        const actualizada = await api.actualizarApp(app.id, cambios);
        const i = apps.findIndex((a) => a.id === app.id);
        if (i >= 0) apps[i] = { ...apps[i], ...cambios, ...actualizada, updated_at: actualizada.updated_at ?? new Date().toISOString() };
        cerrar();
        pintar();
        notificar(`Política de «${app.nombre}» actualizada.`, 'ok');
      } catch (e) {
        aplicar.disabled = false;
        aplicar.textContent = 'Aplicar cambios';
        notificar(mensajeDeError(e), e?.status === 403 ? 'aviso' : 'peligro');
      }
    });
  }

  cargar();
  return { refrescar: cargar };
}
