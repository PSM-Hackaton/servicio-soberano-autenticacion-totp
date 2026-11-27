// Bitácora de auditoría encadenada: tabla paginada, verificación de integridad en el servidor,
// verificación independiente en el navegador (Web Crypto) y ancla local del último hash para
// detectar el borrado de los registros finales (lo que la cadena por sí sola no puede ver).
import { h, reemplazar, numero, fecha, tiempo, almacen } from '../dom.js';
import { icono } from '../iconos.js';
import { api, mensajeDeError, esMock } from '../api.js';
import { cabeceraPagina, tarjeta, estadoError, esqueleto, vacio, notificar, confirmar, botonConPermiso, valorHash } from '../ui.js';
import { verificarFilas, hayWebCrypto, HASH_GENESIS } from '../cadena.js';

const POR_PAGINA = 20;
const LOTE = 500;
const MAX_REGISTROS_LOCAL = 20_000;
const CLAVE_ANCLA = `consola.auditoria.ancla${esMock ? '.demo' : ''}`;

const ACCIONES = {
  'servicio.arranque': 'Arranque del servicio',
  'admin.login': 'Inicio de sesión administrativo',
  'admin.logout': 'Cierre de sesión administrativo',
  'admin.login_fallido': 'Inicio de sesión rechazado',
  'app.crear': 'Alta de aplicación',
  'app.registrada': 'Alta de aplicación',
  'app.politica': 'Cambio de política',
  'app.politica_actualizada': 'Cambio de política',
  'enrolamiento.creado': 'Enrolamiento creado',
  'enrolamiento.activado': 'Enrolamiento activado',
  'enrolamiento.bloqueado': 'Enrolamiento bloqueado',
  'enrolamiento.resincronizado': 'Reloj resincronizado',
  'enrolamiento.revocado': 'Enrolamiento revocado',
  'recuperacion.aceptada': 'Código de recuperación usado',
  'recuperacion.fallida': 'Recuperación rechazada',
  'token.reutilizado': 'Token reutilizado',
  'verificacion.exitosa': 'Verificación correcta',
  'verificacion.alerta': 'Alerta del detector',
  'verificacion.bloqueo': 'Bloqueo progresivo',
  'verificacion.anomalia_bloqueada': 'Bloqueo del detector',
  'llaves.rotadas': 'Rotación de llave',
  'enrolamiento.crear': 'Enrolamiento creado',
  'enrolamiento.activar': 'Enrolamiento activado',
  'enrolamiento.suspender': 'Enrolamiento suspendido',
  'enrolamiento.reactivar': 'Enrolamiento reactivado',
  'enrolamiento.revocar': 'Enrolamiento revocado',
  'verificacion.replay': 'Repetición bloqueada',
  'anomalia.bloqueo': 'Bloqueo del detector',
  'anomalia.alerta': 'Alerta del detector',
  'llave.rotar': 'Rotación de llave',
  'auditoria.verificar': 'Verificación de la cadena',
};
const tonoAccion = (a) => (/anomalia(_bloqueada|\.bloqueo)|replay|revoc|reutilizado/.test(a) ? 'peligro' : /anomalia|alerta|suspend|fallid|bloque/.test(a) ? 'aviso' : /^llave|^app\./.test(a) ? 'acento' : 'neutro');

function detalleLegible(detalle) {
  if (detalle === null || detalle === undefined || detalle === '') return h('span.tenue', { text: '—' });
  let obj = detalle;
  if (typeof detalle === 'string') {
    try { obj = JSON.parse(detalle); } catch { return h('span.detalle-texto', { text: detalle }); }
  }
  if (!obj || typeof obj !== 'object') return h('span.detalle-texto', { text: String(obj) });
  return h('span.detalle-pares', null, Object.entries(obj).slice(0, 4).map(([k, v]) => h('span.par', null, h('span.par-clave', { text: k }), h('span.par-valor', { text: typeof v === 'object' ? JSON.stringify(v) : String(v) }))));
}

export function montar(raiz, ctx) {
  const puedeVerificar = ctx.puede('auditoria.verificar');
  let cursores = [0];
  let total = null;
  let eventos = [];
  let verificacionLocal = null;
  let verificando = false;

  const zonaIntegridad = h('div');
  const zonaTabla = h('div', null, esqueleto(8));
  const resumen = h('p.resumen-tabla', { role: 'status' });
  const botonVerificar = botonConPermiso({ permitido: puedeVerificar, motivo: ctx.motivo('auditoria.verificar'), class: 'boton boton--primario' }, icono('escudo'), h('span', { text: 'Verificar integridad de la cadena' }));
  botonVerificar.addEventListener('click', () => verificar());

  reemplazar(raiz,
    cabeceraPagina({ titulo: 'Auditoría', descripcion: 'Bitácora inmutable encadenada por hashes SHA-256: cada registro incluye el hash del anterior.', acciones: [botonVerificar] }),
    tarjeta({ titulo: 'Integridad de la cadena', clase: 'tarjeta--integridad' }, zonaIntegridad),
    tarjeta({ titulo: 'Registros de la bitácora', clase: 'tarjeta--tabla' }, resumen, zonaTabla));

  // ---------------------------------------------------------------- integridad
  function pintarIntegridadInicial() {
    const ancla = almacen.leer(CLAVE_ANCLA);
    reemplazar(zonaIntegridad,
      h('div.integridad.integridad--neutra', null,
        h('span.integridad-icono', null, icono('cadena')),
        h('div.integridad-texto', null,
          h('p.integridad-titulo', { text: 'Sin verificar en esta sesión' }),
          h('p', { text: 'La verificación recalcula todos los hashes en el servidor y, de forma independiente, en este navegador.' }),
          ancla ? h('p.tenue', null, 'Ancla local: ', h('code', { title: ancla.last_hash, text: `${ancla.last_hash.slice(0, 16)}…` }), ` · ${numero(ancla.registros)} registros · guardada el ${fecha(ancla.fecha)}`) : h('p.tenue', { text: 'Aún no hay un ancla local guardada en este navegador.' }))));
  }

  /** Descarga la cadena completa por lotes para verificarla en el navegador. */
  async function descargarTodo(alProgreso) {
    const filas = [];
    let desde = 0;
    while (filas.length < MAX_REGISTROS_LOCAL) {
      const { eventos: lote } = await api.auditoria({ desde, limite: LOTE });
      filas.push(...lote);
      alProgreso(filas.length);
      if (lote.length < LOTE) break;
      desde = lote[lote.length - 1].id;
    }
    return filas;
  }

  async function verificar() {
    if (verificando) return;
    verificando = true;
    botonVerificar.disabled = true;
    const progreso = h('span', { text: 'Consultando al servidor…' });
    reemplazar(zonaIntegridad, h('div.integridad.integridad--neutra', { role: 'status' }, h('span.spinner', { 'aria-hidden': 'true' }), h('div.integridad-texto', null, h('p.integridad-titulo', { text: 'Verificando la cadena…' }), h('p', null, progreso))));
    try {
      const servidor = await api.verificarCadena();
      let local = null;
      let filas = null;
      if (hayWebCrypto()) {
        progreso.textContent = 'Descargando registros para la verificación independiente…';
        filas = await descargarTodo((n) => { progreso.textContent = `Recalculando hashes en el navegador (${numero(n)} registros)…`; });
        const desdeGenesis = filas[0]?.id === 1 || filas[0]?.prev_hash === HASH_GENESIS;
        local = { ...(await verificarFilas(filas, desdeGenesis ? HASH_GENESIS : null)), total: filas.length };
        verificacionLocal = local.porFila;
      }
      const ancla = evaluarAncla(servidor, filas);
      pintarResultado(servidor, local, ancla);
      pintarTabla();
    } catch (e) {
      if (e?.status !== 401) reemplazar(zonaIntegridad, estadoError(mensajeDeError(e), () => verificar()));
    } finally {
      verificando = false;
      botonVerificar.disabled = !puedeVerificar;
    }
  }

  /**
   * Compara con el ancla local (último hash verificado antes):
   *  - igual: no se añadió ni eliminó nada;
   *  - presente en la cadena: la cadena creció; se actualiza el ancla;
   *  - ausente: se eliminaron o reescribieron registros finales.
   */
  function evaluarAncla(servidor, filas) {
    const ancla = almacen.leer(CLAVE_ANCLA);
    const nueva = { last_hash: servidor.ultimoHash, registros: servidor.registros, fecha: new Date().toISOString() };
    if (!servidor.intacta || !servidor.ultimoHash) return { tipo: 'omitida', ancla };
    if (!ancla) {
      almacen.escribir(CLAVE_ANCLA, nueva);
      return { tipo: 'creada', ancla: nueva };
    }
    if (ancla.last_hash === servidor.ultimoHash) {
      almacen.escribir(CLAVE_ANCLA, { ...ancla, fecha: nueva.fecha });
      return { tipo: 'coincide', ancla };
    }
    const encontrada = filas?.find((f) => f.hash === ancla.last_hash);
    if (encontrada || (!filas && servidor.registros > ancla.registros)) {
      almacen.escribir(CLAVE_ANCLA, nueva);
      return { tipo: 'crecio', ancla, enId: encontrada?.id, nuevos: servidor.registros - (ancla.registros ?? 0) };
    }
    return { tipo: 'ausente', ancla, actual: nueva };
  }

  function pintarResultado(servidor, local, ancla) {
    const integra = servidor.intacta && (!local || local.intacta);
    const truncada = ancla.tipo === 'ausente';
    const tono = !integra || truncada ? 'peligro' : 'ok';
    const titulo = !servidor.intacta
      ? `Cadena rota en el registro #${servidor.rotaEnId ?? '?'}`
      : local && !local.intacta ? `Discrepancia: el navegador detecta una ruptura en el registro #${local.rotaEnId}`
        : truncada ? 'Posible eliminación de los últimos registros' : 'Cadena íntegra';

    const lineas = [
      h('li', { class: servidor.intacta ? 'ok' : 'fallo' }, icono(servidor.intacta ? 'ok' : 'error'),
        h('span', null, h('strong', { text: 'Servidor: ' }), servidor.intacta ? `íntegra, ${numero(servidor.registros)} registros verificados.` : `ruptura en el registro #${servidor.rotaEnId} (${numero(servidor.registros)} revisados).`)),
      local ? h('li', { class: local.intacta ? 'ok' : 'fallo' }, icono(local.intacta ? 'ok' : 'error'),
        h('span', null, h('strong', { text: 'Este navegador: ' }), local.intacta ? `${numero(local.total)} hashes recalculados con SHA-256; coinciden.` : `el registro #${local.rotaEnId} no coincide con su hash.`))
        : h('li.neutro', null, icono('info'), h('span', { text: 'Verificación en el navegador no disponible (requiere HTTPS).' })),
    ];
    const a = ancla;
    if (a.tipo === 'creada') lineas.push(h('li.ok', null, icono('cadena'), h('span', null, h('strong', { text: 'Ancla local: ' }), 'guardada. En la próxima verificación se detectará si desaparecen registros finales.')));
    if (a.tipo === 'coincide') lineas.push(h('li.ok', null, icono('cadena'), h('span', null, h('strong', { text: 'Ancla local: ' }), `coincide con la guardada el ${fecha(a.ancla.fecha)}; no hay registros nuevos ni eliminados.`)));
    if (a.tipo === 'crecio') lineas.push(h('li.ok', null, icono('cadena'), h('span', null, h('strong', { text: 'Ancla local: ' }), `presente${a.enId ? ` en el registro #${a.enId}` : ''}; la cadena creció ${numero(Math.max(0, a.nuevos))} registros. Ancla actualizada.`)));
    if (a.tipo === 'ausente') lineas.push(h('li.fallo', null, icono('error'), h('span', null, h('strong', { text: 'Ancla local: ' }), `el hash verificado el ${fecha(a.ancla.fecha)} (${numero(a.ancla.registros)} registros) ya no está en la cadena actual (${numero(a.actual.registros)} registros).`)));

    const acciones = [];
    const rota = !servidor.intacta ? servidor.rotaEnId : local && !local.intacta ? local.rotaEnId : null;
    if (rota) {
      const ir = h('button.boton.boton--secundario.boton--compacto', { type: 'button', text: `Ver el registro #${rota}` });
      ir.addEventListener('click', async () => {
        const inicio = Math.floor((Number(rota) - 1) / POR_PAGINA) * POR_PAGINA;
        cursores = Array.from({ length: inicio / POR_PAGINA + 1 }, (_, i) => i * POR_PAGINA);
        await cargarPagina();
        zonaTabla.querySelector('.fila-rota')?.scrollIntoView({ block: 'center', behavior: 'smooth' });
      });
      acciones.push(ir);
    }
    if (truncada) {
      const aceptar = h('button.boton.boton--secundario.boton--compacto', { type: 'button', text: 'Aceptar estado actual como nueva ancla' });
      aceptar.addEventListener('click', async () => {
        const ok = await confirmar({ titulo: 'Reemplazar ancla local', mensaje: 'Solo hazlo tras investigar la causa. El ancla anterior se descartará de este navegador.', confirmar: 'Reemplazar ancla', tono: 'peligro' });
        if (!ok) return;
        almacen.escribir(CLAVE_ANCLA, a.actual);
        notificar('Ancla local reemplazada.', 'info');
        aceptar.remove();
      });
      acciones.push(aceptar);
    }

    reemplazar(zonaIntegridad,
      h('div', { class: `integridad integridad--${tono}`, role: tono === 'peligro' ? 'alert' : 'status' },
        h('span.integridad-icono', null, icono(tono === 'ok' ? 'escudo' : 'escudoRoto')),
        h('div.integridad-texto', null,
          h('p.integridad-titulo', { text: titulo }),
          h('ul.integridad-lineas', null, lineas),
          servidor.ultimoHash ? h('div.integridad-hash', null, h('span.tenue', { text: 'Último hash' }), valorHash(servidor.ultimoHash, { corto: false, etiqueta: 'último hash' })) : null,
          truncada ? h('p.ayuda', { text: 'Una cadena de hashes no puede delatar por sí sola el borrado del último registro; por eso la consola conserva un ancla del último hash verificado.' }) : null,
          acciones.length ? h('div.fila-botones.fila-botones--izquierda', null, acciones) : null),
        h('p.integridad-fecha.tenue', { text: `Verificado ${fecha(Date.now())}` })));
  }

  // ---------------------------------------------------------------- tabla
  function pintarTabla() {
    const pagina = cursores.length;
    const paginas = total ? Math.max(1, Math.ceil(total / POR_PAGINA)) : null;
    const inicio = (pagina - 1) * POR_PAGINA;
    resumen.textContent = eventos.length ? `Registros ${numero(eventos[0].id)}–${numero(eventos[eventos.length - 1].id)}${total ? ` de ${numero(total)}` : ''}` : '';
    if (!eventos.length) {
      reemplazar(zonaTabla, vacio('Sin registros', 'La bitácora está vacía.'));
      return;
    }
    const filas = eventos.map((e) => {
      const v = verificacionLocal?.get(e.id);
      return h('tr', { class: v === false ? 'fila-rota' : null },
        h('td.num', { dataset: { etiqueta: '#' }, text: e.id }),
        h('td', { dataset: { etiqueta: 'Fecha' } }, tiempo(e.ts)),
        h('td', { dataset: { etiqueta: 'Actor' } }, h('span.actor', null, icono(e.actor === 'detector' ? 'anomalias' : e.actor === 'sistema' ? 'servidor' : String(e.actor).startsWith('admin:') ? 'usuario' : String(e.actor).startsWith('app:') ? 'aplicaciones' : 'usuario'), e.actor)),
        h('td', { dataset: { etiqueta: 'Acción' } }, h('span', { class: `accion-auditoria accion-auditoria--${tonoAccion(e.accion)}`, title: e.accion, text: ACCIONES[e.accion] ?? e.accion })),
        h('td', { dataset: { etiqueta: 'Objetivo' } }, e.objetivo ? h('code', { title: e.objetivo, text: e.objetivo.length > 18 ? `${e.objetivo.slice(0, 14)}…` : e.objetivo }) : h('span.tenue', { text: '—' })),
        h('td.celda-detalle', { dataset: { etiqueta: 'Detalle' } }, detalleLegible(e.detalle)),
        h('td', { dataset: { etiqueta: 'Hash' } }, h('div.celda-hash', null,
          valorHash(e.hash),
          h('span.prev-hash.tenue', { title: `Hash anterior: ${e.prev_hash}` }, '↳ ', h('code', { text: `${String(e.prev_hash).slice(0, 10)}…` })))),
        h('td.celda-verif', { dataset: { etiqueta: 'Verificado' } }, v === undefined ? h('span.tenue', { title: 'Sin verificar', text: '·' }) : v ? icono('check', { titulo: 'Hash correcto', clase: 'icono--ok' }) : icono('error', { titulo: 'Hash incorrecto', clase: 'icono--peligro' })));
    });

    const primera = h('button.boton.boton--secundario.boton--compacto', { type: 'button', disabled: pagina <= 1, 'aria-label': 'Primera página' }, icono('izquierda'), icono('izquierda', { clase: 'icono--solapado' }));
    const ant = h('button.boton.boton--secundario.boton--compacto', { type: 'button', disabled: pagina <= 1, 'aria-label': 'Página anterior' }, icono('izquierda'), h('span.ocultar-movil', { text: 'Anterior' }));
    const hayMas = total ? inicio + eventos.length < total : eventos.length === POR_PAGINA;
    const sig = h('button.boton.boton--secundario.boton--compacto', { type: 'button', disabled: !hayMas, 'aria-label': 'Página siguiente' }, h('span.ocultar-movil', { text: 'Siguiente' }), icono('derecha'));
    primera.addEventListener('click', () => { cursores = [0]; cargarPagina(); });
    ant.addEventListener('click', () => { cursores.pop(); cargarPagina(); });
    sig.addEventListener('click', () => { cursores.push(eventos[eventos.length - 1].id); cargarPagina(); });

    reemplazar(zonaTabla,
      h('div.tabla-contenedor', null, h('table.tabla.tabla--apilable.tabla--auditoria', null,
        h('caption.solo-lectores', { text: 'Registros de la bitácora de auditoría' }),
        h('thead', null, h('tr', null, ['#', 'Fecha', 'Actor', 'Acción', 'Objetivo', 'Detalle', 'Hash · anterior', 'Verif.'].map((t, i) => h('th', { scope: 'col', class: i === 0 ? 'num' : null, text: t })))),
        h('tbody', null, filas))),
      h('nav.paginador', { 'aria-label': 'Paginación de la bitácora' }, primera, ant, h('span.num', { text: paginas ? `Página ${pagina} de ${paginas}` : `Página ${pagina}` }), sig));
  }

  async function cargarPagina() {
    try {
      const r = await api.auditoria({ desde: cursores[cursores.length - 1], limite: POR_PAGINA });
      eventos = r.eventos;
      total = r.total ?? total;
      pintarTabla();
    } catch (e) {
      if (e?.status !== 401) reemplazar(zonaTabla, estadoError(mensajeDeError(e), cargarPagina));
    }
  }

  pintarIntegridadInicial();
  cargarPagina();
  // La integridad se comprueba al entrar: es la razón de ser de esta sección.
  if (puedeVerificar) verificar();
  return { refrescar: cargarPagina };
}
