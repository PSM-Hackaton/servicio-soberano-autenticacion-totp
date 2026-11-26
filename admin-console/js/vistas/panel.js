// Panel de operación: indicadores clave, verificaciones por resultado, latencia, salud del
// servicio y alertas recientes. Refresco cada 15 s, en pausa mientras la pestaña está oculta.
import { h, reemplazar, numero, porcentaje, ms, decimal, hora, relativo } from '../dom.js';
import { icono } from '../iconos.js';
import { api, mensajeDeError } from '../api.js';
import { cabeceraPagina, tarjetaKpi, tarjeta, estadoError, esqueleto, insigniaNivel, vacio } from '../ui.js';
import { columnasApiladas, lineas, barraProporcion, tablaDatos } from '../graficos.js';

const INTERVALO_MS = 15_000;
const MAX_PUNTOS = 48;
const UMBRAL_LATENCIA_MS = 250;
const RUTA_VERIFICACION = '/api/v1/verify';

const RESULTADOS = [
  { clave: 'ok', etiqueta: 'Correctas', tono: 'ok' },
  { clave: 'invalid_code', etiqueta: 'Código inválido', tono: 'aviso' },
  { clave: 'rate_limited', etiqueta: 'Limitadas por tasa', tono: 'aviso-fuerte' },
  { clave: 'locked', etiqueta: 'Cuenta bloqueada', tono: 'peligro-suave' },
  { clave: 'replay', etiqueta: 'Repetición bloqueada', tono: 'peligro' },
  { clave: 'anomaly_blocked', etiqueta: 'Bloqueo del detector', tono: 'critico' },
];
const SERIE_RESULTADOS = [
  { clave: 'ok', etiqueta: 'Correctas', tono: 'ok' },
  { clave: 'fallido', etiqueta: 'Fallidas', tono: 'aviso' },
  { clave: 'bloqueado', etiqueta: 'Bloqueadas', tono: 'peligro' },
];
const SERIE_LATENCIA = [
  { clave: 'p95Ms', etiqueta: 'p95', tono: 'acento' },
  { clave: 'p50Ms', etiqueta: 'p50', tono: 'neutro' },
];
const NOMBRES_CHEQUEO = {
  base_datos: 'Base de datos', db: 'Base de datos', database: 'Base de datos', almacenamiento: 'Almacenamiento',
  llaves_firma: 'Llaves de firma', llaves: 'Llaves de firma', keys: 'Llaves de firma', signing_keys: 'Llaves de firma',
  detector_anomalias: 'Detector de anomalías', detector: 'Detector de anomalías', heuristics: 'Detector de anomalías',
  reloj: 'Reloj del sistema', clock: 'Reloj del sistema', vault: 'Bóveda de semillas', boveda: 'Bóveda de semillas',
};

// Historial muestreado en cliente cuando el servidor no entrega serie temporal (persiste entre vistas).
const historial = { anterior: null, puntos: [] };

function derivarPunto(m) {
  const r = m.resultadosVerificacion ?? {};
  const bloqueos = (x) => (x.replay ?? 0) + (x.locked ?? 0) + (x.anomaly_blocked ?? 0) + (x.rate_limited ?? 0);
  const rutaVerify = m.latenciaPorRuta?.[RUTA_VERIFICACION] ?? {};
  const prev = historial.anterior;
  if (prev) {
    const p = prev.resultadosVerificacion ?? {};
    historial.puntos.push({
      ts: new Date().toISOString(),
      ok: Math.max(0, (r.ok ?? 0) - (p.ok ?? 0)),
      fallido: Math.max(0, (r.invalid_code ?? 0) - (p.invalid_code ?? 0)),
      bloqueado: Math.max(0, bloqueos(r) - bloqueos(p)),
      p95Ms: rutaVerify.p95Ms ?? 0,
      p50Ms: rutaVerify.p50Ms ?? 0,
    });
    if (historial.puntos.length > MAX_PUNTOS) historial.puntos.shift();
  }
  historial.anterior = m;
}

function serieDe(m) {
  if (Array.isArray(m?.serie) && m.serie.length) return m.serie.slice(-MAX_PUNTOS);
  return historial.puntos;
}

export function montar(raiz, ctx) {
  let temporizador = null;
  let ultimaCarga = 0;
  let cargando = false;
  let fallo = false;
  let graficos = [];
  const indicador = h('span.indicador-refresco', { role: 'status' });
  const botonActualizar = h('button.boton.boton--secundario.boton--compacto', { type: 'button' }, icono('actualizar'), h('span', { text: 'Actualizar' }));

  const zonaKpi = h('div.rejilla-kpi', null, Array.from({ length: 7 }, () => h('div.kpi.kpi--cargando', null, esqueleto(2))));
  const zonaResultados = h('div', null, esqueleto(6));
  const zonaLatencia = h('div', null, esqueleto(6));
  const zonaRutas = h('div', null, esqueleto(4));
  const zonaSalud = h('div', null, esqueleto(4));
  const zonaAlertas = h('div', null, esqueleto(4));
  const subtituloLatencia = h('span', { text: `Ruta ${RUTA_VERIFICACION}` });

  reemplazar(raiz,
    cabeceraPagina({
      titulo: 'Panel de operación',
      descripcion: 'Verificaciones, bloqueos y salud del servicio en tiempo real.',
      acciones: [indicador, botonActualizar],
    }),
    zonaKpi,
    h('div.rejilla-panel', null,
      tarjeta({ titulo: 'Verificaciones por resultado', subtitulo: 'Intervalos recientes y acumulado desde el arranque', clase: 'col-2' }, zonaResultados),
      tarjeta({ titulo: 'Latencia de verificación', clase: 'col-1' }, h('p.tarjeta-subtitulo.tarjeta-subtitulo--suelto', null, subtituloLatencia), zonaLatencia)),
    h('div.rejilla-panel.rejilla-panel--3', null,
      tarjeta({ titulo: 'Latencia por ruta', subtitulo: 'Percentiles por muestreo de reservorio' }, zonaRutas),
      tarjeta({ titulo: 'Estado de salud', subtitulo: 'Comprobación /health/ready' }, zonaSalud),
      tarjeta({ titulo: 'Alertas recientes', subtitulo: 'Detector de anomalías local', acciones: h('a.enlace', { href: '#/anomalias', text: 'Ver todas' }) }, zonaAlertas)));

  function pintarIndicador() {
    const oculto = document.hidden;
    indicador.className = `indicador-refresco${oculto ? ' indicador-refresco--pausa' : ''}`;
    reemplazar(indicador,
      icono(oculto ? 'pausa' : cargando ? 'actualizar' : 'reloj', { clase: cargando ? 'girando' : '' }),
      oculto ? 'Refresco en pausa' : cargando && !ultimaCarga ? 'Cargando…' : fallo ? 'Sin respuesta · reintento cada 15 s' : `Actualizado ${hora(ultimaCarga)} · cada 15 s`);
  }

  function pintarKpis(m, tablero, anomalias) {
    const r = m?.resultadosVerificacion ?? {};
    const total = m?.totales?.verificaciones ?? tablero?.resumen?.totalVerifications ?? Object.values(r).reduce((a, b) => a + b, 0);
    const exito = total ? ((r.ok ?? 0) / total) * 100 : null;
    const bloqueosRep = r.replay ?? tablero?.resumen?.blockedReplayCount ?? 0;
    const bloqueosDet = r.anomaly_blocked ?? tablero?.resumen?.blockedAnomalyCount ?? 0;
    const bloqueosTasa = (r.rate_limited ?? 0) + (r.locked ?? 0);
    const bloqueos = bloqueosRep + bloqueosDet + bloqueosTasa;
    const alertas = anomalias?.alertas ?? tablero?.alertas ?? [];
    const criticas = alertas.filter((a) => a.nivel === 'CRITICAL' || a.nivel === 'HIGH').length;
    const verify = m?.latenciaPorRuta?.[RUTA_VERIFICACION];
    const p95 = verify?.p95Ms ?? Math.max(0, ...Object.values(m?.latenciaPorRuta ?? {}).map((x) => x.p95Ms ?? 0));
    const disp = m?.disponibilidadPct;
    const desfase = m?.desfaseRelojMs;
    const serie = serieDe(m);
    const ultimo = serie[serie.length - 1];
    const enIntervalo = ultimo ? (ultimo.ok ?? 0) + (ultimo.fallido ?? 0) + (ultimo.bloqueado ?? 0) : null;
    const uptime = m?.uptimeSegundos;

    reemplazar(zonaKpi,
      tarjetaKpi({ etiqueta: 'Verificaciones', valor: numero(total), icono: 'escudo', detalle: enIntervalo !== null ? `${numero(enIntervalo)} en el último intervalo` : 'Desde el arranque' }),
      tarjetaKpi({ etiqueta: 'Tasa de éxito', valor: exito === null ? '—' : decimal(exito, 1), unidad: '%', icono: 'ok', tono: exito !== null && exito < 80 ? 'aviso' : undefined, detalle: `${numero(r.ok ?? 0)} correctas` }),
      tarjetaKpi({ etiqueta: 'Bloqueos', valor: numero(bloqueos), icono: 'candado', tono: bloqueos ? 'peligro' : undefined, detalle: `${numero(bloqueosRep)} repetición · ${numero(bloqueosDet)} detector · ${numero(bloqueosTasa)} tasa` }),
      tarjetaKpi({ etiqueta: 'Alertas del detector', valor: numero(alertas.length), icono: 'anomalias', tono: criticas ? 'aviso' : undefined, detalle: `${numero(criticas)} de nivel alto o crítico` }),
      tarjetaKpi({ etiqueta: 'Latencia p95', valor: Number.isFinite(p95) && p95 > 0 ? decimal(p95, 1) : '—', unidad: 'ms', icono: 'reloj', tono: p95 > UMBRAL_LATENCIA_MS ? 'aviso' : undefined, detalle: `Inferencia media ${ms(m?.inferencia?.mediaMs ?? anomalias?.resumen?.avgInferenceMs)}` }),
      tarjetaKpi({ etiqueta: 'Disponibilidad', valor: Number.isFinite(disp) ? decimal(disp, 2) : '—', unidad: '%', icono: 'servidor', tono: Number.isFinite(disp) && disp < 99 ? 'aviso' : undefined, detalle: Number.isFinite(uptime) ? `En servicio desde hace ${duracion(uptime)}` : 'Desde el arranque' }),
      tarjetaKpi({ etiqueta: 'Desfase de reloj', valor: Number.isFinite(desfase) ? `${desfase > 0 ? '+' : ''}${numero(desfase)}` : '—', unidad: 'ms', icono: 'reloj', tono: Math.abs(desfase) > 2000 ? 'aviso' : undefined, detalle: Math.abs(desfase ?? 0) > 2000 ? 'Revisar sincronización NTP' : 'Dentro de tolerancia' }));
  }

  function pintarGraficos(m) {
    for (const g of graficos) g.desmontar();
    graficos = [];
    const serie = serieDe(m);
    const r = m?.resultadosVerificacion ?? {};
    const total = Object.values(r).reduce((a, b) => a + (b || 0), 0);

    // Verificaciones por resultado
    const lienzoCol = h('div');
    const leyenda = h('ul.leyenda', { 'aria-label': 'Acumulado por resultado' }, RESULTADOS.map((x) => h('li', null,
      h('span', { class: `punto punto--${x.tono}`, 'aria-hidden': 'true' }),
      h('span.leyenda-etiqueta', { text: x.etiqueta }),
      h('span.num.leyenda-valor', { text: numero(r[x.clave] ?? 0) }),
      h('span.num.leyenda-pct', { text: total ? porcentaje(((r[x.clave] ?? 0) / total) * 100) : '—' }))));
    reemplazar(zonaResultados,
      serie.length >= 2
        ? h('div', null,
          h('div.leyenda-serie', { 'aria-hidden': 'true' }, SERIE_RESULTADOS.map((c) => h('span', null, h('span', { class: `punto punto--${c.tono}` }), c.etiqueta))),
          lienzoCol,
          tablaDatos('Verificaciones por intervalo', serie, SERIE_RESULTADOS))
        : vacio('Reuniendo muestras', 'El gráfico aparecerá tras dos refrescos (≈30 s).', 'reloj'),
      h('div.separador'),
      h('h3.subtitulo-seccion', { text: 'Acumulado por resultado' }),
      barraProporcion(RESULTADOS.map((x) => ({ etiqueta: x.etiqueta, valor: r[x.clave] ?? 0, tono: x.tono }))),
      leyenda);
    if (serie.length >= 2) {
      lienzoCol.setAttribute('role', 'img');
      lienzoCol.setAttribute('aria-label', `Verificaciones por intervalo: últimos ${serie.length} intervalos.`);
      graficos.push(columnasApiladas(lienzoCol, serie, SERIE_RESULTADOS));
    }

    // Latencia
    const lienzoLat = h('div');
    const maximo = Math.max(0, ...serie.map((p) => p.p95Ms ?? 0));
    const mostrarUmbral = maximo > UMBRAL_LATENCIA_MS * 0.4;
    subtituloLatencia.textContent = `Ruta ${RUTA_VERIFICACION} · umbral de referencia ${UMBRAL_LATENCIA_MS} ms${mostrarUmbral ? '' : ' (holgura amplia)'}`;
    reemplazar(zonaLatencia, serie.length >= 2
      ? h('div', null,
        h('div.leyenda-serie', { 'aria-hidden': 'true' }, SERIE_LATENCIA.map((c) => h('span', null, h('span', { class: `punto punto--${c.tono}` }), c.etiqueta))),
        lienzoLat,
        tablaDatos('Latencia por intervalo', serie, SERIE_LATENCIA, (v) => ms(v)))
      : vacio('Reuniendo muestras', 'La serie de latencia aparecerá en breve.', 'reloj'));
    if (serie.length >= 2) {
      lienzoLat.setAttribute('role', 'img');
      lienzoLat.setAttribute('aria-label', `Latencia p95 actual ${ms(serie[serie.length - 1].p95Ms)}.`);
      graficos.push(lineas(lienzoLat, serie, SERIE_LATENCIA, mostrarUmbral ? { umbral: UMBRAL_LATENCIA_MS } : {}));
    }

    // Latencia por ruta
    const rutas = Object.entries(m?.latenciaPorRuta ?? {}).sort((a, b) => (b[1].total ?? 0) - (a[1].total ?? 0));
    const maxP95 = Math.max(1, ...rutas.map(([, x]) => x.p95Ms ?? 0));
    reemplazar(zonaRutas, rutas.length
      ? h('div.tabla-contenedor', null, h('table.tabla.tabla--compacta', null,
        h('caption.solo-lectores', { text: 'Latencia por ruta' }),
        h('thead', null, h('tr', null, h('th', { scope: 'col', text: 'Ruta' }), h('th.num', { scope: 'col', text: 'p50' }), h('th.num', { scope: 'col', text: 'p95' }), h('th.num', { scope: 'col', text: 'Total' }))),
        h('tbody', null, rutas.map(([ruta, x]) => h('tr', null,
          h('td', null, h('code.ruta', { text: ruta })),
          h('td.num', { text: ms(x.p50Ms) }),
          h('td.num', { class: (x.p95Ms ?? 0) >= maxP95 ? 'texto-fuerte' : null, text: ms(x.p95Ms) }),
          h('td.num', { text: numero(x.total) }))))))
      : vacio('Sin datos de latencia', 'Aún no hay peticiones registradas.'));
  }

  function pintarSalud(s) {
    if (!s) { reemplazar(zonaSalud, esqueleto(4)); return; }
    const checks = s.checks && typeof s.checks === 'object' ? Object.entries(s.checks) : [];
    const okDe = (v) => v === 'ok' || v === true || v?.status === 'ok' || v?.ok === true;
    const datos = s.datos ?? {};
    reemplazar(zonaSalud,
      h('div', { class: `salud-resumen salud-resumen--${s.error ? 'peligro' : s.listo ? 'ok' : 'aviso'}` },
        icono(s.error ? 'error' : s.listo ? 'ok' : 'aviso'),
        h('div', null,
          h('strong', { text: s.error ? 'Servicio no disponible' : s.listo ? 'Servicio listo' : 'Servicio degradado' }),
          h('span', { text: ` · comprobado ${relativo(s.comprobado)}` }))),
      checks.length ? h('ul.lista-chequeos', null, checks.map(([k, v]) => h('li', null,
        h('span', { text: NOMBRES_CHEQUEO[k] ?? k }),
        h('span', { class: `estado estado--${okDe(v) ? 'ok' : 'peligro'}` }, h('span.estado-punto', { 'aria-hidden': 'true' }), okDe(v) ? 'Correcto' : 'Fallo')))) : null,
      h('dl.datos-clave', null,
        datos.dbDriver ? [h('dt', { text: 'Persistencia' }), h('dd', { text: datos.dbDriver === 'sqlite' ? 'SQLite (WAL)' : datos.dbDriver })] : null,
        datos.activeKeyId ? [h('dt', { text: 'Llave activa' }), h('dd', null, h('code', { text: datos.activeKeyId }))] : null,
        datos.heuristicsMode ? [h('dt', { text: 'Detector' }), h('dd', { text: datos.heuristicsMode === 'local' ? 'Local (sin telemetría)' : datos.heuristicsMode })] : null));
  }

  function pintarAlertas(alertas) {
    const recientes = [...alertas].sort((a, b) => String(b.fecha).localeCompare(String(a.fecha))).slice(0, 4);
    reemplazar(zonaAlertas, recientes.length
      ? h('ul.lista-alertas', null, recientes.map((a) => h('li', null,
        h('span', { class: `puntaje puntaje--${a.puntaje >= 75 ? 'peligro' : a.puntaje >= 60 ? 'aviso' : 'neutro'}`, title: 'Puntaje de riesgo' }, decimal(a.puntaje, 1)),
        h('div.lista-alertas-texto', null,
          h('p', { text: a.razones[0] ?? 'Sin razones registradas' }),
          h('p.tenue', null, insigniaNivel(a.nivel), ' ', relativo(a.fecha), a.app ? ` · ${a.app}` : '')))))
      : vacio('Sin alertas', 'El detector no ha registrado comportamientos atípicos.', 'escudo'));
  }

  async function cargar() {
    if (cargando) return;
    cargando = true;
    pintarIndicador();
    const [rm, ra] = await Promise.allSettled([api.metricas(), api.anomalias()]);
    const rt = ra;
    cargando = false;
    fallo = rm.status === 'rejected' && rt.status === 'rejected';
    if (fallo) {
      const e = rm.reason;
      if (e?.status !== 401) {
        if (!ultimaCarga) {
          reemplazar(zonaKpi, h('div.col-completa', null, estadoError(mensajeDeError(e), () => cargar())));
          for (const z of [zonaResultados, zonaLatencia, zonaRutas, zonaAlertas]) reemplazar(z, vacio('Sin datos', 'Pendiente de conexión con el servicio.', 'servidor'));
        }
      }
      pintarIndicador();
      return;
    }
    const m = rm.status === 'fulfilled' ? rm.value : null;
    const t = rt.status === 'fulfilled' ? rt.value : null;
    const a = ra.status === 'fulfilled' ? ra.value : null;
    if (m && !Array.isArray(m.serie)) derivarPunto(m);
    ultimaCarga = Date.now();
    pintarKpis(m, t, a);
    pintarGraficos(m);
    pintarAlertas(a?.alertas ?? t?.alertas ?? []);
    pintarIndicador();
  }

  function programar() {
    clearInterval(temporizador);
    temporizador = setInterval(() => { if (!document.hidden) cargar(); }, INTERVALO_MS);
  }
  const alCambiarVisibilidad = () => {
    pintarIndicador();
    if (!document.hidden && Date.now() - ultimaCarga > INTERVALO_MS) cargar();
  };
  const alSalud = (e) => pintarSalud(e.detail);

  botonActualizar.addEventListener('click', () => { cargar(); programar(); });
  document.addEventListener('visibilitychange', alCambiarVisibilidad);
  ctx.eventos.addEventListener('salud', alSalud);
  pintarSalud(ctx.salud());
  cargar();
  programar();

  return {
    refrescar: cargar,
    desmontar() {
      clearInterval(temporizador);
      for (const g of graficos) g.desmontar();
      document.removeEventListener('visibilitychange', alCambiarVisibilidad);
      ctx.eventos.removeEventListener('salud', alSalud);
    },
  };
}

function duracion(segundos) {
  const s = Number(segundos) || 0;
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min`;
  if (s < 86400 * 2) return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
  return `${Math.floor(s / 86400)} días`;
}
