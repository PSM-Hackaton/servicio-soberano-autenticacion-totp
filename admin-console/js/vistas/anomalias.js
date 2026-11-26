// Detector de anomalías local: resumen, alertas con puntaje, nivel, razones y acción, y
// explicación de las variables que evalúa (todo se calcula en el servidor propio).
import { h, reemplazar, numero, decimal, ms, tiempo, hashCorto } from '../dom.js';
import { icono } from '../iconos.js';
import { api, mensajeDeError } from '../api.js';
import { cabeceraPagina, tarjeta, tarjetaKpi, estadoError, esqueleto, insigniaNivel, etiquetaAccion, vacio, nivelInfo } from '../ui.js';
import { medidor } from '../graficos.js';

const NIVELES = [
  { valor: '', texto: 'Todas' },
  { valor: 'CRITICAL', texto: 'Crítico' },
  { valor: 'HIGH', texto: 'Alto' },
  { valor: 'MEDIUM', texto: 'Medio' },
  { valor: 'LOW', texto: 'Bajo' },
];

/** Variables del vector de características (backend/src/heuristics/caracteristicas.js). */
const VARIABLES = [
  { nombre: 'Fallos por cuenta', clave: 'fallosCuenta15m', texto: 'Intentos fallidos sobre la misma cuenta en los últimos 15 minutos.', senal: 'Fuerza bruta contra una cuenta' },
  { nombre: 'IP distintas por cuenta', clave: 'ipsPorCuenta15m', texto: 'Hashes de IP diferentes que intentan la misma cuenta. Un usuario legítimo usa una o dos.', senal: 'Fuerza bruta distribuida' },
  { nombre: 'Cuentas por IP', clave: 'cuentasPorIp15m', texto: 'Cuentas distintas probadas desde una misma IP (tolera redes de oficina con NAT).', senal: 'Password spraying' },
  { nombre: 'Fallos por IP', clave: 'fallosIp15m', texto: 'Intentos fallidos desde una misma IP, sin importar la cuenta.', senal: 'Origen hostil' },
  { nombre: 'Ritmo entre intentos', clave: 'intervaloMedioIp', texto: 'Segundos medios entre intentos consecutivos de la IP. Pocos segundos delatan automatización.', senal: 'Scripts automatizados' },
  { nombre: 'Hora del día', clave: 'horaSeno · horaCoseno', texto: 'Codificación circular de la hora (las 23:59 quedan junto a las 00:00).', senal: 'Contexto temporal' },
  { nombre: 'Desviación horaria', clave: 'desviacionHora', texto: 'Distancia entre la hora actual y el patrón horario habitual de la cuenta (0 = habitual, 1 = a 12 h).', senal: 'Acceso a hora inusual' },
  { nombre: 'Proporción de fallos por IP', clave: 'proporcionFallosIp', texto: 'Fallos sobre el total de intentos de la IP en la ventana.', senal: 'Tasa de error anómala' },
];

export function montar(raiz, ctx) {
  let datos = null;
  let filtro = '';
  const zonaKpi = h('div.rejilla-kpi.rejilla-kpi--4', null, Array.from({ length: 4 }, () => h('div.kpi.kpi--cargando', null, esqueleto(2))));
  const zonaEscala = h('div');
  const zonaAlertas = h('div', null, esqueleto(6));
  const chips = h('div.chips', { role: 'group', 'aria-label': 'Filtrar por nivel' });

  reemplazar(raiz,
    cabeceraPagina({ titulo: 'Detector de anomalías', descripcion: 'Cada intento de verificación recibe un puntaje de riesgo calculado localmente, sin enviar datos a terceros.' }),
    zonaKpi,
    h('div.rejilla-panel.rejilla-panel--anomalias', null,
      h('div.col-2.columna-pila', null,
        tarjeta({ titulo: 'Escala de riesgo y respuesta adaptativa' }, zonaEscala),
        tarjeta({ titulo: 'Alertas del detector', subtitulo: 'Intentos con puntaje de riesgo igual o superior al umbral de alerta', clase: 'tarjeta--tabla' }, h('div.barra-filtros', null, chips), zonaAlertas)),
      tarjeta({ titulo: '¿Cómo decide el detector?', clase: 'col-1 tarjeta--explicacion' }, explicacion())));

  function pintarEscala() {
    const u = datos.umbrales;
    const alerta = Number(u.alerta ?? 60);
    const bloqueo = Number(u.bloqueo ?? 75);
    reemplazar(zonaEscala,
      h('div.escala-riesgo', { role: 'img', 'aria-label': `Bajo de 0 a ${alerta - 1}, medio de ${alerta} a ${bloqueo - 1}, alto desde ${bloqueo}.` },
        h('span.escala-tramo.escala-tramo--bajo', { vars: { peso: alerta } }),
        h('span.escala-tramo.escala-tramo--medio', { vars: { peso: bloqueo - alerta } }),
        h('span.escala-tramo.escala-tramo--alto', { vars: { peso: 100 - bloqueo } })),
      h('div.escala-marcas', { 'aria-hidden': 'true' },
        h('span', { vars: { pos: 0 }, text: '0' }), h('span', { vars: { pos: alerta / 100 }, text: String(alerta) }), h('span', { vars: { pos: bloqueo / 100 }, text: String(bloqueo) }), h('span', { vars: { pos: 1 }, text: '100' })),
      h('ul.escala-leyenda', null,
        h('li', null, insigniaNivel('LOW'), h('span', { text: `0–${alerta - 1}` }), etiquetaAccion('ALLOW')),
        h('li', null, insigniaNivel('MEDIUM'), h('span', { text: `${alerta}–${bloqueo - 1}` }), etiquetaAccion('DELAY')),
        h('li', null, insigniaNivel('HIGH'), h('span', { text: `${bloqueo}–100` }), etiquetaAccion('BLOCK'))),
      h('p.ayuda', { text: `Modo ${datos.modo === 'local' ? 'local' : datos.modo}. Cada aplicación puede fijar su propio umbral de bloqueo y elegir entre monitorización (solo alerta) o bloqueo.` }));
  }

  function pintarKpis() {
    const r = datos.resumen ?? {};
    const evaluaciones = r.evaluations ?? r.evaluaciones ?? r.totalEvaluations;
    const bloqueos = r.blockedAnomalyCount ?? r.bloqueos ?? datos.alertas.filter((a) => a.accion === 'BLOCK').length;
    const esperas = r.delayedCount ?? r.esperas ?? datos.alertas.filter((a) => a.accion === 'DELAY').length;
    reemplazar(zonaKpi,
      tarjetaKpi({ etiqueta: 'Intentos evaluados', valor: numero(evaluaciones), icono: 'anomalias', detalle: 'Cada verificación pasa por el detector' }),
      tarjetaKpi({ etiqueta: 'Bloqueos preventivos', valor: numero(bloqueos), icono: 'candado', tono: bloqueos ? 'peligro' : undefined, detalle: 'Puntaje sobre el umbral de bloqueo' }),
      tarjetaKpi({ etiqueta: 'Esperas adicionales', valor: numero(esperas), icono: 'reloj', tono: esperas ? 'aviso' : undefined, detalle: 'Fricción añadida ante riesgo medio' }),
      tarjetaKpi({ etiqueta: 'Inferencia media', valor: decimal(r.avgInferenceMs ?? r.mediaMs, 1), unidad: 'ms', icono: 'servidor', detalle: r.p95InferenceMs ? `p95 ${ms(r.p95InferenceMs)} · sin red externa` : 'Sin red externa' }));
  }

  function pintarChips() {
    reemplazar(chips, NIVELES.map((n) => {
      const cuenta = n.valor ? datos.alertas.filter((a) => a.nivel === n.valor).length : datos.alertas.length;
      const activo = filtro === n.valor;
      const b = h('button', { type: 'button', 'aria-pressed': String(activo), class: ['chip-filtro', activo ? 'activo' : ''] },
        n.valor ? h('span', { class: `estado-punto estado-punto--nivel-${nivelInfo(n.valor).tono}`, 'aria-hidden': 'true' }) : null,
        n.texto, h('span.chip-cuenta.num', { text: numero(cuenta) }));
      b.addEventListener('click', () => { filtro = n.valor; pintarChips(); pintarAlertas(); });
      return b;
    }));
  }

  function pintarAlertas() {
    const lista = datos.alertas.filter((a) => !filtro || a.nivel === filtro).sort((a, b) => String(b.fecha).localeCompare(String(a.fecha)));
    if (!lista.length) {
      reemplazar(zonaAlertas, vacio('Sin alertas', filtro ? 'No hay alertas de este nivel.' : 'El detector no ha registrado comportamientos atípicos.', 'escudo'));
      return;
    }
    reemplazar(zonaAlertas, h('ol.alertas', null, lista.map((a) => {
      const tono = nivelInfo(a.nivel).tono;
      return h('li', { class: `alerta-detector alerta-detector--${tono}` },
        h('div.alerta-puntaje', { 'aria-label': `Puntaje de riesgo ${decimal(a.puntaje, 1)} sobre 100` },
          medidor(a.puntaje, tono),
          h('span.num.alerta-puntaje-valor', { text: decimal(a.puntaje, 1) })),
        h('div.alerta-cuerpo', null,
          h('div.alerta-encabezado', null, insigniaNivel(a.nivel), etiquetaAccion(a.accion), h('span.tenue', null, tiempo(a.fecha, { relativa: true }))),
          h('ul.razones', null, a.razones.map((r) => h('li', { text: r }))),
          h('dl.alerta-meta', null,
            a.cuenta ? [h('dt', { text: 'Cuenta' }), h('dd', null, h('code', { title: a.cuenta, text: hashCorto(a.cuenta, 16, 4) }))] : null,
            a.ip_hash ? [h('dt', { text: 'IP (hash)' }), h('dd', null, h('code', { title: a.ip_hash, text: hashCorto(a.ip_hash, 16, 4) }))] : null,
            a.app ? [h('dt', { text: 'Aplicación' }), h('dd', null, h('code', { text: a.app }))] : null,
            a.inferencia_ms !== undefined ? [h('dt', { text: 'Inferencia' }), h('dd.num', { text: ms(a.inferencia_ms) })] : null)));
    })));
  }

  async function cargar() {
    try {
      datos = await api.anomalias();
      pintarKpis();
      pintarEscala();
      pintarChips();
      pintarAlertas();
    } catch (e) {
      if (e?.status !== 401) reemplazar(zonaAlertas, estadoError(mensajeDeError(e), cargar));
    }
  }
  cargar();
  return { refrescar: cargar };
}

function explicacion() {
  return h('div.explicacion', null,
    h('p', { text: 'El detector combina reglas explicables con un modelo Isolation Forest entrenado con tráfico normal. Ambos se ejecutan en el propio servidor y tardan pocos milisegundos.' }),
    h('h3.subtitulo-seccion', { text: 'Variables evaluadas (ventana de 15 min)' }),
    h('dl.variables', null, VARIABLES.map((v) => [
      h('dt', null, h('strong', { text: v.nombre }), h('code', { text: v.clave })),
      h('dd', null, v.texto, h('span.variable-senal', null, icono('anomalias'), v.senal)),
    ])),
    h('h3.subtitulo-seccion', { text: 'Cómo se combina' }),
    h('ol.pasos-explicacion', null,
      h('li', { text: 'Cada regla activa aporta una severidad según cuánto supera su umbral (p. ej., 5 fallos por cuenta empiezan a sumar; 15 saturan).' }),
      h('li', { text: 'El Isolation Forest mide cuán atípico es el intento frente al patrón aprendido; su peso máximo no basta por sí solo para bloquear.' }),
      h('li', { text: 'El puntaje final (0–100) decide la respuesta: permitir, añadir espera o bloquear temporalmente.' }),
      h('li', { text: 'Cada decisión incluye razones legibles y queda en la bitácora de auditoría.' })),
    h('p.ayuda', null, icono('candado'), ' Privacidad: el detector solo ve hashes HMAC de usuario e IP, nunca datos personales en claro.'));
}
