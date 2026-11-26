// Métricas operativas en memoria (sin dependencias) para /metrics y el panel de administración.
// Memoria acotada: latencias por muestreo de reservorio de tamaño fijo, ventana deslizante por
// cubetas temporales y límite de rutas distintas. Nunca se guardan IP ni identificadores de usuario.

/** Resultados de verificación contemplados por el contrato. */
export const RESULTADOS_VERIFICACION = Object.freeze(['ok', 'invalid_code', 'replay', 'locked', 'anomaly_blocked', 'rate_limited']);

const TAMANO_CUBETA_MS = 10_000;
const RUTA_OTRAS = 'otras';

/**
 * Reservorio de tamaño fijo (algoritmo R de Vitter): muestra uniforme de todas las observaciones.
 * @param {number} capacidad @param {() => number} azar
 */
function crearReservorio(capacidad, azar) {
  /** @type {number[]} */
  const muestras = [];
  let vistos = 0;
  return {
    /** @param {number} v */
    agregar(v) {
      vistos++;
      if (muestras.length < capacidad) muestras.push(v);
      else {
        const j = Math.floor(azar() * vistos);
        if (j < capacidad) muestras[j] = v;
      }
    },
    get tamano() { return muestras.length; },
    get vistos() { return vistos; },
    /** Percentil por rango más cercano (p en 0..100). */
    percentil(p) {
      if (muestras.length === 0) return null;
      const orden = [...muestras].sort((a, b) => a - b);
      const idx = Math.min(orden.length - 1, Math.max(0, Math.ceil((p / 100) * orden.length) - 1));
      return orden[idx];
    },
  };
}

/** Quita la cadena de consulta y limita la longitud de la etiqueta de ruta. */
function normalizarRuta(ruta) {
  return String(ruta ?? 'desconocida').split('?')[0].slice(0, 120) || '/';
}

/** Escapa un valor de etiqueta en formato de exposición Prometheus. */
function escaparEtiqueta(v) {
  return String(v).replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

/** @param {number} n @param {number} [decimales] */
function redondear(n, decimales = 3) {
  const f = 10 ** decimales;
  return Math.round(n * f) / f;
}

/**
 * @param {{ ahora?: () => number, ventanaMs?: number, capacidadReservorio?: number,
 *   maxRutas?: number, azar?: () => number }} [opciones]
 */
export function crearMetricas({
  ahora = () => Date.now(),
  ventanaMs = 15 * 60 * 1000,
  capacidadReservorio = 512,
  maxRutas = 64,
  azar = Math.random,
} = {}) {
  const inicio = ahora();
  const totales = { peticiones: 0, errores5xx: 0, errores4xx: 0, erroresBaseDatos: 0, reconexiones: 0 };
  const salud = { total: 0, ok: 0, ultimo: /** @type {boolean | null} */ (null) };
  /** @type {Record<string, number>} */
  const resultados = Object.fromEntries(RESULTADOS_VERIFICACION.map((r) => [r, 0]));
  /** @type {Map<string, { total: number, errores5xx: number, reservorio: ReturnType<typeof crearReservorio> }>} */
  const rutas = new Map();
  /** @type {Map<number, { total: number, errores5xx: number }>} cubetas de la ventana deslizante */
  const cubetas = new Map();
  const inferencia = { total: 0, sumaMs: 0, reservorio: crearReservorio(capacidadReservorio, azar) };
  let desfaseRelojMs = 0;

  function podarCubetas(t) {
    const limite = Math.floor((t - ventanaMs) / TAMANO_CUBETA_MS);
    for (const clave of cubetas.keys()) if (clave <= limite) cubetas.delete(clave);
  }

  function obtenerRuta(ruta) {
    let nombre = normalizarRuta(ruta);
    if (!rutas.has(nombre) && rutas.size >= maxRutas) nombre = RUTA_OTRAS;
    let r = rutas.get(nombre);
    if (!r) {
      r = { total: 0, errores5xx: 0, reservorio: crearReservorio(capacidadReservorio, azar) };
      rutas.set(nombre, r);
    }
    return r;
  }

  function ventana() {
    podarCubetas(ahora());
    let total = 0;
    let errores5xx = 0;
    for (const c of cubetas.values()) { total += c.total; errores5xx += c.errores5xx; }
    return { total, errores5xx };
  }

  /** Disponibilidad: chequeos de salud si los hay; si no, peticiones sin 5xx sobre el total. */
  function disponibilidad() {
    if (salud.total > 0) return redondear((salud.ok / salud.total) * 100);
    if (totales.peticiones > 0) return redondear(((totales.peticiones - totales.errores5xx) / totales.peticiones) * 100);
    return 100;
  }

  const api = {
    /** @param {{ ruta: string, status: number, duracionMs: number }} p */
    registrarPeticion({ ruta, status, duracionMs }) {
      const t = ahora();
      const es5xx = status >= 500;
      totales.peticiones++;
      if (es5xx) totales.errores5xx++;
      else if (status >= 400) totales.errores4xx++;
      const r = obtenerRuta(ruta);
      r.total++;
      if (es5xx) r.errores5xx++;
      if (Number.isFinite(duracionMs) && duracionMs >= 0) r.reservorio.agregar(duracionMs);
      const clave = Math.floor(t / TAMANO_CUBETA_MS);
      const c = cubetas.get(clave) ?? { total: 0, errores5xx: 0 };
      c.total++;
      if (es5xx) c.errores5xx++;
      cubetas.set(clave, c);
      podarCubetas(t);
    },
    /** @param {string} resultado uno de RESULTADOS_VERIFICACION */
    registrarResultadoVerificacion(resultado) {
      if (!RESULTADOS_VERIFICACION.includes(resultado)) throw new Error(`Resultado desconocido: ${resultado}`);
      resultados[resultado]++;
    },
    /** @param {boolean} ok */
    registrarChequeoSalud(ok) {
      salud.total++;
      if (ok) salud.ok++;
      salud.ultimo = Boolean(ok);
    },
    registrarErrorBaseDatos() { totales.erroresBaseDatos++; },
    registrarReconexion() { totales.reconexiones++; },
    /** @param {number} ms */
    registrarInferencia(ms) {
      if (!Number.isFinite(ms) || ms < 0) return;
      inferencia.total++;
      inferencia.sumaMs += ms;
      inferencia.reservorio.agregar(ms);
    },
    /** @param {number} ms desfase medido entre el reloj local y la referencia */
    fijarDesfaseReloj(ms) { if (Number.isFinite(ms)) desfaseRelojMs = ms; },

    /** Fotografía serializable de todas las métricas. */
    instantanea() {
      const t = ahora();
      const v = ventana();
      /** @type {Record<string, { total: number, errores5xx: number, p50Ms: number | null, p95Ms: number | null, muestras: number }>} */
      const latenciaPorRuta = {};
      for (const [nombre, r] of [...rutas.entries()].sort(([a], [b]) => a.localeCompare(b))) {
        latenciaPorRuta[nombre] = {
          total: r.total,
          errores5xx: r.errores5xx,
          p50Ms: r.reservorio.percentil(50),
          p95Ms: r.reservorio.percentil(95),
          muestras: r.reservorio.tamano,
        };
      }
      const totalVerificaciones = Object.values(resultados).reduce((a, b) => a + b, 0);
      return {
        inicio: new Date(inicio).toISOString(),
        uptimeSegundos: Math.max(0, Math.floor((t - inicio) / 1000)),
        totales: { ...totales, verificaciones: totalVerificaciones },
        disponibilidadPct: disponibilidad(),
        salud: { ...salud },
        tasa5xx: totales.peticiones ? redondear(totales.errores5xx / totales.peticiones, 4) : 0,
        ventana: {
          ms: ventanaMs,
          peticiones: v.total,
          errores5xx: v.errores5xx,
          tasa5xx: v.total ? redondear(v.errores5xx / v.total, 4) : 0,
        },
        latenciaPorRuta,
        resultadosVerificacion: { ...resultados },
        inferencia: {
          total: inferencia.total,
          mediaMs: inferencia.total ? redondear(inferencia.sumaMs / inferencia.total) : 0,
          p95Ms: inferencia.reservorio.percentil(95),
        },
        desfaseRelojMs,
      };
    },

    /** Exposición en texto plano estilo Prometheus para GET /metrics. */
    formatoTexto() {
      const s = api.instantanea();
      /** @type {string[]} */
      const lineas = [];
      const metrica = (nombre, tipo, ayuda, valores) => {
        lineas.push(`# HELP ${nombre} ${ayuda}`, `# TYPE ${nombre} ${tipo}`);
        for (const [etiquetas, valor] of valores) {
          const e = Object.entries(etiquetas).map(([k, x]) => `${k}="${escaparEtiqueta(x)}"`).join(',');
          lineas.push(`${nombre}${e ? `{${e}}` : ''} ${valor ?? 'NaN'}`);
        }
      };
      metrica('totp_uptime_seconds', 'gauge', 'Segundos desde el arranque', [[{}, s.uptimeSegundos]]);
      metrica('totp_start_time_seconds', 'gauge', 'Instante de arranque (epoch)', [[{}, Math.floor(inicio / 1000)]]);
      metrica('totp_http_requests_total', 'counter', 'Peticiones HTTP por ruta',
        Object.entries(s.latenciaPorRuta).map(([ruta, r]) => [{ ruta }, r.total]));
      metrica('totp_http_errors_5xx_total', 'counter', 'Respuestas 5xx por ruta',
        Object.entries(s.latenciaPorRuta).map(([ruta, r]) => [{ ruta }, r.errores5xx]));
      metrica('totp_http_request_duration_ms', 'summary', 'Latencia por ruta (reservorio acotado)',
        Object.entries(s.latenciaPorRuta).flatMap(([ruta, r]) => [
          [{ ruta, quantile: '0.5' }, r.p50Ms], [{ ruta, quantile: '0.95' }, r.p95Ms],
        ]));
      metrica('totp_http_5xx_ratio', 'gauge', 'Proporción de 5xx en la ventana deslizante', [[{}, s.ventana.tasa5xx]]);
      metrica('totp_availability_percent', 'gauge', 'Disponibilidad estimada en porcentaje', [[{}, s.disponibilidadPct]]);
      metrica('totp_health_up', 'gauge', 'Último chequeo de salud (1 ok, 0 fallo)',
        [[{}, s.salud.ultimo === null ? 'NaN' : Number(s.salud.ultimo)]]);
      metrica('totp_verifications_total', 'counter', 'Verificaciones por resultado',
        Object.entries(s.resultadosVerificacion).map(([resultado, n]) => [{ resultado }, n]));
      metrica('totp_db_errors_total', 'counter', 'Errores de base de datos', [[{}, s.totales.erroresBaseDatos]]);
      metrica('totp_db_reconnections_total', 'counter', 'Reconexiones a la base de datos', [[{}, s.totales.reconexiones]]);
      metrica('totp_anomaly_inference_ms_avg', 'gauge', 'Latencia media de inferencia del detector', [[{}, s.inferencia.mediaMs]]);
      metrica('totp_clock_skew_ms', 'gauge', 'Desfase de reloj medido', [[{}, s.desfaseRelojMs]]);
      return `${lineas.join('\n')}\n`;
    },
  };
  return api;
}
