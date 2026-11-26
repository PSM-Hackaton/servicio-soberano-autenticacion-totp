// Enrutador HTTP propio: plantillas con parámetros (`/api/v1/enrollments/:id/activate`),
// distinción por método y resultados explícitos para 404 y 405. Sin dependencias.

/** @typedef {(peticion: any) => any} Manejador */
/** @typedef {{ metodo: string, plantilla: string, manejador: Manejador, opciones: Record<string, any> }} Ruta */
/**
 * @typedef {{ tipo: 'ok', ruta: Ruta, params: Record<string, string> }
 *   | { tipo: 'metodo_no_permitido', permitidos: string[], plantilla: string }
 *   | { tipo: 'no_encontrada' }} Resolucion
 */

const METODOS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const MAX_LONGITUD_PARAMETRO = 128;
const NOMBRE_PARAMETRO = /^:[A-Za-z_][A-Za-z0-9_]*$/;

/** Divide una ruta en segmentos; '/' produce []. */
function segmentos(ruta) {
  return ruta === '/' ? [] : ruta.slice(1).split('/');
}

/** Decodifica un segmento de parámetro; null si es inválido (barras, NUL, mal codificado, muy largo). */
function decodificarParametro(seg) {
  if (seg.length === 0 || seg.length > MAX_LONGITUD_PARAMETRO * 3) return null;
  let valor;
  try {
    valor = decodeURIComponent(seg);
  } catch {
    return null;
  }
  if (valor.length === 0 || valor.length > MAX_LONGITUD_PARAMETRO) return null;
  if (/[/\\\0]/.test(valor)) return null;
  return valor;
}

/** Crea un enrutador vacío. */
export function crearRouter() {
  /** @type {{ plantilla: string, partes: string[], estaticos: number, porMetodo: Map<string, Ruta> }[]} */
  const plantillas = [];

  /**
   * Registra una ruta.
   * @param {string} metodo @param {string} plantilla @param {Manejador} manejador
   * @param {Record<string, any>} [opciones] metadatos libres (autenticación, permiso, cuerpo…)
   */
  function agregar(metodo, plantilla, manejador, opciones = {}) {
    const m = String(metodo).toUpperCase();
    if (!METODOS.has(m)) throw new Error(`Método no soportado: ${metodo}`);
    if (typeof plantilla !== 'string' || !plantilla.startsWith('/')) throw new Error('La plantilla debe empezar por /');
    if (typeof manejador !== 'function') throw new Error('Manejador inválido');
    const partes = segmentos(plantilla);
    for (const p of partes) {
      if (p.startsWith(':') && !NOMBRE_PARAMETRO.test(p)) throw new Error(`Parámetro inválido en ${plantilla}`);
    }
    let entrada = plantillas.find((e) => e.plantilla === plantilla);
    if (!entrada) {
      entrada = { plantilla, partes, estaticos: partes.filter((p) => !p.startsWith(':')).length, porMetodo: new Map() };
      plantillas.push(entrada);
      // Prioridad: más segmentos literales primero (/a/b gana a /a/:x).
      plantillas.sort((a, b) => b.estaticos - a.estaticos);
    }
    if (entrada.porMetodo.has(m)) throw new Error(`Ruta duplicada: ${m} ${plantilla}`);
    entrada.porMetodo.set(m, { metodo: m, plantilla, manejador, opciones });
    return api;
  }

  /**
   * Resuelve método y ruta (pathname ya normalizado, sin query).
   * @param {string} metodo @param {string} ruta
   * @returns {Resolucion}
   */
  function resolver(metodo, ruta) {
    const m = String(metodo).toUpperCase();
    const segs = segmentos(ruta);
    for (const e of plantillas) {
      if (e.partes.length !== segs.length) continue;
      /** @type {Record<string, string>} */
      const params = Object.create(null);
      let coincide = true;
      for (let i = 0; i < segs.length; i++) {
        const p = e.partes[i];
        if (p.startsWith(':')) {
          const v = decodificarParametro(segs[i]);
          if (v === null) { coincide = false; break; }
          params[p.slice(1)] = v;
        } else if (p !== segs[i]) {
          coincide = false;
          break;
        }
      }
      if (!coincide) continue;
      const r = e.porMetodo.get(m) ?? (m === 'HEAD' ? e.porMetodo.get('GET') : undefined);
      if (r) return { tipo: 'ok', ruta: r, params: { ...params } };
      const permitidos = [...e.porMetodo.keys()];
      if (permitidos.includes('GET') && !permitidos.includes('HEAD')) permitidos.push('HEAD');
      return { tipo: 'metodo_no_permitido', permitidos, plantilla: e.plantilla };
    }
    return { tipo: 'no_encontrada' };
  }

  const api = {
    agregar,
    resolver,
    /** Lista de rutas registradas ("MÉTODO plantilla"), útil para diagnóstico. */
    listar: () => plantillas.flatMap((e) => [...e.porMetodo.keys()].map((m) => `${m} ${e.plantilla}`)),
  };
  return api;
}
