// Validación estricta de cuerpos JSON con esquemas cerrados (siempre additionalProperties: false).
// Mini validador propio: string, integer, boolean, object. No lanza ante entrada inválida.

/**
 * @typedef {{
 *   type: 'string' | 'integer' | 'boolean' | 'object',
 *   properties?: Record<string, Esquema>,
 *   required?: string[],
 *   minLength?: number, maxLength?: number, pattern?: RegExp,
 *   enum?: Array<string | number | boolean>,
 *   minimum?: number, maximum?: number,
 * }} Esquema
 * @typedef {{ campo: string, motivo: string }} ErrorValidacion
 */

/** Claves prohibidas en cualquier nivel (contaminación de prototipos). */
const CLAVES_PROHIBIDAS = new Set(['__proto__', 'constructor', 'prototype']);
const PROFUNDIDAD_MAXIMA = 8;
const MAX_ERRORES = 20;

/** Objeto JSON plano (no array, no Date, no instancia de clase). */
function esObjetoPlano(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/**
 * Patrón del esquema. Solo se aceptan expresiones literales (RegExp) escritas en el código: nunca se
 * compila una expresión a partir de texto, para que ningún dato pueda convertirse en un patrón.
 * @param {Esquema} esquema
 */
function regexDe(esquema) {
  if (!(esquema.pattern instanceof RegExp)) throw new TypeError('pattern debe ser una expresión regular literal');
  return esquema.pattern;
}

/**
 * @param {unknown} valor @param {Esquema} esquema @param {string} ruta
 * @param {ErrorValidacion[]} errores @param {number} profundidad
 * @returns {unknown} valor saneado (solo con las claves declaradas)
 */
function validarValor(valor, esquema, ruta, errores, profundidad) {
  const campo = ruta || '(raíz)';
  const error = (motivo) => { if (errores.length < MAX_ERRORES) errores.push({ campo, motivo }); };

  switch (esquema.type) {
    case 'string': {
      if (typeof valor !== 'string') return error('debe ser texto');
      const largo = [...valor].length;
      if (esquema.minLength !== undefined && largo < esquema.minLength) error(`longitud mínima ${esquema.minLength}`);
      if (esquema.maxLength !== undefined && largo > esquema.maxLength) return error(`longitud máxima ${esquema.maxLength}`);
      // El patrón solo se evalúa sobre texto ya acotado por maxLength (todos los esquemas lo fijan
      // o usan cuantificadores acotados), y son literales anclados sin repeticiones anidadas.
      // nosemgrep: nodejs_scan.javascript-dos-rule-regex_dos -- validador interno (no un manejador req/res); patrón literal anclado y lineal sobre texto acotado
      if (esquema.pattern !== undefined && !regexDe(esquema).test(valor)) error('formato inválido');
      break;
    }
    case 'integer': {
      if (typeof valor !== 'number' || !Number.isSafeInteger(valor)) return error('debe ser entero');
      if (esquema.minimum !== undefined && valor < esquema.minimum) error(`mínimo ${esquema.minimum}`);
      if (esquema.maximum !== undefined && valor > esquema.maximum) error(`máximo ${esquema.maximum}`);
      break;
    }
    case 'boolean': {
      if (typeof valor !== 'boolean') return error('debe ser booleano');
      break;
    }
    case 'object': {
      if (!esObjetoPlano(valor)) return error('debe ser objeto');
      if (profundidad > PROFUNDIDAD_MAXIMA) return error('anidamiento excesivo');
      const propiedades = esquema.properties ?? {};
      const requeridos = esquema.required ?? [];
      const saneado = {};
      // Reflect.ownKeys incluye "__proto__" como propiedad propia creada por JSON.parse.
      for (const clave of Reflect.ownKeys(/** @type {object} */ (valor))) {
        const nombre = String(clave);
        const sub = ruta ? `${ruta}.${nombre}` : nombre;
        if (typeof clave !== 'string' || CLAVES_PROHIBIDAS.has(nombre)) {
          if (errores.length < MAX_ERRORES) errores.push({ campo: sub, motivo: 'clave prohibida' });
          continue;
        }
        if (!Object.hasOwn(propiedades, nombre)) {
          if (errores.length < MAX_ERRORES) errores.push({ campo: sub, motivo: 'campo no permitido' });
          continue;
        }
        const v = validarValor(valor[nombre], propiedades[nombre], sub, errores, profundidad + 1);
        Object.defineProperty(saneado, nombre, { value: v, enumerable: true, writable: true, configurable: true });
      }
      for (const req of requeridos) {
        if (!Object.hasOwn(valor, req)) {
          if (errores.length < MAX_ERRORES) errores.push({ campo: ruta ? `${ruta}.${req}` : req, motivo: 'requerido' });
        }
      }
      return saneado;
    }
    default:
      throw new TypeError(`Tipo de esquema no soportado en ${campo}`);
  }
  if (esquema.enum !== undefined && !esquema.enum.includes(/** @type {any} */ (valor))) error('valor no permitido');
  return valor;
}

/**
 * Valida un cuerpo contra un esquema cerrado. Cualquier campo no declarado se rechaza.
 * @param {unknown} cuerpo
 * @param {Esquema} esquema
 * @returns {{ ok: true, valor: any } | { ok: false, errores: ErrorValidacion[] }}
 */
export function validarCuerpo(cuerpo, esquema) {
  if (!esquema || typeof esquema !== 'object') throw new TypeError('Esquema inválido');
  /** @type {ErrorValidacion[]} */
  const errores = [];
  let valor;
  try {
    valor = validarValor(cuerpo, esquema, '', errores, 0);
  } catch (e) {
    if (e instanceof TypeError && String(e.message).startsWith('Tipo de esquema')) throw e;
    return { ok: false, errores: [{ campo: '(raíz)', motivo: 'entrada inválida' }] };
  }
  return errores.length === 0 ? { ok: true, valor } : { ok: false, errores };
}
