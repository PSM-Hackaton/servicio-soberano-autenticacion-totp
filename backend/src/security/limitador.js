// Limitador de tasa en memoria (token bucket) con tope de claves y limpieza (anti-DDoS).
// Las claves son valores ya anonimizados (ip_hash, app_id, user_ref_hash…).

/** @typedef {{ permitido: boolean, restantes: number, reintentarEnMs: number }} Resultado */

const MAX_LONGITUD_CLAVE = 256;

/**
 * Crea un limitador: cada clave dispone de `capacidad` fichas que se reponen linealmente en `ventanaMs`.
 * El Map conserva el orden de último uso: al superar `maxClaves` se descarta la clave usada hace más tiempo,
 * y la limpieza recorre solo desde el principio hasta la primera clave reciente.
 * @param {{ capacidad: number, ventanaMs: number, maxClaves?: number }} opciones
 */
export function crearLimitador({ capacidad, ventanaMs, maxClaves = 100000 }) {
  if (!Number.isInteger(capacidad) || capacidad < 1) throw new RangeError('capacidad inválida');
  if (!Number.isInteger(ventanaMs) || ventanaMs < 1) throw new RangeError('ventanaMs inválida');
  if (!Number.isInteger(maxClaves) || maxClaves < 1) throw new RangeError('maxClaves inválido');

  /** @type {Map<string, { fichas: number, ultimo: number }>} */
  const cubetas = new Map();
  let llamadas = 0;

  /** Elimina claves cuya cubeta ya estaría llena (inactivas por al menos una ventana). */
  function limpiar(ahora = Date.now()) {
    for (const [clave, c] of cubetas) {
      if (ahora - c.ultimo < ventanaMs) break; // el resto es más reciente
      cubetas.delete(clave);
    }
  }

  /**
   * Consume una ficha para la clave.
   * @param {string} clave
   * @param {number} [ahora=Date.now()]
   * @returns {Resultado}
   */
  function consumir(clave, ahora = Date.now()) {
    if (typeof clave !== 'string' || clave.length === 0 || clave.length > MAX_LONGITUD_CLAVE) {
      throw new TypeError('Clave de limitador inválida');
    }
    if (++llamadas % 1000 === 0) limpiar(ahora);

    let c = cubetas.get(clave);
    if (c) {
      cubetas.delete(clave); // se reinsertará al final (último uso)
      const transcurrido = Math.max(0, ahora - c.ultimo);
      c.fichas = Math.min(capacidad, c.fichas + (transcurrido * capacidad) / ventanaMs);
      c.ultimo = Math.max(c.ultimo, ahora);
    } else {
      c = { fichas: capacidad, ultimo: ahora };
      while (cubetas.size >= maxClaves) cubetas.delete(cubetas.keys().next().value);
    }
    cubetas.set(clave, c);

    if (c.fichas >= 1) {
      c.fichas -= 1;
      return { permitido: true, restantes: Math.floor(c.fichas), reintentarEnMs: 0 };
    }
    const reintentarEnMs = Math.ceil(((1 - c.fichas) * ventanaMs) / capacidad);
    return { permitido: false, restantes: 0, reintentarEnMs };
  }

  return {
    consumir,
    limpiar,
    /** Olvida una clave (p. ej. tras un inicio de sesión correcto). @param {string} clave */
    reiniciar(clave) { cubetas.delete(clave); },
    /** Cantidad de claves en memoria. */
    get tamano() { return cubetas.size; },
  };
}
