// Generador de tráfico sintético de intentos de verificación TOTP (normal y ataques).
// Determinista con semilla. Produce registros con la forma de la tabla `attempts` ya anonimizada,
// más los campos `etiqueta` y `campana` que solo se usan para medir el detector.

import { createHash } from 'node:crypto';
import { crearAleatorio } from './aleatorio.js';

/** @typedef {'normal' | 'fuerza_bruta_lenta' | 'fuerza_bruta_distribuida' | 'password_spraying'} Etiqueta */

/**
 * @typedef {object} EventoSintetico
 * @property {string} user_ref_hash
 * @property {string} ip_hash
 * @property {string} resultado
 * @property {number} ts Epoch ms.
 * @property {Etiqueta} etiqueta
 * @property {string} campana Identificador de la sesión o campaña que generó el evento.
 */

/** Tipos de ataque soportados. */
export const TIPOS_ATAQUE = Object.freeze(['fuerza_bruta_lenta', 'fuerza_bruta_distribuida', 'password_spraying']);

/** Lunes 5 de enero de 2026, 00:00 UTC: inicio por defecto de la simulación. */
export const INICIO_POR_DEFECTO = Date.UTC(2026, 0, 5);

const MS_MIN = 60 * 1000;
const MS_HORA = 60 * MS_MIN;
const MS_DIA = 24 * MS_HORA;

/** Hash corto con la misma forma que los HMAC de la BD (no es secreto: datos sintéticos). */
function hashSintetico(prefijo, n) {
  return createHash('sha256').update(`${prefijo}:${n}`).digest('hex').slice(0, 32);
}

/** Hash de cuenta sintética número n (sirve para apuntar ataques a cuentas existentes). */
export const hashCuenta = (n) => hashSintetico('usuario', n);
/** Hash de IP sintética. */
export const hashIp = (etiqueta, n) => hashSintetico(`ip-${etiqueta}`, n);

const RESULTADOS_FALLO = ['invalid_code', 'invalid_code', 'invalid_code', 'invalid_code', 'replay'];

/**
 * Tráfico normal: usuarios con horario laboral (lunes a viernes) que aciertan el código,
 * a veces tras un único fallo. El 30 % trabaja detrás de una IP de oficina compartida (NAT) y
 * un 10 % de las sesiones llega desde una IP móvil distinta.
 * @param {{ semilla?: number | string, usuarios?: number, dias?: number, inicio?: number,
 *   probabilidadFallo?: number, oficinas?: number }} [opciones]
 * @returns {EventoSintetico[]}
 */
export function generarTraficoNormal(opciones = {}) {
  const {
    semilla = 7, usuarios = 300, dias = 5, inicio = INICIO_POR_DEFECTO, probabilidadFallo = 0.15, oficinas = 6,
  } = opciones;
  const azar = crearAleatorio(`normal:${semilla}`);
  const perfiles = [];
  for (let u = 0; u < usuarios; u++) {
    perfiles.push({
      cuenta: hashCuenta(u),
      ip: azar.bernoulli(0.3) ? hashIp('oficina', azar.entero(0, oficinas - 1)) : hashIp('casa', u),
      horaPreferida: azar.rango(8.5, 16.5),
      sesionesPorDia: azar.entero(1, 3),
    });
  }
  /** @type {EventoSintetico[]} */
  const eventos = [];
  let sesion = 0;
  for (let d = 0; d < dias; d++) {
    const dia = inicio + d * MS_DIA;
    const diaSemana = new Date(dia).getUTCDay();
    if (diaSemana === 0 || diaSemana === 6) continue;
    for (const p of perfiles) {
      const sesiones = azar.entero(Math.max(0, p.sesionesPorDia - 1), p.sesionesPorDia);
      for (let s = 0; s < sesiones; s++) {
        const hora = Math.min(18.5, Math.max(7.5, azar.normal(p.horaPreferida + s * 1.5, 1.2)));
        let ts = dia + Math.round(hora * MS_HORA + azar.rango(0, MS_MIN));
        const ip = azar.bernoulli(0.1) ? hashIp('movil', azar.entero(0, 1e6)) : p.ip;
        const campana = `normal-${sesion++}`;
        if (azar.bernoulli(probabilidadFallo)) {
          eventos.push({ user_ref_hash: p.cuenta, ip_hash: ip, resultado: azar.elegir(RESULTADOS_FALLO), ts, etiqueta: 'normal', campana });
          ts += Math.round(azar.rango(8, 60) * 1000);
        }
        eventos.push({ user_ref_hash: p.cuenta, ip_hash: ip, resultado: 'ok', ts, etiqueta: 'normal', campana });
      }
    }
  }
  return eventos.sort((a, b) => a.ts - b.ts);
}

/**
 * Genera una campaña de ataque.
 * - fuerza_bruta_lenta: una IP contra una cuenta, un intento cada 50–150 s durante ~45 min.
 * - fuerza_bruta_distribuida: 30–80 IP contra una cuenta, 1–2 intentos por IP en 2–6 min.
 * - password_spraying: una IP contra 40–100 cuentas, un intento por cuenta cada 2–10 s.
 * @param {Etiqueta} tipo
 * @param {{ semilla?: number | string, inicio?: number, victima?: string, cuentas?: string[], id?: string }} [opciones]
 * @returns {EventoSintetico[]}
 */
export function generarAtaque(tipo, opciones = {}) {
  const { semilla = 11, inicio = INICIO_POR_DEFECTO + 10 * MS_HORA, id = `${tipo}-${semilla}` } = opciones;
  const azar = crearAleatorio(`${tipo}:${semilla}`);
  const victima = opciones.victima ?? hashCuenta(azar.entero(0, 299));
  const fallo = () => (azar.bernoulli(0.9) ? 'invalid_code' : 'rate_limited');
  /** @type {EventoSintetico[]} */
  const eventos = [];
  const evento = (cuenta, ip, ts) => eventos.push({
    user_ref_hash: cuenta, ip_hash: ip, resultado: fallo(), ts: Math.round(ts), etiqueta: tipo, campana: id,
  });

  if (tipo === 'fuerza_bruta_lenta') {
    const ip = hashIp(`atacante-${id}`, 0);
    let ts = inicio;
    const fin = inicio + 45 * MS_MIN;
    while (ts < fin) {
      evento(victima, ip, ts);
      ts += azar.rango(50, 150) * 1000;
    }
  } else if (tipo === 'fuerza_bruta_distribuida') {
    const ips = azar.entero(30, 80);
    const duracion = azar.rango(2, 6) * MS_MIN;
    for (let i = 0; i < ips; i++) {
      const ip = hashIp(`botnet-${id}`, i);
      const repeticiones = azar.entero(1, 2);
      for (let k = 0; k < repeticiones; k++) evento(victima, ip, inicio + azar.rango(0, duracion));
    }
  } else if (tipo === 'password_spraying') {
    const ip = hashIp(`spray-${id}`, 0);
    const cuentas = opciones.cuentas ?? Array.from({ length: azar.entero(40, 100) }, (_, i) => (
      azar.bernoulli(0.7) ? hashCuenta(azar.entero(0, 299)) : hashSintetico(`inexistente-${id}`, i)
    ));
    let ts = inicio;
    for (const cuenta of cuentas) {
      evento(cuenta, ip, ts);
      ts += azar.rango(2, 10) * 1000;
    }
  } else {
    throw new Error(`Tipo de ataque desconocido: ${tipo}`);
  }
  return eventos.sort((a, b) => a.ts - b.ts);
}

/**
 * Tráfico mixto: normal más `campanasPorTipo` campañas de cada tipo de ataque repartidas en
 * horario laboral (y alguna nocturna), apuntando a cuentas reales.
 * @param {{ semilla?: number | string, usuarios?: number, dias?: number, inicio?: number, campanasPorTipo?: number }} [opciones]
 * @returns {EventoSintetico[]}
 */
export function generarTraficoMixto(opciones = {}) {
  const { semilla = 99, usuarios = 300, dias = 5, inicio = INICIO_POR_DEFECTO, campanasPorTipo = 10 } = opciones;
  const azar = crearAleatorio(`mixto:${semilla}`);
  const eventos = generarTraficoNormal({ semilla, usuarios, dias, inicio });
  for (const tipo of TIPOS_ATAQUE) {
    for (let k = 0; k < campanasPorTipo; k++) {
      const dia = azar.entero(0, Math.max(0, dias - 1));
      const hora = azar.bernoulli(0.2) ? azar.rango(0, 6) : azar.rango(8, 18);
      eventos.push(...generarAtaque(tipo, {
        semilla: `${semilla}-${k}`,
        inicio: inicio + dia * MS_DIA + hora * MS_HORA,
        victima: hashCuenta(azar.entero(0, usuarios - 1)),
        id: `${tipo}-${k}`,
      }));
    }
  }
  return eventos.sort((a, b) => a.ts - b.ts);
}
