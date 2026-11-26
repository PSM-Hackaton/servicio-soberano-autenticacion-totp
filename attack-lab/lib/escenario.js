// Infraestructura común de escenarios: contexto, registro de verificaciones (esperado vs. obtenido),
// creación de usuarios de prueba y ejecución como script independiente.

import { randomBytes } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { cargarConfig } from './config.js';
import { crearCliente, codigoError, reintentarEn, etiquetaEstado } from './http.js';
import { analizarOtpauth, codigoNuevo, pasoActual } from './totp.js';
import { color, marca, registro, tabla, titulo, usarColor } from './consola.js';
import { dormir, formatearDistribucion } from './metricas.js';
import { soportaOrigenes } from './servicio.js';

/** Identificador corto de esta ejecución, para que los user_ref de prueba no choquen. */
export const ID_EJECUCION = `${Date.now().toString(36)}${randomBytes(2).toString('hex')}`;
let contadorUsuarios = 0;

/**
 * Segundo octeto de loopback propio de esta ejecución (127.<octeto>.<escenario>.<n>). El detector
 * local de anomalías puntúa por IP de origen; separar orígenes por ejecución y por escenario evita
 * que el historial de un ataque contamine el siguiente (o la siguiente ejecución en la demo).
 */
export const OCTETO_EJECUCION = 1 + (randomBytes(1)[0] % 250);

/** Envuelve un cliente para que todas sus peticiones salgan por `origen` salvo que se indique otro. */
export function conOrigen(cliente, origen) {
  const peticion = (metodo, ruta, op = {}) => cliente.peticion(metodo, ruta, { origen, ...op });
  return {
    ...cliente,
    origen,
    peticion,
    get: (ruta, op) => peticion('GET', ruta, op),
    post: (ruta, cuerpo, op = {}) => peticion('POST', ruta, { ...op, cuerpo }),
  };
}

/** user_ref opaco y único de prueba (nunca datos personales). */
export const nuevoUserRef = (prefijo = 'lab') => `${prefijo}-${ID_EJECUCION}-${++contadorUsuarios}`;

/**
 * Crea el contexto compartido por los escenarios.
 * @param {ReturnType<typeof cargarConfig>} config
 */
export function crearContexto(config) {
  usarColor(config.color);
  const [app1, app2] = config.apps;
  const opcionesCliente = { url: config.url, ca: config.ca, inseguro: config.inseguro, timeoutMs: config.timeoutMs };
  const cliente = crearCliente({ ...opcionesCliente, ...(app1 ?? {}) });
  const cliente2 = app2 ? crearCliente({ ...opcionesCliente, ...app2 }) : null;
  /** @type {Promise<boolean> | null} */
  let soporte = null;
  return {
    config,
    cliente,
    cliente2,
    /** ¿Se pueden usar direcciones 127.x de origen? (se comprueba una vez). */
    puedeSimularOrigenes() {
      if (config.opciones['sin-origenes']) return Promise.resolve(false);
      soporte ??= soportaOrigenes(cliente);
      return soporte;
    },
    /** Opciones de petición con origen simulado si la plataforma lo permite. */
    async opOrigen(ip) { return (await this.puedeSimularOrigenes()) ? { origen: ip } : {}; },
    /** Bloque de orígenes del escenario actual (lo fija contextoEscenario). */
    bloque: 1,
    /** Dirección n (2–254) del bloque del escenario: 127.<ejecución>.<bloque>.<n>. */
    ip(n) { return `127.${OCTETO_EJECUCION}.${this.bloque}.${n}`; },
    /** k direcciones consecutivas del bloque a partir de `desde`. */
    ips(k, desde = 10) { return Array.from({ length: Math.min(k, 254 - desde) }, (_, i) => this.ip(desde + i)); },
    /** Crea otro cliente (p. ej. hacia el proxy de caos) con las mismas credenciales. */
    clienteHacia: (url, extra = {}) => crearCliente({ ...opcionesCliente, ...(app1 ?? {}), ...extra, url }),
    log: (...p) => { if (config.detallado) registro(...p); },
    cerrar() { cliente.cerrar(); cliente2?.cerrar(); },
  };
}

/**
 * Acumulador de resultados de un escenario.
 * @param {string} id @param {string} nombre @param {string} demuestra
 */
export function crearResultado(id, nombre, demuestra) {
  const inicio = Date.now();
  /** @type {{ descripcion: string, esperado: string, obtenido: string, ok: boolean | null }[]} */
  const verificaciones = [];
  /** @type {Record<string, unknown>} */
  const metricas = {};
  /** @type {string[]} */
  const notas = [];
  /** @type {string[]} */
  const hallazgos = [];
  return {
    /** ok=null registra una observación informativa que no cuenta como fallo. */
    verificar(descripcion, esperado, obtenido, ok) {
      verificaciones.push({ descripcion, esperado: String(esperado), obtenido: String(obtenido), ok: ok === null ? null : Boolean(ok) });
      return ok;
    },
    metrica(clave, valor) { metricas[clave] = valor; },
    nota(texto) { notas.push(texto); },
    /** Hallazgo de seguridad sobre el backend (se reporta, no se corrige aquí). */
    hallazgo(texto) { hallazgos.push(texto); },
    cerrar(error = null) {
      if (error) {
        verificaciones.push({ descripcion: 'Ejecución del escenario', esperado: 'sin errores del laboratorio', obtenido: String(error.message ?? error), ok: false });
      }
      const evaluadas = verificaciones.filter((v) => v.ok !== null);
      return {
        id, nombre, demuestra,
        ok: evaluadas.length > 0 && evaluadas.every((v) => v.ok),
        verificaciones, metricas, notas, hallazgos,
        inicio: new Date(inicio).toISOString(),
        duracionMs: Date.now() - inicio,
      };
    },
  };
}

/** Error del laboratorio cuando falta algo para poder ejecutar (credenciales, servicio caído…). */
export class ErrorPrecondicion extends Error {}

/** Exige credenciales de app de prueba. */
export function exigirCredenciales(ctx) {
  if (!ctx.config.apps.length) {
    throw new ErrorPrecondicion('Faltan credenciales de app de prueba: usa --client-id/--client-secret, ATTACK_CLIENT_ID/ATTACK_CLIENT_SECRET o --credenciales archivo.json');
  }
}

/**
 * Petición de PREPARACIÓN (no de ataque): si el servicio responde 429, espera lo indicado y reintenta.
 * Así los límites provocados por un escenario anterior no invalidan el siguiente.
 */
export async function peticionPreparacion(cliente, metodo, ruta, op = {}, { maxEsperaMs = 90000 } = {}) {
  const limite = Date.now() + maxEsperaMs;
  for (;;) {
    const r = await cliente.peticion(metodo, ruta, op);
    if (r.status !== 429 || Date.now() > limite) return r;
    const s = Math.min(Math.max(reintentarEn(r) ?? 2, 1), 30);
    await dormir(s * 1000 + 200);
  }
}

/**
 * Crea y activa un usuario de prueba vía la API pública (enrolamiento + activación con el primer código).
 * @returns {Promise<{ userRef: string, enrollmentId: string, datos: import('./totp.js').DatosTotp, ultimoPaso: number, recoveryCodes: string[] }>}
 */
export async function crearUsuarioPrueba(ctx, { cliente = ctx.cliente, userRef = nuevoUserRef(), politica = {}, ventana = ctx.config.ventana } = {}) {
  const alta = await peticionPreparacion(cliente, 'POST', '/api/v1/enrollments', { cuerpo: { user_ref: userRef, ...politica } });
  if (alta.status !== 201 || !alta.cuerpo?.otpauth_uri || !alta.cuerpo?.enrollment_id) {
    throw new ErrorPrecondicion(`No se pudo crear el enrolamiento de prueba (${etiquetaEstado(alta)} ${codigoError(alta) ?? alta.texto.slice(0, 120)})`);
  }
  const datos = analizarOtpauth(alta.cuerpo.otpauth_uri);
  // Se activa con el código del paso ACTUAL (deriva 0), como haría la app autenticadora.
  const usuario = { userRef, enrollmentId: alta.cuerpo.enrollment_id, datos, ultimoPaso: pasoActual(datos) - 1, deriva: 0, recoveryCodes: [] };
  const { codigo } = await codigoNuevo(usuario, { ventana: 0 });
  const act = await peticionPreparacion(cliente, 'POST', `/api/v1/enrollments/${encodeURIComponent(usuario.enrollmentId)}/activate`, { cuerpo: { code: codigo } });
  if (act.status !== 200) {
    throw new ErrorPrecondicion(`No se pudo activar el enrolamiento de prueba (${etiquetaEstado(act)} ${codigoError(act) ?? ''})`);
  }
  usuario.recoveryCodes = act.cuerpo?.recovery_codes ?? [];
  ctx.log(`usuario de prueba ${userRef} activo (${datos.algoritmo}, ${datos.digitos} dígitos, ${datos.periodo} s)`);
  return usuario;
}

/** Comprueba /health; devuelve la respuesta. */
export const sondearSalud = (cliente, ruta = '/health', timeoutMs = 2000) => cliente.peticion('GET', ruta, { timeoutMs, sinCredenciales: true });

/** Imprime el resultado de un escenario en la consola. */
export function imprimirResultado(res) {
  console.log(titulo(`${res.nombre} ${marca(res.ok)}`));
  console.log(color('gris', res.demuestra));
  console.log(tabla(['Verificación', 'Esperado', 'Obtenido', ''], res.verificaciones.map((v) => [v.descripcion, v.esperado, v.obtenido, marca(v.ok)])));
  const met = Object.entries(res.metricas);
  if (met.length) {
    console.log(tabla(['Métrica', 'Valor'], met.map(([k, v]) => [k, formatearValor(v)]), { anchoMax: 90 }));
  }
  for (const n of res.notas) console.log(color('amarillo', `  nota: ${n}`));
  for (const h of res.hallazgos) console.log(color('rojo', `  hallazgo: ${h}`));
  console.log(color('gris', `  duración: ${(res.duracionMs / 1000).toFixed(1)} s`));
}

/** Representación compacta de un valor de métrica. */
export function formatearValor(v) {
  if (v === null || v === undefined) return '—';
  if (typeof v !== 'object') return String(v);
  if (Object.values(v).every((x) => typeof x === 'number' || x === null)) {
    if ('p50' in v) return `p50 ${v.p50 ?? '—'} ms · p95 ${v.p95 ?? '—'} ms · máx ${v.max ?? '—'} ms (n=${v.n})`;
    // Distribución de estados ("200", "429", "ECONNREFUSED"…) o contadores con nombre.
    if (Object.keys(v).every((k) => /^(\d{3}|[A-Z_]+)$/.test(k))) return formatearDistribucion(v);
    return Object.entries(v).map(([k, x]) => `${k}=${x}`).join(' · ');
  }
  return JSON.stringify(v);
}

/**
 * Ejecuta un escenario con manejo de errores; siempre devuelve un resultado.
 * @param {{ id: string, nombre: string, demuestra: string, ejecutar: (ctx: any, res: any) => Promise<void> }} escenario
 */
export async function correrEscenario(escenario, ctx, bloque = 1) {
  const res = crearResultado(escenario.id, escenario.nombre, escenario.demuestra);
  try {
    await escenario.ejecutar(await contextoEscenario(ctx, bloque), res);
    return res.cerrar();
  } catch (e) {
    return res.cerrar(e);
  }
}

/**
 * Contexto propio de un escenario: mismo config y credenciales, pero sus clientes salen por defecto
 * desde 127.<ejecución>.<bloque>.2 (si la plataforma lo permite).
 */
export async function contextoEscenario(ctx, bloque) {
  const esc = Object.create(ctx);
  esc.bloque = bloque;
  if (await ctx.puedeSimularOrigenes()) {
    esc.cliente = conOrigen(ctx.cliente, esc.ip(2));
    esc.cliente2 = ctx.cliente2 ? conOrigen(ctx.cliente2, esc.ip(3)) : null;
  }
  return esc;
}

/** ¿Este módulo es el punto de entrada (node archivo.js)? */
export function esPrincipal(importMetaUrl) {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(fileURLToPath(importMetaUrl)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
}

/** Punto de entrada común: carga configuración, corre el escenario, imprime y sale con código 0/1. */
export async function principal(escenario) {
  let ctx;
  try {
    const config = cargarConfig();
    ctx = crearContexto(config);
    const res = await correrEscenario(escenario, ctx);
    if (config.opciones.json) console.log(JSON.stringify(res, null, 2));
    else imprimirResultado(res);
    process.exitCode = res.ok ? 0 : 1;
  } catch (e) {
    console.error(color('rojo', `Error: ${e.message}`));
    process.exitCode = 2;
  } finally {
    ctx?.cerrar();
  }
}
