// Cliente HTTPS mínimo para el laboratorio (node:https / node:http). Nunca lanza por errores
// de red: devuelve { status: 0, error } para poder medir cortes, reinicios y tiempos de espera.

import http from 'node:http';
import https from 'node:https';
import { readFileSync } from 'node:fs';
import { esHostLocal } from './config.js';

/**
 * @typedef {{
 *   status: number, cabeceras: Record<string, string | string[] | undefined>, texto: string,
 *   cuerpo: any, ms: number, error: string | null
 * }} Respuesta
 */

/**
 * @param {{
 *   url: string, ca?: string | null, inseguro?: boolean, clientId?: string, clientSecret?: string,
 *   timeoutMs?: number, keepAlive?: boolean, maxSockets?: number
 * }} opciones
 */
export function crearCliente({ url, ca = null, inseguro = false, clientId, clientSecret, timeoutMs = 5000, keepAlive = true, maxSockets = 64 }) {
  const base = new URL(url);
  const esHttps = base.protocol === 'https:';
  if (inseguro && !esHostLocal(base.hostname)) throw new Error('El modo inseguro solo se permite contra localhost.');
  const modulo = esHttps ? https : http;
  const agente = new modulo.Agent({
    keepAlive,
    maxSockets,
    ...(esHttps ? { ca: ca ? readFileSync(ca) : undefined, rejectUnauthorized: !inseguro, minVersion: 'TLSv1.2' } : {}),
  });

  /**
   * @param {string} metodo @param {string} ruta
   * @param {{ cuerpo?: any, crudo?: string | Buffer, cabeceras?: Record<string, string>, timeoutMs?: number,
   *           sinCredenciales?: boolean, credenciales?: { clientId: string, clientSecret: string },
   *           origen?: string, sinLongitud?: boolean }} [op]
   *   origen: dirección local de salida (p. ej. 127.0.0.23) para simular otro cliente en loopback.
   *   sinLongitud: envía el cuerpo con Transfer-Encoding: chunked (sin Content-Length).
   * @returns {Promise<Respuesta>}
   */
  function peticion(metodo, ruta, op = {}) {
    const inicio = performance.now();
    const cabeceras = { accept: 'application/json', ...(op.cabeceras ?? {}) };
    const cred = op.credenciales ?? (clientId ? { clientId, clientSecret } : null);
    if (cred && !op.sinCredenciales) {
      cabeceras['x-client-id'] ??= cred.clientId;
      cabeceras['x-client-secret'] ??= cred.clientSecret;
    }
    let datos = null;
    if (op.crudo !== undefined) datos = Buffer.isBuffer(op.crudo) ? op.crudo : Buffer.from(op.crudo);
    else if (op.cuerpo !== undefined) datos = Buffer.from(JSON.stringify(op.cuerpo));
    if (datos) {
      cabeceras['content-type'] ??= 'application/json';
      if (!op.sinLongitud) cabeceras['content-length'] = String(datos.length);
    }
    const limite = op.timeoutMs ?? timeoutMs;

    return new Promise((resolver) => {
      let terminado = false;
      const fin = (r) => {
        if (terminado) return;
        terminado = true;
        clearTimeout(temporizador);
        resolver({ ms: performance.now() - inicio, ...r });
      };
      const opcionesReq = { method: metodo, headers: cabeceras, agent: agente };
      if (op.origen) Object.assign(opcionesReq, { localAddress: op.origen, family: op.origen.includes(':') ? 6 : 4 });
      const req = modulo.request(new URL(ruta, base), opcionesReq, (res) => {
        const trozos = [];
        res.on('data', (t) => trozos.push(t));
        res.on('error', (e) => fin({ status: 0, cabeceras: {}, texto: '', cuerpo: null, error: e.code ?? e.message }));
        res.on('end', () => {
          const texto = Buffer.concat(trozos).toString('utf8');
          let cuerpo = null;
          try { cuerpo = texto ? JSON.parse(texto) : null; } catch { cuerpo = null; }
          fin({ status: res.statusCode ?? 0, cabeceras: res.headers, texto, cuerpo, error: null });
        });
      });
      const temporizador = setTimeout(() => {
        req.destroy(new Error('TIEMPO_AGOTADO'));
        fin({ status: 0, cabeceras: {}, texto: '', cuerpo: null, error: 'TIEMPO_AGOTADO' });
      }, limite);
      req.on('error', (e) => fin({
        status: 0, cabeceras: {}, texto: '', cuerpo: null,
        error: e.message === 'TIEMPO_AGOTADO' ? 'TIEMPO_AGOTADO' : (e.code ?? e.message),
      }));
      if (datos && op.sinLongitud) {
        // Se envía en trozos para forzar la codificación chunked.
        for (let i = 0; i < datos.length; i += 64 * 1024) req.write(datos.subarray(i, i + 64 * 1024));
        req.end();
      } else if (datos) req.end(datos);
      else req.end();
    });
  }

  return {
    base,
    peticion,
    get: (ruta, op) => peticion('GET', ruta, op),
    post: (ruta, cuerpo, op = {}) => peticion('POST', ruta, { ...op, cuerpo }),
    cerrar: () => agente.destroy(),
  };
}

/** Código de error del cuerpo genérico (GenericError.error) o del mock (errorCode). */
export const codigoError = (r) => r?.cuerpo?.error ?? r?.cuerpo?.errorCode ?? null;
/** Segundos de reintento: cuerpo.retry_after_seconds o cabecera Retry-After. */
export function reintentarEn(r) {
  const v = r?.cuerpo?.retry_after_seconds ?? r?.cuerpo?.retryAfterSeconds ?? r?.cabeceras?.['retry-after'];
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
/** Etiqueta corta para tablas: "200", "429" o "TIEMPO_AGOTADO". */
export const etiquetaEstado = (r) => (r.status ? String(r.status) : r.error ?? 'ERROR');
