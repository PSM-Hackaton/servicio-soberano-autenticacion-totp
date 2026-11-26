// Transporte HTTP(S) mínimo sobre node:https / node:http con plazo total y límite de tamaño.

import http from 'node:http';
import https from 'node:https';
import { ErrorTotp, CODIGOS_LOCALES } from './errores.js';

const MAX_RESPUESTA = 1024 * 1024; // 1 MiB: ninguna respuesta del contrato se acerca a esto.
const HOSTS_LOCALES = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

/**
 * Valida la URL base. HTTP en claro solo se admite contra el propio equipo (pruebas):
 * las credenciales de la app nunca viajan sin TLS por la red.
 * @param {string} baseUrl @returns {URL}
 */
export function validarBaseUrl(baseUrl) {
  let url;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new ErrorTotp('baseUrl inválida', { codigo: CODIGOS_LOCALES.CONFIGURACION });
  }
  if (url.protocol === 'http:' && !HOSTS_LOCALES.has(url.hostname)) {
    throw new ErrorTotp('HTTP sin TLS solo se permite contra localhost', { codigo: CODIGOS_LOCALES.CONFIGURACION });
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ErrorTotp('baseUrl debe usar https://', { codigo: CODIGOS_LOCALES.CONFIGURACION });
  }
  if (url.username || url.password) {
    throw new ErrorTotp('baseUrl no debe contener credenciales', { codigo: CODIGOS_LOCALES.CONFIGURACION });
  }
  return url;
}

/**
 * Crea el agente con keep-alive. Con `ca` se confía SOLO en esa CA (p. ej. la CA local del servicio).
 * @param {URL} url @param {{ ca?: string | Buffer | Array<string | Buffer> }} opciones
 */
export function crearAgente(url, { ca } = {}) {
  if (url.protocol === 'http:') return new http.Agent({ keepAlive: true, maxSockets: 16 });
  return new https.Agent({
    keepAlive: true,
    maxSockets: 16,
    minVersion: 'TLSv1.2',
    ...(ca ? { ca } : {}),
  });
}

/**
 * Ejecuta una petición. Rechaza con ErrorTotp (ERROR_RED o TIEMPO_AGOTADO) si no hay respuesta completa.
 * @param {{ url: URL, metodo: string, cabeceras: Record<string, string>, cuerpo?: string, timeoutMs: number, agente: any, operacion: string }} p
 * @returns {Promise<{ status: number, cabeceras: import('node:http').IncomingHttpHeaders, cuerpo: Buffer }>}
 */
export function peticion({ url, metodo, cabeceras, cuerpo, timeoutMs, agente, operacion }) {
  const modulo = url.protocol === 'https:' ? https : http;
  return new Promise((resolver, rechazar) => {
    let terminado = false;
    const fin = (fn, valor) => {
      if (terminado) return;
      terminado = true;
      clearTimeout(temporizador);
      fn(valor);
    };

    const req = modulo.request(url, {
      method: metodo,
      agent: agente,
      headers: {
        ...cabeceras,
        ...(cuerpo !== undefined ? { 'Content-Length': Buffer.byteLength(cuerpo) } : {}),
      },
    }, (res) => {
      const trozos = [];
      let total = 0;
      res.on('data', (t) => {
        total += t.length;
        if (total > MAX_RESPUESTA) {
          req.destroy();
          fin(rechazar, new ErrorTotp('Respuesta demasiado grande', { codigo: CODIGOS_LOCALES.RESPUESTA_INVALIDA, operacion }));
          return;
        }
        trozos.push(t);
      });
      res.on('end', () => fin(resolver, { status: res.statusCode ?? 0, cabeceras: res.headers, cuerpo: Buffer.concat(trozos) }));
      res.on('error', (e) => fin(rechazar, errorRed(e, operacion)));
      res.on('aborted', () => fin(rechazar, errorRed(new Error('respuesta interrumpida'), operacion)));
    });

    // Plazo total (conexión + TLS + respuesta), no solo inactividad del socket.
    const temporizador = setTimeout(() => {
      fin(rechazar, new ErrorTotp(`El servicio no respondió en ${timeoutMs} ms`, {
        codigo: CODIGOS_LOCALES.TIEMPO_AGOTADO, operacion,
      }));
      req.destroy();
    }, timeoutMs);

    req.on('error', (e) => fin(rechazar, errorRed(e, operacion)));
    if (cuerpo !== undefined) req.write(cuerpo);
    req.end();
  });
}

/** @param {any} e @param {string} operacion */
function errorRed(e, operacion) {
  // Solo el código del sistema (ECONNREFUSED, CERT_HAS_EXPIRED…), nunca cabeceras ni cuerpo.
  const detalle = typeof e?.code === 'string' ? e.code : 'desconocido';
  return new ErrorTotp(`No se pudo contactar con el servicio (${detalle})`, {
    codigo: CODIGOS_LOCALES.ERROR_RED, operacion, causa: e,
  });
}
