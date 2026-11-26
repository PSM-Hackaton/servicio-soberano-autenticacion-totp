#!/usr/bin/env node
// Escenario DAST (Dynamic Application Security Testing) propio, sin herramientas externas.
// Audita en vivo todas las rutas del servicio: TLS 1.3 (rechazo de TLS <= 1.2), cabeceras OWASP,
// métodos HTTP peligrosos/no permitidos, CORS estricto, atributos de cookies/sesión, aislamiento
// de /metrics y respuestas de error sin fugas de información interna.
//
// Uso independiente:
//   node attack-lab/escenarios/dast.js --url https://localhost:8443 --ca backend/certs/ca.crt [--salida docs/evidencias]

import tls from 'node:tls';
import { isIP } from 'node:net';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { RAIZ_LAB, cargarConfig } from '../lib/config.js';
import { color } from '../lib/consola.js';
import { correrEscenario, crearContexto, esPrincipal, imprimirResultado } from '../lib/escenario.js';
import { codigoError, etiquetaEstado } from '../lib/http.js';
import { escribirInforme, resumir } from '../lib/informe.js';
import { filtraDetallesInternos } from '../lib/servicio.js';

export const id = 'dast';
export const nombre = 'Escaneo dinámico de seguridad (DAST propio)';
export const demuestra = 'TLS 1.3 estricto, cabeceras OWASP en todas las rutas, métodos 405, CORS cerrado, cookies seguras y respuestas de error sin filtraciones.';

const UUID_PRUEBA = '00000000-0000-4000-8000-000000000000';

/** Catálogo completo de rutas del contrato (públicas, estáticas, MFA v1 y consola admin). */
export const RUTAS_CONTRATO = Object.freeze([
  { metodo: 'GET', ruta: '/health', tipo: 'api', auth: 'publica' },
  { metodo: 'GET', ruta: '/health/ready', tipo: 'api', auth: 'publica' },
  { metodo: 'GET', ruta: '/.well-known/jwks.json', tipo: 'jwks', auth: 'publica' },
  { metodo: 'GET', ruta: '/ca.crt', tipo: 'api', auth: 'publica' },
  { metodo: 'GET', ruta: '/metrics', tipo: 'texto', auth: 'loopback' },
  { metodo: 'GET', ruta: '/app/', tipo: 'estatico', auth: 'publica' },
  { metodo: 'GET', ruta: '/consola/', tipo: 'estatico', auth: 'publica' },
  { metodo: 'POST', ruta: '/api/v1/enrollments', tipo: 'api', auth: 'app' },
  { metodo: 'POST', ruta: `/api/v1/enrollments/${UUID_PRUEBA}/activate`, tipo: 'api', auth: 'app' },
  { metodo: 'POST', ruta: '/api/v1/verify', tipo: 'api', auth: 'app' },
  { metodo: 'POST', ruta: '/api/v1/tokens/validate', tipo: 'api', auth: 'app' },
  { metodo: 'POST', ruta: `/api/v1/enrollments/${UUID_PRUEBA}/resync`, tipo: 'api', auth: 'app' },
  { metodo: 'POST', ruta: '/api/v1/recovery', tipo: 'api', auth: 'app' },
  { metodo: 'DELETE', ruta: `/api/v1/enrollments/${UUID_PRUEBA}`, tipo: 'api', auth: 'app' },
  { metodo: 'POST', ruta: '/admin/api/login', tipo: 'api', auth: 'publica' },
  { metodo: 'GET', ruta: '/admin/api/session', tipo: 'api', auth: 'admin' },
  { metodo: 'POST', ruta: '/admin/api/logout', tipo: 'api', auth: 'admin' },
  { metodo: 'GET', ruta: '/admin/api/apps', tipo: 'api', auth: 'admin' },
  { metodo: 'GET', ruta: '/admin/api/enrollments', tipo: 'api', auth: 'admin' },
  { metodo: 'POST', ruta: '/admin/api/keys/rotate', tipo: 'api', auth: 'admin' },
  { metodo: 'GET', ruta: '/admin/api/audit', tipo: 'api', auth: 'admin' },
  { metodo: 'GET', ruta: '/admin/api/audit/verify-chain', tipo: 'api', auth: 'admin' },
  { metodo: 'GET', ruta: '/admin/api/anomalies', tipo: 'api', auth: 'admin' },
  { metodo: 'GET', ruta: '/admin/api/metrics', tipo: 'api', auth: 'admin' },
  { metodo: 'GET', ruta: '/admin/api/keys', tipo: 'api', auth: 'admin' },
  { metodo: 'POST', ruta: '/admin/api/apps', tipo: 'api', auth: 'admin' },
  { metodo: 'POST', ruta: `/admin/api/apps/${UUID_PRUEBA}/secret`, tipo: 'api', auth: 'admin' },
  { metodo: 'POST', ruta: `/admin/api/enrollments/${UUID_PRUEBA}/suspend`, tipo: 'api', auth: 'admin' },
  { metodo: 'POST', ruta: `/admin/api/enrollments/${UUID_PRUEBA}/reactivate`, tipo: 'api', auth: 'admin' },
  { metodo: 'POST', ruta: `/admin/api/enrollments/${UUID_PRUEBA}/revoke`, tipo: 'api', auth: 'admin' },
  { metodo: 'GET', ruta: '/admin/api/admins', tipo: 'api', auth: 'admin' },
  { metodo: 'POST', ruta: '/admin/api/admins', tipo: 'api', auth: 'admin' },
  { metodo: 'POST', ruta: `/admin/api/admins/${UUID_PRUEBA}/disable`, tipo: 'api', auth: 'admin' },
  { metodo: 'GET', ruta: '/ruta-inexistente-dast', tipo: 'error', auth: 'publica' },
]);

/**
 * Realiza una conexión TLS directa para comprobar protocolo negociado, cifrado y certificado.
 * @param {URL} base
 * @param {{ ca?: string | null, inseguro?: boolean, minVersion?: string, maxVersion?: string, timeoutMs?: number }} op
 */
export function probarHandshakeTls(base, { ca = null, inseguro = false, minVersion, maxVersion, timeoutMs = 4000 } = {}) {
  return new Promise((resolver) => {
    let terminado = false;
    const fin = (r) => {
      if (terminado) return;
      terminado = true;
      clearTimeout(temporizador);
      resolver(r);
    };
    const opciones = {
      host: base.hostname,
      port: Number(base.port) || 443,
      ...(isIP(base.hostname) ? {} : { servername: base.hostname }),
      rejectUnauthorized: !inseguro,
      ...(ca ? { ca: readFileSync(ca) } : {}),
      ...(minVersion ? { minVersion } : {}),
      ...(maxVersion ? { maxVersion } : {}),
    };
    const socket = tls.connect(opciones, () => {
      const protocolo = socket.getProtocol();
      const cifrado = socket.getCipher();
      const cert = socket.getPeerCertificate(false);
      socket.end();
      fin({
        conectado: true,
        protocolo,
        cifrado: cifrado?.name ?? null,
        autorizado: socket.authorized,
        certValidoDesde: cert?.valid_from ?? null,
        certValidoHasta: cert?.valid_to ?? null,
        error: null,
      });
    });
    const temporizador = setTimeout(() => {
      socket.destroy();
      fin({ conectado: false, protocolo: null, cifrado: null, autorizado: false, error: 'TIEMPO_AGOTADO' });
    }, timeoutMs);
    socket.on('error', (e) => {
      fin({ conectado: false, protocolo: null, cifrado: null, autorizado: false, error: e.code ?? e.message });
    });
  });
}

/**
 * Audita las cabeceras de seguridad OWASP de una respuesta HTTP.
 * @param {Record<string, string | string[] | undefined>} cabeceras
 * @param {{ ruta: string, tipo: string, esHttps: boolean }} meta
 * @returns {{ faltantes: string[], avisos: string[], inseguras: string[] }}
 */
export function auditarCabecerasRespuesta(cabeceras, { ruta, tipo, esHttps }) {
  const get = (k) => {
    const v = cabeceras[k.toLowerCase()];
    return Array.isArray(v) ? v.join(', ') : (v ?? '');
  };
  const faltantes = [];
  const inseguras = [];
  const avisos = [];

  if (get('x-content-type-options').toLowerCase() !== 'nosniff') faltantes.push('X-Content-Type-Options: nosniff');
  if (!/^(deny|sameorigin)$/i.test(get('x-frame-options'))) faltantes.push('X-Frame-Options');
  if (!get('referrer-policy')) faltantes.push('Referrer-Policy');
  if (!get('permissions-policy')) faltantes.push('Permissions-Policy');
  if (!get('cross-origin-opener-policy')) faltantes.push('Cross-Origin-Opener-Policy');
  if (!get('cross-origin-resource-policy')) faltantes.push('Cross-Origin-Resource-Policy');

  const csp = get('content-security-policy');
  if (!csp) faltantes.push('Content-Security-Policy');
  else if (/unsafe-inline|unsafe-eval/i.test(csp)) inseguras.push(`CSP permisiva (${csp})`);

  if (esHttps) {
    const hsts = get('strict-transport-security');
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    if (!maxAgeMatch || Number(maxAgeMatch[1]) < 31_536_000) {
      faltantes.push('Strict-Transport-Security (>=1 año)');
    }
  }

  if (tipo === 'api' && !/no-store/i.test(get('cache-control'))) {
    faltantes.push('Cache-Control: no-store');
  }

  if (get('x-powered-by')) inseguras.push(`X-Powered-By expuesto (${get('x-powered-by')})`);
  if (get('server')) inseguras.push(`Server expuesto (${get('server')})`);

  // Observación específica sobre la cámara en la PWA (/app/) — referencia Issue #20 (C2)
  if (ruta === '/app/' && /camera=\(\s*\)/i.test(get('permissions-policy'))) {
    avisos.push('Permissions-Policy en /app/ bloquea camera=() (impide escáner QR por cámara; ver Issue #20 C2)');
  }

  return { faltantes, avisos, inseguras };
}

/**
 * Audita una cabecera Set-Cookie para sesiones administrativas.
 * @param {string | string[] | undefined} setCookieHeader
 * @param {{ esHttps: boolean }} meta
 */
export function auditarCookies(setCookieHeader, { esHttps }) {
  const lista = Array.isArray(setCookieHeader) ? setCookieHeader : (setCookieHeader ? [setCookieHeader] : []);
  const problemas = [];
  for (const raw of lista) {
    const partes = raw.split(';').map((p) => p.trim());
    const nombre = partes[0]?.split('=')[0] || '(sin nombre)';
    const flags = partes.slice(1).map((f) => f.toLowerCase());
    if (!flags.includes('httponly')) problemas.push(`${nombre}: falta HttpOnly`);
    if (esHttps && !flags.includes('secure')) problemas.push(`${nombre}: falta Secure`);
    if (!flags.some((f) => f === 'samesite=strict' || f === 'samesite=lax')) {
      problemas.push(`${nombre}: falta SameSite=Strict`);
    }
  }
  return { total: lista.length, problemas };
}

/**
 * Audita que una respuesta a un origen no autorizado no filtre permisos CORS indebidos.
 * @param {Record<string, string | string[] | undefined>} cabeceras
 * @param {string} origenAtacante
 */
export function auditarCorsRespuesta(cabeceras, origenAtacante) {
  const acao = String(cabeceras['access-control-allow-origin'] ?? '').trim();
  const acac = String(cabeceras['access-control-allow-credentials'] ?? '').trim().toLowerCase();
  const problemas = [];
  if (acao === '*') problemas.push('Access-Control-Allow-Origin: * (comodín abierto)');
  if (acao && acao.toLowerCase() === origenAtacante.toLowerCase()) {
    problemas.push(`Refleja origen no autorizado (${acao})`);
  }
  if (acao === '*' && acac === 'true') {
    problemas.push('Combina Access-Control-Allow-Origin: * con Allow-Credentials: true');
  }
  return { ok: problemas.length === 0, acao, acac, problemas };
}

export async function ejecutar(ctx, res) {
  const { cliente, config } = ctx;
  const base = cliente.base;
  const esHttps = base.protocol === 'https:';
  const metricas = {
    rutasAuditadas: 0,
    cabecerasOk: 0,
    metodosRechazadosOk: 0,
    corsOk: 0,
    errores5xx: 0,
    fugasDetectadas: 0,
  };

  // 1. AUDITORÍA TLS (solo si el destino es HTTPS)
  if (esHttps) {
    const tls13 = await probarHandshakeTls(base, {
      ca: config.ca,
      inseguro: config.inseguro,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    });
    const cifradoFuerte = Boolean(tls13.cifrado && /^TLS_(AES_256_GCM|CHACHA20_POLY1305|AES_128_GCM)/i.test(tls13.cifrado));
    res.verificar(
      'TLS 1.3 negociado con cifrado AEAD moderno',
      'TLSv1.3 + cifrado AEAD',
      tls13.conectado ? `${tls13.protocolo} · ${tls13.cifrado}` : `error ${tls13.error}`,
      tls13.conectado && tls13.protocolo === 'TLSv1.3' && cifradoFuerte,
    );
    if (!tls13.conectado) res.hallazgo(`Fallo de handshake TLS 1.3: ${tls13.error}`);

    const tls12 = await probarHandshakeTls(base, {
      ca: config.ca,
      inseguro: true,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
    });
    res.verificar(
      'TLS 1.2 y versiones antiguas rechazados',
      'conexión rechazada',
      tls12.conectado ? `ACEPTADO (${tls12.protocolo})` : `rechazado (${tls12.error})`,
      !tls12.conectado,
    );
    if (tls12.conectado) res.hallazgo(`El servidor aceptó TLS antiguo (${tls12.protocolo}); debe exigir TLS 1.3.`);

    if (tls13.certValidoHasta) {
      const expMs = Date.parse(tls13.certValidoHasta);
      const vigente = Number.isFinite(expMs) && expMs > Date.now();
      res.verificar('Certificado TLS vigente', 'no expirado', tls13.certValidoHasta, vigente);
      if (!vigente) res.hallazgo(`Certificado TLS expirado: ${tls13.certValidoHasta}`);
    }
    res.metrica('tlsProtocolo', tls13.protocolo ?? 'error');
    res.metrica('tlsCifrado', tls13.cifrado ?? 'error');
  } else {
    res.nota('Destino HTTP (sin TLS): se omiten las sondas de handshake TLS 1.3.');
  }

  // 2. AUDITORÍA DE CABECERAS, RESPUESTAS DE ERROR Y CONTROL DE ACCESO EN TODAS LAS RUTAS
  const fallosCabeceras = [];
  const avisosCabeceras = [];
  const fallosErrorGenerico = [];
  const adminSinSesionFallos = [];
  let politicaPwa = '';

  for (const item of RUTAS_CONTRATO) {
    metricas.rutasAuditadas++;
    const sinCred = item.auth !== 'app' || !config.apps.length;
    const op = { sinCredenciales: sinCred, timeoutMs: 5000 };
    if (item.metodo === 'POST') op.cuerpo = {};
    const r = await cliente.peticion(item.metodo, item.ruta, op);

    if (r.status >= 500 || r.status === 0) {
      metricas.errores5xx++;
      res.hallazgo(`${item.metodo} ${item.ruta} devolvió ${etiquetaEstado(r)}`);
    }

    if (filtraDetallesInternos(r.texto)) {
      metricas.fugasDetectadas++;
      res.hallazgo(`${item.metodo} ${item.ruta} filtra detalles internos en la respuesta`);
    }

    const cab = auditarCabecerasRespuesta(r.cabeceras, { ruta: item.ruta, tipo: item.tipo, esHttps });
    if (cab.faltantes.length === 0 && cab.inseguras.length === 0) {
      metricas.cabecerasOk++;
    } else {
      fallosCabeceras.push(`${item.ruta}: ${[...cab.faltantes, ...cab.inseguras].join(', ')}`);
    }
    for (const av of cab.avisos) avisosCabeceras.push(av);
    if (item.ruta === '/app/') politicaPwa = String(r.cabeceras['permissions-policy'] ?? '');

    // En rutas API con respuesta 4xx, exige formato GenericError { error, message }
    if (item.tipo === 'api' && r.status >= 400 && r.status < 500) {
      if (!r.cuerpo || typeof r.cuerpo.error !== 'string' || typeof r.cuerpo.message !== 'string') {
        fallosErrorGenerico.push(`${item.metodo} ${item.ruta} (${r.status})`);
      }
    }

    // Rutas administrativas protegidas deben exigir sesión (401 sin cookie)
    if (item.auth === 'admin' && r.status !== 401) {
      adminSinSesionFallos.push(`${item.metodo} ${item.ruta} → ${r.status}`);
    }

    // Si alguna respuesta emite Set-Cookie, auditar atributos
    if (r.cabeceras['set-cookie']) {
      const ck = auditarCookies(r.cabeceras['set-cookie'], { esHttps });
      if (ck.problemas.length) {
        res.hallazgo(`Cookie insegura en ${item.ruta}: ${ck.problemas.join('; ')}`);
      }
    }
  }

  res.verificar(
    `Cabeceras OWASP en todas las rutas (${metricas.rutasAuditadas} rutas)`,
    `${metricas.rutasAuditadas}/${metricas.rutasAuditadas} sin faltantes ni huellas`,
    fallosCabeceras.length ? `${metricas.cabecerasOk}/${metricas.rutasAuditadas} (${fallosCabeceras.slice(0, 2).join(' | ')})` : `${metricas.cabecerasOk}/${metricas.rutasAuditadas} OK`,
    fallosCabeceras.length === 0,
  );
  if (fallosCabeceras.length) res.hallazgo(`Cabeceras incompletas o huellas expuestas: ${fallosCabeceras.join(' ; ')}`);

  // La PWA necesita la cámara para leer el QR; el resto del servicio la mantiene bloqueada.
  res.verificar(
    'Política Permissions-Policy en PWA (/app/)',
    'camera=(self) para escáner QR',
    politicaPwa || '(sin cabecera)',
    /camera=\(self\)/i.test(politicaPwa),
  );
  for (const av of avisosCabeceras) res.nota(av);

  res.verificar(
    'Rutas administrativas protegidas sin sesión',
    '401 en todas las rutas /admin/api/* privadas',
    adminSinSesionFallos.length ? adminSinSesionFallos.join(', ') : 'todas devolvieron 401',
    adminSinSesionFallos.length === 0,
  );
  if (adminSinSesionFallos.length) res.hallazgo(`Rutas admin accesibles sin sesión: ${adminSinSesionFallos.join(', ')}`);

  res.verificar(
    'Errores genéricos y cero fugas internas / 5xx',
    '0 errores 5xx, 0 fugas, formato { error, message }',
    `5xx=${metricas.errores5xx}, fugas=${metricas.fugasDetectadas}, formatoInvalido=${fallosErrorGenerico.length}`,
    metricas.errores5xx === 0 && metricas.fugasDetectadas === 0 && fallosErrorGenerico.length === 0,
  );

  // 3. MÉTODOS HTTP NO PERMITIDOS Y PELIGROSOS
  const sondasMetodos = [
    { m: 'TRACE', r: '/health', esp: [400, 405, 501] },
    { m: 'DELETE', r: '/health', esp: [405] },
    { m: 'PUT', r: '/.well-known/jwks.json', esp: [405] },
    { m: 'PATCH', r: '/api/v1/verify', esp: [405] },
    { m: 'GET', r: '/api/v1/verify', esp: [405] },
    { m: 'PUT', r: '/admin/api/login', esp: [405] },
    { m: 'DELETE', r: '/admin/api/apps', esp: [405] },
  ];
  const fallosMetodos = [];
  for (const s of sondasMetodos) {
    const r = await cliente.peticion(s.m, s.r, {
      sinCredenciales: true,
      cabeceras: { 'x-dast-canary': 'CANARIO-NO-REFLEJAR' },
      timeoutMs: 4000,
    });
    const reflejaCanario = r.texto.includes('CANARIO-NO-REFLEJAR');
    if (s.esp.includes(r.status) && !reflejaCanario) {
      metricas.metodosRechazadosOk++;
    } else {
      fallosMetodos.push(`${s.m} ${s.r} → ${etiquetaEstado(r)}${reflejaCanario ? ' (REFLEJA TRACE)' : ''}`);
    }
  }
  res.verificar(
    'Métodos HTTP peligrosos / no permitidos (TRACE, PUT, PATCH, DELETE)',
    `${sondasMetodos.length}/${sondasMetodos.length} rechazados sin reflejo`,
    fallosMetodos.length ? fallosMetodos.join(', ') : `${metricas.metodosRechazadosOk}/${sondasMetodos.length} OK`,
    fallosMetodos.length === 0,
  );
  if (fallosMetodos.length) res.hallazgo(`Métodos no restringidos correctamente: ${fallosMetodos.join(', ')}`);

  // 4. CORS ESTRICTO (orígenes maliciosos y preflight OPTIONS)
  const origenesMaliciosos = ['https://atacante.invalid', 'null', 'http://evil.local:8080'];
  const fallosCors = [];
  for (const origen of origenesMaliciosos) {
    for (const [m, ruta] of [['GET', '/health'], ['OPTIONS', '/api/v1/verify'], ['OPTIONS', '/admin/api/login']]) {
      const r = await cliente.peticion(m, ruta, {
        sinCredenciales: true,
        cabeceras: {
          origin: origen,
          'access-control-request-method': 'POST',
          'access-control-request-headers': 'content-type,x-client-id,x-client-secret',
        },
        timeoutMs: 4000,
      });
      const evalCors = auditarCorsRespuesta(r.cabeceras, origen);
      if (evalCors.ok && r.status < 500) {
        metricas.corsOk++;
      } else {
        fallosCors.push(`${m} ${ruta} (${origen}): ${evalCors.problemas.join(', ') || etiquetaEstado(r)}`);
      }
    }
  }
  res.verificar(
    'CORS cerrado ante orígenes maliciosos y preflight OPTIONS',
    'sin comodín * ni reflejo de orígenes externos',
    fallosCors.length ? fallosCors.join(' | ') : `${metricas.corsOk} sondas CORS seguras`,
    fallosCors.length === 0,
  );
  if (fallosCors.length) res.hallazgo(`Fallo de política CORS: ${fallosCors.join(' ; ')}`);

  // 5. AISLAMIENTO LOOPBACK DE /metrics (si Linux permite orígenes 127.x)
  if (await ctx.puedeSimularOrigenes()) {
    const rMetrics = await cliente.peticion('GET', '/metrics', {
      sinCredenciales: true,
      origen: ctx.ip(99),
      timeoutMs: 4000,
    });
    res.verificar(
      'Aislamiento de /metrics fuera de 127.0.0.1',
      '403',
      etiquetaEstado(rMetrics),
      rMetrics.status === 403,
    );
    if (rMetrics.status === 200) res.hallazgo('/metrics respondió 200 a una dirección distinta de 127.0.0.1');
  }

  // 6. COOKIES DE SESIÓN ADMINISTRATIVA (opcional si se proveen credenciales admin de prueba)
  const adminUser = config.opciones['admin-user'] || process.env.DAST_ADMIN_USER;
  const adminPass = config.opciones['admin-pass'] || process.env.DAST_ADMIN_PASS;
  const adminTotp = config.opciones['admin-totp'] || process.env.DAST_ADMIN_TOTP;
  if (adminUser && adminPass) {
    const body = { usuario: String(adminUser), password: String(adminPass), ...(adminTotp ? { totp_code: String(adminTotp) } : {}) };
    const login = await cliente.peticion('POST', '/admin/api/login', { sinCredenciales: true, cuerpo: body });
    if (login.status === 200 && login.cabeceras['set-cookie']) {
      const ck = auditarCookies(login.cabeceras['set-cookie'], { esHttps });
      res.verificar(
        'Cookie de sesión admin (HttpOnly, Secure, SameSite=Strict)',
        '0 atributos inseguros',
        ck.problemas.length ? ck.problemas.join('; ') : `${ck.total} cookie(s) endurecida(s)`,
        ck.problemas.length === 0,
      );
      if (ck.problemas.length) res.hallazgo(`Cookie de sesión admin débil: ${ck.problemas.join('; ')}`);

      // Comprobar rechazo CSRF en mutación con cookie pero sin cabecera X-CSRF-Token
      const rawCookie = (Array.isArray(login.cabeceras['set-cookie']) ? login.cabeceras['set-cookie'][0] : login.cabeceras['set-cookie']).split(';')[0];
      const sinCsrf = await cliente.peticion('POST', '/admin/api/keys/rotate', {
        sinCredenciales: true,
        cabeceras: { cookie: rawCookie },
        cuerpo: {},
      });
      res.verificar('Protección CSRF en mutación admin sin X-CSRF-Token', '403', etiquetaEstado(sinCsrf), sinCsrf.status === 403);
      if (sinCsrf.status === 200) res.hallazgo('Mutación admin aceptada sin token CSRF');
    } else {
      res.nota(`Login admin DAST no emitió cookie (estado ${etiquetaEstado(login)}); se validaron cabeceras y cookies en rutas públicas.`);
    }
  } else {
    res.nota('Auditoría de Set-Cookie admin en vivo disponible pasando --admin-user, --admin-pass y --admin-totp.');
  }

  for (const [k, v] of Object.entries(metricas)) res.metrica(k, v);
}

const escenario = { id, nombre, demuestra, ejecutar };
export default escenario;

if (esPrincipal(import.meta.url)) {
  let ctx;
  try {
    const config = cargarConfig();
    ctx = crearContexto(config);
    const resultado = await correrEscenario(escenario, ctx, 10);
    if (config.opciones.json) {
      console.log(JSON.stringify(resultado, null, 2));
    } else {
      imprimirResultado(resultado);
    }
    if (config.opciones.salida) {
      const informe = {
        generado: new Date().toISOString(),
        destino: config.url,
        entorno: { node: process.version, plataforma: process.platform },
        resumen: resumir([resultado], resultado.duracionMs),
        resultados: [resultado],
      };
      const rutas = escribirInforme(informe, String(config.opciones.salida) || join(RAIZ_LAB, 'resultados'));
      console.log(`\ninforme DAST: ${rutas.json}\n              ${rutas.html}`);
    }
    process.exitCode = resultado.ok ? 0 : 1;
  } catch (e) {
    console.error(color('rojo', `Error: ${e.message}`));
    process.exitCode = 2;
  } finally {
    ctx?.cerrar();
  }
}
