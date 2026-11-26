// Portal de Trámites del Estado (demo): sistema institucional que integra el segundo factor
// del Servicio Soberano TOTP mediante el SDK. Servidor propio sobre node:http / node:https.

import http from 'node:http';
import https from 'node:https';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { crearClienteTotp, ErrorTotp, decodificarSinVerificar } from '../../sdk/src/index.js';
import { RAIZ } from './config.js';
import { abrirUsuarios } from './usuarios.js';
import { crearAlmacenSesiones, csrfValido, trazar } from './sesiones.js';
import { buscarTramite, validarCampos } from './tramites.js';
import * as V from './vistas.js';

const MAX_CUERPO = 8 * 1024;
const CODIGO = /^[0-9]{6,8}$/;
const RUTAS_CONOCIDAS = /^\/(?:|ingresar|enrolar(?:\/codigos)?|verificar|recuperar|panel|tramites\/[a-z-]+|comprobantes\/[A-Z0-9-]+)$/;

const ESTATICOS = {
  '/publico/estilos.css': 'text/css; charset=utf-8',
  '/publico/app.js': 'text/javascript; charset=utf-8',
  '/publico/emblema.svg': 'image/svg+xml',
};

/** Cabeceras de seguridad comunes. CSP estricta: nada en línea, nada externo. */
function cabecerasSeguridad(tls) {
  return {
    'Content-Security-Policy': [
      "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:",
      "form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'", "connect-src 'self'", "manifest-src 'self'",
    ].join('; '),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    // same-origin (no no-referrer): con no-referrer el navegador envía `Origin: null` en los POST de
    // formularios y la comprobación de origen no podría distinguirlos de un ataque.
    'Referrer-Policy': 'same-origin',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    ...(tls ? { 'Strict-Transport-Security': 'max-age=63072000; includeSubDomains' } : {}),
  };
}

/**
 * @param {{ config: ReturnType<typeof import('./config.js').configuracion>, cliente?: any, registrar?: (m: string) => void }} o
 */
export async function crearPortal({ config, cliente: clienteInyectado, registrar = () => {} }) {
  const usuarios = await abrirUsuarios(config.archivoUsuarios);
  const tls = config.tls ? { cert: readFileSync(config.tls.cert), key: readFileSync(config.tls.key) } : null;
  const sesiones = crearAlmacenSesiones({
    nombreCookie: tls ? '__Host-ptd_sesion' : 'ptd_sesion',
    minutosInactividad: config.sesionMinutos,
    trazasPorDefecto: config.trazasPorDefecto,
  });
  const estaticos = Object.fromEntries(Object.keys(ESTATICOS).map((r) => [r, readFileSync(resolve(RAIZ, r.slice(1)))]));

  // Contexto por petición: el observador del SDK escribe las trazas en la sesión correcta.
  /** @type {AsyncLocalStorage<any>} */
  const contexto = new AsyncLocalStorage();
  const alTrazar = (t) => {
    const s = contexto.getStore();
    const ok = t.status !== null && t.status < 400;
    trazar(s, {
      tipo: 'servicio',
      titulo: `${t.metodo} ${acortarRuta(t.ruta)}`,
      detalle: [
        t.status === null ? `sin respuesta (${t.codigo})` : `HTTP ${t.status}${t.codigo ? ` · ${t.codigo}` : ''}`,
        `intento ${t.intento}`,
        t.idempotencyKey ? `Idempotency-Key ${t.idempotencyKey.slice(0, 8)}…` : null,
      ].filter(Boolean).join(' · '),
      ms: t.ms,
      estado: ok ? 'ok' : 'error',
    });
  };

  const ca = config.servicio.caPath && existsSync(config.servicio.caPath) ? readFileSync(config.servicio.caPath) : undefined;
  const cliente = clienteInyectado ?? crearClienteTotp({
    baseUrl: config.servicio.baseUrl,
    clientId: config.servicio.clientId,
    clientSecret: config.servicio.clientSecret || 'sin-configurar',
    timeoutMs: config.servicio.timeoutMs,
    reintentos: 1,
    ca,
    issuer: config.servicio.issuer,
    audience: config.servicio.audience,
    alTrazar,
  });

  // jti aceptados por el portal (impide reutilizar un JWT si se validó en modo sin red).
  /** @type {Map<string, number>} */
  const jtiAceptados = new Map();
  // Freno de fuerza bruta de contraseñas por usuario (propio del portal).
  /** @type {Map<string, { fallos: number, hasta: number }>} */
  const intentosContrasena = new Map();

  // ------------------------------------------------------------ segundo factor

  /**
   * Verifica un código TOTP con el servicio y valida el JWT (local + remoto). Falla cerrado.
   * @returns {Promise<{ ok: true, claims: any, header: any, modo: string } | { ok: false, tipo: 'codigo'|'bloqueo'|'servicio'|'token', reintentarEn?: number, status: number }>}
   */
  async function segundoFactor(sesion, usuario, codigo, proposito) {
    const ahora = Date.now();
    if (sesion.bloqueadoHasta > ahora) {
      const s = Math.ceil((sesion.bloqueadoHasta - ahora) / 1000);
      trazar(sesion, { tipo: 'decision', titulo: 'Bloqueo vigente: el portal ni siquiera consulta al servicio', detalle: `Faltan ${s} s`, estado: 'error' });
      return { ok: false, tipo: 'bloqueo', reintentarEn: s, status: 429 };
    }
    if (!CODIGO.test(codigo)) {
      trazar(sesion, { tipo: 'local', titulo: 'Formato de código inválido: se rechaza sin llamar al servicio', estado: 'error' });
      return { ok: false, tipo: 'codigo', status: 401 };
    }
    trazar(sesion, {
      tipo: 'local',
      titulo: proposito === 'step-up' ? 'Operación sensible: se exige un código nuevo (step-up)' : 'Se solicita la verificación del segundo factor',
      detalle: `El portal envía solo user_ref ${usuario.userRef.slice(0, 12)}… (opaco) y el código. Ni nombre ni documento salen del portal.`,
    });

    let v;
    try {
      v = await cliente.verificar(usuario.userRef, codigo);
    } catch (e) {
      return clasificar(sesion, e);
    }

    const dec = decodificarSinVerificar(v.token);
    trazar(sesion, {
      tipo: 'jwt',
      titulo: 'JWT MFA recibido (cabecera y claims, sin la firma)',
      detalle: v.riesgo ? `Riesgo ${v.riesgo.level} (${v.riesgo.score}) · acción ${v.riesgo.action} · deriva ${v.derivaPasos ?? 0} pasos` : '',
      bloque: dec ? JSON.stringify({ header: dec.header, claims: dec.claims }, null, 2) : null,
    });

    const t0 = performance.now();
    const local = await cliente.verificarTokenLocal(v.token);
    const msLocal = Math.round(performance.now() - t0);
    if (!local.valido) {
      trazar(sesion, { tipo: 'decision', titulo: `Firma o claims rechazados localmente (${local.motivo}): acceso denegado`, ms: msLocal, estado: 'error' });
      return { ok: false, tipo: 'token', status: 401 };
    }
    const segs = local.claims.exp - Math.floor(Date.now() / 1000);
    trazar(sesion, {
      tipo: 'local',
      titulo: 'Firma EdDSA (Ed25519) verificada en el portal con la JWKS en caché',
      detalle: `kid ${local.header.kid} · iss y aud correctos · amr ${JSON.stringify(local.claims.amr)} · vence en ${segs} s`,
      ms: msLocal,
    });

    let modo;
    try {
      const r = await cliente.validarToken(v.token);
      if (!r.valido) {
        trazar(sesion, { tipo: 'decision', titulo: `El servicio invalidó el token (${r.motivo ?? 'sin motivo'}): acceso denegado`, estado: 'error' });
        return { ok: false, tipo: 'token', status: 401 };
      }
      modo = 'Validada en el servicio (jti de un solo uso consumido)';
    } catch (e) {
      if (e instanceof ErrorTotp && e.servicioNoDisponible) {
        modo = 'Validada sin red con JWKS en caché';
        trazar(sesion, {
          tipo: 'decision',
          titulo: 'tokens/validate no responde: se acepta la verificación local',
          detalle: 'La firma y la vigencia ya se comprobaron offline. El portal registra el jti para que el token no pueda reutilizarse.',
          estado: 'aviso',
        });
      } else {
        trazar(sesion, { tipo: 'decision', titulo: 'Error al validar el token: acceso denegado', estado: 'error' });
        return { ok: false, tipo: 'token', status: 401 };
      }
    }

    limpiarJti();
    if (jtiAceptados.has(local.claims.jti)) {
      trazar(sesion, { tipo: 'decision', titulo: 'jti ya utilizado en este portal: acceso denegado', estado: 'error' });
      return { ok: false, tipo: 'token', status: 401 };
    }
    jtiAceptados.set(local.claims.jti, local.claims.exp);
    return { ok: true, claims: local.claims, header: local.header, modo };
  }

  function clasificar(sesion, e) {
    if (e instanceof ErrorTotp && e.bloqueado) {
      const s = Number.isFinite(e.reintentarEn) && e.reintentarEn > 0 ? e.reintentarEn : 60;
      sesion.bloqueadoHasta = Date.now() + s * 1000;
      trazar(sesion, { tipo: 'decision', titulo: `Bloqueo progresivo del servicio (429): reintentar en ${s} s`, detalle: e.codigo, estado: 'error' });
      return { ok: false, tipo: 'bloqueo', reintentarEn: s, status: 429 };
    }
    if (e instanceof ErrorTotp && (e.rechazado || e.status === 400 || e.codigo === 'ENTRADA_INVALIDA')) {
      trazar(sesion, { tipo: 'decision', titulo: 'Código rechazado por el servicio: acceso denegado', detalle: `${e.codigo} (mensaje genérico, sin pistas para un atacante)`, estado: 'error' });
      return { ok: false, tipo: 'codigo', status: 401 };
    }
    const codigo = e instanceof ErrorTotp ? e.codigo : 'ERROR';
    trazar(sesion, {
      tipo: 'decision',
      titulo: 'Servicio no disponible: el portal falla cerrado y NO concede acceso',
      detalle: `${codigo}${e?.status ? ` (HTTP ${e.status})` : ''}. El SDK ya reintentó una vez con la misma clave de idempotencia.`,
      estado: 'error',
    });
    return { ok: false, tipo: 'servicio', status: 503 };
  }

  function limpiarJti() {
    const ahora = Math.floor(Date.now() / 1000);
    for (const [j, exp] of jtiAceptados) if (exp + 60 < ahora) jtiAceptados.delete(j);
  }

  // ------------------------------------------------------------ utilidades HTTP

  function enviar(res, status, cuerpo, cabeceras = {}) {
    res.writeHead(status, { ...cabecerasSeguridad(Boolean(tls)), ...cabeceras });
    res.end(cuerpo);
  }

  function pagina(res, sesion, { status = 200, titulo, contenido, ancho, ruta, usuario }) {
    const cuerpo = V.layout({ titulo, sesion, usuario, contenido, ancho, ruta });
    sesion.aviso = null; // los avisos se muestran una vez
    enviar(res, status, cuerpo, {
      'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Set-Cookie': sesiones.cookie(sesion),
    });
  }

  function redirigir(res, sesion, destino) {
    enviar(res, 303, '', { Location: destino, 'Cache-Control': 'no-store', 'Set-Cookie': sesiones.cookie(sesion) });
  }

  async function leerCuerpo(req) {
    const tipo = String(req.headers['content-type'] ?? '');
    if (!tipo.startsWith('application/x-www-form-urlencoded')) return null;
    let total = 0;
    const trozos = [];
    for await (const t of req) {
      total += t.length;
      if (total > MAX_CUERPO) return null;
      trozos.push(t);
    }
    return new URLSearchParams(Buffer.concat(trozos).toString('utf8'));
  }

  /** Mismo origen: si el navegador envía Origin, debe coincidir con el Host servido. */
  function origenValido(req) {
    const origen = req.headers.origin;
    if (!origen || origen === 'null') return origen !== 'null';
    try {
      return new URL(origen).host === req.headers.host;
    } catch {
      return false;
    }
  }

  const rutaSegura = (r) => (typeof r === 'string' && /^\/[A-Za-z0-9/_-]*$/.test(r) && !r.startsWith('//') ? r : '/');

  // ------------------------------------------------------------ rutas

  async function atender(req, res) {
    const url = new URL(req.url ?? '/', 'http://portal');
    const ruta = url.pathname;
    const metodo = req.method ?? 'GET';

    if (metodo === 'GET' && Object.hasOwn(ESTATICOS, ruta)) {
      return enviar(res, 200, estaticos[ruta], { 'Content-Type': ESTATICOS[ruta], 'Cache-Control': 'no-cache' });
    }
    if (metodo === 'GET' && ruta === '/favicon.ico') {
      return enviar(res, 200, estaticos['/publico/emblema.svg'], { 'Content-Type': ESTATICOS['/publico/emblema.svg'], 'Cache-Control': 'max-age=86400' });
    }
    if (metodo === 'GET' && ruta === '/salud') {
      return enviar(res, 200, JSON.stringify({ status: 'ok' }), { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    }

    const { sesion, nueva } = sesiones.obtener(req);
    // Una ruta desconocida no crea sesión: evita que peticiones paralelas del navegador con una cookie
    // vencida emitan cookies nuevas que pisen la de la página (y su token CSRF).
    if (nueva && metodo === 'GET' && !RUTAS_CONOCIDAS.test(ruta)) {
      sesiones.destruir(sesion);
      return enviar(res, 404, 'No encontrado', { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    }
    const usuario = sesion.usuario ? usuarios.buscar(sesion.usuario) : null;

    /** @type {URLSearchParams | null} */
    let cuerpo = null;
    if (metodo === 'POST') {
      cuerpo = await leerCuerpo(req);
      if (!cuerpo || !origenValido(req) || !csrfValido(sesion, cuerpo.get('_csrf'))) {
        return pagina(res, sesion, {
          status: 403, titulo: 'Solicitud rechazada', ruta: '/',
          contenido: V.paginaMensaje({ tipo: 'error', titulo: 'Solicitud rechazada', texto: 'El formulario caducó o no proviene de este portal. Vuelva a intentarlo.' }),
        });
      }
    } else if (metodo !== 'GET' && metodo !== 'HEAD') {
      return enviar(res, 405, '', { Allow: 'GET, POST' });
    }

    return contexto.run(sesion, () => despachar({ req, res, metodo, ruta, sesion, usuario, cuerpo }));
  }

  async function despachar({ res, metodo, ruta, sesion, usuario, cuerpo }) {
    const etapa = usuario ? sesion.etapa : 'anonima';
    const enSegundoPaso = etapa === 'contrasena';
    const ver = (p) => pagina(res, sesion, { usuario, ruta, ...p });

    if (metodo === 'POST' && ruta === '/trazas') {
      sesion.trazasVisibles = !sesion.trazasVisibles;
      return redirigir(res, sesion, rutaSegura(cuerpo.get('volver')));
    }
    if (metodo === 'POST' && ruta === '/salir') {
      if (usuario) trazar(sesion, { tipo: 'local', titulo: 'Sesión cerrada', detalle: 'El identificador de sesión se destruye en el servidor.' });
      sesiones.destruir(sesion);
      const nueva = sesiones.obtener({ headers: {} }).sesion;
      nueva.trazasVisibles = sesion.trazasVisibles;
      nueva.aviso = { tipo: 'info', texto: 'Sesión cerrada correctamente.' };
      return redirigir(res, nueva, '/ingresar');
    }

    if (ruta === '/') {
      if (etapa === 'autenticado') return redirigir(res, sesion, '/panel');
      if (enSegundoPaso) return redirigir(res, sesion, usuario.factor ? '/verificar' : '/enrolar');
      return redirigir(res, sesion, '/ingresar');
    }

    // ---- paso 1: contraseña
    if (ruta === '/ingresar') {
      if (etapa === 'autenticado') return redirigir(res, sesion, '/panel');
      if (metodo === 'GET') return ver({ titulo: 'Ingresar', contenido: V.paginaIngresar({ sesion, demo: usuarios.listar() }) });

      const nombre = String(cuerpo.get('usuario') ?? '').trim().toLowerCase().slice(0, 64);
      const clave = String(cuerpo.get('contrasena') ?? '').slice(0, 128);
      const freno = intentosContrasena.get(nombre);
      if (freno && freno.hasta > Date.now()) {
        const s = Math.ceil((freno.hasta - Date.now()) / 1000);
        trazar(sesion, { tipo: 'decision', titulo: 'Demasiados intentos de contraseña: el portal frena el ingreso', detalle: `${s} s`, estado: 'error' });
        return ver({
          status: 429, titulo: 'Ingresar',
          contenido: V.paginaIngresar({ sesion, usuario: nombre, demo: usuarios.listar(), error: { tipo: 'bloqueo', titulo: 'Demasiados intentos', texto: `Espere ${s} segundos antes de volver a intentarlo.` } }),
        });
      }
      const t0 = performance.now();
      const u = await usuarios.autenticar(nombre, clave);
      const ms = Math.round(performance.now() - t0);
      if (!u) {
        const f = intentosContrasena.get(nombre) ?? { fallos: 0, hasta: 0 };
        f.fallos += 1;
        if (f.fallos >= 5) { f.hasta = Date.now() + 60 * 1000; f.fallos = 0; }
        intentosContrasena.set(nombre, f);
        trazar(sesion, { tipo: 'local', titulo: 'Usuario o contraseña incorrectos', detalle: 'scrypt con el mismo coste exista o no el usuario (sin enumeración).', ms, estado: 'error' });
        return ver({
          status: 401, titulo: 'Ingresar',
          contenido: V.paginaIngresar({ sesion, usuario: nombre, demo: usuarios.listar(), error: { titulo: 'Usuario o contraseña incorrectos', texto: 'Revise los datos e inténtelo de nuevo.' } }),
        });
      }
      intentosContrasena.delete(nombre);
      sesiones.rotar(sesion);
      sesion.usuario = u.usuario;
      sesion.etapa = 'contrasena';
      sesion.mfa = null;
      sesion.bloqueadoHasta = 0;
      trazar(sesion, { tipo: 'local', titulo: 'Contraseña verificada en el portal (scrypt N=2¹⁵, r=8)', detalle: 'Primer factor propio de la institución. Se rota el identificador de sesión.', ms });
      trazar(sesion, {
        tipo: 'decision',
        titulo: u.factor ? 'El ciudadano ya tiene segundo factor: se pide el código' : 'El ciudadano no tiene segundo factor: se inicia el enrolamiento',
        estado: 'ok',
      });
      return redirigir(res, sesion, u.factor ? '/verificar' : '/enrolar');
    }

    // ---- paso 2: enrolamiento / verificación / recuperación
    if (['/enrolar', '/enrolar/activar', '/enrolar/codigos', '/enrolar/confirmar', '/verificar', '/recuperar'].includes(ruta)) {
      if (etapa === 'autenticado') return redirigir(res, sesion, '/panel');
      if (!enSegundoPaso) return redirigir(res, sesion, '/ingresar');
    }

    if (ruta === '/enrolar' && metodo === 'GET') {
      if (usuario.factor) return redirigir(res, sesion, '/verificar');
      const e = sesion.enrolamiento;
      if (!e || e.usuario !== usuario.usuario || Date.parse(e.expiraEn) - 30000 < Date.now()) {
        try {
          const n = await cliente.enrolar(usuario.userRef, { etiquetaCuenta: `${config.etiquetaCuenta} (${usuario.usuario})` });
          if (typeof n.qrSvg !== 'string' || !n.qrSvg.trimStart().startsWith('<svg') || n.qrSvg.length > 200_000) throw new ErrorTotp('QR inválido', { codigo: 'RESPUESTA_INVALIDA' });
          sesion.enrolamiento = { ...n, usuario: usuario.usuario };
          trazar(sesion, {
            tipo: 'servicio',
            titulo: 'Enrolamiento PENDIENTE creado (vence en 10 min)',
            detalle: `enrollment_id ${n.enrollmentId.slice(0, 8)}… · ${n.algoritmo} · ${n.digitos} dígitos · ${n.periodo} s. La semilla viaja una sola vez dentro del QR; el portal no la guarda.`,
          });
        } catch (err) {
          clasificar(sesion, err);
          return ver({ status: 503, titulo: 'Vincular autenticador', contenido: V.paginaEnrolar({ sesion, usuario, errorServicio: true }) });
        }
      }
      return ver({ titulo: 'Vincular autenticador', ancho: 'amplio', contenido: V.paginaEnrolar({ sesion, usuario, enrolamiento: sesion.enrolamiento, autenticadorUrl: config.autenticadorUrl }) });
    }

    if (ruta === '/enrolar/activar' && metodo === 'POST') {
      const e = sesion.enrolamiento;
      if (!e || e.usuario !== usuario.usuario) return redirigir(res, sesion, '/enrolar');
      const codigo = String(cuerpo.get('codigo') ?? '').replace(/\s+/g, '');
      let resultado;
      if (sesion.bloqueadoHasta > Date.now()) {
        resultado = { ok: false, tipo: 'bloqueo', reintentarEn: Math.ceil((sesion.bloqueadoHasta - Date.now()) / 1000), status: 429 };
      } else if (!CODIGO.test(codigo)) {
        resultado = { ok: false, tipo: 'codigo', status: 401 };
      } else {
        try {
          const a = await cliente.activar(e.enrollmentId, codigo);
          usuarios.fijarFactor(usuario.usuario, { enrollmentId: a.enrollmentId, activadoEn: a.activadoEn ?? new Date().toISOString() });
          sesion.codigosRecuperacion = a.codigosRecuperacion;
          sesion.enrolamiento = null;
          trazar(sesion, {
            tipo: 'servicio', titulo: 'Factor ACTIVO: 10 códigos de recuperación emitidos (una sola vez)',
            detalle: 'El portal guarda solo el enrollment_id. Los códigos se muestran al ciudadano y se olvidan.',
          });
          return redirigir(res, sesion, '/enrolar/codigos');
        } catch (err) {
          resultado = clasificar(sesion, err);
        }
      }
      return ver({
        status: resultado.status, titulo: 'Vincular autenticador', ancho: 'amplio',
        contenido: V.paginaEnrolar({ sesion, usuario, enrolamiento: e, resultado, autenticadorUrl: config.autenticadorUrl }),
      });
    }

    if (ruta === '/enrolar/codigos' && metodo === 'GET') {
      const codigos = sesion.codigosRecuperacion;
      if (!codigos) return redirigir(res, sesion, '/verificar');
      sesion.codigosRecuperacion = null; // se muestran una sola vez
      return ver({ titulo: 'Códigos de recuperación', contenido: V.paginaCodigosRecuperacion({ sesion, codigos }) });
    }

    if (ruta === '/enrolar/confirmar' && metodo === 'POST') {
      sesion.aviso = { tipo: 'info', texto: 'Listo. Espere a que su app muestre un código nuevo y úselo para entrar.' };
      return redirigir(res, sesion, '/verificar');
    }

    if (ruta === '/verificar') {
      if (!usuario.factor) return redirigir(res, sesion, '/enrolar');
      if (metodo === 'GET') {
        const resultado = sesion.bloqueadoHasta > Date.now()
          ? { ok: false, tipo: 'bloqueo', reintentarEn: Math.ceil((sesion.bloqueadoHasta - Date.now()) / 1000) } : null;
        return ver({ titulo: 'Verificación en dos pasos', contenido: V.paginaVerificar({ sesion, usuario, resultado }) });
      }
      const codigo = String(cuerpo.get('codigo') ?? '').replace(/\s+/g, '');
      const r = await segundoFactor(sesion, usuario, codigo, 'ingreso');
      if (!r.ok) return ver({ status: r.status, titulo: 'Verificación en dos pasos', contenido: V.paginaVerificar({ sesion, usuario, resultado: r }) });
      sesiones.rotar(sesion);
      sesion.etapa = 'autenticado';
      sesion.mfa = { en: Date.now(), jti: r.claims.jti, exp: r.claims.exp, amr: r.claims.amr, kid: r.header.kid, modo: r.modo };
      trazar(sesion, {
        tipo: 'decision', titulo: 'Acceso concedido: sesión del portal creada',
        detalle: 'Cookie HttpOnly; Secure; SameSite=Strict con identificador nuevo. El JWT no se guarda en el navegador.',
      });
      return redirigir(res, sesion, '/panel');
    }

    if (ruta === '/recuperar') {
      if (!usuario.factor) return redirigir(res, sesion, '/enrolar');
      if (metodo === 'GET') return ver({ titulo: 'Código de recuperación', contenido: V.paginaRecuperar({ sesion }) });
      const codigo = String(cuerpo.get('recuperacion') ?? '').trim().toUpperCase();
      let resultado;
      if (sesion.bloqueadoHasta > Date.now()) {
        resultado = { ok: false, tipo: 'bloqueo', reintentarEn: Math.ceil((sesion.bloqueadoHasta - Date.now()) / 1000), status: 429 };
      } else {
        try {
          const r = await cliente.recuperar(usuario.userRef, codigo);
          usuarios.fijarFactor(usuario.usuario, null);
          trazar(sesion, {
            tipo: 'decision', titulo: 'Código de recuperación aceptado: se obliga a re-enrolar',
            detalle: `Quedan ${r.codigosRestantes} códigos. No se concede acceso hasta vincular y verificar un autenticador nuevo.`,
          });
          sesion.aviso = { tipo: 'info', texto: 'Código de recuperación aceptado. Vincule ahora su autenticador nuevo.' };
          return redirigir(res, sesion, '/enrolar');
        } catch (err) {
          resultado = clasificar(sesion, err);
        }
      }
      return ver({ status: resultado.status, titulo: 'Código de recuperación', contenido: V.paginaRecuperar({ sesion, resultado }) });
    }

    // ---- paso 3: área autenticada
    if (ruta === '/panel' || ruta.startsWith('/tramites/') || ruta.startsWith('/comprobantes/')) {
      if (etapa !== 'autenticado') return redirigir(res, sesion, enSegundoPaso ? '/' : '/ingresar');
    }

    if (ruta === '/panel' && metodo === 'GET') {
      return ver({ titulo: 'Área personal', ancho: 'amplio', contenido: V.paginaPanel({ sesion, usuario }) });
    }

    const mTramite = /^\/tramites\/([a-z-]{1,40})$/.exec(ruta);
    if (mTramite) {
      const tramite = buscarTramite(mTramite[1]);
      if (!tramite) return noEncontrada(res, sesion, usuario, ruta);
      if (tramite.id === 'consulta') return ver({ titulo: tramite.titulo, contenido: V.paginaConsulta({ sesion }) });
      if (metodo === 'GET') {
        const resultado = sesion.bloqueadoHasta > Date.now()
          ? { ok: false, tipo: 'bloqueo', reintentarEn: Math.ceil((sesion.bloqueadoHasta - Date.now()) / 1000) } : null;
        return ver({ titulo: tramite.titulo, contenido: V.paginaTramite({ sesion, tramite, resultado }) });
      }
      const { datos, error } = validarCampos(tramite, cuerpo);
      const valores = Object.fromEntries(tramite.campos.map((c) => [c.nombre, String(cuerpo.get(c.nombre) ?? '')]));
      if (error) return ver({ status: 400, titulo: tramite.titulo, contenido: V.paginaTramite({ sesion, tramite, error, valores }) });

      const codigo = String(cuerpo.get('codigo') ?? '').replace(/\s+/g, '');
      const r = await segundoFactor(sesion, usuario, codigo, 'step-up');
      if (!r.ok) return ver({ status: r.status, titulo: tramite.titulo, contenido: V.paginaTramite({ sesion, tramite, resultado: r, valores }) });

      if (tramite.id === 'desactivar-factor') {
        try {
          await cliente.revocar(usuario.factor.enrollmentId);
        } catch (err) {
          clasificar(sesion, err);
          return ver({ status: 503, titulo: tramite.titulo, contenido: V.paginaTramite({ sesion, tramite, resultado: { ok: false, tipo: 'servicio' } }) });
        }
        usuarios.fijarFactor(usuario.usuario, null);
        trazar(sesion, { tipo: 'decision', titulo: 'Factor revocado y sesión cerrada', detalle: 'El próximo ingreso exigirá un enrolamiento nuevo.' });
        const trazas = sesion.trazas;
        const visibles = sesion.trazasVisibles;
        sesiones.destruir(sesion);
        const nueva = sesiones.obtener({ headers: {} }).sesion;
        nueva.trazas = trazas;
        nueva.trazasVisibles = visibles;
        nueva.aviso = { tipo: 'exito', texto: tramite.exito() };
        return redirigir(res, nueva, '/ingresar');
      }

      const comprobante = {
        folio: `PT-${new Date().getFullYear()}-${randomBytes(3).toString('hex').toUpperCase()}`,
        titulo: tramite.titulo, mensaje: tramite.exito(datos), en: Date.now(), jti: r.claims.jti,
      };
      sesion.comprobantes.push(comprobante);
      trazar(sesion, { tipo: 'decision', titulo: `Operación sensible autorizada: comprobante ${comprobante.folio}`, detalle: 'Autorizada con un JWT nuevo y de un solo uso, distinto del usado al entrar.' });
      return redirigir(res, sesion, `/comprobantes/${comprobante.folio}`);
    }

    const mComp = /^\/comprobantes\/(PT-\d{4}-[0-9A-F]{6})$/.exec(ruta);
    if (mComp && metodo === 'GET') {
      const comprobante = sesion.comprobantes.find((c) => c.folio === mComp[1]);
      if (!comprobante) return noEncontrada(res, sesion, usuario, ruta);
      return ver({ titulo: `Comprobante ${comprobante.folio}`, contenido: V.paginaComprobante({ comprobante }) });
    }

    return noEncontrada(res, sesion, usuario, ruta);
  }

  function noEncontrada(res, sesion, usuario, ruta) {
    return pagina(res, sesion, {
      status: 404, titulo: 'Página no encontrada', usuario, ruta,
      contenido: V.paginaMensaje({ tipo: 'info', titulo: 'Página no encontrada', texto: 'La dirección no existe o ya no está disponible.' }),
    });
  }

  const manejador = (req, res) => {
    atender(req, res).catch((e) => {
      registrar(`error interno: ${e?.message ?? e}`);
      if (!res.headersSent) enviar(res, 500, 'Error interno', { 'Content-Type': 'text/plain; charset=utf-8' });
      else res.end();
    });
  };

  const servidor = tls
    ? https.createServer({ ...tls, minVersion: 'TLSv1.2' }, manejador)
    : http.createServer(manejador);
  servidor.headersTimeout = 10_000;
  servidor.requestTimeout = 15_000;

  return {
    servidor,
    cliente,
    usuarios,
    tls: Boolean(tls),
    /** @returns {Promise<string>} URL */
    async iniciar(puerto = config.puerto, host = config.host) {
      await new Promise((ok, mal) => { servidor.once('error', mal); servidor.listen(puerto, host, ok); });
      const { port } = /** @type {any} */ (servidor.address());
      const h = host === '127.0.0.1' || host === '0.0.0.0' || host === '::1' ? 'localhost' : host;
      return `${tls ? 'https' : 'http'}://${h}:${port}`;
    },
    async detener() {
      sesiones.detener();
      if (!clienteInyectado) cliente.cerrar();
      servidor.closeAllConnections?.();
      await new Promise((r) => servidor.close(() => r(undefined)));
    },
  };
}

/** Acorta UUIDs en rutas para la traza. */
function acortarRuta(ruta) {
  return ruta.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, (u) => `${u.slice(0, 8)}…`);
}
