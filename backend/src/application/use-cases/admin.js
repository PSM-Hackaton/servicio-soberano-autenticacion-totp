// Casos de uso de la consola administrativa (/admin/api/*) y autenticación de apps.
// ctx.admin = { id, usuario, rol } lo fija el servidor a partir de la sesión creada tras adminLogin.

import { randomBytes } from 'node:crypto';
import { verifyTotpWithDrift } from '../../core/totp/totp.js';
import {
  errorGenerico, generarClientId, generarSecretoCliente, hashSecretoAsync, verificarSecretoAsync,
} from '../../security/index.js';
import { verificarCadena, respuestaVerificacion } from '../../audit/index.js';
import {
  HASH_FICTICIO, anonimizarIp, errorEntrada, iso, noEncontrado, prohibido, separarEntrada, validar,
} from './comun.js';
import {
  ESQUEMA_ADMIN_ANOMALIAS, ESQUEMA_ADMIN_APP, ESQUEMA_ADMIN_AUDITORIA, ESQUEMA_ADMIN_ENROLAMIENTOS,
  ESQUEMA_ADMIN_LOGIN, ESQUEMA_VACIO,
} from './esquemas.js';
import { puede } from './rbac.js';
import { generarYGuardarClave } from './firmas.js';

/** @typedef {import('./comun.js').Respuesta} Respuesta */

const MAX_INTENTOS_ADMIN = 5;
const RIESGO_MINIMO_ANOMALIA = 60;

/** Fila de app sin el hash del secreto. */
function appPublica(app) {
  if (!app) return null;
  const { secret_hash: _omitido, ...resto } = app;
  return resto;
}

/** Nivel y acción del contrato a partir de un intento guardado. */
function nivelDe(score) {
  if (score >= 90) return 'CRITICAL';
  if (score >= 75) return 'HIGH';
  if (score >= 60) return 'MEDIUM';
  return 'LOW';
}

/** Entero de un parámetro de consulta ya validado, acotado a [1, maximo]. */
const entero = (texto, porDefecto, maximo) => Math.min(maximo, Math.max(1, texto === undefined ? porDefecto : Number(texto)));

/**
 * @param {{ repos: any, vault: any, firmas: any, bitacora: any, metricas: any, config: any,
 *   reloj: () => number, consultas: any, bloqueos: any }} d
 */
export function crearCasosAdmin(d) {
  const { repos, vault, firmas, bitacora, metricas, config, reloj, consultas, bloqueos } = d;
  const auditar = (actor, accion, objetivo, detalle) => bitacora.registrar({ actor, accion, objetivo, detalle });
  const actorAdmin = (admin) => `admin:${admin.usuario}`;

  /** RBAC: null si se permite; respuesta 401/403 si no. */
  function exigir(ctx, accion) {
    const admin = ctx?.admin;
    if (!admin || typeof admin.rol !== 'string') return errorGenerico('credenciales');
    return puede(admin.rol, accion) ? null : prohibido();
  }

  /** Lee la entrada de una ruta GET (consulta) con esquema cerrado. */
  const consulta = (entrada, esquema) => validar(separarEntrada(entrada ?? {}).cuerpo ?? {}, esquema);

  // ------------------------------------------------------------------ autenticarApp
  /**
   * Autentica una app integradora por cabeceras X-Client-Id / X-Client-Secret.
   * Tiempo homogéneo: si el client_id no existe se verifica contra un hash ficticio.
   * Apps suspendidas → null.
   * @param {unknown} clientId @param {unknown} clientSecret
   * @returns {Promise<Record<string, any> | null>} fila completa de apps
   */
  async function autenticarApp(clientId, clientSecret) {
    if (typeof clientId !== 'string' || typeof clientSecret !== 'string') return null;
    if (clientId.length === 0 || clientId.length > 128 || clientSecret.length === 0 || clientSecret.length > 256) return null;
    const app = repos.apps.buscarPorClientId(clientId);
    const ok = await verificarSecretoAsync(clientSecret, app?.secret_hash ?? HASH_FICTICIO);
    return ok && app && app.estado === 'activo' ? app : null;
  }

  // ------------------------------------------------------------------ adminLogin
  /**
   * POST /admin/api/login — ESQUEMA_ADMIN_LOGIN { usuario, password, totp_code } (se acepta
   * `codigo` como alias de totp_code). Contraseña scrypt + TOTP del enrolamiento del admin con
   * anti replay. Respuestas genéricas (401) y bloqueo progresivo (429).
   * 200 → { status, cuerpo: { usuario, rol, csrf_token }, admin: { id, usuario, rol, csrf_token } }:
   * `admin` es para que el servidor cree la sesión (cookie HttpOnly; Secure; SameSite=Strict).
   * @param {unknown} entrada @param {{ ip?: string }} [ctx]
   * @returns {Promise<Respuesta & { admin?: { id: string, usuario: string, rol: string, csrf_token: string } }>}
   */
  async function adminLogin(entrada, ctx = {}) {
    const v = validar(separarEntrada(entrada).cuerpo, ESQUEMA_ADMIN_LOGIN);
    if (!v) return errorEntrada();
    const ahora = reloj();
    const ipHash = anonimizarIp(ctx?.ip, config.ipPepperSemilla, ahora);
    const claveF = `admin:${v.usuario}`;
    const codigo = v.totp_code ?? v.codigo;

    const restante = bloqueos.restanteFantasma(claveF, ahora);
    if (restante > 0) return errorGenerico('limite', { reintentarEnSegundos: restante });

    const fallo = (motivo) => {
      bloqueos.falloFantasma(claveF, MAX_INTENTOS_ADMIN, ahora);
      auditar('anonimo', 'admin.login_fallido', null, { ip_hash: ipHash, motivo });
      return errorGenerico('credenciales');
    };

    const admin = repos.admins.buscarPorUsuario(v.usuario);
    const passOk = await verificarSecretoAsync(v.password, admin?.password_hash ?? HASH_FICTICIO);
    if (!admin || !admin.activo || !passOk) return fallo('credenciales');
    if (!codigo) return fallo('sin_totp');

    const enrol = admin.totp_enrollment_id ? repos.enrollments.buscarPorId(admin.totp_enrollment_id) : null;
    if (!enrol || enrol.estado !== 'activo') return fallo('sin_totp');
    const restanteEnrol = bloqueos.restanteEnrolamiento(enrol, ahora);
    if (restanteEnrol > 0) return errorGenerico('limite', { reintentarEnSegundos: restanteEnrol });

    const appTotp = repos.apps.buscarPorId(enrol.app_id);
    const semilla = vault.decryptSeed({
      ct: enrol.seed_ct, nonce: enrol.seed_nonce, authTag: enrol.seed_auth_tag, keyVersion: enrol.key_version,
    }, enrol.id);
    let r;
    try {
      r = verifyTotpWithDrift(semilla, codigo, ahora, {
        algoritmo: enrol.algoritmo, digitos: enrol.digitos, periodo: enrol.periodo,
        ventana: appTotp?.ventana ?? 1, driftSteps: enrol.drift_steps, lastStep: enrol.last_step,
      });
    } finally {
      semilla.fill(0);
    }
    const aceptado = repos.transaccion(() => {
      if (r.valid && repos.enrollments.registrarPasoAceptado(enrol.id, r.matchedStep, r.driftSteps)) return true;
      bloqueos.falloEnrolamiento(enrol.id, appTotp?.max_intentos ?? MAX_INTENTOS_ADMIN, ahora);
      return false;
    });
    if (!aceptado) return fallo(r.reason === 'replay' ? 'replay' : 'totp');

    bloqueos.exitoFantasma(claveF);
    const csrf = randomBytes(32).toString('base64url');
    auditar(actorAdmin(admin), 'admin.login', admin.id, { rol: admin.rol, ip_hash: ipHash });
    return {
      status: 200,
      cuerpo: { usuario: admin.usuario, rol: admin.rol, csrf_token: csrf },
      cabeceras: { 'Cache-Control': 'no-store' },
      admin: { id: admin.id, usuario: admin.usuario, rol: admin.rol, csrf_token: csrf },
    };
  }

  // ------------------------------------------------------------------ apps
  /**
   * GET /admin/api/apps — permiso apps.leer. 200 { apps: [fila sin secret_hash] }.
   * @param {unknown} _entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminListarApps(_entrada, ctx) {
    const negado = exigir(ctx, 'apps.leer');
    if (negado) return negado;
    return { status: 200, cuerpo: { apps: repos.apps.listar().map(appPublica) }, cabeceras: {} };
  }

  /**
   * POST /admin/api/apps — permiso apps.escribir. ESQUEMA_ADMIN_APP.
   * Sin `id`: registra (requiere `nombre`) → 201 { app, client_id, client_secret } (secreto una sola vez).
   * Con `id`: actualiza la política → 200 { app } | 404. `nombre` no se puede cambiar (400).
   * SHA1 solo con permitir_sha1 = true.
   * @param {unknown} entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminActualizarApp(entrada, ctx) {
    const negado = exigir(ctx, 'apps.escribir');
    if (negado) return negado;
    const { id: idRuta, cuerpo } = separarEntrada(entrada);
    const v = validar(cuerpo, ESQUEMA_ADMIN_APP);
    if (!v) return errorEntrada();
    const id = v.id ?? (typeof idRuta === 'string' ? idRuta : undefined);
    const { id: _i, nombre, ...politica } = v;

    if (id === undefined) {
      if (!nombre) return errorEntrada();
      if ((politica.algoritmo ?? 'SHA256') === 'SHA1' && !politica.permitir_sha1) return errorEntrada();
      const clientId = generarClientId('app');
      const clientSecret = generarSecretoCliente();
      const app = repos.apps.crear({ nombre, client_id: clientId, secret_hash: await hashSecretoAsync(clientSecret), ...politica });
      auditar(actorAdmin(ctx.admin), 'app.registrada', app.id, { nombre, client_id: clientId, ...politica });
      return {
        status: 201,
        cuerpo: { app: appPublica(app), client_id: clientId, client_secret: clientSecret },
        cabeceras: { 'Cache-Control': 'no-store' },
      };
    }

    if (nombre !== undefined) return errorEntrada();
    const actual = repos.apps.buscarPorId(id);
    if (!actual) return noEncontrado();
    const final = { ...actual, ...politica };
    if (final.algoritmo === 'SHA1' && !final.permitir_sha1) return errorEntrada();
    if (Object.keys(politica).length > 0) repos.apps.actualizarPolitica(id, politica);
    auditar(actorAdmin(ctx.admin), 'app.politica_actualizada', id, politica);
    return { status: 200, cuerpo: { app: appPublica(repos.apps.buscarPorId(id)) }, cabeceras: {} };
  }

  // ------------------------------------------------------------------ enrolamientos
  /**
   * GET /admin/api/enrollments?app_id&estado&limite — permiso enrolamientos.leer (ruta no
   * definida aún en openapi.yaml). 200 { enrollments: [...] } sin material cifrado.
   * @param {unknown} entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminListarEnrolamientos(entrada, ctx) {
    const negado = exigir(ctx, 'enrolamientos.leer');
    if (negado) return negado;
    const q = consulta(entrada, ESQUEMA_ADMIN_ENROLAMIENTOS);
    if (!q) return errorEntrada();
    const filas = consultas.listarEnrolamientos({ appId: q.app_id, estado: q.estado, limite: entero(q.limite, 100, 500) });
    const enrollments = filas.map(({ seed_ct: _a, seed_nonce: _b, seed_auth_tag: _c, ...resto }) => resto);
    return { status: 200, cuerpo: { enrollments }, cabeceras: {} };
  }

  // ------------------------------------------------------------------ llaves
  /**
   * POST /admin/api/keys/rotate — permiso llaves.rotar (solo Administrador). Sin cuerpo.
   * Genera un par Ed25519 nuevo (privada cifrada con AAD 'signing:'+kid) y deja la anterior en
   * 'solo_verificacion' (sigue en el JWKS y valida tokens ya emitidos).
   * 200 { new_kid, previous_kid, rotated_at }.
   * @param {unknown} entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminRotarLlaves(entrada, ctx) {
    const negado = exigir(ctx, 'llaves.rotar');
    if (negado) return negado;
    const { cuerpo } = separarEntrada(entrada ?? {});
    if (cuerpo !== undefined && cuerpo !== null && !validar(cuerpo, ESQUEMA_VACIO)) return errorEntrada();
    const rotadoEn = iso(reloj());
    const { nuevo, previo } = repos.transaccion(() => {
      const anterior = repos.signingKeys.activa();
      const clave = generarYGuardarClave({ repos, vault });
      if (anterior) repos.signingKeys.cambiarEstado(anterior.kid, 'solo_verificacion', rotadoEn);
      return { nuevo: clave.kid, previo: anterior?.kid ?? null };
    });
    if (typeof firmas.recargar === 'function') firmas.recargar();
    auditar(actorAdmin(ctx.admin), 'llaves.rotadas', nuevo, { previous_kid: previo });
    return { status: 200, cuerpo: { new_kid: nuevo, previous_kid: previo, rotated_at: rotadoEn }, cabeceras: {} };
  }

  // ------------------------------------------------------------------ auditoría
  /**
   * GET /admin/api/audit?desde&limite — permiso auditoria.leer. `desde` = id (cursor exclusivo)
   * o fecha ISO (inclusive). 200 { eventos: [filas de audit_log], siguiente: id | null }.
   * @param {unknown} entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminAuditoria(entrada, ctx) {
    const negado = exigir(ctx, 'auditoria.leer');
    if (negado) return negado;
    const q = consulta(entrada, ESQUEMA_ADMIN_AUDITORIA);
    if (!q) return errorEntrada();
    const desde = q.desde === undefined ? 0 : /^[0-9]+$/.test(q.desde) ? Number(q.desde) : q.desde;
    const limite = entero(q.limite, 100, 500);
    const eventos = repos.auditLog.listar(desde, limite);
    const siguiente = eventos.length === limite ? eventos[eventos.length - 1].id : null;
    return { status: 200, cuerpo: { eventos, siguiente }, cabeceras: {} };
  }

  /**
   * GET /admin/api/audit/verify-chain — permiso auditoria.verificar.
   * 200 { intact, checked_records, broken_at_id, last_hash }.
   * @param {unknown} _entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminVerificarCadena(_entrada, ctx) {
    const negado = exigir(ctx, 'auditoria.verificar');
    if (negado) return negado;
    return { status: 200, cuerpo: respuestaVerificacion(verificarCadena(repos.auditLog.recorrerTodo())), cabeceras: {} };
  }

  // ------------------------------------------------------------------ anomalías y métricas
  /**
   * GET /admin/api/anomalies?riesgo_minimo&limite — permiso anomalias.leer.
   * 200 { summary: { totalVerifications, blockedReplayCount, blockedAnomalyCount, avgInferenceMs },
   *       alerts: [{ id, userRefHash, ipHash, riskScore, level, action, reasons, resultado, createdAt }] }
   * (forma de contracts/mocks/admin-dashboard.json; userRefHash sustituye a externalUserId).
   * @param {unknown} entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminAnomalias(entrada, ctx) {
    const negado = exigir(ctx, 'anomalias.leer');
    if (negado) return negado;
    const q = consulta(entrada, ESQUEMA_ADMIN_ANOMALIAS);
    if (!q) return errorEntrada();
    const minimo = q.riesgo_minimo === undefined ? RIESGO_MINIMO_ANOMALIA : Math.min(100, Number(q.riesgo_minimo));
    const filas = consultas.intentosRiesgoAlto(minimo, entero(q.limite, 50, 500));
    const m = metricas?.instantanea?.();
    return {
      status: 200,
      cuerpo: {
        summary: {
          totalVerifications: m?.totales?.verificaciones ?? 0,
          blockedReplayCount: m?.resultadosVerificacion?.replay ?? 0,
          blockedAnomalyCount: m?.resultadosVerificacion?.anomaly_blocked ?? 0,
          avgInferenceMs: m?.inferencia?.mediaMs ?? 0,
        },
        alerts: filas.map((f) => ({
          id: f.id,
          userRefHash: f.user_ref_hash,
          ipHash: f.ip_hash,
          riskScore: f.risk_score,
          level: nivelDe(f.risk_score ?? 0),
          action: f.resultado === 'anomaly_blocked' ? 'BLOCK' : 'ALLOW',
          reasons: Array.isArray(f.reasons_json) ? f.reasons_json : [],
          resultado: f.resultado,
          createdAt: f.ts,
        })),
      },
      cabeceras: {},
    };
  }

  /**
   * GET /admin/api/metrics — permiso metricas.leer (ruta no definida aún en openapi.yaml).
   * 200 metricas.instantanea().
   * @param {unknown} _entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminMetricas(_entrada, ctx) {
    const negado = exigir(ctx, 'metricas.leer');
    if (negado) return negado;
    return { status: 200, cuerpo: metricas?.instantanea?.() ?? {}, cabeceras: {} };
  }

  return {
    autenticarApp, adminLogin, adminListarApps, adminActualizarApp, adminListarEnrolamientos,
    adminRotarLlaves, adminAuditoria, adminVerificarCadena, adminAnomalias, adminMetricas,
  };
}
