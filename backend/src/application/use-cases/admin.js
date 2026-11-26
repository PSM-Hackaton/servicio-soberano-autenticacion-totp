// Casos de uso de la consola administrativa (/admin/api/*) y autenticación de apps.
// ctx.admin = { id, usuario, rol } lo fija el servidor a partir de la sesión creada tras adminLogin.

import { randomBytes } from 'node:crypto';
import { verifyTotpWithDrift } from '../../core/totp/totp.js';
import {
  errorGenerico, generarClientId, generarSecretoCliente, hashSecretoAsync, verificarSecretoAsync,
} from '../../security/index.js';
import { verificarCadena, respuestaVerificacion } from '../../audit/index.js';
import { hashPepper } from '../../core/vault/vault.js';
import { derivarUserRefDesdeCedula, normalizarCedula } from '../../core/identidad/cedula.js';
import { contextoCedula } from '../../infrastructure/persistence/rotacionLlaveMaestra.js';
import {
  HASH_FICTICIO, PATRON_UUID, anonimizarIp, conflicto, derivaAGuardar, errorEntrada, topeDeriva, iso, noEncontrado, prohibido,
  separarEntrada, validar,
} from './comun.js';
import {
  ESQUEMA_ADMIN_ANOMALIAS, ESQUEMA_ADMIN_APP, ESQUEMA_ADMIN_AUDITORIA, ESQUEMA_ADMIN_ENROLAMIENTOS,
  ESQUEMA_ADMIN_LOGIN, ESQUEMA_VACIO,
} from './esquemas.js';
import { puede } from './rbac.js';

/** @typedef {import('./comun.js').Respuesta} Respuesta */

const MAX_INTENTOS_ADMIN = 5;
const RIESGO_MINIMO_ANOMALIA = 60;

/** Fila de app sin el hash del secreto ni el secreto de derivación de la cédula (ni cifrado). */
function appPublica(app) {
  if (!app) return null;
  const {
    secret_hash: _a, cedula_secreto_ct: _b, cedula_secreto_nonce: _c, cedula_secreto_auth_tag: _d, cedula_key_version: _e, ...resto
  } = app;
  return resto;
}

const MENSAJE_SIN_CEDULA = 'La aplicación no declara cómo deriva el user_ref desde la cédula.';

/** Nivel y acción del contrato a partir de un intento guardado. */
function nivelDe(score) {
  if (score >= 90) return 'CRITICAL';
  if (score >= 75) return 'HIGH';
  if (score >= 60) return 'MEDIUM';
  return 'LOW';
}

/**
 * Fila de audit_log para la API: `detalle` como objeto. La verificación de la cadena no usa esta
 * forma, sino el texto almacenado (el hash se calculó sobre él).
 */
function eventoPublico(fila) {
  if (typeof fila.detalle !== 'string') return { ...fila, detalle: null };
  try {
    return { ...fila, detalle: JSON.parse(fila.detalle) };
  } catch {
    return { ...fila }; // texto no JSON (no lo genera la bitácora): se entrega tal cual
  }
}

/** Fila de enrolamiento para la API: sin material cifrado. */
function enrolamientoPublico(e) {
  const { seed_ct: _a, seed_nonce: _b, seed_auth_tag: _c, ...resto } = e;
  return resto;
}

/** Transiciones del ciclo de vida desde la consola: acción → estados de origen, destino y evento de auditoría. */
const TRANSICIONES = Object.freeze({
  suspender: { desde: ['activo'], hacia: 'suspendido', evento: 'enrolamiento.suspendido' },
  reactivar: { desde: ['suspendido'], hacia: 'activo', evento: 'enrolamiento.reactivado' },
  revocar: { desde: ['activo', 'suspendido'], hacia: 'revocado', evento: 'enrolamiento.revocado' },
});

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
   * POST /admin/api/login — ESQUEMA_ADMIN_LOGIN { usuario, password, totp_code }. Contraseña
   * scrypt + TOTP del enrolamiento del admin con anti replay. Respuestas genéricas (401) y bloqueo progresivo (429).
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
    const codigo = v.totp_code;

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
        derivaMaxima: topeDeriva(enrol.drift_steps, appTotp?.ventana ?? 1),
      });
    } finally {
      semilla.fill(0);
    }
    const aceptado = repos.transaccion(() => {
      if (r.valid && repos.enrollments.registrarPasoAceptado(enrol.id, r.matchedStep,
        derivaAGuardar(enrol.drift_steps, r.driftSteps, appTotp?.ventana ?? 1))) return true;
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
    const {
      id: _i, nombre, user_ref_desde_cedula: modoCedula, cedula_prefijo: prefijoCedula, cedula_secreto: secretoCedula, ...politica
    } = v;
    const pideCedula = modoCedula !== undefined || prefijoCedula !== undefined || secretoCedula !== undefined;

    if (id === undefined) {
      if (!nombre) return errorEntrada();
      if ((politica.algoritmo ?? 'SHA256') === 'SHA1' && !politica.permitir_sha1) return errorEntrada();
      const planCedula = pideCedula ? planDerivacion(null, modoCedula, prefijoCedula, secretoCedula) : null;
      if (pideCedula && !planCedula) return errorEntrada();
      const clientId = generarClientId('app');
      const clientSecret = generarSecretoCliente();
      const secretHash = await hashSecretoAsync(clientSecret);
      const app = repos.transaccion(() => {
        const creada = repos.apps.crear({ nombre, client_id: clientId, secret_hash: secretHash, ...politica });
        if (planCedula) aplicarDerivacion(creada.id, planCedula);
        return repos.apps.buscarPorId(creada.id);
      });
      auditar(actorAdmin(ctx.admin), 'app.registrada', app.id, { nombre, client_id: clientId, ...politica, ...planCedula?.detalle });
      const cuerpoRespuesta = { app: appPublica(app), client_id: clientId, client_secret: clientSecret };
      if (planCedula?.generado) cuerpoRespuesta.cedula_secreto = planCedula.generado;
      return { status: 201, cuerpo: cuerpoRespuesta, cabeceras: { 'Cache-Control': 'no-store' } };
    }

    if (nombre !== undefined) return errorEntrada();
    const actual = repos.apps.buscarPorId(id);
    if (!actual) return noEncontrado();
    const final = { ...actual, ...politica };
    if (final.algoritmo === 'SHA1' && !final.permitir_sha1) return errorEntrada();
    const planCedula = pideCedula ? planDerivacion(actual, modoCedula, prefijoCedula, secretoCedula) : null;
    if (pideCedula && !planCedula) return errorEntrada();
    repos.transaccion(() => {
      if (Object.keys(politica).length > 0) repos.apps.actualizarPolitica(id, politica);
      if (planCedula) aplicarDerivacion(id, planCedula);
    });
    auditar(actorAdmin(ctx.admin), 'app.politica_actualizada', id, { ...politica, ...planCedula?.detalle });
    const cuerpoRespuesta = { app: appPublica(repos.apps.buscarPorId(id)) };
    if (planCedula?.generado) cuerpoRespuesta.cedula_secreto = planCedula.generado;
    return { status: 200, cuerpo: cuerpoRespuesta, cabeceras: planCedula?.generado ? { 'Cache-Control': 'no-store' } : {} };
  }

  /**
   * Decide la derivación del user_ref desde la cédula a partir de la app actual (null al registrar)
   * y de los campos recibidos. null → combinación inválida (400). Con 'hmac' y sin secreto aportado
   * se conserva el que ya hubiera o se genera uno nuevo (32 bytes aleatorios) que se devuelve una vez.
   * El detalle para la bitácora nunca incluye el secreto.
   */
  function planDerivacion(actual, modo, prefijo, secreto) {
    const modoFinal = modo ?? actual?.user_ref_desde_cedula ?? 'ninguno';
    if (modoFinal === 'ninguno') {
      if (prefijo !== undefined || secreto !== undefined) return null;
      return { modo: 'ninguno', prefijo: '', cifrado: null, claro: null, generado: null, detalle: { user_ref_desde_cedula: 'ninguno' } };
    }
    const prefijoFinal = prefijo ?? actual?.cedula_prefijo ?? '';
    let origen;
    let generado = null;
    let claro = null;
    let cifrado = null;
    if (secreto !== undefined) {
      claro = Buffer.from(secreto, 'base64url');
      if (claro.length < 32 || claro.length > 64) return null;
      origen = 'aportado';
    } else if (actual?.cedula_secreto_ct) {
      cifrado = { ct: actual.cedula_secreto_ct, nonce: actual.cedula_secreto_nonce, authTag: actual.cedula_secreto_auth_tag, keyVersion: actual.cedula_key_version };
      origen = 'conservado';
    } else {
      claro = randomBytes(32);
      generado = claro.toString('base64url');
      origen = 'generado';
    }
    return {
      modo: 'hmac', prefijo: prefijoFinal, cifrado, claro, generado,
      detalle: { user_ref_desde_cedula: 'hmac', cedula_prefijo: prefijoFinal, secreto_cedula: origen },
    };
  }

  /** Guarda el plan (cifra el secreto en claro con la bóveda, AAD 'cedula:' + app_id) y borra el claro. */
  function aplicarDerivacion(appId, plan) {
    let cifrado = plan.cifrado;
    if (plan.claro) {
      try {
        cifrado = vault.encryptBlob(plan.claro, contextoCedula(appId));
      } finally {
        plan.claro.fill(0);
        plan.claro = null;
      }
    }
    repos.apps.configurarCedula(appId, { modo: plan.modo, prefijo: plan.prefijo, cifrado });
  }

  /**
   * POST /admin/api/apps/:id/secret — permiso apps.secreto (solo Administrador). Sin cuerpo.
   * Genera un client_secret nuevo (scrypt) que sustituye al anterior de inmediato; el servidor
   * invalida su caché de autenticación de apps. 200 { app, client_id, client_secret } (una sola vez,
   * Cache-Control no-store) | 404.
   * @param {unknown} entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminRegenerarSecretoApp(entrada, ctx) {
    const negado = exigir(ctx, 'apps.secreto');
    if (negado) return negado;
    const { id, cuerpo } = separarEntrada(entrada ?? {});
    if (cuerpo !== undefined && cuerpo !== null && !validar(cuerpo, ESQUEMA_VACIO)) return errorEntrada();
    if (typeof id !== 'string' || id.length === 0 || id.length > 64) return noEncontrado();
    const app = repos.apps.buscarPorId(id);
    if (!app) return noEncontrado();
    const clientSecret = generarSecretoCliente();
    if (!repos.apps.actualizarSecreto(app.id, await hashSecretoAsync(clientSecret))) return noEncontrado();
    auditar(actorAdmin(ctx.admin), 'app.secreto_regenerado', app.id, { client_id: app.client_id });
    return {
      status: 200,
      cuerpo: { app: appPublica(repos.apps.buscarPorId(app.id)), client_id: app.client_id, client_secret: clientSecret },
      cabeceras: { 'Cache-Control': 'no-store' },
    };
  }

  // ------------------------------------------------------------------ enrolamientos
  /**
   * GET /admin/api/enrollments?app_id&estado&limite — permiso enrolamientos.leer.
   * 200 { enrollments: [...] } sin material cifrado.
   * @param {unknown} entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminListarEnrolamientos(entrada, ctx) {
    const negado = exigir(ctx, 'enrolamientos.leer');
    if (negado) return negado;
    const q = consulta(entrada, ESQUEMA_ADMIN_ENROLAMIENTOS);
    if (!q) return errorEntrada();
    if (q.cedula !== undefined || q.user_ref !== undefined) return buscarEnrolamientos(q, ctx);
    const filas = consultas.listarEnrolamientos({ appId: q.app_id, estado: q.estado, limite: entero(q.limite, 100, 500) });
    const enrollments = filas.map(enrolamientoPublico);
    return { status: 200, cuerpo: { enrollments }, cabeceras: {} };
  }

  /**
   * Búsqueda de soporte (GET /admin/api/enrollments con `cedula` o `user_ref`, excluyentes, y
   * `app_id` obligatorio). Con `cedula`, la app debe haber declarado user_ref_desde_cedula = 'hmac':
   * el servicio descifra su secreto de derivación, recalcula user_ref = prefijo + HMAC y busca por
   * user_ref_hash. 400 entrada inválida | 404 app inexistente | 409 la app no deriva desde la cédula.
   * Cada búsqueda queda en la bitácora sin la cédula ni el user_ref en claro: solo
   * HMAC-SHA256('cedula:' + canónica, USER_REF_PEPPER) o el user_ref_hash.
   */
  function buscarEnrolamientos(q, ctx) {
    if (q.cedula !== undefined && q.user_ref !== undefined) return errorEntrada();
    if (q.app_id === undefined) return errorEntrada();
    const cedula = q.cedula === undefined ? null : normalizarCedula(q.cedula);
    if (q.cedula !== undefined && !cedula) return errorEntrada();
    const app = repos.apps.buscarPorId(q.app_id);
    if (!app) return noEncontrado();

    let userRef = q.user_ref;
    if (cedula) {
      if (app.user_ref_desde_cedula !== 'hmac' || !app.cedula_secreto_ct) return conflicto(MENSAJE_SIN_CEDULA);
      const claro = vault.decryptBlob({
        ct: app.cedula_secreto_ct, nonce: app.cedula_secreto_nonce, authTag: app.cedula_secreto_auth_tag, keyVersion: app.cedula_key_version,
      }, contextoCedula(app.id));
      try {
        userRef = derivarUserRefDesdeCedula(cedula.canonica, claro.toString('base64url'), app.cedula_prefijo ?? '');
      } finally {
        claro.fill(0);
      }
    }
    const urh = hashPepper(userRef, config.userRefPepper);
    const filas = consultas.listarEnrolamientos({ appId: app.id, userRefHash: urh, estado: q.estado, limite: entero(q.limite, 100, 500) });
    auditar(actorAdmin(ctx.admin), 'enrolamientos.busqueda', app.id, cedula
      ? { criterio: 'cedula', cedula_hmac: hashPepper(`cedula:${cedula.canonica}`, config.userRefPepper), resultados: filas.length }
      : { criterio: 'user_ref', user_ref_hash: urh, resultados: filas.length });
    return { status: 200, cuerpo: { enrollments: filas.map(enrolamientoPublico) }, cabeceras: { 'Cache-Control': 'no-store' } };
  }

  /**
   * POST /admin/api/enrollments/:id/{suspend|reactivate|revoke} — permiso enrolamientos.gestionar
   * (Administrador y Operador). Sin cuerpo (o {}). Transiciones: activo ↔ suspendido y
   * activo | suspendido → revocado (final). 200 { enrollment } | 404 genérico (id inexistente o no
   * UUID) | 409 transición no válida, otro enrolamiento activo del mismo usuario (reactivar) o factor
   * de un administrador de la consola (se gestiona con /admin/api/admins).
   * Un enrolamiento suspendido no aparece como activo: verify responde igual que un código incorrecto.
   * @param {'suspender' | 'reactivar' | 'revocar'} accion
   */
  function cambiarEstadoEnrolamiento(accion) {
    const t = TRANSICIONES[accion];
    return async (entrada, ctx) => {
      const negado = exigir(ctx, 'enrolamientos.gestionar');
      if (negado) return negado;
      const { id, cuerpo } = separarEntrada(entrada ?? {});
      if (cuerpo !== undefined && cuerpo !== null && !validar(cuerpo, ESQUEMA_VACIO)) return errorEntrada();
      if (typeof id !== 'string' || !PATRON_UUID.test(id)) return noEncontrado();
      const ahora = iso(reloj());
      const r = repos.transaccion(() => {
        const e = repos.enrollments.buscarPorId(id.toLowerCase());
        if (!e) return { status: 404 };
        if (repos.admins.buscarPorEnrolamiento(e.id)) return { status: 409, mensaje: 'El factor de un administrador se gestiona desde Administradores.' };
        if (!t.desde.includes(e.estado)) return { status: 409, mensaje: 'La transición de estado no es válida.' };
        if (accion === 'reactivar') {
          const otro = repos.enrollments.buscarActivoPorUsuario(e.app_id, e.user_ref_hash);
          if (otro && otro.id !== e.id) return { status: 409, mensaje: 'El usuario ya tiene otro enrolamiento activo en la aplicación.' };
        }
        const ok = accion === 'suspender' ? repos.enrollments.suspender(e.id)
          : accion === 'reactivar' ? repos.enrollments.reactivar(e.id)
            : repos.enrollments.revocarVigente(e.id, ahora);
        if (!ok) return { status: 409, mensaje: 'La transición de estado no es válida.' };
        return { status: 200, previo: e.estado, enrol: repos.enrollments.buscarPorId(e.id) };
      });
      if (r.status === 404) return noEncontrado();
      if (r.status === 409) return conflicto(r.mensaje);
      auditar(actorAdmin(ctx.admin), t.evento, r.enrol.id, { app_id: r.enrol.app_id, estado_previo: r.previo, motivo: 'consola' });
      return { status: 200, cuerpo: { enrollment: enrolamientoPublico(r.enrol) }, cabeceras: {} };
    };
  }

  // ------------------------------------------------------------------ llaves
  /**
   * GET /admin/api/keys — permiso llaves.leer (Administrador, Operador, Auditor). Sin parámetros.
   * 200 { active_kid, keys: [{ kid, estado, created_at, rotated_at, alg: 'EdDSA', crv: 'Ed25519' }] }.
   * Nunca incluye material privado (ni cifrado) ni la versión de la llave maestra.
   * @param {unknown} entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminListarLlaves(entrada, ctx) {
    const negado = exigir(ctx, 'llaves.leer');
    if (negado) return negado;
    if (!consulta(entrada, ESQUEMA_VACIO)) return errorEntrada();
    const keys = repos.signingKeys.listarTodas().map((k) => ({
      kid: k.kid, estado: k.estado, created_at: k.created_at, rotated_at: k.rotated_at ?? null, alg: 'EdDSA', crv: 'Ed25519',
    }));
    const activa = firmas.kidActivo ?? keys.find((k) => k.estado === 'activa')?.kid ?? null;
    return { status: 200, cuerpo: { active_kid: activa, keys }, cabeceras: {} };
  }

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
    const { new_kid: nuevo, previous_kid: previo, rotated_at: rotadoEn } = firmas.rotar(iso(reloj()));
    auditar(actorAdmin(ctx.admin), 'llaves.rotadas', nuevo, { previous_kid: previo });
    return { status: 200, cuerpo: { new_kid: nuevo, previous_kid: previo, rotated_at: rotadoEn }, cabeceras: {} };
  }

  // ------------------------------------------------------------------ auditoría
  /**
   * GET /admin/api/audit?desde&limite — permiso auditoria.leer. `desde` = id (cursor exclusivo)
   * o fecha ISO (inclusive). 200 { eventos: [filas de audit_log con `detalle` objeto], siguiente: id | null }.
   * @param {unknown} entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminAuditoria(entrada, ctx) {
    const negado = exigir(ctx, 'auditoria.leer');
    if (negado) return negado;
    const q = consulta(entrada, ESQUEMA_ADMIN_AUDITORIA);
    if (!q) return errorEntrada();
    const desde = q.desde === undefined ? 0 : /^[0-9]+$/.test(q.desde) ? Number(q.desde) : q.desde;
    const limite = entero(q.limite, 100, 500);
    const filas = repos.auditLog.listar(desde, limite);
    const siguiente = filas.length === limite ? filas[filas.length - 1].id : null;
    return { status: 200, cuerpo: { eventos: filas.map(eventoPublico), siguiente }, cabeceras: {} };
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
   * GET /admin/api/metrics — permiso metricas.leer.
   * 200 metricas.instantanea() (vía de acceso remoto a las métricas; /metrics es solo loopback).
   * @param {unknown} _entrada @param {{ admin: any }} ctx @returns {Promise<Respuesta>}
   */
  async function adminMetricas(_entrada, ctx) {
    const negado = exigir(ctx, 'metricas.leer');
    if (negado) return negado;
    return { status: 200, cuerpo: metricas?.instantanea?.() ?? {}, cabeceras: {} };
  }

  return {
    autenticarApp, adminLogin, adminListarApps, adminActualizarApp, adminRegenerarSecretoApp, adminListarEnrolamientos,
    adminSuspenderEnrolamiento: cambiarEstadoEnrolamiento('suspender'),
    adminReactivarEnrolamiento: cambiarEstadoEnrolamiento('reactivar'),
    adminRevocarEnrolamiento: cambiarEstadoEnrolamiento('revocar'),
    adminListarLlaves, adminRotarLlaves, adminAuditoria, adminVerificarCadena, adminAnomalias, adminMetricas,
  };
}
