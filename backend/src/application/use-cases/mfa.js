// Casos de uso de la API v1 para integradores (/api/v1/*) y JWKS público.
// Cada función recibe (entrada, ctx) y devuelve { status, cuerpo, cabeceras? } según
// contracts/openapi.yaml. ctx.app es la fila de `apps` ya autenticada por el servidor.

import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as esperar } from 'node:timers/promises';
import { buildOtpauthUri, resyncTwoConsecutiveCodes, verifyTotpWithDrift } from '../../core/totp/totp.js';
import { generateSeed, hashPepper } from '../../core/vault/vault.js';
import { signMfaJwt, verifyMfaJwt } from '../../core/tokens/tokens.js';
import { encodeQr, qrToSvg } from '../../core/qr/qr.js';
import {
  errorGenerico, generarCodigosRecuperacion, hashSecretoAsync, normalizarCodigoRecuperacion, normalizarIp, verificarSecretoAsync,
} from '../../security/index.js';
import {
  PATRON_UUID, EVALUACION_NEUTRA, HASH_FICTICIO, anonimizarOrigen, crearMapaAcotado, derivaAGuardar, errorEntrada, huella, iso,
  noEncontrado, riesgoContrato, separarEntrada, topeDeriva, validar,
} from './comun.js';
import {
  ESQUEMA_ACTIVAR, ESQUEMA_ENROLAR, ESQUEMA_RECUPERAR, ESQUEMA_RESINCRONIZAR, ESQUEMA_VACIO,
  ESQUEMA_VALIDAR_TOKEN, ESQUEMA_VERIFICAR,
} from './esquemas.js';

/** @typedef {import('./comun.js').Respuesta} Respuesta */

const TTL_IDEMPOTENCIA_MS = 5 * 60 * 1000;
const MAX_IDEMPOTENCIA = 1000;
const PATRON_IDEMPOTENCIA = /^[A-Za-z0-9._:-]{1,128}$/;
const SEGUNDOS_BLOQUEO_ANOMALIA = 300;
const LIMITE_HISTORIAL = 50;

/** Descifra la semilla de una fila de enrollments (AAD = id + ':' + key_version). */
function semillaDe(vault, enrol) {
  return vault.decryptSeed({
    ct: enrol.seed_ct, nonce: enrol.seed_nonce, authTag: enrol.seed_auth_tag, keyVersion: enrol.key_version,
  }, enrol.id);
}

/**
 * Política TOTP del enrolamiento con la ventana de la app y el tope de deriva:
 * |deriva resultante| <= max(|drift_steps guardado|, ventana) (solo resync fija derivas mayores).
 */
const politicaDe = (enrol, app) => {
  const ventana = app?.ventana ?? 1;
  return {
    algoritmo: enrol.algoritmo, digitos: enrol.digitos, periodo: enrol.periodo, ventana,
    derivaMaxima: topeDeriva(enrol.drift_steps, ventana),
  };
};

/**
 * IP de origen del usuario final: `client_ip` (si la app lo envía) en forma canónica o la IP TCP.
 * @param {unknown} clientIp @param {string | undefined} ipTcp
 * @returns {{ ok: true, ip: string | undefined } | { ok: false }}
 */
function resolverOrigen(clientIp, ipTcp) {
  if (clientIp === undefined) return { ok: true, ip: ipTcp };
  const ip = normalizarIp(clientIp);
  return ip ? { ok: true, ip } : { ok: false };
}

/** Respuesta 429 de bloqueo progresivo. @param {number} segundos */
const respuestaBloqueo = (segundos) => errorGenerico('limite', { reintentarEnSegundos: segundos });

/**
 * @param {{ repos: any, vault: any, firmas: any, detector: any, bitacora: any, metricas: any,
 *   config: any, reloj: () => number, consultas: ReturnType<typeof import('./consultas.js').crearConsultas>,
 *   bloqueos: ReturnType<typeof import('./bloqueos.js').crearControlBloqueos> }} d
 */
export function crearCasosMfa(d) {
  const { repos, vault, firmas, detector, bitacora, metricas, config, reloj, consultas, bloqueos } = d;
  /** @type {ReturnType<typeof crearMapaAcotado<{ huella: string, respuesta: Promise<Respuesta> }>>} */
  const idempotencia = crearMapaAcotado({ maxEntradas: MAX_IDEMPOTENCIA, ttlMs: TTL_IDEMPOTENCIA_MS, reloj });

  const userRefHash = (userRef) => hashPepper(userRef, config.userRefPepper);
  const actorApp = (app) => `app:${app.client_id}`;
  const auditar = (actor, accion, objetivo, detalle) => bitacora.registrar({ actor, accion, objetivo, detalle });
  const metrica = (resultado) => { try { metricas?.registrarResultadoVerificacion(resultado); } catch { /* sin métricas */ } };

  /** Busca el enrolamiento solo si pertenece a la app que llama. */
  function enrolamientoDeApp(id, app) {
    // nosemgrep: nodejs_scan.javascript-dos-rule-regex_dos -- no es un manejador req/res; PATRON_UUID es un literal anclado de longitud fija (36)
    if (typeof id !== 'string' || id.length !== 36 || !PATRON_UUID.test(id)) return null;
    const e = repos.enrollments.buscarPorId(id.toLowerCase());
    return e && e.app_id === app.id ? e : null;
  }

  /** Registra un intento en attempts (sin datos personales: solo hashes). */
  function registrarIntento({ enrol, app, urh, ipHash, resultado, evaluacion, ahora }) {
    repos.attempts.registrar({
      enrollment_id: enrol?.id ?? null,
      app_id: app.id,
      user_ref_hash: urh,
      ip_hash: ipHash,
      resultado,
      risk_score: evaluacion?.riskScore ?? null,
      reasons_json: evaluacion?.reasons ?? null,
      inference_ms: evaluacion?.inferenceMs ?? null,
      ts: iso(ahora),
    });
  }

  /**
   * Historial reciente por origen y por cuenta, sin duplicados, para el detector.
   * El origen (ip_hash) es HMAC(app_id + ':' + IP del usuario final): es propio de cada app. Antes
   * se puntuaba por la IP TCP, que es la del servidor del integrador; todos los ciudadanos de un
   * portal compartían historial y unos pocos fallos bloqueaban al portal entero. El historial por
   * cuenta también es por app de forma natural: user_ref_hash solo coincide dentro de la misma app.
   */
  function historial(ipHash, urh) {
    const vistos = new Set();
    const filas = [];
    const porOrigen = consultas.historialDetector({ ipHash }, LIMITE_HISTORIAL);
    const porCuenta = consultas.historialDetector({ userRefHash: urh }, LIMITE_HISTORIAL);
    for (const f of [...porOrigen, ...porCuenta]) {
      if (vistos.has(f.id)) continue;
      vistos.add(f.id);
      filas.push({ user_ref_hash: f.user_ref_hash, ip_hash: f.ip_hash, resultado: f.resultado, ts: f.ts });
    }
    return filas;
  }

  /** Evalúa con el detector inyectado; si falla, evaluación neutra (el servicio no cae). */
  async function evaluarRiesgo(ipHash, urh, ahora) {
    let e;
    try {
      e = await detector.evaluar({ user_ref_hash: urh, ip_hash: ipHash, ts: ahora }, historial(ipHash, urh), ahora);
    } catch {
      e = null;
    }
    const evaluacion = e && Number.isFinite(e.riskScore) ? e : { ...EVALUACION_NEUTRA };
    try { metricas?.registrarInferencia(evaluacion.inferenceMs); } catch { /* sin métricas */ }
    return evaluacion;
  }

  /**
   * ¿Puede el detector bloquear o retrasar intentos de esta app? HEURISTICS_MODE=monitorizacion
   * (config.modoHeuristica) prevalece sobre la política de cada app: nunca se bloquea por anomalía.
   */
  const bloqueoActivo = (app) => config.modoHeuristica !== 'monitorizacion' && app.modo_heuristica === 'bloqueo';

  /**
   * En monitorización (global o de la app) las acciones restrictivas se degradan a 'alerta':
   * el intento sigue su curso y se audita (verificacion.alerta) con la acción realmente aplicada.
   */
  function accionEfectiva(app, e) {
    if (bloqueoActivo(app) || (e.action !== 'bloqueo_temporal' && e.action !== 'espera_extra')) return e;
    return { ...e, action: 'alerta' };
  }

  /**
   * Bloqueo adaptativo: el detector pide bloqueo temporal o el riesgo alcanza el umbral de la app.
   * Si el detector cedió al bloqueo progresivo (una cuenta, un origen, menos fallos que el primer
   * escalón), tampoco bloquea el umbral propio de la app: el ciudadano que se equivoca rápido no
   * queda 5 min fuera; a partir del 5.º fallo manda el bloqueo progresivo (30 s → 2 min → …).
   */
  function debeBloquear(app, e) {
    if (!bloqueoActivo(app)) return false;
    if (e.cedidoAlProgresivo === true) return false;
    return e.action === 'bloqueo_temporal' || e.riskScore >= (app.umbral_riesgo_bloqueo ?? 101);
  }

  // ------------------------------------------------------------------ enrolar
  /**
   * POST /api/v1/enrollments — esquema ESQUEMA_ENROLAR { user_ref, account_label?, algorithm?, digits?, period? }.
   * 201 EnrollmentCreatedResponse | 400 GenericError.
   * La política por defecto es la de la app; SHA1 solo si app.permitir_sha1.
   * @param {unknown} entrada @param {{ app: any, ip?: string }} ctx @returns {Promise<Respuesta>}
   */
  async function enrolar(entrada, ctx) {
    const { app } = ctx ?? {};
    if (!app) return errorGenerico('credenciales');
    const v = validar(separarEntrada(entrada).cuerpo, ESQUEMA_ENROLAR);
    if (!v) return errorEntrada();
    const politica = { algoritmo: v.algorithm ?? app.algoritmo, digitos: v.digits ?? app.digitos, periodo: v.period ?? app.periodo };
    if (politica.algoritmo === 'SHA1' && !app.permitir_sha1) return errorEntrada();

    const ahora = reloj();
    const id = randomUUID(); // primero el id: forma parte del AAD del cifrado
    const semilla = generateSeed(politica.algoritmo);
    try {
      const cifrado = vault.encryptSeed(semilla, id);
      const expiresAt = iso(ahora + (config.minutosPendiente ?? 10) * 60_000);
      repos.enrollments.crearPendiente({
        id,
        app_id: app.id,
        user_ref_hash: userRefHash(v.user_ref),
        ...politica,
        seed_ct: cifrado.ct,
        seed_nonce: cifrado.nonce,
        seed_auth_tag: cifrado.authTag,
        key_version: cifrado.keyVersion,
        pending_expires_at: expiresAt,
      });
      const otpauthUri = buildOtpauthUri({ semilla, emisor: config.emisorTotp, cuenta: v.account_label ?? v.user_ref, ...politica });
      const qrSvg = qrToSvg(encodeQr(otpauthUri));
      auditar(actorApp(app), 'enrolamiento.creado', id, { ...politica, expires_at: expiresAt });
      return {
        status: 201,
        cuerpo: {
          enrollment_id: id,
          estado: 'pendiente',
          algoritmo: politica.algoritmo,
          digitos: politica.digitos,
          periodo: politica.periodo,
          otpauth_uri: otpauthUri,
          qr_svg: qrSvg,
          expires_at: expiresAt,
        },
        cabeceras: { 'Cache-Control': 'no-store' },
      };
    } finally {
      semilla.fill(0);
    }
  }

  // ------------------------------------------------------------------ activar
  /**
   * POST /api/v1/enrollments/{id}/activate — entrada { id, cuerpo: { code, client_ip? } } (ESQUEMA_ACTIVAR).
   * 200 ActivateResponse | 400 entrada | 401 código inválido/expirado/ajeno | 429 bloqueo.
   * Si ya había un enrolamiento activo del mismo usuario en la app, se revoca en la misma transacción.
   * @param {unknown} entrada @param {{ app: any, ip?: string }} ctx @returns {Promise<Respuesta>}
   */
  async function activar(entrada, ctx) {
    const { app } = ctx ?? {};
    if (!app) return errorGenerico('credenciales');
    const { id, cuerpo } = separarEntrada(entrada);
    const v = validar(cuerpo, ESQUEMA_ACTIVAR);
    if (!v || typeof id !== 'string' || !PATRON_UUID.test(id) || !resolverOrigen(v.client_ip, ctx.ip).ok) return errorEntrada();
    const ahora = reloj();
    const enrol = enrolamientoDeApp(id, app);
    if (!enrol || enrol.estado !== 'pendiente' || !(Date.parse(enrol.pending_expires_at) > ahora)) {
      return errorGenerico('codigo');
    }
    const restante = bloqueos.restanteEnrolamiento(enrol, ahora);
    if (restante > 0) return respuestaBloqueo(restante);

    const semilla = semillaDe(vault, enrol);
    let r;
    try {
      r = verifyTotpWithDrift(semilla, v.code, ahora, { ...politicaDe(enrol, app), driftSteps: 0, lastStep: enrol.last_step });
    } finally {
      semilla.fill(0);
    }
    if (!r.valid) {
      const hasta = repos.transaccion(() => bloqueos.falloEnrolamiento(enrol.id, app.max_intentos, ahora));
      if (hasta) auditar(actorApp(app), 'enrolamiento.bloqueado', enrol.id, { locked_until: hasta, origen: 'activacion' });
      return errorGenerico('codigo');
    }

    const codigos = generarCodigosRecuperacion(10);
    const hashes = await Promise.all(codigos.map((c) => hashSecretoAsync(normalizarCodigoRecuperacion(c) ?? c)));
    const activadoEn = iso(ahora);
    let revocadoPrevio = null;
    const ok = repos.transaccion(() => {
      const previo = repos.enrollments.buscarActivoPorUsuario(app.id, enrol.user_ref_hash);
      if (!repos.enrollments.activar(enrol.id, activadoEn)) return false;
      if (!repos.enrollments.registrarPasoAceptado(enrol.id, r.matchedStep, r.driftSteps)) {
        throw new Error('Carrera al activar el enrolamiento');
      }
      if (previo && previo.id !== enrol.id && repos.enrollments.revocar(previo.id, activadoEn)) revocadoPrevio = previo.id;
      repos.recoveryCodes.insertarLote(enrol.id, hashes);
      return true;
    });
    if (!ok) return errorGenerico('codigo');
    if (revocadoPrevio) auditar(actorApp(app), 'enrolamiento.revocado', revocadoPrevio, { motivo: 'reemplazado', por: enrol.id });
    auditar(actorApp(app), 'enrolamiento.activado', enrol.id, { recovery_codes_emitidos: codigos.length });
    return {
      status: 200,
      cuerpo: { enrollment_id: enrol.id, estado: 'activo', activated_at: activadoEn, recovery_codes: codigos },
      cabeceras: { 'Cache-Control': 'no-store' },
    };
  }

  // ------------------------------------------------------------------ verificar
  /** Núcleo de verify (sin idempotencia). `ip` = IP de origen ya resuelta (client_ip o TCP). */
  async function verificarInterno(v, app, ip) {
    const ahora = reloj();
    const urh = userRefHash(v.user_ref);
    const ipHash = anonimizarOrigen(app.id, ip, config.ipPepperSemilla, ahora);
    const enrol = repos.enrollments.buscarActivoPorUsuario(app.id, urh);
    const base = { enrol, app, urh, ipHash, ahora };

    // 1. Bloqueo progresivo vigente (cuenta real o inexistente: misma respuesta).
    const restante = enrol ? bloqueos.restanteEnrolamiento(enrol, ahora) : bloqueos.restanteInexistente(app.id, urh, app.max_intentos, ahora);
    if (restante > 0) {
      registrarIntento({ ...base, resultado: 'locked', evaluacion: null });
      metrica('locked');
      return respuestaBloqueo(restante);
    }

    // 2. Detector local de anomalías (antes de verificar el código).
    const evaluacion = accionEfectiva(app, await evaluarRiesgo(ipHash, urh, ahora));
    if (debeBloquear(app, evaluacion)) {
      // Detalle (puntuación, razones, umbral) solo en attempts, bitácora y /admin/api/anomalies.
      // Hacia fuera, el mismo 429 TOO_MANY_REQUESTS genérico que cualquier otro límite.
      registrarIntento({ ...base, resultado: 'anomaly_blocked', evaluacion });
      metrica('anomaly_blocked');
      auditar('detector', 'verificacion.anomalia_bloqueada', enrol?.id ?? null, {
        app_id: app.id, ip_hash: ipHash, risk_score: evaluacion.riskScore, reasons: evaluacion.reasons,
        umbral: app.umbral_riesgo_bloqueo ?? null,
      });
      return respuestaBloqueo(config.segundosBloqueoAnomalia ?? SEGUNDOS_BLOQUEO_ANOMALIA);
    }
    if (evaluacion.action === 'alerta') {
      auditar('detector', 'verificacion.alerta', enrol?.id ?? null, {
        app_id: app.id, ip_hash: ipHash, risk_score: evaluacion.riskScore, reasons: evaluacion.reasons,
      });
    }
    if (evaluacion.action === 'espera_extra' && config.esperaExtraMs > 0) {
      await esperar(config.esperaExtraMs);
    }

    // 3. Usuario sin enrolamiento activo: trabajo equivalente y misma respuesta que código incorrecto.
    //    Los fallos quedan en attempts y de ahí sale su bloqueo progresivo (sobrevive a un reinicio).
    if (!enrol) {
      verifyTotpWithDrift(randomBytes(32), v.code, ahora, { algoritmo: 'SHA256', digitos: app.digitos, periodo: app.periodo, ventana: app.ventana });
      // Una sola transacción (una confirmación a disco): intento + bloqueo + evento de bitácora.
      repos.transaccion(() => {
        registrarIntento({ ...base, resultado: 'invalid_code', evaluacion });
        const hasta = bloqueos.falloInexistente(app.id, urh, app.max_intentos, ahora);
        if (hasta) auditar(actorApp(app), 'verificacion.bloqueo', null, { user_ref_hash: urh, locked_until: hasta });
      });
      metrica('invalid_code');
      return errorGenerico('codigo');
    }

    // 4. RFC 6238 con ventana, deriva acotada y anti replay.
    const semilla = semillaDe(vault, enrol);
    let r;
    try {
      r = verifyTotpWithDrift(semilla, v.code, ahora, { ...politicaDe(enrol, app), driftSteps: enrol.drift_steps, lastStep: enrol.last_step });
    } finally {
      semilla.fill(0);
    }
    let resultado = r.valid ? 'ok' : r.reason === 'replay' ? 'replay' : 'invalid_code';
    const ventana = app?.ventana ?? 1;
    const derivaFinal = r.valid ? derivaAGuardar(enrol.drift_steps, r.driftSteps, ventana) : enrol.drift_steps;

    // 5. Si el código es válido, el JWT Ed25519 de un solo uso (sub = user_ref_hash, aud = client_id)
    //    se firma ANTES de abrir la transacción: así la transacción solo contiene escrituras y el
    //    evento de bitácora (que lleva el jti) se confirma con el paso aceptado y el intento.
    //    Si otra petición gana la carrera con el mismo paso, el token se descarta sin emitirse.
    let token = null;
    let claims = null;
    let kid = null;
    if (resultado === 'ok') {
      const activa = firmas.activa();
      kid = activa.kid;
      token = signMfaJwt({
        privateKey: activa.privateKey, kid, issuer: config.emisorJwt, audience: app.client_id, subject: urh,
        ttlSegundos: config.ttlJwtSegundos ?? 300, ahora,
      });
      claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    }

    // Una sola transacción por verificación (una confirmación a disco): paso aceptado (anti replay
    // atómico) + intento + eventos de bitácora. Si algo falla, nada queda escrito y no hay token.
    repos.transaccion(() => {
      if (resultado === 'ok' && !repos.enrollments.registrarPasoAceptado(enrol.id, r.matchedStep, derivaFinal)) {
        resultado = 'replay'; // otra petición ganó la carrera con el mismo paso
      }
      registrarIntento({ ...base, resultado, evaluacion });
      if (resultado === 'ok') {
        auditar(actorApp(app), 'verificacion.exitosa', enrol.id, { jti: claims.jti, kid, drift_steps: derivaFinal, drift_observado: r.driftSteps });
        return;
      }
      const hasta = bloqueos.falloEnrolamiento(enrol.id, app.max_intentos, ahora);
      // Un replay responde EXACTAMENTE igual que un código incorrecto (401 VERIFICATION_FAILED, sin
      // Retry-After): distinguirlo sería un oráculo que confirma que el código fue válido. Internamente
      // queda como 'replay' en attempts, en la bitácora y en las métricas, y cuenta para el bloqueo.
      if (resultado === 'replay') auditar(actorApp(app), 'verificacion.replay', enrol.id, { ip_hash: ipHash, locked_until: hasta });
      if (hasta) auditar(actorApp(app), 'enrolamiento.bloqueado', enrol.id, { locked_until: hasta, origen: 'verificacion' });
    });
    metrica(resultado);
    if (resultado !== 'ok') return errorGenerico('codigo');

    return {
      status: 200,
      cuerpo: {
        verified: true,
        token,
        jti: claims.jti,
        kid,
        expires_at: iso(claims.exp * 1000),
        drift_steps: derivaFinal,
        // Solo el nivel: el integrador puede pedir un paso adicional si es HIGH/CRITICAL, pero
        // nunca recibe puntuación, razones ni umbrales del detector.
        risk: riesgoContrato(evaluacion),
      },
      cabeceras: { 'Cache-Control': 'no-store' },
    };
  }

  /**
   * POST /api/v1/verify — ESQUEMA_VERIFICAR { user_ref, code, client_ip? }.
   * 200 VerifySuccessResponse | 400 entrada | 401 VERIFICATION_FAILED (código incorrecto, usuario
   * inexistente o código ya usado: idénticos) | 429 TOO_MANY_REQUESTS (bloqueo progresivo o
   * bloqueo adaptativo del detector: idénticos salvo retry_after_seconds).
   * Con ctx.idempotencyKey la respuesta se cachea 5 min por (app.id, clave) y se repite sin reevaluar;
   * reutilizar la clave con otro cuerpo → 400.
   * @param {unknown} entrada @param {{ app: any, ip?: string, idempotencyKey?: string }} ctx
   * @returns {Promise<Respuesta>}
   */
  async function verificar(entrada, ctx) {
    const { app, ip, idempotencyKey } = ctx ?? {};
    if (!app) return errorGenerico('credenciales');
    const v = validar(separarEntrada(entrada).cuerpo, ESQUEMA_VERIFICAR);
    if (!v) return errorEntrada();
    const origen = resolverOrigen(v.client_ip, ip);
    if (!origen.ok) return errorEntrada();
    if (idempotencyKey === undefined || idempotencyKey === null || idempotencyKey === '') return verificarInterno(v, app, origen.ip);
    if (typeof idempotencyKey !== 'string' || !PATRON_IDEMPOTENCIA.test(idempotencyKey)) return errorEntrada();

    const clave = `${app.id}:${idempotencyKey}`;
    const h = huella(v);
    const previa = idempotencia.obtener(clave);
    if (previa) {
      if (previa.huella !== h) return errorEntrada();
      return structuredClone(await previa.respuesta);
    }
    const respuesta = verificarInterno(v, app, origen.ip);
    idempotencia.poner(clave, { huella: h, respuesta });
    try {
      return structuredClone(await respuesta);
    } catch (error) {
      idempotencia.borrar(clave); // un fallo interno no se cachea
      throw error;
    }
  }

  // ------------------------------------------------------------------ validarToken
  /**
   * POST /api/v1/tokens/validate — ESQUEMA_VALIDAR_TOKEN { token, consume_jti? = true }.
   * 200 { valid: true, sub, aud, jti, kid, amr, exp } | 200 { valid: false, reason } | 400 entrada.
   * La audiencia exigida es el client_id de la app que llama; el jti se consume una sola vez.
   * @param {unknown} entrada @param {{ app: any }} ctx @returns {Promise<Respuesta>}
   */
  async function validarToken(entrada, ctx) {
    const { app } = ctx ?? {};
    if (!app) return errorGenerico('credenciales');
    const v = validar(separarEntrada(entrada).cuerpo, ESQUEMA_VALIDAR_TOKEN);
    if (!v) return errorEntrada();
    const ahora = reloj();
    const r = verifyMfaJwt(v.token, {
      buscarClave: (kid) => firmas.buscarClave(kid), issuer: config.emisorJwt, audience: app.client_id, ahora,
    });
    if (!r.valid) return { status: 200, cuerpo: { valid: false, reason: r.reason }, cabeceras: { 'Cache-Control': 'no-store' } };
    const { claims, header } = r;
    if (typeof claims.jti !== 'string' || claims.jti.length === 0) {
      return { status: 200, cuerpo: { valid: false, reason: 'formato' }, cabeceras: {} };
    }
    const yaUsado = v.consume_jti === false
      ? repos.consumedJti.estaConsumido(claims.jti)
      : !repos.consumedJti.consumir(claims.jti, iso(claims.exp * 1000));
    if (yaUsado) {
      auditar(actorApp(app), 'token.reutilizado', claims.jti, { kid: header.kid });
      return { status: 200, cuerpo: { valid: false, reason: 'jti_consumido' }, cabeceras: { 'Cache-Control': 'no-store' } };
    }
    return {
      status: 200,
      cuerpo: {
        valid: true,
        sub: claims.sub,
        aud: app.client_id,
        jti: claims.jti,
        kid: header.kid,
        amr: Array.isArray(claims.amr) ? claims.amr : [],
        exp: claims.exp,
      },
      cabeceras: { 'Cache-Control': 'no-store' },
    };
  }

  // ------------------------------------------------------------------ resincronizar
  /**
   * POST /api/v1/enrollments/{id}/resync — entrada { id, cuerpo: { code_1, code_2, client_ip? } } (ESQUEMA_RESINCRONIZAR).
   * 200 { resynced: true, drift_steps } | 400 entrada | 401 genérico | 429 bloqueo.
   * Busca dos códigos consecutivos en ±10 pasos y guarda el paso y la deriva (anti replay atómico).
   * Es la única vía para fijar una deriva mayor que la ventana: verify la acota a max(|deriva|, ventana).
   * @param {unknown} entrada @param {{ app: any }} ctx @returns {Promise<Respuesta>}
   */
  async function resincronizar(entrada, ctx) {
    const { app } = ctx ?? {};
    if (!app) return errorGenerico('credenciales');
    const { id, cuerpo } = separarEntrada(entrada);
    const v = validar(cuerpo, ESQUEMA_RESINCRONIZAR);
    if (!v || typeof id !== 'string' || !PATRON_UUID.test(id) || !resolverOrigen(v.client_ip, ctx.ip).ok) return errorEntrada();
    const ahora = reloj();
    const enrol = enrolamientoDeApp(id, app);
    if (!enrol || enrol.estado !== 'activo') return errorGenerico('codigo');
    const restante = bloqueos.restanteEnrolamiento(enrol, ahora);
    if (restante > 0) return respuestaBloqueo(restante);

    const semilla = semillaDe(vault, enrol);
    let r;
    try {
      r = resyncTwoConsecutiveCodes(semilla, v.code_1, v.code_2, ahora, {
        algoritmo: enrol.algoritmo, digitos: enrol.digitos, periodo: enrol.periodo, rango: 10, lastStep: enrol.last_step,
      });
    } finally {
      semilla.fill(0);
    }
    const ok = repos.transaccion(() => {
      if (r.valid && repos.enrollments.registrarPasoAceptado(enrol.id, r.matchedStep, r.driftSteps)) return true;
      bloqueos.falloEnrolamiento(enrol.id, app.max_intentos, ahora);
      return false;
    });
    if (!ok) return errorGenerico('codigo');
    auditar(actorApp(app), 'enrolamiento.resincronizado', enrol.id, { drift_steps: r.driftSteps, drift_anterior: enrol.drift_steps });
    return { status: 200, cuerpo: { resynced: true, drift_steps: r.driftSteps }, cabeceras: {} };
  }

  // ------------------------------------------------------------------ recuperar
  /**
   * POST /api/v1/recovery — ESQUEMA_RECUPERAR { user_ref, recovery_code, client_ip? }.
   * 200 { recovered: true, must_reenroll: true, remaining_codes } | 400 entrada | 401 genérico | 429 bloqueo.
   * Consume el código (atómico) y revoca el enrolamiento: el usuario debe volver a enrolarse.
   * @param {unknown} entrada @param {{ app: any, ip?: string }} ctx @returns {Promise<Respuesta>}
   */
  async function recuperar(entrada, ctx) {
    const { app, ip } = ctx ?? {};
    if (!app) return errorGenerico('credenciales');
    const v = validar(separarEntrada(entrada).cuerpo, ESQUEMA_RECUPERAR);
    if (!v) return errorEntrada();
    const origen = resolverOrigen(v.client_ip, ip);
    if (!origen.ok) return errorEntrada();
    const ahora = reloj();
    const urh = userRefHash(v.user_ref);
    const ipHash = anonimizarOrigen(app.id, origen.ip, config.ipPepperSemilla, ahora);
    const enrol = repos.enrollments.buscarActivoPorUsuario(app.id, urh);
    const restante = enrol ? bloqueos.restanteEnrolamiento(enrol, ahora) : bloqueos.restanteInexistente(app.id, urh, app.max_intentos, ahora);
    if (restante > 0) return respuestaBloqueo(restante);

    const codigo = normalizarCodigoRecuperacion(v.recovery_code);
    const candidatos = enrol ? repos.recoveryCodes.listarNoUsados(enrol.id) : [];
    let acierto = null;
    if (codigo) {
      for (const c of candidatos) {
        if (await verificarSecretoAsync(codigo, c.code_hash)) { acierto = c; break; }
      }
    }
    if (candidatos.length === 0 || !codigo) await verificarSecretoAsync('AAAA-AAAA', HASH_FICTICIO);

    const ahoraIso = iso(ahora);
    let restantes = null;
    if (acierto) {
      restantes = repos.transaccion(() => {
        if (!repos.recoveryCodes.marcarUsado(acierto.id, ahoraIso)) return null;
        repos.enrollments.revocar(enrol.id, ahoraIso);
        repos.attempts.registrar({ enrollment_id: enrol.id, app_id: app.id, user_ref_hash: urh, ip_hash: ipHash, resultado: 'ok', ts: ahoraIso });
        return repos.recoveryCodes.listarNoUsados(enrol.id).length;
      });
    }
    if (restantes === null) {
      let hasta;
      if (enrol) {
        hasta = repos.transaccion(() => {
          repos.attempts.registrar({ enrollment_id: enrol.id, app_id: app.id, user_ref_hash: urh, ip_hash: ipHash, resultado: 'invalid_code', ts: ahoraIso });
          return bloqueos.falloEnrolamiento(enrol.id, app.max_intentos, ahora);
        });
      } else {
        hasta = repos.transaccion(() => {
          repos.attempts.registrar({ app_id: app.id, user_ref_hash: urh, ip_hash: ipHash, resultado: 'invalid_code', ts: ahoraIso });
          return bloqueos.falloInexistente(app.id, urh, app.max_intentos, ahora);
        });
      }
      auditar(actorApp(app), 'recuperacion.fallida', enrol?.id ?? null, { ip_hash: ipHash, locked_until: hasta ?? null });
      return errorGenerico('codigo');
    }
    auditar(actorApp(app), 'recuperacion.aceptada', enrol.id, { recovery_codes_restantes: restantes, revocado: true });
    return { status: 200, cuerpo: { recovered: true, must_reenroll: true, remaining_codes: restantes }, cabeceras: { 'Cache-Control': 'no-store' } };
  }

  // ------------------------------------------------------------------ revocar
  /**
   * DELETE /api/v1/enrollments/{id} — entrada { id } (cuerpo vacío, ESQUEMA_VACIO).
   * 200 { enrollment_id, estado: 'revocado', revoked_at } | 400 id inválido | 404 genérico si no
   * existe o pertenece a otra app. Idempotente: revocar de nuevo devuelve la fecha original.
   * @param {unknown} entrada @param {{ app: any }} ctx @returns {Promise<Respuesta>}
   */
  async function revocar(entrada, ctx) {
    const { app } = ctx ?? {};
    if (!app) return errorGenerico('credenciales');
    const { id, cuerpo } = separarEntrada(entrada);
    if (typeof id !== 'string' || !PATRON_UUID.test(id)) return errorEntrada();
    if (cuerpo !== undefined && cuerpo !== null && !validar(cuerpo, ESQUEMA_VACIO)) return errorEntrada();
    const enrol = enrolamientoDeApp(id, app);
    if (!enrol) return noEncontrado();
    const ahoraIso = iso(reloj());
    if (repos.enrollments.revocar(enrol.id, ahoraIso)) {
      auditar(actorApp(app), 'enrolamiento.revocado', enrol.id, { motivo: 'solicitud_integrador' });
    }
    const final = repos.enrollments.buscarPorId(enrol.id);
    return { status: 200, cuerpo: { enrollment_id: enrol.id, estado: 'revocado', revoked_at: final.revoked_at ?? ahoraIso }, cabeceras: {} };
  }

  // ------------------------------------------------------------------ jwks
  /**
   * GET /.well-known/jwks.json — sin autenticación ni ctx. 200 { keys: [...] }.
   * @returns {Promise<Respuesta>}
   */
  async function jwks() {
    return { status: 200, cuerpo: firmas.jwks(), cabeceras: { 'Cache-Control': 'public, max-age=300' } };
  }

  return { enrolar, activar, verificar, validarToken, resincronizar, recuperar, revocar, jwks };
}
