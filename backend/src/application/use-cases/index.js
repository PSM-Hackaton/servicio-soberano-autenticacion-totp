// Capa de aplicación: une núcleo (TOTP, bóveda, tokens, QR), seguridad, persistencia,
// auditoría y detector de anomalías en los casos de uso que expone el servidor HTTP.
//
// Convenciones para el servidor (backend/src/api/):
//   - Cada caso de uso es async (entrada, ctx) => { status, cuerpo, cabeceras? }.
//   - entrada = cuerpo JSON ya parseado para rutas sin parámetro; { id, cuerpo } para rutas con
//     {id} (también se acepta { params: { id }, cuerpo | body }); el objeto de la query string
//     (Object.fromEntries(searchParams)) para las rutas GET de administración.
//   - ctx = { app } (fila autenticada con autenticarApp) para /api/v1/*, { admin } para /admin/api/*,
//     más ip (en claro; aquí se anonimiza con pepper diario) e idempotencyKey (cabecera Idempotency-Key).
//
// Rutas atendidas:
//   POST   /api/v1/enrollments                → enrolar            201 | 400 | 401
//   POST   /api/v1/enrollments/{id}/activate  → activar            200 | 400 | 401 | 429
//   POST   /api/v1/verify                     → verificar          200 | 400 | 401 | 429
//   POST   /api/v1/tokens/validate            → validarToken       200 | 400 | 401
//   POST   /api/v1/enrollments/{id}/resync    → resincronizar      200 | 400 | 401 | 429
//   POST   /api/v1/recovery                   → recuperar          200 | 400 | 401 | 429
//   DELETE /api/v1/enrollments/{id}           → revocar            200 | 400 | 401 | 404
//   GET    /.well-known/jwks.json             → jwks               200
//   POST   /admin/api/login                   → adminLogin         200 | 400 | 401 | 429
//   GET    /admin/api/apps                    → adminListarApps    200 | 401 | 403
//   POST   /admin/api/apps                    → adminActualizarApp 201 | 200 | 400 | 401 | 403 | 404
//   POST   /admin/api/apps/{id}/secret        → adminRegenerarSecretoApp 200 | 400 | 401 | 403 | 404
//   GET    /admin/api/enrollments             → adminListarEnrolamientos 200 | 400 | 401 | 403 | 404 | 409
//          (con ?cedula= o ?user_ref= y app_id: búsqueda de soporte auditada)
//   POST   /admin/api/enrollments/{id}/suspend    → adminSuspenderEnrolamiento 200 | 400 | 401 | 403 | 404 | 409
//   POST   /admin/api/enrollments/{id}/reactivate → adminReactivarEnrolamiento 200 | 400 | 401 | 403 | 404 | 409
//   POST   /admin/api/enrollments/{id}/revoke     → adminRevocarEnrolamiento   200 | 400 | 401 | 403 | 404 | 409
//   GET    /admin/api/keys                    → adminListarLlaves  200 | 400 | 401 | 403
//   POST   /admin/api/keys/rotate             → adminRotarLlaves   200 | 400 | 401 | 403
//   GET    /admin/api/audit                   → adminAuditoria     200 | 400 | 401 | 403
//   GET    /admin/api/audit/verify-chain      → adminVerificarCadena 200 | 401 | 403
//   GET    /admin/api/anomalies               → adminAnomalias     200 | 400 | 401 | 403
//   GET    /admin/api/metrics                 → adminMetricas      200 | 401 | 403

import { crearConsultas } from './consultas.js';
import { crearControlBloqueos } from './bloqueos.js';
import { crearCasosMfa } from './mfa.js';
import { crearCasosAdmin } from './admin.js';

export { puede, MATRIZ_RBAC, ACCIONES } from './rbac.js';

/**
 * @typedef {object} ConfigCasos
 * @property {string} userRefPepper Pepper de user_ref_hash = HMAC-SHA256(user_ref, pepper).
 * @property {string} ipPepperSemilla Semilla del pepper diario de ip_hash.
 * @property {string} emisorTotp issuer del URI otpauth://.
 * @property {string} emisorJwt iss del JWT MFA.
 * @property {number} ttlJwtSegundos Vida del JWT (300 según contrato).
 * @property {number} minutosPendiente Caducidad del enrolamiento pendiente (10).
 * @property {number} [segundosBloqueoAnomalia] Retry-After del bloqueo adaptativo (300).
 * @property {number} [esperaExtraMs] Retardo ante 'espera_extra' en modo bloqueo (0 = sin retardo).
 * @property {number} [ventanaInexistentesMin] Ventana (min) de fallos de usuarios sin enrolamiento
 *   contados desde attempts para su bloqueo progresivo (BLOQUEO_INEXISTENTES_VENTANA_MIN, 1440).
 * @property {'local' | 'monitorizacion' | 'mock'} [modoHeuristica] HEURISTICS_MODE. 'monitorizacion'
 *   prevalece sobre modo_heuristica de cada app: nunca se bloquea por anomalía, solo se alerta y audita.
 */

/**
 * @typedef {object} DependenciasCasos
 * @property {ReturnType<typeof import('../../infrastructure/persistence/repositorios.js').crearRepositorios>} repos
 * @property {ReturnType<typeof import('../../core/vault/vault.js').crearVault>} vault
 * @property {{ activa(): { kid: string, privateKey: any }, jwks(): { keys: any[] }, buscarClave(kid: string): any, recargar(): any, rotar(rotadaEn?: string): { new_kid: string, previous_kid: string | null, rotated_at: string } }} firmas
 * @property {{ evaluar(intento: any, historial: any[], ahora: number): any }} detector
 * @property {{ registrar(e: { actor: string, accion: string, objetivo?: string | null, detalle?: unknown }): any }} bitacora
 * @property {ReturnType<typeof import('../../audit/metricas.js').crearMetricas>} metricas
 * @property {ConfigCasos} config
 * @property {() => number} [reloj] Epoch ms (inyectable en pruebas).
 * @property {import('node:sqlite').DatabaseSync} [db] Conexión opcional para consultas de lectura que
 *   los repositorios no exponen (historial de intentos por cuenta, listado de enrolamientos y anomalías).
 */

/**
 * Construye todos los casos de uso.
 * @param {DependenciasCasos} deps
 */
export function crearCasosDeUso(deps) {
  const { repos, vault, firmas, detector, bitacora, metricas, config, reloj = () => Date.now(), db = null } = deps ?? {};
  for (const [nombre, valor] of Object.entries({ repos, vault, firmas, detector, bitacora, config })) {
    if (!valor) throw new Error(`Falta la dependencia ${nombre}`);
  }
  if (typeof detector.evaluar !== 'function') throw new Error('El detector debe exponer evaluar()');
  for (const clave of ['userRefPepper', 'ipPepperSemilla', 'emisorTotp', 'emisorJwt']) {
    if (typeof config[clave] !== 'string' || config[clave].length === 0) throw new Error(`Falta config.${clave}`);
  }

  const consultas = crearConsultas({ repos, db });
  const bloqueos = crearControlBloqueos({ repos, reloj, ventanaInexistentesMin: config.ventanaInexistentesMin });
  const comunes = { repos, vault, firmas, detector, bitacora, metricas, config, reloj, consultas, bloqueos };

  return Object.freeze({ ...crearCasosMfa(comunes), ...crearCasosAdmin(comunes) });
}
