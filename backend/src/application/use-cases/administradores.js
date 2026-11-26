// Alta de cuentas de la consola con su propio factor TOTP. Lo usan la semilla
// (backend/scripts/semilla.js, primer Administrador) y POST /admin/api/admins.
//
// Activación del TOTP: el servicio genera la semilla y activa el enrolamiento en el mismo acto,
// con el código del paso actual derivado de la propia URI (como hacía la semilla). Se eligió así
// porque es lo más simple y no deja ninguna ventana en la que exista una cuenta con solo contraseña
// ni un enrolamiento pendiente que caduque: la contraseña, la URI otpauth y el QR se entregan UNA
// sola vez a quien crea la cuenta, que los hace llegar a su titular por un canal separado; el
// primer inicio de sesión (contraseña + código) demuestra que el factor quedó bien instalado.
// El código del paso actual ya se consumió al activar: el primer login usa el siguiente.

import { randomBytes } from 'node:crypto';
import { generateTotp } from '../../core/totp/totp.js';
import { base32Decode } from '../../core/totp/base32.js';
import { hashSecretoAsync } from '../../security/index.js';

/** Nombre de la app interna que aloja los factores TOTP de la consola. */
export const APP_CONSOLA = 'Consola Administrativa';

/** Bytes aleatorios de la contraseña inicial (144 bits → 24 caracteres base64url). */
const BYTES_PASSWORD = 18;

/**
 * Devuelve la app interna de la consola y la crea si no existe (su client_secret se descarta: no
 * integra a nadie; solo aloja los enrolamientos de los administradores).
 * @param {{ repos: any, casos: { adminActualizarApp: Function }, ctxAdmin: { admin: any } }} d
 */
export async function asegurarAppConsola({ repos, casos, ctxAdmin }) {
  const existente = repos.apps.listar().find((a) => a.nombre === APP_CONSOLA);
  if (existente) return existente;
  const r = await casos.adminActualizarApp({ nombre: APP_CONSOLA }, ctxAdmin);
  if (r.status !== 201) throw new Error(`No se pudo registrar la app ${APP_CONSOLA} (HTTP ${r.status})`);
  return repos.apps.buscarPorId(r.cuerpo.app.id);
}

/**
 * Crea un administrador con contraseña aleatoria fuerte y TOTP activo en la app de la consola.
 * Quien llama comprueba antes que el usuario no exista y registra la auditoría de la cuenta.
 * @param {{
 *   repos: any,
 *   casos: { enrolar: Function, activar: Function, adminActualizarApp: Function },
 *   reloj?: () => number,
 *   usuario: string,
 *   rol: 'Administrador' | 'Operador' | 'Auditor',
 *   ctxAdmin: { admin: any },
 * }} d
 * @returns {Promise<{ admin: any, password: string, otpauthUri: string, qrSvg: string, codigosRecuperacion: string[] }>}
 */
export async function provisionarAdministrador({ repos, casos, reloj = () => Date.now(), usuario, rol, ctxAdmin }) {
  const consola = await asegurarAppConsola({ repos, casos, ctxAdmin });
  const ctxApp = { app: consola, ip: '127.0.0.1' };
  const enrol = await casos.enrolar({ user_ref: `admin:${usuario}`, account_label: usuario }, ctxApp);
  if (enrol.status !== 201) throw new Error(`No se pudo crear el enrolamiento del administrador (HTTP ${enrol.status})`);
  const { enrollment_id: enrollmentId, otpauth_uri: uri, qr_svg: qr, algoritmo, digitos, periodo } = enrol.cuerpo;

  // Activación con el código actual derivado de la propia URI (la semilla no se guarda en ningún sitio).
  const semilla = base32Decode(new URL(uri).searchParams.get('secret') ?? '');
  let codigo;
  try {
    codigo = generateTotp(semilla, reloj(), { algoritmo, digitos, periodo });
  } finally {
    semilla.fill(0);
  }
  const act = await casos.activar({ id: enrollmentId, cuerpo: { code: codigo } }, ctxApp);
  if (act.status !== 200) throw new Error(`No se pudo activar el TOTP del administrador (HTTP ${act.status})`);

  const password = randomBytes(BYTES_PASSWORD).toString('base64url');
  let admin;
  try {
    admin = repos.admins.crear({ usuario, password_hash: await hashSecretoAsync(password), rol, totp_enrollment_id: enrollmentId });
  } catch (error) {
    repos.enrollments.revocar(enrollmentId); // sin cuenta, el factor recién creado no debe quedar vivo
    throw error;
  }
  return { admin, password, otpauthUri: uri, qrSvg: qr, codigosRecuperacion: act.cuerpo.recovery_codes ?? [] };
}
