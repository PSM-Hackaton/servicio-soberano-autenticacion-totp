// Configuración del portal: parser propio de .env (sin dependencias) + valores por defecto.

import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const RAIZ = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Parser de .env: CLAVE=valor, comentarios con #, comillas simples o dobles, `export ` opcional.
 * No interpola variables ni ejecuta nada.
 * @param {string} texto @returns {Record<string, string>}
 */
export function parsearEnv(texto) {
  /** @type {Record<string, string>} */
  const salida = {};
  for (const lineaCruda of texto.split(/\r?\n/)) {
    const linea = lineaCruda.trim();
    if (!linea || linea.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(linea);
    if (!m) continue;
    let valor = m[2];
    if ((valor.startsWith('"') && valor.endsWith('"') && valor.length >= 2)) {
      valor = valor.slice(1, -1).replace(/\\n/g, '\n').replace(/\\"/g, '"');
    } else if (valor.startsWith("'") && valor.endsWith("'") && valor.length >= 2) {
      valor = valor.slice(1, -1);
    } else {
      valor = valor.replace(/\s+#.*$/, '').trim();
    }
    salida[m[1]] = valor;
  }
  return salida;
}

/** Lee demo-portal-tramites/.env si existe; las variables de entorno del proceso tienen prioridad. */
export function cargarEnv(ruta = resolve(RAIZ, '.env')) {
  const archivo = existsSync(ruta) ? parsearEnv(readFileSync(ruta, 'utf8')) : {};
  return { ...archivo, ...Object.fromEntries(Object.entries(process.env).filter(([k]) => k in archivo || /^(PORTAL_|TOTP_)/.test(k))) };
}

const rutaRel = (p) => (p ? resolve(RAIZ, p) : null);

/**
 * Configuración efectiva.
 * @param {Record<string, string>} env
 */
export function configuracion(env = cargarEnv()) {
  // Sin valor por defecto: el client_id lo emite el servicio (npm run seed o la consola admin).
  const clientId = (env.TOTP_CLIENT_ID ?? '').trim();
  if (!clientId || /COPIAR|CAMBIAR|CHANGE_ME/i.test(clientId)) {
    throw new Error('Falta TOTP_CLIENT_ID en demo-portal-tramites/.env: copie el client_id (app_…) que imprime `cd backend && npm run seed` o el de una app registrada en la consola admin.');
  }
  const tlsCert = rutaRel(env.PORTAL_TLS_CERT ?? '../backend/certs/localhost.crt');
  const tlsKey = rutaRel(env.PORTAL_TLS_KEY ?? '../backend/certs/localhost.key');
  return {
    host: env.PORTAL_HOST ?? '127.0.0.1',
    puerto: Number(env.PORTAL_PUERTO ?? 8444),
    tls: tlsCert && tlsKey && existsSync(tlsCert) && existsSync(tlsKey) ? { cert: tlsCert, key: tlsKey } : null,
    servicio: {
      baseUrl: env.TOTP_BASE_URL ?? 'https://localhost:8443',
      clientId,
      clientSecret: env.TOTP_CLIENT_SECRET ?? '',
      caPath: rutaRel(env.TOTP_CA_PATH ?? ''),
      issuer: env.TOTP_ISSUER ?? 'https://totp.soberano.local',
      audience: env.TOTP_AUDIENCE || clientId,
      timeoutMs: Number(env.TOTP_TIMEOUT_MS ?? 3000),
    },
    autenticadorUrl: env.AUTENTICADOR_URL ?? 'https://localhost:8443/app/',
    etiquetaCuenta: env.PORTAL_ETIQUETA_CUENTA ?? 'Portal de Trámites',
    archivoUsuarios: rutaRel(env.PORTAL_USUARIOS ?? 'datos/usuarios.json'),
    // Derivación del user_ref desde la cédula (modo 'hmac' de la app en el servicio): el secreto es el
    // `cedula_secreto` que devolvió el servicio al registrar la app y el prefijo su `cedula_prefijo`.
    // Vacío = secreto local en datos/seudonimos.clave (sin búsqueda por cédula en la consola).
    secretoSeudonimos: (env.TOTP_CEDULA_SECRETO ?? '').trim(),
    prefijoSeudonimos: (env.TOTP_CEDULA_PREFIJO ?? 'ptd-').trim(),
    trazasPorDefecto: (env.PORTAL_TRAZAS ?? '1') !== '0',
    sesionMinutos: Number(env.PORTAL_SESION_MINUTOS ?? 15),
    // Solo si hay un proxy inverso PROPIO delante del portal: entonces la IP del ciudadano llega en
    // X-Forwarded-For (última entrada). Por defecto se usa la dirección del socket.
    confiarXForwardedFor: env.PORTAL_CONFIAR_X_FORWARDED_FOR === '1',
  };
}
