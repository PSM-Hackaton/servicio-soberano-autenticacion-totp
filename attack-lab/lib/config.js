// Configuración del laboratorio: argumentos de línea de órdenes + variables de entorno.
// Regla de seguridad: solo se ataca a nuestro propio servicio local (localhost / 127.0.0.1 / ::1)
// salvo que se pase explícitamente --permitir-host (entornos propios, nunca de terceros).

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const RAIZ_LAB = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const RAIZ_REPO = resolve(RAIZ_LAB, '..');

const HOSTS_LOCALES = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

/** ¿El nombre de host es la propia máquina? */
export function esHostLocal(host) {
  const h = String(host ?? '').toLowerCase().replace(/\.$/, '');
  return HOSTS_LOCALES.has(h) || h.endsWith('.localhost') || /^127(\.\d{1,3}){3}$/.test(h);
}

/**
 * Lanza un error si el destino no es local y no se permitió explícitamente.
 * @param {string} url @param {boolean} permitirHost
 */
export function exigirDestinoPermitido(url, permitirHost) {
  let u;
  try {
    u = new URL(url);
  } catch {
    throw new Error(`URL de destino inválida: ${url}`);
  }
  if (!['https:', 'http:'].includes(u.protocol)) throw new Error(`Protocolo no soportado: ${u.protocol}`);
  if (!esHostLocal(u.hostname) && !permitirHost) {
    throw new Error(
      `Destino "${u.hostname}" rechazado: el laboratorio solo ataca a localhost/127.0.0.1. ` +
      'Si es un entorno PROPIO, repite con --permitir-host (nunca contra sistemas de terceros).',
    );
  }
  return u;
}

/**
 * Analizador mínimo de argumentos: --clave valor, --clave=valor, --bandera, y posicionales.
 * @param {string[]} argv
 * @returns {{ opciones: Record<string, string | boolean>, posicionales: string[] }}
 */
export function analizarArgumentos(argv) {
  /** @type {Record<string, string | boolean>} */
  const opciones = {};
  const posicionales = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { posicionales.push(...argv.slice(i + 1)); break; }
    if (!a.startsWith('--')) { posicionales.push(a); continue; }
    const cuerpo = a.slice(2);
    const igual = cuerpo.indexOf('=');
    if (igual >= 0) { opciones[cuerpo.slice(0, igual)] = cuerpo.slice(igual + 1); continue; }
    const siguiente = argv[i + 1];
    if (siguiente !== undefined && !siguiente.startsWith('--')) { opciones[cuerpo] = siguiente; i++; } else opciones[cuerpo] = true;
  }
  return { opciones, posicionales };
}

function leerCredencialesArchivo(ruta) {
  const datos = JSON.parse(readFileSync(ruta, 'utf8'));
  // Formatos aceptados: { client_id, client_secret } o { apps: [ {...}, {...} ] } o [ {...} ].
  const lista = Array.isArray(datos) ? datos : Array.isArray(datos.apps) ? datos.apps : [datos];
  return lista
    .map((a) => ({ clientId: a.client_id ?? a.clientId, clientSecret: a.client_secret ?? a.clientSecret }))
    .filter((a) => a.clientId && a.clientSecret);
}

/** Busca la CA local generada por el backend si no se indicó ninguna. */
function buscarCaLocal() {
  const candidatos = [
    join(RAIZ_REPO, 'backend', 'certs', 'ca.crt'),
    join(RAIZ_REPO, 'backend', 'certs', 'localhost.crt'),
    join(RAIZ_REPO, 'certs', 'localhost.crt'),
  ];
  return candidatos.find((c) => existsSync(c)) ?? null;
}

const num = (v, defecto) => (v === undefined || v === true || v === '' ? defecto : Number(v));

/**
 * Construye la configuración final.
 * Precedencia: argumento > variable de entorno > archivo de credenciales > valor por defecto.
 * @param {string[]} [argv] @param {NodeJS.ProcessEnv} [env]
 */
export function cargarConfig(argv = process.argv.slice(2), env = process.env) {
  const { opciones: o, posicionales } = analizarArgumentos(argv);
  const url = String(o.url ?? env.ATTACK_URL ?? 'https://localhost:8443').replace(/\/+$/, '');
  const permitirHost = Boolean(o['permitir-host'] ?? (env.ATTACK_PERMITIR_HOST === '1'));
  const destino = exigirDestinoPermitido(url, permitirHost);

  const inseguro = Boolean(o.inseguro ?? (env.ATTACK_INSEGURO === '1'));
  if (inseguro && !esHostLocal(destino.hostname)) {
    throw new Error('--inseguro solo se permite contra localhost (no desactives la verificación TLS en otros hosts).');
  }

  let apps = [];
  const archivo = o.credenciales ?? env.ATTACK_CREDENCIALES;
  if (archivo) apps = leerCredencialesArchivo(String(archivo));
  const id1 = o['client-id'] ?? env.ATTACK_CLIENT_ID;
  const secreto1 = o['client-secret'] ?? env.ATTACK_CLIENT_SECRET;
  if (id1 && secreto1) apps[0] = { clientId: String(id1), clientSecret: String(secreto1) };
  const id2 = o['client-id-2'] ?? env.ATTACK_CLIENT_ID_2;
  const secreto2 = o['client-secret-2'] ?? env.ATTACK_CLIENT_SECRET_2;
  if (id2 && secreto2) apps[1] = { clientId: String(id2), clientSecret: String(secreto2) };

  const ca = o.ca ?? env.ATTACK_CA ?? (inseguro ? null : buscarCaLocal());

  return {
    url,
    destino,
    permitirHost,
    inseguro,
    ca: ca ? String(ca) : null,
    apps: apps.filter(Boolean),
    color: !(o['sin-color'] || env.NO_COLOR) && process.stdout.isTTY !== false,
    detallado: Boolean(o.detallado),
    timeoutMs: num(o.timeout ?? env.ATTACK_TIMEOUT_MS, 5000),
    ventana: num(o.ventana, 1),
    maxIntentos: num(o['max-intentos'], 5),
    usarXff: o.xff === undefined ? 'auto' : o.xff === true ? 'si' : String(o.xff),
    opciones: o,
    posicionales,
  };
}

/** Lee un número de las opciones crudas. */
export function opcionNumero(config, nombre, defecto) {
  return num(config.opciones[nombre], defecto);
}
